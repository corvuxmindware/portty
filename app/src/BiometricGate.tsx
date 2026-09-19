/**
 * Biometric app-lock gate (D2 hardening).
 *
 * Wraps the entire app. Two lifecycle rules drive it:
 *
 *   1. COLD START - the app's first mount is GATED behind a successful unlock.
 *      Until the owner authenticates, `<App/>` is not mounted at all, so nothing
 *      dials the host, no terminals render, no xterm initializes. This is the
 *      `bootstrapped` signal: it flips true exactly once.
 *
 *   2. BACKGROUND RESUME - when the app returns from background
 *      (`document.visibilitychange` hidden→visible), it re-locks by showing the
 *      lock screen as an OVERLAY. Crucially the app underneath stays mounted -
 *      remounting would destroy the xterm instance and drop the iroh connection.
 *      So after the first unlock we never unmount the children; we just cover
 *      them.
 *
 * Graceful degradation: the gate passes through only when there is genuinely
 * nothing to enforce - the user disabled it in prefs, the device has no owner
 * credential at all ("none"), or the plugin isn't registered ("unsupported",
 * e.g. desktop dev). A biometry LOCKOUT does NOT pass through - it fails closed
 * and prompts, so the OS passcode fallback still gates the owner (see D2).
 *
 * Threat model: stops the casual "someone picks up your unlocked phone and opens
 * Portty" case. NOT a hardened boundary against webview injection - the real
 * trust boundary is the host's pairing/crypto. See Portty/13 (D2).
 */
import {
  createEffect,
  createSignal,
  onCleanup,
  onMount,
  Show,
  type ParentComponent,
} from "solid-js";
import { Icon } from "./Icon";
import logo from "./assets/logo.png";
import {
  biometricAvailability,
  getBiometricPref,
  mustGate,
  promptBiometric,
} from "./lib/biometric";

type Phase = "checking" | "locked" | "unlocked";

export const BiometricGate: ParentComponent = (props) => {
  // `bootstrapped` flips true exactly once the app has been unlocked for the
  // first time; before that, children don't mount at all.
  const [bootstrapped, setBootstrapped] = createSignal(false);
  // `phase` tracks the current lock state for the overlay / lock screen.
  const [phase, setPhase] = createSignal<Phase>("checking");
  const [error, setError] = createSignal("");
  // Privacy cover for the app-switcher snapshot: raised on the background edge
  // so the OS thumbnail never captures the terminal / a pending approval. This
  // is orthogonal to the biometric lock - it applies even when the lock is off.
  const [covered, setCovered] = createSignal(false);
  // Guards against the prompt re-triggering itself (the BiometricPrompt overlay
  // does NOT change document.visibilityState, but this covers any edge case).
  let attempting = false;

  /**
   * Is the gate enforceable RIGHT NOW (pref on AND a credential to enforce with)?
   *
   * Re-read on every lifecycle transition, never cached from mount. It used to be
   * a plain `let` set once in `onMount`, so turning the lock on while the app was
   * running left the live gate inactive: the settings screen said "on", and the
   * next background→foreground return walked straight back into the app.
   */
  const enforcementActive = async (): Promise<boolean> => {
    if (!getBiometricPref()) return false;
    return mustGate(await biometricAvailability());
  };

  // Tell the Android back handler (App's window.__porttyOnBack) when the app is
  // locked, so a back press backgrounds the app instead of navigating or
  // dismissing anything underneath - and never counts as an unlock.
  createEffect(() => {
    (window as unknown as { __porttyLocked?: boolean }).__porttyLocked =
      !bootstrapped() || phase() === "locked";
  });

  const runPrompt = async () => {
    if (attempting) return;
    attempting = true;
    setError("");
    setPhase("locked");
    const ok = await promptBiometric("Authenticate to access your terminals");
    attempting = false;
    if (ok) {
      setPhase("unlocked");
      setCovered(false);
      setBootstrapped(true);
    } else {
      setError("Authentication canceled. Tap to try again.");
    }
  };

  onMount(async () => {
    // Nothing to enforce: the user disabled the lock, there is no owner
    // credential at all ("none"), or the plugin isn't registered ("unsupported",
    // desktop dev). Pass through rather than brick the app. A biometry LOCKOUT
    // does NOT reach here - mustGate treats it as gate-required, so we fall
    // through to runPrompt() and the OS passcode fallback
    // (allowDeviceCredential) unlocks. (D2 fail-closed.)
    if (!(await enforcementActive())) {
      setBootstrapped(true);
      setPhase("unlocked");
      return;
    }
    await runPrompt();
  });

  // Re-lock on a REAL background→foreground edge. Some Android biometric
  // implementations themselves produce a visible event as their system prompt
  // closes. Remembering the preceding hidden state lets us consume that edge
  // while `attempting` is true instead of immediately prompting again.
  let wasHidden = document.visibilityState === "hidden";
  const onVisibility = () => {
    if (document.visibilityState === "hidden") {
      wasHidden = true;
      // Raise the privacy cover BEFORE the OS snapshots the app switcher, so the
      // thumbnail never shows the terminal, agent chat, or a pending approval.
      // Best-effort in the webview (iOS/Android may snapshot before this fires -
      // native FLAG_SECURE / resign-active is the guaranteed layer); harmless
      // pre-bootstrap because the lock-screen fallback is already up.
      if (bootstrapped()) setCovered(true);
      return;
    }
    if (!wasHidden) return;
    wasHidden = false;
    if (attempting) return;
    if (phase() === "locked") return; // already showing the lock screen
    // Re-read enforcement on the resume edge: the pref may have been turned on
    // (or a credential enrolled) while this instance was already running. The
    // privacy cover stays up across the await so the terminal is never briefly
    // visible while we decide.
    void (async () => {
      if (!(await enforcementActive())) {
        // No lock to re-run - just drop the privacy cover on return.
        setCovered(false);
        return;
      }
      if (attempting || phase() === "locked") return;
      await runPrompt();
    })();
  };
  document.addEventListener("visibilitychange", onVisibility);
  onCleanup(() => document.removeEventListener("visibilitychange", onVisibility));

  return (
    <Show when={bootstrapped()} fallback={<LockScreen error={error()} onUnlock={() => void runPrompt()} busy={phase() === "checking"} />}>
      {/* Instantiate App exactly once. Moving it between two conditional
          branches remounted it on every lock/unlock, and App's onMount reconnect
          then deliberately replaced the healthy iroh connection. */}
      {props.children}
      <Show when={phase() === "locked"}>
        <LockScreen error={error()} onUnlock={() => void runPrompt()} busy={false} overlay />
      </Show>
      {/* Privacy cover for the background snapshot when the app is NOT locked
          (lock disabled/unavailable). When locked, the lock screen above already
          covers everything, so this only fills the no-lock case. */}
      <Show when={covered() && phase() !== "locked"}>
        <div class="portty-lock portty-lock--overlay" aria-hidden="true">
          <img src={logo} class="portty-lock-logo" alt="" />
          <h1 class="portty-lock-title">Portty</h1>
        </div>
      </Show>
    </Show>
  );
};

/** The full-screen lock surface. Used both as the pre-bootstrap fallback and as
 *  the background-resume overlay (overlay = positioned absolutely on top). */
function LockScreen(props: {
  error: string;
  onUnlock: () => void;
  busy: boolean;
  overlay?: boolean;
}) {
  return (
    <div class="portty-lock" classList={{ "portty-lock--overlay": !!props.overlay }}>
      <img src={logo} class="portty-lock-logo" alt="Portty" />
      <h1 class="portty-lock-title">Portty</h1>
      <p class="portty-lock-sub">{props.busy ? "Checking…" : "Authenticate to unlock"}</p>
      <Show when={props.error}>
        <p class="portty-lock-error">{props.error}</p>
      </Show>
      <button class="portty-lock-btn" onClick={props.onUnlock} disabled={props.busy}>
        <Icon name="unlock" />
        Unlock
      </button>
    </div>
  );
}
