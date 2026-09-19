// Biometric app-lock wrapper (D2 security hardening).
//
// Thin layer over `@tauri-apps/plugin-biometric` that adds two things the raw
// plugin doesn't give us:
//   1. Graceful degradation - the plugin is MOBILE-ONLY (Android/iOS). On
//      desktop dev (or any device where the plugin isn't registered) the calls
//      throw; we catch and report "unsupported" so the app stays usable instead
//      of bricking.
//   2. A user preference (localStorage) - the lock defaults ON (this is a
//      remote-shell product) but can be turned off. The pref is a UX toggle, not
//      a security control; the prompt itself is OS-enforced.
//
// Threat model this gate addresses: a casual attacker who picks up an unlocked
// phone and opens Portty to read terminals / approve agent actions. It is NOT a
// hardened boundary against webview injection - the real trust boundary is the
// host's pairing/crypto. See Portty/13 - Real-World Defects & Fixes (D2).
import { invoke } from "@tauri-apps/api/core";
import { authenticate, checkStatus, type Status } from "@tauri-apps/plugin-biometric";

const PREF_KEY = "portty.biometric.enabled";

/** The lock defaults ON. Set to false only if the user explicitly disables it. */
export function getBiometricPref(): boolean {
  const v = localStorage.getItem(PREF_KEY);
  return v === null ? true : v === "1";
}

export function setBiometricPref(on: boolean): void {
  localStorage.setItem(PREF_KEY, on ? "1" : "0");
}

/**
 * Does THIS platform ship the biometric plugin? Answered by the Rust core's
 * `cfg!(mobile)`, so it is a compile-time fact, not a guess from the user agent.
 *
 * Security note: it is the difference between "there is nothing to enforce"
 * (desktop dev, no plugin) and "enforcement is broken" (mobile, plugin call
 * failed). The first may pass through; the second must not.
 */
let enforcedPlatform: boolean | null = null;
export async function platformEnforcesLock(): Promise<boolean> {
  if (enforcedPlatform !== null) return enforcedPlatform;
  try {
    const answer = await invoke<boolean>("biometric_platform_enforced");
    // Cache only a REAL answer. Caching the failure path memoized "not mobile"
    // for the rest of the process: one transient IPC hiccup during startup and
    // every later check - including the one on returning from background - would
    // keep passing through on a phone. A retry costs one IPC round trip.
    enforcedPlatform = answer;
    return answer;
  } catch {
    // No Tauri IPC at all (vitest, plain browser dev) → nothing to enforce, but
    // do not remember it.
    return false;
  }
}

export type BioAvailability =
  | "available" // biometric enrolled → a biometric prompt will work
  | "lockout" // enrolled but TEMPORARILY locked out after failed attempts - a
  //            prompt still works via the device-credential (passcode) fallback
  | "credential" // no usable biometric, but a device passcode CAN still gate
  | "none" // no biometric AND no device passcode → nothing to enforce
  | "unsupported"; // plugin not registered (desktop dev) or the call threw

/**
 * Whether biometric auth can run on THIS device right now, and - crucially - how
 * to treat the not-"available" cases. Never throws.
 *
 * Security note (D2): a biometry LOCKOUT (too many failed attempts) must NOT be
 * treated the same as "no biometric configured". Collapsing both into a single
 * pass-through let an attacker deliberately trigger lockout and then walk into a
 * fully unlocked app. We distinguish them here so the gate can fail CLOSED on
 * lockout - the OS passcode fallback (allowDeviceCredential) still gates the
 * owner. See `mustGate`.
 */
/**
 * Pure classification of an OS biometry `Status` (or `null` when the call
 * failed - plugin not registered / platform unsupported). Extracted so the
 * security-critical mapping is unit-testable without mocking a rejection.
 */
export function classifyBioStatus(s: Status | null): BioAvailability {
  if (!s) return "unsupported"; // the call threw → nothing to enforce
  if (s.isAvailable) return "available";
  switch (s.errorCode) {
    case "biometryLockout":
      return "lockout";
    case "passcodeNotSet":
      return "none"; // no owner credential of any kind → can't enforce
    default:
      // biometryNotEnrolled / biometryNotAvailable / anything else: a device
      // passcode can still gate via allowDeviceCredential, so we prompt.
      return "credential";
  }
}

export async function biometricAvailability(): Promise<BioAvailability> {
  try {
    return classifyBioStatus(await checkStatus());
  } catch {
    // A throw is ambiguous on its own, so ask the core which platform this is.
    // On mobile the plugin is always registered, so the call failing means
    // enforcement is BROKEN, not absent - gate via the device credential rather
    // than hand over the terminals. Desktop dev has no plugin: pass through.
    return (await platformEnforcesLock()) ? "credential" : "unsupported";
  }
}

/**
 * Should the gate ENFORCE (prompt) for this availability, or pass through?
 *
 * Fail-closed by construction: everything except a genuine can't-enforce state
 * ("none" = no credential at all, "unsupported" = no plugin) must gate. In
 * particular "lockout" GATES - that is the exact fail-open this guards against.
 * Pure + unit-tested so the regression can't silently return.
 */
export function mustGate(avail: BioAvailability): boolean {
  return avail === "available" || avail === "lockout" || avail === "credential";
}

/**
 * Prompt the user to authenticate. Resolves true on success, false on cancel or
 * failure. Never throws - the caller just decides whether to stay locked.
 *
 * `allowDeviceCredential: true` lets the user fall back to their phone PIN/pattern
 * if biometric fails (dirty finger, etc.) - standard app-lock UX, and the device
 * credential is still an owner gate, so it doesn't weaken the protection. */
export async function promptBiometric(reason: string): Promise<boolean> {
  try {
    await authenticate(reason, {
      allowDeviceCredential: true,
      title: "Unlock Portty",
      subtitle: reason,
      cancelTitle: "Cancel",
      // Biometric match → immediate unlock (no extra confirmation tap).
      confirmationRequired: false,
    });
    return true;
  } catch {
    return false;
  }
}
