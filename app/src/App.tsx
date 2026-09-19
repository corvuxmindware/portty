import { createEffect, createSignal, on, onCleanup, onMount, Show, For } from "solid-js";
import type { JSX } from "solid-js";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { open, save } from "@tauri-apps/plugin-dialog";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import * as portty from "./lib/portty";
import {
  biometricAvailability,
  getBiometricPref,
  promptBiometric,
  setBiometricPref,
} from "./lib/biometric";
import { AltScreenScanner } from "./lib/altscreen";
import { appIsVisible, ensureNotificationPermission, notifyPendingApproval } from "./lib/notify";
import {
  decisionKey,
  loadDecisionLog,
  migrateDecisionLogFromLocalStorage,
  persistDecisionLog,
} from "./lib/decisionLog";
import { isSensitivePrompt, PredictiveEcho } from "./lib/echo";
import {
  DEFAULT_POLICY,
  hasExactAllowRule,
  learnExactAllowRule,
  permissionCategory,
  permissionToolInput,
  persistentPolicy,
  policyAllows,
  touchesSensitivePath,
} from "./lib/policy";
import {
  dragScrollLines,
  localDisplayModeSequence,
  scaledTerminalFont,
  shouldDragScroll,
  visibleScreenText,
} from "./lib/terminalDisplay";
import type { SessionInfo } from "./lib/portty";
import { Icon } from "./Icon";
import { KeyBar } from "./KeyBar";
import { CommandBar } from "./CommandBar";
import { applyLatches, modifySequence } from "./lib/keys";
import { QrScanner } from "./QrScanner";
import { AgentView } from "./AgentView";
import logo from "./assets/logo.png";

/**
 * Portty phone UI.
 *
 * Four screens, driven by `view()`:
 *   - **list** (home): the sessions on the connected host, each named. Tap one
 *     to open (resume) it; the edit control renames it; the power control ends
 *     it (two-tap armed - the shell on the host dies). The disconnect control
 *     in the header drops the link without
 *     ending anything. A "New session" button goes to the pair screen. When
 *     there are no sessions, only that button shows.
 *   - **pair**: paste the host's `portty1:` ticket + PIN, scan the QR, or
 *     reconnect to the last host by stored token.
 *   - **terminal**: xterm.js + the accessory key bar for one session.
 *   - **agent**: a structured ACP feed for Claude Code, OpenCode, Codex, or Goose -
 *     messages, plans, tools, and approvals without mirroring a terminal TUI.
 *
 * All terminal/agent work happens in the Rust core; this UI just invokes
 * commands and renders the `portty://*` events / binary output channel it emits.
 */

type View = "list" | "pair" | "terminal" | "agent";

/** Convert a single letter to its control byte (Ctrl+C → 0x03). Null otherwise. */

// ── Rendering modes (fixed-size model) ─────────────────────────────────
// The phone never resizes the host PTY. It renders around the PTY's
// authoritative size (learned via the kind=2 size message) in one of two modes:
//   - "fit":   xterm at phone dimensions; long lines soft-wrap readably. Right
//              for shells / append-only streams; WRONG for anything that
//              repaints with cursor math (full-screen apps, Ink TUIs).
//   - "match": xterm at the PTY's real cols×rows, font shrunk to fit the width
//              (pinch to zoom, pan to read). Cursor math is exact by
//              construction. Default for agent sessions; also flipped to
//              automatically while an app is on the alternate screen (vim…).
type RenderMode = "fit" | "match";

const BASE_FONT = 13;
const MIN_FONT = 4;
const MAX_FONT = 24;

// Stops typing past what the backend keeps. Mirrors MAX_HOST_NICKNAME_CHARS in
// src-tauri/src/lib.rs, which stays authoritative - this only spares the user a
// name that silently gets shortened on save.
const MAX_HOST_NAME_LEN = 40;

const policyKey = (host: string) => `portty:approval-policy:${host}`;
/* Auto-opening an agent when an approval arrives is for the NOTIFICATION-TAP
   flow only: you tap a banner, the app comes forward, the host replays its
   queued card, and you should land on that card. It is NOT for ordinary use -
   being yanked off the home screen while deliberately starting a session or
   switching hosts fights the user, and it repeats every time they navigate back.
   The count badge and the per-session amber dot already say what is waiting.
   Armed only when a wake blob is consumed, and time-bounded so a wake whose card
   never arrives (already answered elsewhere) cannot hijack an unrelated approval
   minutes later. */
const WAKE_ATTACH_WINDOW_MS = 15_000;
let wakeAttachUntil = 0;
const armWakeAttach = () => {
  wakeAttachUntil = Date.now() + WAKE_ATTACH_WINDOW_MS;
};
const consumeWakeAttach = () => {
  const armed = Date.now() < wakeAttachUntil;
  wakeAttachUntil = 0;
  return armed;
};


/** Arrow keys in DECCKM application-cursor mode use SS3 (ESC O _) instead of the
 * CSI (ESC [ _) the KeyBar emits. Rewritten per-key when the app requests it. */
const CURSOR_CSI_TO_SS3: Record<string, string> = {
  "\x1b[A": "\x1bOA",
  "\x1b[B": "\x1bOB",
  "\x1b[C": "\x1bOC",
  "\x1b[D": "\x1bOD",
};

/**
 * Erase everything this phone remembers ABOUT a host once its pairing is gone.
 *
 * The decision log is the sensitive part: up to 200 entries of the exact
 * commands, arguments, and paths an agent asked to run on that machine. It used
 * to outlive the credential entirely - remove the host, re-pair it later (or
 * never), and the history was still sitting in localStorage under the same
 * device-id key, inside the app container and so inside an iOS device backup.
 * Removing a host is the user saying they are done with it, so the record of
 * what happened there goes too, along with its approval policy (whose tier must
 * never silently apply to a future re-pair of the same machine).
 */
function forgetHostStorage(host: string): void {
  localStorage.removeItem(policyKey(host));
  // Also clear any pre-migration copy: a host forgotten before its log had been
  // migrated would otherwise leave the old plaintext record behind forever.
  localStorage.removeItem(decisionKey(host));
  void portty.forgetDecisionLog(host);
}

function loadPolicy(host: string): portty.ApprovalPolicy {
  try {
    return persistentPolicy({
      ...DEFAULT_POLICY,
      ...JSON.parse(localStorage.getItem(policyKey(host)) ?? "{}"),
    });
  } catch {
    return DEFAULT_POLICY;
  }
}

/** Monospace advance-width : font-size ratio, for sizing match-mode text. */
function measureCellRatio(fontFamily: string): number {
  const ctx = document.createElement("canvas").getContext("2d");
  if (!ctx) return 0.6;
  ctx.font = `100px ${fontFamily}`;
  const w = ctx.measureText("W").width;
  return w > 0 ? w / 100 : 0.6;
}

export default function App() {
  const [view, setView] = createSignal<View>("list");
  const [paired, setPaired] = createSignal(false);
  const [ticket, setTicket] = createSignal("");
  // The comparison code the host asks a human to confirm. Set mid-handshake by
  // the `portty://pair-code` event and cleared when the attempt ends - it is a
  // live-exchange value, never a saved credential.
  const [pairCode, setPairCode] = createSignal("");
  const [phrase, setPhrase] = createSignal("");
  const [status, setStatus] = createSignal("not paired");

  /** Whether we hold an out-of-band secret to pair WITH.
   *
   *  Since the PIN was removed the secret in the ticket/QR/phrase is the entire
   *  first-pair credential, and there is no weaker path to fall back to. A full
   *  `portty1:`/`portty3:` code carries one; a bare 64-hex NodeId does not, so
   *  it needs the six-word phrase beside it. Mirrors the core's own check, so
   *  the button explains itself instead of failing after a dial. */
  const canPair = () => {
    const t = ticket().trim();
    if (!t) return false;
    if (/^[0-9a-fA-F]{64}$/.test(t)) {
      return phrase().trim().split(/[-\s]+/).filter(Boolean).length === 6;
    }
    return t.startsWith("portty1:") || t.startsWith("portty3:");
  };

  /** The status pill only renders on the home header - a failure reported
   *  while the user is in the terminal or agent view would be invisible.
   *  Mirror status CHANGES into a transient toast on those screens.
   *
   *  NOT on the pair screen: it prints `status()` inline under the form, so
   *  mirroring put the same words on screen twice, and the fixed toast landed
   *  on top of the saved-hosts heading ("Saved hosts - tap to connect") while
   *  the reader was trying to use it. A screen that already shows the status
   *  does not need it shouted over the top. */
  const showsStatusInline = (v: View) => v === "list" || v === "pair";
  const [statusToast, setStatusToast] = createSignal("");
  let statusToastTimer: number | undefined;
  /** True from the moment a terminal attach starts until the first bytes render,
   * so the user sees "opening portal…" instead of a blank black screen on slow
   * links. */
  const [attaching, setAttaching] = createSignal(false);
  const showToast = (message: string) => {
    setStatusToast(message);
    window.clearTimeout(statusToastTimer);
    statusToastTimer = window.setTimeout(() => setStatusToast(""), 4000);
  };
  createEffect(
    on(
      status,
      (message) => {
        if (!message || showsStatusInline(view())) return;
        setStatusToast(message);
        window.clearTimeout(statusToastTimer);
        statusToastTimer = window.setTimeout(() => setStatusToast(""), 4000);
      },
      { defer: true },
    ),
  );
  const [sessions, setSessions] = createSignal<SessionInfo[]>([]);
  const [activeId, setActiveId] = createSignal<number | null>(null);
  // Ctrl latch: when on, the next soft-keyboard letter becomes a control byte.
  const [ctrl, setCtrl] = createSignal(false);
  const [alt, setAlt] = createSignal(false);
  /** Both latches, read together - they compose (Ctrl+Alt) rather than exclude. */
  const latches = () => ({ ctrl: ctrl(), alt: alt() });
  const clearLatches = () => {
    setCtrl(false);
    setAlt(false);
  };
  // Live-stream pause: freezes host→phone output so you can scroll/read without
  // the cursor jumping (and save cellular data). Switching tabs/detaching resets
  // it - pause is a property of the host's active forwarder, which restarts then.
  const [paused, setPaused] = createSignal(false);
  // Authoritative PTY size per session (host-sent; the phone never drives it).
  const [hostSizes, setHostSizes] = createSignal<Map<number, { cols: number; rows: number }>>(
    new Map(),
  );
  // Per-session manual fit/match choice (the terminal header toggle). Structured
  // agent sessions do not use xterm; raw shell sessions default to fit-to-phone.
  const [modeOverride, setModeOverride] = createSignal<Map<number, RenderMode>>(new Map());
  // True while the viewed session is on the alternate screen (vim/htop/less) -
  // forces match rendering for exactly that stretch, then restores.
  const [altScreen, setAltScreen] = createSignal(false);
  // Whether the match-mode container really overflows on each axis. Set by
  // measurePan(); gates both `touch-action` and the drag-scroll handler.
  const [panX, setPanX] = createSignal(false);
  const [panY, setPanY] = createSignal(false);
  // True while the program has mouse reporting on (Claude Code, vim, htop with
  // mouse enabled). Makes the keyboard overlay click-through so taps reach
  // xterm as clicks - see `.portty-mouse-mode`.
  const [mouseMode, setMouseMode] = createSignal(false);
  // Whether the soft keyboard is up. TWO surfaces can hold it - xterm's helper
  // textarea and the command composer - so the keyboard toggle asks about both. Reading
  // only the textarea made the button claim the keyboard was down while the user
  // was visibly typing into the composer. Each flag is driven by its element's
  // own focus/blur so it stays right even when the webview steals or drops focus
  // on its own.
  const [termFocused, setTermFocused] = createSignal(false);
  const [composerFocused, setComposerFocused] = createSignal(false);
  const keyboardUp = () => termFocused() || composerFocused();
  // Biometric app-lock preference. The gate itself lives in BiometricGate (which
  // wraps App from the outside); this toggle only writes the pref so the gate
  // honors it on next launch / next background-return re-lock. Shown only when
  // the device actually has biometric available (checked onMount).
  const [bioOn, setBioOn] = createSignal(getBiometricPref());
  const [bioAvailable, setBioAvailable] = createSignal(false);
  onMount(async () => {
    setBioAvailable((await biometricAvailability()) === "available");
  });
  // QR pairing: when true, the pair screen shows the camera scanner.
  const [scanning, setScanning] = createSignal(false);
  const [scanError, setScanError] = createSignal("");
  // Inline rename on the session list: which session is being renamed + its text.
  const [renamingId, setRenamingId] = createSignal<number | null>(null);
  const [renameText, setRenameText] = createSignal("");
  // The same, for the saved-hosts list (keyed by device-id hex). Declared here
  // rather than beside its handlers so the Android back handler can close it.
  const [renamingHostId, setRenamingHostId] = createSignal<string | null>(null);
  const [hostRenameText, setHostRenameText] = createSignal("");
  // True while a "New session" create is in flight - disables the button and
  // debounces repeated taps. The create is a correlated request (its own
  // timeout + ack), so no manual timer or SessionAdded-guessing is needed.
  const [creating, setCreating] = createSignal(false);
  const [creatingAgent, setCreatingAgent] = createSignal(false);
  const [showAgentPicker, setShowAgentPicker] = createSignal(false);
  // The same folder browser, for a plain shell. Only one sheet is open at a time
  // (they share the `dir*` browse signals below), so opening either closes the
  // other.
  const [showTerminalPicker, setShowTerminalPicker] = createSignal(false);
  const [sendingPrompt, setSendingPrompt] = createSignal(false);
  const [agentEvents, setAgentEvents] = createSignal<Map<number, portty.AgentTimelineEvent[]>>(
    new Map(),
  );
  const [permissions, setPermissions] = createSignal<portty.AgentPermission[]>([]);
  const [policyHost, setPolicyHost] = createSignal("unpaired");
  const [policy, setPolicy] = createSignal<portty.ApprovalPolicy>(DEFAULT_POLICY);
  const [decisionLog, setDecisionLog] = createSignal<portty.DecisionLogEntry[]>([]);
  const [transferStatus, setTransferStatus] = createSignal("");
  // Host picker: the laptops this phone can resume by stored token (no PIN).
  // Refreshed whenever the pair screen opens.
  const [hostList, setHostList] = createSignal<portty.SavedHost[]>([]);
  // Custom in-app host dropdown. A native <select> pops a full-screen OS picker
  // on Android (jarring); this is a styled inline menu instead. Closes on
  // outside tap / Escape.
  const [hostMenuOpen, setHostMenuOpen] = createSignal(false);
  let hostMenuWrap: HTMLDivElement | undefined;
  createEffect(() => {
    if (!hostMenuOpen()) return;
    const onPointer = (e: PointerEvent) => {
      if (hostMenuWrap && !hostMenuWrap.contains(e.target as Node)) setHostMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setHostMenuOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    onCleanup(() => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    });
  });
  // Loaded at mount too (cheap local store read): the home footer and first-run
  // empty state branch on "are there saved hosts at all", not just the pair
  // screen.
  onMount(() => {
    portty
      .listHosts()
      .then(setHostList)
      .catch(() => setHostList([]));
  });
  createEffect(() => {
    if (view() === "pair") {
      portty
        .listHosts()
        .then(setHostList)
        .catch(() => setHostList([]));
    }
  });
  // A successful pair/reconnect saves (or rotates) a credential - keep the
  // saved-hosts snapshot in step so the footer's Reconnect branch is right.
  createEffect(
    on(
      paired,
      (isPaired) => {
        if (!isPaired) return;
        portty
          .listHosts()
          .then(setHostList)
          .catch(() => {});
      },
      { defer: true },
    ),
  );

  let termEl: HTMLDivElement | undefined;
  let term: Terminal | undefined;
  let fit: FitAddon | undefined;
  // Monospace cell-width ratio, measured once the terminal exists.
  let cellRatio = 0.6;
  // Terminal-local pinch-zoom font override; null = the mode's automatic size.
  let pinchFont: number | null = null;
  // Conservative predictive echo (see lib/echo.ts): activates only after
  // repeated evidence the remote PTY echoes input AND measured RTT is slow;
  // collapses fail-closed the moment echoes stop (password prompts, TUIs).
  const echo = new PredictiveEcho();
  // Prompt-text belt over the timing heuristic's braces.
  let recentOutput = "";
  let sensitivePrompt = false;
  // Measured keystroke→echo latency, surfaced in the terminal header. This is
  // the Phase-3 "perceived keystroke latency" instrument: it reads the same
  // EWMA the prediction gate uses, on LAN / LTE / relay alike.
  const [echoLatency, setEchoLatency] = createSignal(0);

  /** The user-facing mode for the viewed session (before the alt-screen flip). */
  const renderMode = (): RenderMode => {
    const id = activeId();
    if (id == null) return "fit";
    return modeOverride().get(id) ?? "fit";
  };
  /** True when the terminal should render at the host's real grid. */
  const matchActive = () => renderMode() === "match" || altScreen();

  /**
   * Keep xterm's local cursor semantics aligned with its rendering grid. In
   * fit mode the phone can soft-wrap before the authoritative host PTY does;
   * DEC reverse-wraparound lets the host's ordinary BS-SP-BS erase sequence
   * cross that phone-only boundary. Nothing written here is sent to the host.
   */
  const syncLocalDisplayMode = () => {
    if (!term) return;
    const matchesHostGrid = matchActive();
    if (term.modes.reverseWraparoundMode !== !matchesHostGrid) {
      term.write(localDisplayModeSequence(matchesHostGrid));
    }
  };

  /**
   * Make the xterm layout agree with the current mode. Idempotent - safe to
   * call from every trigger (mode toggle, size frame, viewport change, attach).
   * Fit mode: FitAddon at phone dimensions. Match mode: the host's grid, font
   * auto-shrunk to fit the container width (pinch overrides, pan to read).
   */
  const applyLayout = () => {
    if (!term || !termEl) return;
    if (matchActive()) {
      const id = activeId();
      const size = (id != null ? hostSizes().get(id) : undefined) ?? { cols: 160, rows: 48 };
      const avail = Math.max(40, termEl.clientWidth - 8); // minus p-1 padding
      const fitFont = Math.floor(avail / (size.cols * cellRatio));
      const font = pinchFont ?? Math.max(MIN_FONT, Math.min(BASE_FONT, fitFont));
      if (term.options.fontSize !== font) term.options.fontSize = font;
      if (term.cols !== size.cols || term.rows !== size.rows) term.resize(size.cols, size.rows);
    } else {
      const font = pinchFont ?? BASE_FONT;
      if (term.options.fontSize !== font) term.options.fontSize = font;
      fit?.fit();
    }
    syncLocalDisplayMode();
    measurePan();
  };

  /**
   * Record which axes the match-mode container can actually pan.
   *
   * This drives `touch-action`, and BOTH webviews make that load-bearing: once
   * touch-action permits panning along an axis, the compositor claims the
   * gesture and `preventDefault()` on pointermove is ignored (WebKit will also
   * stop delivering moves outright). A blanket `pan-x pan-y` therefore hands
   * every vertical drag to a container that, at a 10-row grid, has nothing to
   * scroll - the gesture dies on iOS and is flaky on Android. So the axes are
   * opened only when there is real overflow, and the drag-scroll handler reads
   * the SAME signal, which keeps CSS and JS from ever disagreeing about who
   * owns the gesture. Measured in a frame so xterm's rows are laid out first.
   */
  const measurePan = () => {
    requestAnimationFrame(() => {
      if (!termEl) return;
      setPanX(termEl.scrollWidth > termEl.clientWidth + 1);
      setPanY(termEl.scrollHeight > termEl.clientHeight + 1);
    });
  };

  // Window-resize relayout for xterm; registered once in ensureTerm, removed in
  // onMount's cleanup (an anonymous closure could never be removed). Same for
  // the textarea focus/blur pair behind the keyboard toggle.
  const onWinResize = () => applyLayout();
  const onTaFocus = () => setTermFocused(true);
  const onTaBlur = () => setTermFocused(false);

  // Keep the whole app attached to the part of the WebView that is actually
  // visible. A soft keyboard can both shrink the visual viewport and pan it
  // away from the layout viewport's origin. Applying only `height` creates a
  // black gap equal to `offsetTop`, and leaves the layout document scrollable.
  // Sync all four bounds and listen for viewport scroll as well as resize.
  onMount(() => {
    const viewport = window.visualViewport;
    const root = document.getElementById("root");
    if (!viewport || !root) return;

    let refitTimer: number | undefined;
    const syncViewport = () => {
      root.style.setProperty("--portty-viewport-top", `${viewport.offsetTop}px`);
      root.style.setProperty("--portty-viewport-left", `${viewport.offsetLeft}px`);
      root.style.setProperty("--portty-viewport-width", `${viewport.width}px`);
      root.style.setProperty("--portty-viewport-height", `${viewport.height}px`);

      // WebViews emit a burst while the keyboard animates. Updating the shell
      // is cheap and immediate; xterm is refitted only after the bounds settle
      // so its helper textarea keeps focus and the keyboard stays open.
      window.clearTimeout(refitTimer);
      refitTimer = window.setTimeout(() => {
        if (view() === "terminal" && term) applyLayout();
      }, 250);
    };

    viewport.addEventListener("resize", syncViewport);
    viewport.addEventListener("scroll", syncViewport);
    syncViewport();

    onCleanup(() => {
      viewport.removeEventListener("resize", syncViewport);
      viewport.removeEventListener("scroll", syncViewport);
      window.clearTimeout(refitTimer);
      root.style.removeProperty("--portty-viewport-top");
      root.style.removeProperty("--portty-viewport-left");
      root.style.removeProperty("--portty-viewport-width");
      root.style.removeProperty("--portty-viewport-height");
    });
  });

  // True while a disconnect was user-initiated from the home screen -
  // suppresses auto-reconnect.
  let manualDisconnect = false;
  // True for the whole duration of a deliberate pair/reconnect. It gates the JS
  // side to a single in-flight connection op (the Rust core enforces this too)
  // and, crucially, makes the self-induced `disconnect()` those ops issue NOT
  // trigger the auto-reconnect handler.
  const [connecting, setConnecting] = createSignal(false);
  let reconnectAttempt = 0;
  let reconnectTimer: number | undefined;
  let disconnectedAt = 0;
  let sweepTimer: number | undefined;
  const [reconnectToast, setReconnectToast] = createSignal(false);

  const sendInput = (s: string) => {
    if (activeId() != null) {
      // A submitted/cancelled command can hand control to a password reader
      // whose prompt wording we do not recognize. Never carry learned echo
      // confidence across that boundary; rebuild it from authoritative output.
      if (/[\r\n\x03\x04\x1a]/.test(s)) {
        const erase = echo.commandBoundary();
        if (erase) term?.write(erase);
      }
      echo.noteSent(s, performance.now());
      portty.input(activeId()!, s);
    }
  };

  // Alt-screen detector for the byte stream (client-side VT awareness; the
  // host stays a dumb pipe). Reset whenever the terminal is reset.
  const scanner = new AltScreenScanner();

  const outputCb = (id: number, data: Uint8Array | null) => {
    if (id !== activeId()) return;
    if (data === null) {
      // ScreenReset: a fresh snapshot follows; any alt-screen state died with
      // the old content (the snapshot re-establishes it if still active).
      term?.reset();
      syncLocalDisplayMode();
      scanner.reset();
      setMouseMode(false);
      if (altScreen()) {
        setAltScreen(false);
        applyLayout();
      }
      return;
    }
    if (!term) return;
    setAttaching(false); // first real bytes for the active session are rendering
    const plain = new TextDecoder().decode(data);
    recentOutput = (recentOutput + plain).slice(-512);
    sensitivePrompt = isSensitivePrompt(recentOutput);
    // RTT/confidence sampling (in-order matching) + erase of provisional
    // cells BEFORE authoritative bytes are parsed. Both writes use xterm's
    // ordered queue, so the screen never races itself.
    const erase = echo.onOutput(plain, performance.now());
    if (erase) term.write(erase);
    setEchoLatency(echo.stats().rttMs);
    for (const seg of scanner.scan(data)) {
      const alt = seg.alt;
      if (alt === null) {
        if (seg.bytes.length) term.write(seg.bytes);
      } else {
        // Flip the render mode BETWEEN this segment (which ends on the switch
        // sequence) and the next - xterm's write callback is the sequencing
        // point, so the full-screen app's first paint parses at the right grid.
        term.write(seg.bytes, () => {
          setAltScreen(alt);
          applyLayout();
        });
      }
    }
    // Mouse reporting is a flag, not a re-layout, so it needs no segment
    // split - just mirror the scanner's synchronous state once per chunk.
    setMouseMode(scanner.mouseReporting());
  };

  /** Authoritative PTY size from the host (kind=2 on the ordered channel:
   *  arrives between the attach ScreenReset and the snapshot bytes). */
  const sizeCb = (id: number, cols: number, rows: number) => {
    setHostSizes((p) => {
      const m = new Map(p);
      m.set(id, { cols, rows });
      return m;
    });
    if (id === activeId()) applyLayout();
  };

  /** Force the soft keyboard open by focusing xterm's hidden textarea. On Android
   *  the CSS stretches that textarea over the whole terminal, so a tap lands on
   *  it directly and the IME opens; the keyboard button is the fallback. */
  // ── Text selection & clipboard ── the full-cover helper textarea (styles.css)
  // eats every touch, so a long-press could never reach the terminal text on
  // Android or iOS. `Select` (KeyBar) flips the textarea to click-through - the
  // same trick as .portty-mouse-mode - and the OS long-press selection works on
  // xterm's DOM rows, which styles.css keeps `user-select: text`. The native
  // handles + Copy menu do the rest; the chip's "Copy screen" is the one-tap
  // fallback that also covers OEM webviews with flaky touch selection.
  const [selectMode, setSelectMode] = createSignal(false);
  // The docked select bar changes the terminal's height - refit after the DOM
  // settles or the bottom rows render clipped/stale.
  const refitAfterBarToggle = () => window.requestAnimationFrame(() => applyLayout());
  const enterSelectMode = () => {
    setSelectMode(true);
    // Drop the keyboard: selecting wants the whole screen visible, and a
    // focused textarea would grab the next tap. The composer is a second thing
    // that can be holding the keyboard up - blur it too, or select mode starts
    // with half the screen still covered.
    term?.textarea?.blur();
    draftEl?.blur();
    setInputTarget("terminal");
    // Same reason the keyboard goes away: the panel is the other thing that eats
    // the screen you are trying to select from. (Select itself lives in it, so
    // this is the common path in, not an edge case.)
    setKeysExpanded(false);
    refitAfterBarToggle();
  };
  const exitSelectMode = () => {
    setSelectMode(false);
    window.getSelection()?.removeAllRanges();
    refitAfterBarToggle();
  };

  // ── Command composer ── see CommandBar.tsx for why the line is composed
  // locally instead of typed straight into the PTY.
  const [draft, setDraft] = createSignal("");
  let draftEl: HTMLInputElement | undefined;
  /**
   * Which surface the user last aimed input at.
   *
   * Tracked as intent rather than read from document.activeElement, because a
   * KeyBar tap can blur the composer before its onClick runs - live focus would
   * say "terminal" for the very tap the user made while composing.
   */
  const [inputTarget, setInputTarget] = createSignal<"terminal" | "composer">("terminal");
  const focusComposer = () => {
    setInputTarget("composer");
    setComposerFocused(true);
    // The latches only ever produce bytes for the TERMINAL. Leaving one armed
    // across a compose would strand a lit `Ctrl`/`Alt` key that silently fires
    // on the next character typed into xterm, long after the tap.
    clearLatches();
  };
  // Hidden while a full-screen app owns the screen: those read single keys, not
  // lines, so the row would be dead weight exactly where the grid is tightest.
  // (Claude Code and friends render into the NORMAL buffer, so the composer
  // stays up for them - which is the case it was built for.)
  const commandBarVisible = () => !altScreen();
  // The KeyBar's expandable panel. Owned here because opening it changes the
  // terminal's height and so needs the same refit the select bar does.
  const [keysExpanded, setKeysExpanded] = createSignal(false);
  const toggleKeysExpanded = () => {
    setKeysExpanded((v) => !v);
    refitAfterBarToggle();
  };
  const submitDraft = () => {
    const line = draft().trim();
    if (!line) return;
    sendInput(`${line}\r`);
    setDraft("");
  };
  // Showing/hiding the row changes the terminal's height. altScreen already
  // calls applyLayout synchronously at the write callback - that runs before
  // the DOM has reflowed around this row, so refit once more after it settles,
  // the same way the select bar does. applyLayout is idempotent.
  //
  // Gated on the view: the terminal block stays mounted but display:none when
  // we're elsewhere, and measuring a hidden element yields clientWidth 0, which
  // would pin the font to MIN_FONT. attachTo refits on the way back in.
  createEffect(
    on(
      commandBarVisible,
      () => {
        if (view() === "terminal") refitAfterBarToggle();
      },
      { defer: true },
    ),
  );

  // Plugin first - inside the Android/iOS webview navigator.clipboard can't
  // show its permission prompt and read silently fails. Browser API stays as
  // the desktop-dev fallback (`pnpm dev` without the plugin registered).
  const clipboardRead = async (): Promise<string> => {
    try {
      return (await readText()) ?? "";
    } catch {
      try {
        return await navigator.clipboard.readText();
      } catch {
        return "";
      }
    }
  };
  const clipboardWrite = async (text: string): Promise<boolean> => {
    try {
      await writeText(text);
      return true;
    } catch {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        return false;
      }
    }
  };

  const pasteFromClipboard = async () => {
    const text = await clipboardRead();
    if (!text) {
      showToast("Nothing to paste - the clipboard is empty");
      return;
    }
    // Paste follows the caret. Before the composer existed there was exactly one
    // possible target; now sending straight to the PTY while the user is mid-
    // compose would fire the clipboard at the shell behind a field they were
    // still editing.
    if (inputTarget() === "composer" && draftEl) {
      // Newlines flattened to spaces: the field is one command by construction
      // (see CommandBar.tsx), and a pasted script must not become N commands.
      const flat = text.replace(/\r?\n/g, " ");
      const start = draftEl.selectionStart ?? draftEl.value.length;
      const end = draftEl.selectionEnd ?? start;
      const next = draftEl.value.slice(0, start) + flat + draftEl.value.slice(end);
      setDraft(next);
      draftEl.focus();
      const caret = start + flat.length;
      draftEl.setSelectionRange(caret, caret);
      return;
    }
    // term.paste() honors bracketed-paste mode and emits through onData, so
    // pasted bytes take the exact same gated sendInput path as typed keys.
    term?.paste(text);
  };

  const copyVisibleScreen = async () => {
    if (!term) return;
    const text = visibleScreenText(term.buffer.active, term.rows);
    if (!text.trim()) {
      showToast("Nothing to copy - the screen is empty");
      return;
    }
    showToast((await clipboardWrite(text)) ? "Screen copied" : "Copy failed - clipboard unavailable");
    exitSelectMode();
  };

  // The OS selection menu's Copy fires a document `copy` event - confirm it
  // and leave select mode. Deferred: clearing the selection synchronously
  // inside the event would race the webview's clipboard write.
  onMount(() => {
    const onDocCopy = () => {
      if (!selectMode()) return;
      showToast("Copied to clipboard");
      window.setTimeout(exitSelectMode, 100);
    };
    document.addEventListener("copy", onDocCopy);
    // While select mode is on, the synthesized mouse events that follow every
    // touch must never reach xterm: its internal mousedown handler refocuses
    // the helper textarea, which tears a just-made OS selection back out of
    // the rows. Swallow them at document CAPTURE phase - propagation stops,
    // but the browser's default selection behavior is untouched (no
    // preventDefault). Only for events aimed inside .xterm, so the scroll
    // controls and the select bar keep working.
    const SWALLOW = ["mousedown", "mouseup", "click", "dblclick", "contextmenu"] as const;
    const swallowInXterm = (e: Event) => {
      if (!selectMode()) return;
      const target = e.target as Element | null;
      if (target?.closest?.(".xterm")) e.stopPropagation();
    };
    for (const type of SWALLOW) {
      document.addEventListener(type, swallowInXterm, { capture: true });
    }
    onCleanup(() => {
      document.removeEventListener("copy", onDocCopy);
      for (const type of SWALLOW) {
        document.removeEventListener(type, swallowInXterm, { capture: true });
      }
    });
  });

  const termTextarea = () =>
    (term as unknown as { textarea?: HTMLTextAreaElement } | undefined)?.textarea;
  const focusTerm = () => {
    // Summoning the keyboard means "I want to type" - leave select mode so the
    // helper textarea becomes tappable again.
    if (selectMode()) exitSelectMode();
    const ta = termTextarea();
    // Re-focusing an already-focused textarea can restart the iOS keyboard
    // animation (and with it another visualViewport burst) for no reason.
    setInputTarget("terminal");
    if (ta && document.activeElement === ta) return;
    term?.focus();
    ta?.focus();
  };
  /**
   * Put the soft keyboard away. iOS gives a WKWebView textarea no "Done" key,
   * so without an explicit blur the keyboard can only be dismissed by leaving
   * the screen - it sits over the terminal covering the very output the user
   * is trying to read.
   */
  const blurTerm = () => {
    // Both surfaces, because either can be the one holding the keyboard up and
    // the caller's intent is "put it away" - not "blur one specific element".
    termTextarea()?.blur();
    draftEl?.blur();
  };
  /** The keyboard button is a TOGGLE, not a summon: the same button puts the keyboard away. */
  const toggleKeyboard = () => {
    if (keyboardUp()) blurTerm();
    else focusTerm();
  };
  /**
   * Is there anything ABOVE the viewport to scroll to?
   *
   * The alternate screen has no scrollback buffer at all, so `scrollPages` on it
   * is a silent no-op - which reads as "the scroll controls are broken" rather
   * than "a full-screen app is running". Report that difference instead.
   */
  const scrollbackState = (): "available" | "alternate" | "empty" => {
    const buffer = term?.buffer.active;
    if (!buffer) return "empty";
    if (buffer.type === "alternate") return "alternate";
    return buffer.baseY > buffer.viewportY ? "available" : "empty";
  };
  /** Explain a scroll that could not move, so the controls never look dead. */
  const noticeNothingAbove = () => {
    showToast("Nothing above - this is the start of the output");
  };
  /**
   * Does the PROGRAM own scrolling rather than our local buffer?
   *
   * True on the alternate screen (a TUI keeps its own history - there is no
   * xterm scrollback to move) and whenever mouse reporting is on (the app asked
   * to be told about wheel events). In both cases scrolling the local buffer is
   * either impossible or wrong; the gesture has to reach the app.
   */
  const appOwnsScroll = () => mouseMode() || scrollbackState() === "alternate";
  /**
   * Hand a scroll gesture to the program as a wheel event.
   *
   * Deliberately a synthetic `WheelEvent` on xterm's own element rather than a
   * hand-rolled escape sequence: xterm already knows which protocol the app
   * negotiated and picks the right output for us - an SGR/X10 wheel report when
   * mouse reporting is on, or `ESC O/[ A|B` cursor keys (honoring DECCKM) in an
   * alt buffer with no scrollback. Re-encoding that here would duplicate the
   * negotiation and drift out of sync with it.
   *
   * Pixel deltas (deltaMode 0) are passed straight through so xterm's own
   * sub-cell accumulator turns a slow drag into smooth scrolling.
   */
  const sendWheelToApp = (deltaY: number, clientX: number, clientY: number) => {
    const el = term?.element;
    if (!el || deltaY === 0) return;
    el.dispatchEvent(
      new WheelEvent("wheel", {
        deltaY,
        deltaMode: 0,
        clientX,
        clientY,
        bubbles: true,
        cancelable: true,
      }),
    );
  };
  /** Centre of the terminal, for wheel events that come from a button not a touch. */
  const termCentre = (): { x: number; y: number } => {
    const rect = term?.element?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  };
  /**
   * Rendered height of one grid row, for converting drag pixels into lines.
   * Measured off the live screen element so it tracks pinch zoom and the
   * match-mode auto-shrink; falls back to the usual ~1.2 line-height ratio
   * before the first paint has laid the rows out.
   */
  const rowHeightPx = (): number => {
    const screen = termEl?.querySelector(".xterm-screen") as HTMLElement | null;
    if (screen && term && term.rows > 0) {
      const measured = screen.getBoundingClientRect().height / term.rows;
      if (measured > 0) return measured;
    }
    return (term?.options.fontSize ?? BASE_FONT) * 1.2;
  };
  // Scroll xterm's LOCAL scrollback buffer - no bytes are sent to the host.
  // Surfaced as on-screen controls (and the drag gesture below) because the
  // full-cover helper textarea eats swipe gestures on touch, leaving the
  // 10k-line buffer otherwise unreachable.
  const scrollTermPages = (pages: number) => {
    if (!term) return;
    if (appOwnsScroll()) {
      // A "page" for the app is one viewport of wheel travel.
      const { x, y } = termCentre();
      sendWheelToApp(pages * term.rows * rowHeightPx(), x, y);
      return;
    }
    if (pages < 0 && scrollbackState() !== "available") {
      noticeNothingAbove();
      return;
    }
    term.scrollPages(pages);
  };
  const scrollTermToBottom = () => {
    term?.scrollToBottom();
  };

  const ensureTerm = () => {
    if (term || !termEl) return;
    term = new Terminal({
      fontFamily:
        '"JetBrainsMono Nerd Font Mono", "SF Mono", ui-monospace, "JetBrains Mono", Menlo, monospace',
      fontSize: BASE_FONT,
      cursorBlink: true,
      // Mirror terminal output into an ARIA live region so VoiceOver/TalkBack
      // users can hear it - without this the terminal is silent to a screen
      // reader (WCAG). xterm keeps the live region bounded to recent rows.
      screenReaderMode: true,
      // 10k lines (~xterm default is 1k): the host now streams multi-thousand-
      // line catch-up snapshots, and scrolling back through a training run's
      // tail shouldn't hit a wall. ~2 MB worst-case per session buffer.
      scrollback: 10000,
      // OSC 8 hyperlinks come from whatever is running on the host - an agent, a
      // build script, a `curl`ed banner. With no handler xterm falls back to
      // window.open, which inside the app's own webview can navigate the SPA
      // itself: a phishing page would then render inside Portty's chrome with no
      // address bar to give it away. Route links through the Rust command that
      // already refuses anything but http(s) and hands the URL to the SYSTEM
      // browser, where the real address is visible. Same path the agent chat's
      // markdown links already take (AgentView). The status line names the
      // destination, because a link's label is host-controlled text and can
      // claim to be anywhere.
      linkHandler: {
        activate: (_event, uri) => {
          void portty
            .openExternal(uri)
            .then(() => setStatus(`opened ${uri} in your browser`))
            .catch((error) => setStatus(`could not open that link: ${error}`));
        },
      },
      // On-brand theme: true black canvas, lime cursor + selection (the vortex).
      // xterm takes concrete colours, not CSS variables, so these are the one
      // place the accent has to be repeated by hand - keep them in step with
      // --lime / --lime-rgb in styles.css.
      theme: {
        background: "#000000",
        foreground: "#e6e6e6",
        cursor: "#95c247",
        cursorAccent: "#000000",
        selectionBackground: "rgba(149, 194, 71, 0.3)",
      },
    });
    fit = new FitAddon();
    term.loadAddon(fit);
    term.open(termEl);
    cellRatio = measureCellRatio(term.options.fontFamily ?? "monospace");
    fit.fit();
    syncLocalDisplayMode();
    // The bundled Nerd Font loads async (@font-face). xterm's first open above
    // measures the cell against whatever fallback was ready, so on a cold start
    // the grid can be sized to the wrong glyph width until the font arrives.
    // Once both weights are loaded, force xterm to re-measure (toggling
    // fontFamily fires its option-change re-measure), recompute the cell ratio,
    // refit, and repaint so box-drawing/powerline glyphs align. Without this the
    // very first screen on Android can render with a fallback font.
    void Promise.all([
      document.fonts.load(`${BASE_FONT}px "JetBrainsMono Nerd Font Mono"`),
      document.fonts.load(`bold ${BASE_FONT}px "JetBrainsMono Nerd Font Mono"`),
    ])
      .then(() => document.fonts.ready)
      .then(() => {
        if (!term) return;
        const ff = term.options.fontFamily;
        term.options.fontFamily = "monospace";
        term.options.fontFamily = ff;
        cellRatio = measureCellRatio(ff ?? "monospace");
        fit?.fit();
        term.refresh(0, term.rows - 1);
      })
      .catch(() => {
        /* font load can reject on unsupported platforms - the CSS fallback
           stack still applies, so just leave the terminal as-is. */
      });
    term.onData((d) => {
      // All safety gating (confidence, RTT floor, echo-off, alt-screen,
      // grapheme cell width, wrap prevention, length cap) lives in lib/echo.ts.
      const buffer = term?.buffer.active;
      const cellsRemaining = term && buffer ? term.cols - buffer.cursorX : 0;
      // Resolve the latches before prediction so Ctrl-M/C/D/Z are treated as
      // control boundaries, never as printable provisional characters. An
      // Alt-prefixed key is multi-byte and so is never predicted either.
      const outgoing = applyLatches(d, latches());
      clearLatches();
      const provisional = echo.onInput(
        outgoing,
        // Use the scanner's SYNCHRONOUS alt state, not the altScreen() signal:
        // the signal only flips in xterm.write's callback, one tick late, which
        // let a keystroke mispredict into a TUI on the switching chunk.
        { sensitivePrompt, altScreen: scanner.altActive(), cellsRemaining },
        performance.now(),
      );
      if (provisional) term?.write(provisional);
      sendInput(outgoing);
    });
    // Echo-off sweeper: if sent keystrokes stop echoing (password prompt,
    // `read -s`, a TUI eating input) the engine collapses and this timer
    // erases any provisional cells - a typed secret never lingers on screen.
    // Cleared in onMount's cleanup (ensureTerm runs outside a reactive root).
    if (sweepTimer === undefined) {
      sweepTimer = window.setInterval(() => {
        const erase = echo.sweep(performance.now());
        if (erase) term?.write(erase);
        setEchoLatency(echo.stats().rttMs);
      }, 400);
    }
    // Mirror the helper textarea's real focus state. Listening to the element
    // rather than setting a flag in focusTerm/blurTerm keeps the keyboard toggle
    // honest when the webview focuses or blurs it without us (tap-to-type,
    // select mode, app backgrounding).
    const ta = termTextarea();
    if (ta) {
      ta.addEventListener("focus", onTaFocus);
      ta.addEventListener("blur", onTaBlur);
      setTermFocused(document.activeElement === ta);
    }
    // Relayout when the viewport changes (soft keyboard show/hide, rotation).
    // Named handler so onMount's cleanup can remove it (see onCleanup below).
    window.addEventListener("resize", onWinResize);
  };

  // ── Terminal-local pinch-to-zoom ── two-pointer distance scales the xterm
  // font in both modes. Fit mode reflows around the larger text; match mode
  // preserves the host grid and lets the overflowing terminal pan.
  const pinchPointers = new Map<number, { x: number; y: number }>();
  let pinchStartDist = 0;
  let pinchStartFont = BASE_FONT;
  const pinchDist = () => {
    const [a, b] = [...pinchPointers.values()];
    return Math.hypot(a.x - b.x, a.y - b.y);
  };
  // A long-press on the terminal ARMS select mode - phone muscle memory. The
  // overlay textarea owns the in-flight gesture (pointer-events can't retarget
  // a touch mid-stream), so this first hold only flips the pass-through; the
  // toast tells the user the NEXT long-press selects natively. Any movement,
  // a second finger, or lifting early cancels.
  let selectArmTimer: number | undefined;
  let selectArmStart: { x: number; y: number } | null = null;
  const cancelSelectArm = () => {
    window.clearTimeout(selectArmTimer);
    selectArmTimer = undefined;
    selectArmStart = null;
  };
  const startSelectArm = (e: PointerEvent) => {
    selectArmStart = { x: e.clientX, y: e.clientY };
    window.clearTimeout(selectArmTimer);
    // 450ms: ahead of the webview's own ~500ms long-press (which would pop the
    // empty textarea's paste bubble - the blur in enterSelectMode preempts it).
    selectArmTimer = window.setTimeout(() => {
      cancelSelectArm();
      enterSelectMode();
      showToast("Selection ready - long-press the text");
    }, 450);
  };
  // ── One-finger drag-to-scroll ── the natural way to reach the top of a
  // terminal on a phone. xterm's full-cover helper textarea is the touch TARGET,
  // but pointer events bubble to this container, so the gesture is tracked here
  // and translated into `scrollLines` on the LOCAL buffer (no host bytes). Only
  // claimed when the container itself cannot pan - see `shouldDragScroll`.
  const DRAG_SCROLL_START_PX = 8;
  // Past this much travel the gesture is a swipe, not a tap, so it must not
  // summon the keyboard. Looser than the drag-scroll threshold so a slightly
  // sloppy tap still types.
  const TAP_SLOP_PX = 10;
  let tapCandidate = false;
  let tapOrigin: { x: number; y: number } | null = null;
  let dragOrigin: { x: number; y: number } | null = null;
  let dragPointerId: number | null = null;
  let dragLastY = 0;
  let dragAccumPx = 0;
  let dragScrolling = false;
  let dragNoticed = false;
  const endDragScroll = () => {
    dragOrigin = null;
    dragPointerId = null;
    dragAccumPx = 0;
    dragScrolling = false;
    dragNoticed = false;
  };
  const onTermPointerDown = (e: PointerEvent) => {
    // In select mode the OS selection gesture owns every touch: no keyboard
    // re-focus, no pinch tracking.
    if (selectMode()) return;
    // NOT focusTerm() here. Focusing on pointerDOWN raises the keyboard for
    // every touch, including a scroll swipe and a pinch - the keyboard then
    // covers the output the gesture was trying to read. Deferred to pointerUP,
    // and only for a gesture that turned out to be a plain tap.
    pinchPointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinchPointers.size === 1) {
      tapCandidate = true;
      tapOrigin = { x: e.clientX, y: e.clientY };
      startSelectArm(e);
      // Touch/pen only. Mouse-reporting apps are deliberately NOT excluded: a
      // vertical swipe is how a phone scrolls, and for those the drag is
      // forwarded to the app as a wheel event rather than moving a local
      // buffer. Taps still reach the TUI as clicks, since only a vertical drag
      // past the threshold is claimed. A real mouse keeps xterm's native text
      // selection - it has a wheel already (the local-proof browser).
      dragOrigin = e.pointerType === "mouse" ? null : { x: e.clientX, y: e.clientY };
      dragPointerId = e.pointerId;
      dragLastY = e.clientY;
      dragAccumPx = 0;
      dragScrolling = false;
      dragNoticed = false;
    } else {
      cancelSelectArm();
      endDragScroll(); // a second finger means pinch, not scroll
      tapCandidate = false; // ...and a pinch is never a tap
    }
    if (pinchPointers.size === 2) {
      pinchStartDist = pinchDist();
      pinchStartFont = term?.options.fontSize ?? BASE_FONT;
    }
  };
  const onTermPointerMove = (e: PointerEvent) => {
    if (selectMode()) return;
    if (
      selectArmStart &&
      Math.hypot(e.clientX - selectArmStart.x, e.clientY - selectArmStart.y) > 10
    ) {
      cancelSelectArm();
    }
    if (!pinchPointers.has(e.pointerId)) return;
    pinchPointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    // Travelled too far to be a tap - whatever this gesture is, it must not
    // summon the keyboard on release.
    if (
      tapCandidate &&
      tapOrigin &&
      Math.hypot(e.clientX - tapOrigin.x, e.clientY - tapOrigin.y) > TAP_SLOP_PX
    ) {
      tapCandidate = false;
    }
    if (pinchPointers.size === 2 && pinchStartDist > 0) {
      e.preventDefault();
      const clamped = scaledTerminalFont(
        pinchStartFont,
        pinchStartDist,
        pinchDist(),
        MIN_FONT,
        MAX_FONT,
      );
      if (clamped !== pinchFont) {
        pinchFont = clamped;
        applyLayout();
      }
      return;
    }
    if (!term || pinchPointers.size !== 1 || e.pointerId !== dragPointerId) return;
    if (!dragScrolling) {
      if (!dragOrigin) return;
      // panY(), not a live measurement: `touch-action` is derived from the same
      // signal, so this cannot disagree with what the compositor already did.
      if (
        !shouldDragScroll(
          e.clientX - dragOrigin.x,
          e.clientY - dragOrigin.y,
          DRAG_SCROLL_START_PX,
          panY(),
        )
      ) {
        return;
      }
      // The gesture is a scroll, not a tap: drop the pending select arm and
      // start measuring from HERE so the threshold isn't scrolled twice.
      cancelSelectArm();
      dragScrolling = true;
      dragAccumPx = 0;
      dragLastY = e.clientY;
      return;
    }
    e.preventDefault();
    const stepPx = e.clientY - dragLastY;
    dragLastY = e.clientY;
    if (appOwnsScroll()) {
      // Drag down = reveal older = wheel up, so the delta is inverted.
      sendWheelToApp(-stepPx, e.clientX, e.clientY);
      return;
    }
    dragAccumPx += stepPx;
    const { lines, remainderPx } = dragScrollLines(dragAccumPx, rowHeightPx());
    dragAccumPx = remainderPx;
    if (lines === 0) return;
    if (lines < 0 && scrollbackState() !== "available") {
      // Dragging toward history with nothing there - say why, once per gesture,
      // instead of letting the screen sit motionless under the finger.
      if (!dragNoticed) {
        dragNoticed = true;
        noticeNothingAbove();
      }
      return;
    }
    term.scrollLines(lines);
  };
  const onTermPointerEnd = (e: PointerEvent) => {
    cancelSelectArm();
    pinchPointers.delete(e.pointerId);
    if (pinchPointers.size < 2) pinchStartDist = 0;
    const wasScrolling = dragScrolling;
    if (e.pointerId === dragPointerId) endDragScroll();
    const tapped = tapCandidate && !wasScrolling && e.type === "pointerup";
    tapCandidate = false;
    tapOrigin = null;
    // A plain tap - and only a tap - means "I want to type". A swipe, a pinch,
    // a long-press, or a cancelled touch leaves the keyboard exactly as it was.
    // Deliberately NOT auto-hiding after a swipe either: the complaint is churn,
    // so the keyboard changes state only when the user actually asks it to.
    if (!tapped || selectMode() || pinchPointers.size > 0) return;
    // Except while the program is reading the mouse, where a tap is a CLICK for
    // the app. The keyboard toggle is how you type there (see `.portty-mouse-mode`).
    if (mouseMode()) return;
    focusTerm();
  };

  /** Open a session in the terminal view (from the list). */
  const attachTo = (id: number) => {
    setView("terminal");
    // Show a loading state until the first output/snapshot renders (outputCb
    // clears it). Safety timeout so a stalled attach can't strand the spinner.
    setAttaching(true);
    window.setTimeout(() => setAttaching(false), 8000);
    ensureTerm();
    term?.reset();
    scanner.reset();
    // Echo confidence/RTT earned on one session must not prime prediction on
    // another (and a stale `predicted` would erase into the fresh screen).
    echo.reset();
    recentOutput = "";
    sensitivePrompt = false;
    // An uncommitted draft belongs to the session it was typed for. Carrying it
    // across an attach would leave a command aimed at one host sitting one tap
    // from Send on another.
    setDraft("");
    setInputTarget("terminal");
    // A modifier armed against the old session must not fire into the new one.
    clearLatches();
    setAltScreen(false);
    pinchFont = null;
    setActiveId(id);
    // reset() restored xterm's default modes. Restore the local fit/match mode
    // before attach can enqueue the snapshot bytes.
    syncLocalDisplayMode();
    setPaused(false); // new active forwarder on the host → live
    setSessions((p) => p.map((s) => (s.id === id ? { ...s, has_activity: false } : s)));
    // Correlated attach: if the session is gone, surface it and go back to the
    // list instead of leaving the user on a blank terminal. (Ignore errors once
    // we've already switched away - a later disconnect handles those.)
    portty.attach(id).catch((e) => {
      setAttaching(false);
      if (activeId() === id && view() === "terminal") {
        setStatus(`${e}`);
        setActiveId(null);
        setView("list");
      }
    });
    // The terminal was display:none until now; relayout once it's laid out.
    requestAnimationFrame(() => applyLayout());
  };

  /** Open a structured agent feed. The same host Attach command replays the
   * bounded agent timeline, but no terminal bytes/xterm are involved. */
  /** How many approvals this session is waiting on. Per-session on purpose: a
      single top-level total cannot say WHICH agent needs you. */
  const pendingFor = (id: number) =>
    permissions().filter((request) => request.id === id).length;

  const attachAgent = (id: number) => {
    setActiveId(id);
    setView("agent");
    setPaused(false);
    // Opening an agent is the moment approvals become possible, and the user is
    // looking at the screen - so this is where the notification prompt belongs.
    // It cannot go on the notification path itself: that fires when the app is
    // off screen, and neither OS shows a permission dialog to a backgrounded
    // app, so the prompt would never appear and every banner would be dropped.
    // Cached per session, so re-entering an agent does not re-ask.
    void ensureNotificationPermission().then((outcome) => {
      if (outcome === "denied") {
        setStatus(
          "Notifications are off, so approvals will only show while Portty is open. Turn them on in your phone's Settings.",
        );
      }
    });
    setSessions((p) => p.map((s) => (s.id === id ? { ...s, has_activity: false } : s)));
    portty.attach(id).catch((e) => {
      if (activeId() === id && view() === "agent") {
        setStatus(`${e}`);
        setActiveId(null);
        setView("list");
      }
    });
  };

  const openSession = (session: SessionInfo) => {
    if (session.kind === "agent") attachAgent(session.id);
    else attachTo(session.id);
  };

  /** Header toggle: flip the viewed session between fit and match rendering. */
  const toggleMode = () => {
    const id = activeId();
    if (id == null) return;
    const next: RenderMode = renderMode() === "match" ? "fit" : "match";
    setModeOverride((p) => {
      const m = new Map(p);
      m.set(id, next);
      return m;
    });
    pinchFont = null;
    applyLayout();
  };

  /** Leave the terminal and go back to the session list (stay connected). */
  const backToList = () => {
    exitSelectMode();
    void portty.detach();
    // Detach ends the host's forwarder; the next attach streams live again,
    // so a stale paused=true here would show the resume state while output runs.
    setPaused(false);
    setView("list");
  };

  /** The "New session" action.
   *
   *  Not connected: opens the pairing screen - that's the "Add host" path.
   *
   *  Connected: opens the folder picker. Creating a shell ALWAYS goes through it
   *  now, so there is one way to start a terminal and it always says where it
   *  will start. The sheet opens at the workspace root, so accepting the default
   *  is the same shell you used to get immediately, one tap later. The actual
   *  create lives in `startTerminalIn`. */
  const newSessionOrPair = () => {
    if (!paired()) {
      setScanError("");
      setScanning(false);
      setView("pair");
      return;
    }
    if (creating()) return; // debounce: one create in flight at a time
    toggleTerminalPicker();
  };

  // ── Agent workspace picker ──
  // Starting an agent is two steps: pick the provider, then pick the directory
  // it runs in. Before this, every agent started in whatever directory the host
  // daemon happened to be launched from - which on a phone you cannot `cd` out
  // of, and which also set the agent's file-access sandbox. The chosen directory
  // is now BOTH, so picking deeper is strictly less reachable filesystem.
  const [pendingProvider, setPendingProvider] = createSignal<portty.AgentProvider | null>(null);
  // Adapter availability, asked when the sheet opens. Empty means "not asked or
  // the host is older" - in which case every agent stays tappable, because
  // hiding an agent we simply have no information about would be worse than
  // letting the start fail with the host's own explanation.
  const [providerRows, setProviderRows] = createSignal<portty.AgentProviderRow[]>([]);
  const providerState = (provider: portty.AgentProvider) =>
    providerRows().find((row) => row.provider === provider);
  const [dirRel, setDirRel] = createSignal("");
  /** Which root the browse signals are relative to.
   *
   *  The AGENT picker never changes this - it is pinned to the workspace, because
   *  an agent's directory is also its file-access sandbox root. Only the terminal
   *  picker offers the switch. */
  const [dirRoot, setDirRoot] = createSignal<portty.TerminalRoot>("workspace");
  /** Roots this host serves. Empty until asked; an older host (or a restricted
   *  one) leaves it at workspace-only, which is the pre-v10 behaviour. */
  const [terminalRoots, setTerminalRoots] = createSignal<portty.TerminalRoot[]>(["workspace"]);
  const ROOT_LABEL: Record<portty.TerminalRoot, string> = {
    workspace: "Workspace",
    home: "Home",
  };
  const [dirNames, setDirNames] = createSignal<string[]>([]);
  const [dirLoading, setDirLoading] = createSignal(false);
  // Titled so a failure reads as a sentence, not a dumped error string. The
  // title names what the user tried; the body carries the host's explanation.
  const [dirError, setDirError] = createSignal("");
  const [dirErrorTitle, setDirErrorTitle] = createSignal("");
  /**
   * Strip the layers each hop added on the way here.
   *
   * The host prefixes its own context, the ACP layer prefixes `acp:`, and the
   * command wrapper prefixes again - so a genuinely useful sentence arrived
   * behind "could not start agent: acp: ". Only leading noise is removed; the
   * message itself is never rewritten, because the host is the one that knows
   * what actually went wrong.
   */
  const cleanHostError = (raw: string) => {
    let text = `${raw}`.trim();
    for (const prefix of ["could not start agent:", "could not resume:", "acp:"]) {
      // Repeat: the same prefix can appear twice when a hop re-wraps its child.
      while (text.toLowerCase().startsWith(prefix)) {
        text = text.slice(prefix.length).trim();
      }
    }
    return text.charAt(0).toUpperCase() + text.slice(1);
  };
  const showPickerError = (title: string, raw: unknown) => {
    setDirErrorTitle(title);
    setDirError(cleanHostError(`${raw}`));
  };

  /** The workspace root has no parent to reach - `..` is refused by the host. */
  const dirParent = () => {
    const rel = dirRel();
    if (!rel) return null;
    const cut = rel.lastIndexOf("/");
    return cut === -1 ? "" : rel.slice(0, cut);
  };

  // Conversations you can continue in the directory in view - the ones started
  // from this phone AND the ones started with the agent's own CLI on the laptop,
  // which the host gets by asking the agent itself.
  //
  // Scoped to the provider whose picker you are in, unlike the old all-providers
  // listing: asking costs the host an adapter launch per agent, and a row you tap
  // starts the agent that owns it, so offering OpenCode chats on the Claude Code
  // screen was a promise the next tap broke.
  const [dirSessions, setDirSessions] = createSignal<portty.AgentSessionRow[]>([]);
  // Separate from `dirLoading` because it resolves separately: folders come back
  // in milliseconds, the agent's own history takes as long as its adapter takes
  // to boot. Blocking the folder list behind that would make every tap feel like
  // the slowest agent on the host.
  const [dirSessionsLoading, setDirSessionsLoading] = createSignal(false);
  // Only the newest listing may write the list. Without this, thumbing through
  // folders faster than the probes resolve lets a stale answer land last and
  // offer conversations from a directory you already left.
  let dirSessionsToken = 0;

  /** Load the conversation list for `rel` beside the folder list, never in front
   *  of it. Deliberately not awaited by `browseDir`. */
  const loadDirSessions = (rel: string, provider: portty.AgentProvider | null) => {
    const token = ++dirSessionsToken;
    setDirSessions([]);
    // No provider means the terminal picker, which shows no conversations at all
    // - asking would launch an adapter to answer a question nobody asked.
    if (!provider) {
      setDirSessionsLoading(false);
      return;
    }
    setDirSessionsLoading(true);
    void (async () => {
      try {
        const saved = await portty.listAgentSessionsFor(rel, provider);
        if (token === dirSessionsToken) setDirSessions(saved.sessions);
      } catch {
        // Conversations are a bonus, not a precondition: a failure here must not
        // stop you navigating or starting something new, so it leaves the list
        // empty rather than surfacing over the directory error slot.
        if (token === dirSessionsToken) setDirSessions([]);
      } finally {
        if (token === dirSessionsToken) setDirSessionsLoading(false);
      }
    })();
  };

  /** Returns whether the listing succeeded, so a caller that guessed the folder
   *  (the terminal picker opening at a saved default) can fall back instead of
   *  leaving an error and an empty list on screen. */
  const browseDir = async (rel: string, root?: portty.TerminalRoot): Promise<boolean> => {
    const target = root ?? dirRoot();
    setDirLoading(true);
    setDirError("");
    setDirErrorTitle("");
    try {
      // The workspace keeps using the pre-v10 request so the agent picker's wire
      // traffic is untouched by any of this; only a non-workspace root needs the
      // rooted one.
      const listing =
        target === "workspace"
          ? await portty.listWorkspaceDirs(rel)
          : await portty.listDirsIn(target, rel);
      setDirRoot(target);
      // Trust the host's RESOLVED rel, not the one we asked for - it normalized
      // the path and is the authority on where we actually are.
      setDirRel(listing.rel);
      setDirNames(listing.names);
      loadDirSessions(listing.rel, pendingProvider());
      return true;
    } catch (e) {
      // Keep the previous listing on screen: blanking it would read as "this
      // folder is empty" when the truth is that the request failed.
      showPickerError("Couldn't open that folder", e);
      return false;
    } finally {
      setDirLoading(false);
    }
  };

  const resumeSaved = async (row: portty.AgentSessionRow) => {
    if (!paired() || creatingAgent()) return;
    setCreatingAgent(true);
    try {
      const id = await portty.resumeAgentSession(dirRel(), row.acp_session_id);
      closeAgentPicker();
      attachAgent(id);
    } catch (e) {
      showPickerError("Couldn't resume that conversation", e);
      setStatus(`could not resume: ${e}`);
    } finally {
      setCreatingAgent(false);
    }
  };

  const chooseAgentProvider = (provider: portty.AgentProvider) => {
    setPendingProvider(provider);
    setDirRel("");
    setDirNames([]);
    setDirSessions([]);
    setDirError("");
    void browseDir("");
  };

  /** Coarse "when" for a saved conversation. Exact timestamps are noise here -
   *  you are picking between a handful of chats, not auditing them. */
  const agoLabel = (unixMs: number) => {
    const minutes = Math.floor((Date.now() - unixMs) / 60_000);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };
  const PROVIDER_LABEL: Record<portty.AgentProvider, string> = {
    claude_code: "Claude Code",
    open_code: "OpenCode",
    codex: "Codex",
    goose: "Goose",
  };

  const closeAgentPicker = () => {
    setShowAgentPicker(false);
    setPendingProvider(null);
    setDirError("");
  };
  // Ask the host what it can launch each time the sheet opens - an adapter can
  // be installed while the app is running, and a stale "not installed" would be
  // worse than a moment's delay.
  createEffect(
    on(
      showAgentPicker,
      (open) => {
        if (!open) return;
        void portty
          .listAgentProviders()
          .then(setProviderRows)
          .catch(() => setProviderRows([]));
      },
      { defer: true },
    ),
  );
  // Several paths close this sheet (starting an agent, switching host, leaving
  // the list). Resetting on the SIGNAL rather than in each of them means
  // reopening always starts at the provider list, never mid-browse for an agent
  // the user already backed out of.
  createEffect(
    on(
      showAgentPicker,
      (open) => {
        if (!open) setPendingProvider(null);
      },
      { defer: true },
    ),
  );

  const startAgent = async (provider: portty.AgentProvider, rel: string) => {
    if (!paired() || creatingAgent()) return;
    setCreatingAgent(true);
    try {
      const id = await portty.newAgentIn(provider, rel);
      closeAgentPicker();
      attachAgent(id);
    } catch (e) {
      // Show it IN the sheet. `status` only reaches the home header's pill on
      // this view (the toast effect skips view "list"), so a failure raised from
      // a sheet in the middle of the screen was announced in a small pill above
      // it - which reads as the button doing nothing at all. The host's message
      // names the missing adapter and the fix; it just has to be seen.
      showPickerError(`Couldn't start ${PROVIDER_LABEL[provider] ?? provider}`, e);
      setStatus(`could not start agent: ${e}`);
    } finally {
      setCreatingAgent(false);
    }
  };

  // ── Terminal folder picker ──
  // The ONLY way to start a shell: "+ New session" opens this, and it opens at
  // the workspace root - which is where a phone shell now actually lands, since
  // the host used to ignore its own workspace and put every one of them in HOME.
  // Accepting the default is therefore the old behaviour, one tap later, and the
  // create can no longer happen without showing you where.
  //
  // The browse state is shared with the agent picker deliberately - one folder
  // browser, one set of signals, so the two cannot drift into listing
  // differently. Unlike the agent picker, a deeper pick here grants nothing and
  // restricts nothing: a shell can `cd` wherever its user can reach. It only
  // decides where you start.
  /** This host's chosen default folder, or "" for the workspace root.
   *
   *  Read from the saved-host record rather than a separate signal, so it cannot
   *  disagree with what the switcher shows. Per host, so switching machines
   *  switches the default with it. */
  const savedHost = () => hostList().find((h) => h.id === policyHost());
  const hostDefaultDir = () => savedHost()?.default_dir ?? "";
  /** Which root the default is relative to. Absent means the workspace, which is
   *  also what every pre-v10 stored default meant. */
  const hostDefaultRoot = (): portty.TerminalRoot => savedHost()?.default_root ?? "workspace";
  /** How to name a folder in prose: the rel, or the root's own name for "". */
  const dirLabel = (rel: string, root: portty.TerminalRoot = dirRoot()) =>
    rel === "" ? (root === "home" ? "home" : "workspace root") : rel;
  /** Whether the folder in view is this host's default - root AND rel, since the
   *  same rel under a different root is a different folder. */
  const dirIsDefault = () => dirRoot() === hostDefaultRoot() && dirRel() === hostDefaultDir();

  /** The default-folder toggle for ONE folder, wherever that folder appears.
   *
   *  Used on the "you are here" row AND on every row in the list, so starring a
   *  folder never requires opening it first - which is what the caption promises
   *  and what makes setting the FIRST default possible from the root, where there
   *  is no current folder to star.
   *
   *  One component rather than two copies: the filled/empty rule, the labels and
   *  the toggle-to-clear behaviour have to be identical in both places or the star
   *  means different things a few pixels apart. */
  const DefaultStar = (props: { rel: string }) => {
    // Root-aware: `code/app` under home is not `code/app` under the workspace.
    const isDefault = () => dirRoot() === hostDefaultRoot() && props.rel === hostDefaultDir();
    const shown = () => dirLabel(props.rel);
    return (
      <button
        class="portty-dir-star"
        classList={{ "portty-dir-star--on": isDefault() }}
        aria-pressed={isDefault()}
        title={
          isDefault()
            ? "This is the default folder - tap to clear it"
            : `Make “${shown()}” the default folder`
        }
        aria-label={
          isDefault()
            ? `${shown()} is the default folder - tap to clear`
            : `Make ${shown()} the default folder`
        }
        onClick={(event) => {
          // The list rows sit INSIDE a tappable row, so without this a tap on the
          // star would also navigate into the folder it just starred.
          event.stopPropagation();
          // Clearing always returns to the workspace root - that is what "no
          // default" means, whichever root you cleared it from.
          if (isDefault()) void setDefaultDir("workspace", "");
          else void setDefaultDir(dirRoot(), props.rel);
        }}
      >
        <Icon name="star" />
      </button>
    );
  };

  const closeTerminalPicker = () => {
    setShowTerminalPicker(false);
    setDirError("");
  };

  /** Remember a folder as this host's default (or clear it). */
  const setDefaultDir = async (root: portty.TerminalRoot, rel: string) => {
    const host = policyHost();
    if (!host) return;
    try {
      const stored = await portty.setHostDefaultDir(host, root, rel);
      // Patch in place rather than re-listing: `listHosts` would also re-resolve
      // `is_last`, and these two fields are all that changed.
      setHostList((hosts) =>
        hosts.map((saved) =>
          saved.id === host
            ? { ...saved, default_dir: stored, default_root: stored == null ? null : root }
            : saved,
        ),
      );
      setStatus(
        stored == null
          ? "Default folder cleared"
          : `Default folder: ${ROOT_LABEL[root]}${stored ? ` / ${stored}` : ""}`,
      );
    } catch (e) {
      showPickerError("Couldn't save that as the default", e);
    }
  };
  const toggleTerminalPicker = () => {
    if (showTerminalPicker()) {
      closeTerminalPicker();
      return;
    }
    // Both sheets read the same browse signals, so the agent one cannot stay up.
    closeAgentPicker();
    setShowTerminalPicker(true);
    setDirRel("");
    setDirNames([]);
    setDirSessions([]);
    setDirError("");
    // Ask what this host serves each time the sheet opens: a restriction can
    // change, and an older host rejects the request entirely - which means
    // workspace-only, exactly as before v10.
    void portty
      .listTerminalRoots()
      .then((roots) => setTerminalRoots(roots.length > 0 ? roots : ["workspace"]))
      .catch(() => setTerminalRoots(["workspace"]));
    void openPickerAtDefault();
  };

  /** Open the browser ON this host's default folder.
   *
   *  Landing here rather than at the root is what makes the whole sheet legible:
   *  "Open here" is then one tap to your usual folder, and CHANGING the default is
   *  "navigate away, tap the star" - a thing you can discover by looking, because
   *  you start standing on the current answer.
   *
   *  A stored rel can go stale (daemon relaunched elsewhere, folder deleted) and
   *  the host refuses it. Falling back to the root keeps the sheet usable and says
   *  what happened, instead of an error over an empty list. */
  const openPickerAtDefault = async () => {
    const preferred = hostDefaultDir();
    const root = hostDefaultRoot();
    if ((preferred === "" && root === "workspace") || (await browseDir(preferred, root))) return;
    // Workspace root FIRST, then the message: `browseDir` clears the error slot as
    // it starts, so telling the user before falling back would wipe what we said.
    // The fallback is always the workspace, since the saved root itself may be the
    // thing this host no longer serves.
    await browseDir("", "workspace");
    showPickerError(
      `“${dirLabel(preferred, root)}” isn't available any more`,
      "Showing the workspace root instead - star another folder to change the default.",
    );
  };

  const startTerminalIn = async (rel: string) => {
    if (!paired() || creating()) return; // same one-create-in-flight debounce
    setCreating(true);
    try {
      // Workspace keeps the pre-v10 request; only another root needs the new one.
      const id =
        dirRoot() === "workspace"
          ? await portty.newSessionIn(rel)
          : await portty.newSessionInRoot(dirRoot(), rel);
      closeTerminalPicker();
      attachTo(id);
    } catch (e) {
      // In the sheet, not the header pill - a failure raised from a sheet in the
      // middle of the screen otherwise reads as the button doing nothing (same
      // reasoning as startAgent).
      showPickerError("Couldn't open a session there", e);
      setStatus(`could not create session: ${e}`);
    } finally {
      setCreating(false);
    }
  };

  /**
   * Where-am-I header, error slot, and the folder list. Shared by the agent and
   * terminal pickers.
   *
   * Extracted rather than copied: two copies of a directory browser would be two
   * places for "Up", the empty state, and the error slot to drift apart, and the
   * agent copy is the one carrying the accessibility bits (`aria-live` on the
   * path, `role="alert"` on the error) that a hand-copy quietly loses.
   *
   * Every control here is disabled by `dirLoading()` alone, because navigating is
   * safe while a create is in flight; it is the commit buttons in each sheet that
   * gate on `creating()` / `creatingAgent()`.
   *
   * Three optional slots, all used only by the terminal picker - the agent picker
   * passes none, because an agent has no default folder to set:
   *   `trailing`     - rides in the "you are here" row
   *   `caption`      - sits directly under it
   *   `entryTrailing` - rides on each folder row, given an ACCESSOR for that
   *                     folder's rel
   *
   * `entryTrailing` is why a row is a `div` wrapping the button rather than the
   * button itself: a control inside the row cannot be a `button` nested in a
   * `button`.
   */
  const FolderBrowser = (props: {
    trailing?: JSX.Element;
    caption?: JSX.Element;
    // An accessor, NOT a string: `For` is keyed on folder NAMES, and the same
    // names recur at different depths (`src` under any project), so a row is not
    // re-created on every navigation. A rel captured once would then point at the
    // previous directory - a star that silently defaults the wrong folder.
    entryTrailing?: (rel: () => string) => JSX.Element;
  }) => (
    <>
      <div class="portty-dir-path" aria-live="polite">
        <Icon name="host" class="portty-btn-icon" />
        <span class="portty-dir-path-text">{dirRel() === "" ? "workspace root" : dirRel()}</span>
        {props.trailing}
      </div>
      {props.caption}

      <Show when={dirError()}>
        <div class="portty-dir-error" role="alert">
          <Show when={dirErrorTitle()}>
            <strong>{dirErrorTitle()}</strong>
          </Show>
          <span>{dirError()}</span>
        </div>
      </Show>

      <div class="portty-dir-list">
        <Show when={dirParent() !== null}>
          <button
            class="portty-dir-entry portty-dir-up"
            onClick={() => void browseDir(dirParent()!)}
            disabled={dirLoading()}
          >
            <Icon name="arrow-left" class="portty-btn-icon" />
            Up
          </button>
        </Show>
        <For each={dirNames()}>
          {(name) => {
            const rel = () => (dirRel() ? `${dirRel()}/${name}` : name);
            return (
              <div class="portty-dir-row">
                <button
                  class="portty-dir-entry"
                  onClick={() => void browseDir(rel())}
                  disabled={dirLoading()}
                >
                  {name}
                </button>
                {props.entryTrailing?.(rel)}
              </div>
            );
          }}
        </For>
        <Show when={!dirLoading() && dirNames().length === 0 && !dirError()}>
          <div class="portty-dir-empty">No sub-folders here</div>
        </Show>
      </div>
    </>
  );

  const sendAgentPrompt = async (text: string): Promise<boolean> => {
    const id = activeId();
    if (id == null || sendingPrompt()) return false;
    setSendingPrompt(true);
    try {
      await portty.agentPrompt(id, text);
      return true;
    } catch (e) {
      setStatus(`could not send prompt: ${e}`);
      return false;
    } finally {
      setSendingPrompt(false);
    }
  };

  const [stoppingAgent, setStoppingAgent] = createSignal(false);
  const cancelAgentTurn = async () => {
    const id = activeId();
    if (id == null || stoppingAgent()) return;
    setStoppingAgent(true);
    try {
      await portty.agentCancel(id);
    } catch (error) {
      setStatus(`could not stop agent turn: ${error}`);
    } finally {
      setStoppingAgent(false);
    }
  };

  const setAgentMode = async (modeId: string) => {
    const id = activeId();
    if (id == null) return false;
    try {
      await portty.agentSetMode(id, modeId);
      return true;
    } catch (error) {
      setStatus(`could not change agent mode: ${error}`);
      return false;
    }
  };

  const setAgentConfig = async (configId: string, value: portty.AgentConfigValue) => {
    const id = activeId();
    if (id == null) return false;
    try {
      await portty.agentSetConfig(id, configId, value);
      return true;
    } catch (error) {
      setStatus(`could not change agent setting: ${error}`);
      return false;
    }
  };

  const authenticateAgent = async (methodId: string) => {
    const id = activeId();
    if (id == null) return false;
    try {
      await portty.agentAuthenticate(id, methodId);
      return true;
    } catch (error) {
      setStatus(`could not authenticate agent: ${error}`);
      return false;
    }
  };

  /** ACP tool-call ids are only unique WITHIN one session (two agents can both
   * emit "call_0"), so permission cards are always matched by session id AND
   * tool-call id together - never by tool-call id alone. */
  const samePermission = (a: portty.AgentPermission, b: portty.AgentPermission) =>
    a.id === b.id && a.tool_call.tool_call_id === b.tool_call.tool_call_id;

  const decidePermission = (request: portty.AgentPermission, optionId: string | null) => {
    const callKey = `${request.id}:${request.tool_call.tool_call_id}`;
    const tier = policy().session_overrides[String(request.id)] ?? policy().tier;
    const source: portty.DecisionSource = optionId === null ? "manual-reject" : "manual-allow";
    setPermissions((items) => items.filter((item) => !samePermission(item, request)));
    portty
      .permissionDecision(request, optionId)
      .then(() => {
        // Mark as locally decided so our own resolution echo doesn't re-log it
        // as "resolved-elsewhere", then record the manual allow/reject + command.
        autoDecided.add(callKey);
        logDecision(request, source, tier);
      })
      .catch((e) => {
        setStatus(`could not send permission decision: ${e}`);
        setPermissions((items) =>
          items.some((item) => samePermission(item, request)) ? items : [...items, request],
        );
      });
  };

  /** Approve this request once at the ACP layer, then remember only the exact
   * category + title + canonical raw input locally. We intentionally do not send
   * ACP's provider-wide `allow_always`, whose scope may be broader. */
  const learnExactPermission = (request: portty.AgentPermission) => {
    const category = permissionCategory(request, agentEvents().get(request.id) ?? []);
    const input = permissionToolInput(request, agentEvents().get(request.id) ?? []);
    const candidate = learnExactAllowRule(policy(), category, request.tool_call.title, input);
    const option = request.options.find((item) => item.kind === "allow_once");
    if (!candidate || !option) {
      // One reason is that the request carries something credential-shaped, and
      // an exact rule would have to store it verbatim. Say so, so the refusal
      // reads as deliberate rather than broken.
      setStatus(
        "this permission cannot be saved as a rule - it carries something that looks like a secret, or its shape is not one we store",
      );
      return;
    }
    setPermissions((items) => items.filter((item) => !samePermission(item, request)));
    portty
      .permissionDecision(request, option.option_id)
      .then(() => {
        // The decision crosses an async boundary. Merge the learned rule into
        // the policy that is current now instead of restoring a stale snapshot.
        autoDecided.add(`${request.id}:${request.tool_call.tool_call_id}`);
        const next = learnExactAllowRule(policy(), category, request.tool_call.title, input);
        if (next) changePolicy(next);
        logDecision(request, "learned-exact", "exact");
      })
      .catch((error) => {
        setStatus(`could not send permission decision: ${error}`);
        setPermissions((items) =>
          items.some((item) => samePermission(item, request)) ? items : [...items, request],
        );
      });
  };

  /** Reset to the fail-closed sentinel: while it's active every card prompts
   * (see maybeAutoApprove). Called at the START of any connect op so replayed
   * cards can never be evaluated under the PREVIOUS host's policy. */
  const resetPolicyToLoading = () => {
    setPolicyHost("unpaired");
    setPolicy(DEFAULT_POLICY);
  };

  const selectPolicyHost = async (preferred?: string) => {
    const hosts = await portty.listHosts().catch(() => [] as portty.SavedHost[]);
    const host = hosts.find((item) => item.id === preferred) ?? hosts.find((item) => item.is_last);
    const key = host?.id ?? "unpaired";
    setPolicyHost(key);
    setPolicy(loadPolicy(key));
    // Move any WebView-era record into the core store and delete the original,
    // THEN load. Doing it in this order means a host whose log has already been
    // migrated pays one cheap `getItem` miss, and one that has not never ends up
    // with two divergent copies.
    await migrateDecisionLogFromLocalStorage(localStorage, portty.decisionLogStore, key);
    // Re-redacts anything written by an older build as a side effect.
    setDecisionLog(await loadDecisionLog(portty.decisionLogStore, key));
  };

  const changePolicy = (next: portty.ApprovalPolicy) => {
    setPolicy(next);
    localStorage.setItem(policyKey(policyHost()), JSON.stringify(persistentPolicy(next)));
  };

  /** Auto-decisions already sent, keyed `${session}:${tool_call}` - a snapshot
   * resync can re-deliver a still-pending card between our decision and the
   * host's resolution, and it must not double-log/double-send. Cleared on
   * disconnect (ids are only meaningful within a host run). */
  let autoDecided = new Set<string>();

  /** Append one decision to the per-host audit log and persist it. Central so
   * EVERY outcome is recorded with the command it acted on - not just the
   * auto-approvals, which was all the log used to capture. */
  const logDecision = (
    request: portty.AgentPermission,
    source: portty.DecisionSource,
    tier: portty.PolicyTier | "exact",
    external?: Pick<portty.PermissionResolvedInfo, "resolution" | "by">,
  ) => {
    const events = agentEvents().get(request.id) ?? [];
    const entry: portty.DecisionLogEntry = {
      at: new Date().toISOString(),
      session_id: request.id,
      tool_call_id: request.tool_call.tool_call_id,
      title: request.tool_call.title,
      category: permissionCategory(request, events),
      policy: tier,
      source,
      input: permissionToolInput(request, events),
      resolution: external?.resolution,
      resolved_by: external?.by,
    };
    const next = [entry, ...decisionLog()].slice(0, 200);
    setDecisionLog(next);
    // Fire-and-forget: the in-memory log is what the UI reads, and a failed
    // write must not block answering an approval.
    void persistDecisionLog(portty.decisionLogStore, policyHost(), next);
  };

  const maybeAutoApprove = (request: portty.AgentPermission): boolean => {
    // Fail closed while the per-host policy is still loading (connect/switch
    // in flight): prompting is always safe; the wrong host's yolo is not.
    if (policyHost() === "unpaired") return false;
    const callKey = `${request.id}:${request.tool_call.tool_call_id}`;
    if (autoDecided.has(callKey)) return true; // replay of an in-flight decision
    const current = policy();
    const events = agentEvents().get(request.id) ?? [];
    const category = permissionCategory(request, events);
    const input = permissionToolInput(request, events);
    if (
      !policyAllows(
        current,
        request.id,
        category,
        request.tool_call.title,
        input,
        request.workspace_scope,
      )
    ) {
      return false;
    }
    const effectiveTier = hasExactAllowRule(current, category, request.tool_call.title, input)
      ? "exact"
      : (current.session_overrides[String(request.id)] ?? current.tier);
    const option = request.options.find((item) => item.kind === "allow_once");
    if (!option) return false;
    autoDecided.add(callKey);
    // Log AFTER the decision actually lands - a log entry claiming an
    // auto-approval that never reached the host would be a false record.
    portty
      .permissionDecision(request, option.option_id)
      .then(() => {
        // Log AFTER the decision actually lands - a log entry claiming an
        // auto-approval that never reached the host would be a false record.
        logDecision(request, "auto", effectiveTier);
      })
      .catch((e) => {
        // Decision never landed: surface the card after all (fail closed).
        autoDecided.delete(callKey);
        setStatus(`could not send permission decision: ${e}`);
        setPermissions((items) =>
          items.some((item) => samePermission(item, request)) ? items : [...items, request],
        );
      });
    return true;
  };

  /** Transfer paths are collected in an in-app sheet: `window.prompt` (like
   *  confirm) is a silent no-op in WKWebView, so the old prompt-based flow
   *  simply did nothing on iOS. The "outside home" escape hatch is a visible
   *  toggle instead of a magic `outside:` prefix. */
  const [transferSheet, setTransferSheet] = createSignal<
    null | { mode: "download" } | { mode: "upload"; localPath: string }
  >(null);
  const [transferPath, setTransferPath] = createSignal("");
  const [transferOutside, setTransferOutside] = createSignal(false);

  const startDownload = () => {
    setTransferPath("");
    setTransferOutside(false);
    setTransferSheet({ mode: "download" });
  };

  const startUpload = async () => {
    const localPath = await open({ multiple: false, directory: false });
    if (typeof localPath !== "string") return;
    setTransferPath(localPath.split(/[\\/]/).at(-1) ?? "upload");
    setTransferOutside(false);
    setTransferSheet({ mode: "upload", localPath });
  };

  const submitTransfer = async () => {
    const sheet = transferSheet();
    const hostPath = transferPath().trim();
    if (!sheet || !hostPath) return;
    setTransferSheet(null);
    if (sheet.mode === "download") {
      const localPath = await save({ defaultPath: hostPath.split(/[\\/]/).at(-1) ?? "download" });
      if (!localPath) return;
      try {
        await portty.downloadFile(hostPath, localPath, transferOutside());
        setTransferStatus("Download started");
      } catch (error) {
        setTransferStatus(`Download failed: ${error}`);
      }
    } else {
      try {
        await portty.uploadFile(sheet.localPath, hostPath, transferOutside());
        setTransferStatus("Upload started");
      } catch (error) {
        setTransferStatus(`Upload failed: ${error}`);
      }
    }
  };

  // Android hardware back / swipe-back handler. The native side (MainActivity)
  // calls window.__porttyOnBack() on every back gesture: we peel ONE layer off
  // the top and return true if we consumed it; the native side backgrounds the
  // app only when we return false. Order = most-transient first, matching how
  // the layers stack visually.
  onMount(() => {
    const w = window as unknown as {
      __porttyOnBack?: () => boolean;
      __porttyLocked?: boolean;
    };
    w.__porttyOnBack = () => {
      // Under the biometric lock, back must NEVER navigate or dismiss anything -
      // it should background the app (handled by returning false), never count
      // as an unlock. BiometricGate owns this flag.
      if (w.__porttyLocked) return false;
      // 1) Transient overlays first (topmost UI).
      if (transferSheet()) {
        setTransferSheet(null);
        return true;
      }
      if (showAgentPicker()) {
        setShowAgentPicker(false);
        return true;
      }
      if (showTerminalPicker()) {
        closeTerminalPicker();
        return true;
      }
      if (hostMenuOpen()) {
        setHostMenuOpen(false);
        return true;
      }
      if (renamingId() != null) {
        setRenamingId(null);
        return true;
      }
      if (renamingHostId() != null) {
        setRenamingHostId(null);
        return true;
      }
      // 2) Sub-screens fall back to the session list (same as their header back).
      switch (view()) {
        case "terminal":
        case "agent":
          backToList();
          return true;
        case "pair":
          setScanning(false);
          setView("list");
          return true;
        default:
          // 3) Home list with nothing open → let Android background the app.
          return false;
      }
    };
    onCleanup(() => {
      delete w.__porttyOnBack;
    });
  });

  /** Union-merge a snapshot or live batch into the per-session timeline.
   * Events are immutable and seq-unique, and the host never reuses session
   * ids, so union is always safe - and it keeps locally-buffered history that
   * the host has already pruned from its bounded replay window (a
   * background/foreground cycle must not shrink the visible chat). */
  const mergeAgentBatch = (batch: portty.AgentEventBatch) => {
    setAgentEvents((current) => {
      const next = new Map(current);
      const existing = next.get(batch.id) ?? [];
      const bySeq = new Map<number, portty.AgentTimelineEvent>();
      for (const event of [...existing, ...batch.events]) bySeq.set(event.seq, event);
      const ordered = [...bySeq.values()].sort((a, b) => a.seq - b.seq);
      const retained = ordered.slice(-2000);
      // Must mirror the host's sticky set (StickyAgentEvent in session.rs) -
      // any kind the host preserves across pruning must survive the client
      // cap too, or late state silently vanishes on long sessions.
      const reducerTypes = new Set<portty.AgentEvent["type"]>([
        "available_commands",
        "mode_state",
        "config_options",
        "session_info",
        "replaying",
        "auth_required",
        "usage",
      ]);
      for (const type of reducerTypes) {
        let latest: portty.AgentTimelineEvent | undefined;
        for (let i = ordered.length - 1; i >= 0; i--) {
          if (ordered[i].event.type === type) {
            latest = ordered[i];
            break;
          }
        }
        if (latest && !retained.some((event) => event.seq === latest.seq)) retained.push(latest);
      }
      retained.sort((a, b) => a.seq - b.seq);
      next.set(batch.id, retained);
      return next;
    });
  };

  /** Confirm before killing a session - close is destructive and irreversible
   *  (the shell and its processes die). `window.confirm` is a silent no-op in
   *  WKWebView (iOS) - a blocking dialog never appears and the call returns
   *  falsy - so this is a two-tap arm/confirm instead: the first tap arms the
   *  button (it turns red and gains a question badge), then a second tap kills. */
  const [armedKillId, setArmedKillId] = createSignal<number | null>(null);
  let armedKillTimer: number | undefined;
  /** Terminal overflow sheet (upload / pause / end session). Closed on every
   *  view change and session switch so it can never reopen over a different
   *  session than the one whose actions it lists. */
  const [termMenu, setTermMenu] = createSignal(false);
  createEffect(
    on([view, activeId], () => setTermMenu(false), { defer: true }),
  );
  const killWithConfirm = (id: number) => {
    if (armedKillId() === id) {
      window.clearTimeout(armedKillTimer);
      setArmedKillId(null);
      portty
        .kill(id)
        .then(() => {
          // Navigation normally rides the SessionRemoved event; this is the
          // fallback so a confirmed kill never leaves the user staring at a
          // blank terminal if that one event is delayed or lost.
          if (activeId() === id && (view() === "terminal" || view() === "agent")) {
            setActiveId(null);
            setView("list");
          }
        })
        .catch((e) => setStatus(`${e}`));
    } else {
      setArmedKillId(id);
      window.clearTimeout(armedKillTimer);
      armedKillTimer = window.setTimeout(() => setArmedKillId(null), 3500);
    }
  };

  /** Removing a saved host deletes its reconnect credential, so use the same
   *  mobile-safe two-tap confirmation as session kill. */
  const [armedHostRemoval, setArmedHostRemoval] = createSignal<string | null>(null);
  let armedHostRemovalTimer: number | undefined;
  const removeHostWithConfirm = async (host: portty.SavedHost) => {
    if (armedHostRemoval() !== host.id) {
      setArmedHostRemoval(host.id);
      window.clearTimeout(armedHostRemovalTimer);
      armedHostRemovalTimer = window.setTimeout(() => setArmedHostRemoval(null), 3500);
      return;
    }

    window.clearTimeout(armedHostRemovalTimer);
    setArmedHostRemoval(null);
    // Removing the CONNECTED host drops the link, and that drop fires the
    // `disconnected` handler - which would auto-reconnect (to this very host
    // if the token deletion raced, or silently to ANOTHER saved host), making
    // removal look broken. Flag it as deliberate BEFORE the drop can fire.
    const removingCurrent = policyHost() === host.id;
    if (removingCurrent) manualDisconnect = true;
    try {
      const removal = await portty.removeHost(host.id);
      const disconnected = removal.disconnected;
      // Wasn't actually the live connection: don't leave a stale manual flag
      // that would suppress the auto-reconnect of a FUTURE real drop.
      if (!disconnected) manualDisconnect = false;
      // The credential is gone, so the approval history and policy for that
      // machine must go with it (see forgetHostStorage).
      forgetHostStorage(host.id);
      if (policyHost() === host.id) setDecisionLog([]);
      setHostList((hosts) => hosts.filter((saved) => saved.id !== host.id));
      if (disconnected) {
        setPaired(false);
        setPaused(false);
        setSessions([]);
        setActiveId(null);
        term?.reset();
        scanner.reset();
        setStatus(
          removal.remote_revoked
            ? "pair ended on both devices"
            : "removed here - laptop could not confirm revocation",
        );
      } else {
        setStatus("saved host removed locally - revoke it on the laptop if needed");
      }
    } catch (e) {
      if (removingCurrent) manualDisconnect = false;
      setStatus(`could not remove host: ${e}`);
    }
  };

  /** Renaming a saved host is cosmetic and phone-local, so unlike removal it
   *  needs no two-tap confirmation - and clearing the field is the undo. */
  const startHostRename = (host: portty.SavedHost) => {
    // Seed with the nickname only. Prefilling the announced hostname would make
    // "clear the field to go back to the hostname" impossible to discover.
    setHostRenameText(host.is_renamed ? (host.name ?? "") : "");
    setRenamingHostId(host.id);
    // A rename and an armed removal on the same row would both be listening for
    // the next tap; opening the editor disarms.
    window.clearTimeout(armedHostRemovalTimer);
    setArmedHostRemoval(null);
  };

  const commitHostRename = async (host: portty.SavedHost) => {
    const typed = hostRenameText();
    setRenamingHostId(null);
    // The backend trims and caps, so compare against what it would store rather
    // than the raw field - retyping the same name must not fire a pointless write.
    const current = host.is_renamed ? (host.name ?? "") : "";
    if (typed.trim() === current.trim()) return;
    try {
      const nickname = await portty.renameHost(host.id, typed);
      // Patch in place instead of re-listing: `listHosts` is cheap but would
      // also re-resolve `is_last`, and the row is the only thing that changed.
      setHostList((hosts) =>
        hosts.map((saved) =>
          saved.id === host.id
            ? {
                ...saved,
                name: nickname ?? saved.announced_name,
                is_renamed: nickname != null,
              }
            : saved,
        ),
      );
      setStatus(nickname ? `host renamed to ${nickname}` : "host name reset to its hostname");
    } catch (e) {
      setStatus(`could not rename host: ${e}`);
    }
  };

  /** Forget every saved laptop in one gesture (same two-tap arm as single
   *  removal, keyed by a sentinel that can never collide with a host id). */
  const ALL_HOSTS = "**all**";
  const removeAllHostsWithConfirm = async () => {
    if (armedHostRemoval() !== ALL_HOSTS) {
      setArmedHostRemoval(ALL_HOSTS);
      window.clearTimeout(armedHostRemovalTimer);
      armedHostRemovalTimer = window.setTimeout(() => setArmedHostRemoval(null), 3500);
      return;
    }
    window.clearTimeout(armedHostRemovalTimer);
    setArmedHostRemoval(null);
    const hosts = hostList();
    // Same live-connection care as single removal: flag the deliberate drop
    // BEFORE any credential deletion can fire the disconnect handler.
    const removingCurrent = hosts.some((h) => policyHost() === h.id);
    if (removingCurrent) manualDisconnect = true;
    let disconnected = false;
    let failures = 0;
    for (const h of hosts) {
      try {
        const removal = await portty.removeHost(h.id);
        disconnected = removal.disconnected || disconnected;
        forgetHostStorage(h.id);
      } catch {
        failures += 1;
      }
    }
    setDecisionLog([]);
    if (removingCurrent && !disconnected) manualDisconnect = false;
    setHostList(failures ? await portty.listHosts().catch(() => []) : []);
    if (disconnected) {
      setPaired(false);
      setPaused(false);
      setSessions([]);
      setActiveId(null);
      term?.reset();
      scanner.reset();
    }
    setStatus(
      failures
        ? `could not remove ${failures} saved host${failures === 1 ? "" : "s"}`
        : "all saved hosts removed - pair again to reconnect",
    );
  };

  const togglePause = () => {
    if (paused()) {
      setPaused(false);
      void portty.resumeStream();
    } else {
      setPaused(true);
      void portty.pauseStream();
    }
  };

  /** A deliberate pair/host switch crosses a trust and session-id boundary.
   * Clear every host-scoped view before the replacement host can replay data. */
  const resetForHostChange = () => {
    setPaired(false);
    setPaused(false);
    setSessions([]);
    setPermissions([]);
    setAgentEvents(new Map());
    setHostSizes(new Map());
    setModeOverride(new Map());
    setActiveId(null);
    setAltScreen(false);
    setShowAgentPicker(false);
    // A folder listing belongs to the host that answered it, so it must not
    // survive into the next one.
    setShowTerminalPicker(false);
    pinchFont = null;
    term?.reset();
    scanner.reset();
    echo.reset();
    autoDecided = new Set();
    resetPolicyToLoading();
  };

  const doPair = async () => {
    if (connecting()) return; // one connection op at a time
    setConnecting(true);
    // A deliberate connect consumes any earlier disconnect intent and cancels a
    // scheduled auto-retry - a stale timer firing later must not fight this op,
    // and a stuck manualDisconnect must not suppress future auto-reconnects.
    manualDisconnect = false;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    setStatus("connecting…");
    try {
      // ALWAYS drop the previous connection first. The core keeps the old
      // (possibly dead) channel around after a silent drop - without this,
      // pair/reconnect fails with "already paired" even though the link is gone.
      // The resulting `disconnected` event is ignored while `connecting` (below).
      await portty.disconnect().catch(() => {});
      resetForHostChange();
      // Subscribe BEFORE pairing: the code arrives mid-handshake, and the host
      // will not acknowledge until someone confirms it there, so a late listener
      // would leave the user staring at a spinner with nothing to compare.
      const unlistenCode = await portty.onPairCode((code) => setPairCode(code));
      try {
        await portty.pair(ticket().trim(), outputCb, sizeCb, phrase().trim());
      } finally {
        unlistenCode();
      }
      // Load THIS host's policy before any replayed approval card can be
      // auto-evaluated (cards prompt fail-closed until this resolves).
      await selectPolicyHost();
      setPaired(true);
      disconnectedAt = 0;
      setStatus("paired");
      setView("list");
    } catch (e) {
      setStatus(`pair failed: ${e}`);
    } finally {
      setConnecting(false);
      setPairCode("");
    }
  };

  /** Resume a saved host by stored token. `host` (from the saved-hosts picker)
   *  switches to a SPECIFIC laptop; omitted = the most recent one. */
  const doReconnect = async (host?: string) => {
    if (connecting()) return;
    setConnecting(true);
    // See doPair: consume disconnect intent + cancel any scheduled auto-retry.
    manualDisconnect = false;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    setStatus("resuming…");
    try {
      await portty.disconnect().catch(() => {});
      resetForHostChange();
      await portty.reconnect(outputCb, sizeCb, host);
      // Policy first, THEN paired: replayed cards prompt until it's loaded.
      await selectPolicyHost(host);
      setPaired(true);
      disconnectedAt = 0;
      setStatus("paired");
      setView("list");
    } catch (e) {
      setStatus(`reconnect failed: ${e}`);
    } finally {
      setConnecting(false);
    }
  };

  /** Auto-reconnect after a silent drop (phone dozed, host restarted, Wi-Fi
   *  blip). Cleans up the dead channel, resumes by stored token with backoff,
   *  and puts the user back in the session they were viewing. */
  const tryAutoReconnect = async () => {
    if (paired() || connecting()) return;
    setConnecting(true);
    setStatus(`reconnecting… (${reconnectAttempt + 1})`);
    try {
      await portty.disconnect().catch(() => {});
      resetPolicyToLoading();
      await portty.reconnect(outputCb, sizeCb);
      reconnectAttempt = 0;
      await selectPolicyHost();
      setPaired(true);
      setStatus("paired");
      if (disconnectedAt && Date.now() - disconnectedAt > 3000) {
        setReconnectToast(true);
        window.setTimeout(() => setReconnectToast(false), 2400);
      }
      disconnectedAt = 0;
      // Drop the user back into the session they were viewing.
      const want = activeId();
      if ((view() === "terminal" || view() === "agent") && want != null) {
        // The session may be gone (host restarted → new ids, or it ended while
        // we were offline). Without this catch the user is stranded on a blank
        // terminal with no way back - fall back to the list like attachTo does.
        const strandGuard = (e: unknown) => {
          if (activeId() === want && (view() === "terminal" || view() === "agent")) {
            setStatus(`${e}`);
            setActiveId(null);
            setView("list");
          }
        };
        if (view() === "terminal") {
          // Warm resume: the xterm buffer still holds the session - ask for
          // the delta after the last seen seq instead of a full repaint. The
          // HOST falls back to ScreenReset + snapshot when the boundary aged
          // out, and outputCb handles that reset - no client fallback needed.
          // Stale echo predictions/RTT die with the old link either way.
          echo.reset();
          portty.resumeOutput(want).catch(strandGuard);
          requestAnimationFrame(() => applyLayout());
        } else {
          portty.attach(want).catch(strandGuard);
        }
      }
    } catch {
      reconnectAttempt++;
      if (reconnectAttempt < 6) {
        reconnectTimer = window.setTimeout(
          () => void tryAutoReconnect(),
          Math.min(8000, 1000 * 2 ** reconnectAttempt),
        );
      } else {
        reconnectAttempt = 0;
        setStatus("disconnected - reconnect from the home screen");
        setActiveId(null);
        if (view() === "terminal" || view() === "agent") setView("list");
      }
    } finally {
      // Release the in-flight guard on every path - including before a scheduled
      // retry fires, so the next attempt isn't blocked by a stale flag.
      setConnecting(false);
    }
  };

  const startRename = (s: SessionInfo) => {
    setRenameText(s.title);
    setRenamingId(s.id);
  };

  const commitRename = (id: number) => {
    const t = renameText().trim();
    if (t) portty.rename(id, t).catch((e) => setStatus(`${e}`));
    setRenamingId(null);
  };

  /** Connection state → header dot color. Deliberately TWO-state: green when
   *  paired and connected, red otherwise - including while resuming/reconnecting
   *  and after a failure. No amber "busy" state: a single dot is enough to say
   *  connected-or-not at a glance (transient detail still lives in the toasts). */
  const statusState = (): "ok" | "err" => (paired() ? "ok" : "err");

  onMount(async () => {
    const unlistens: Array<() => void> = [];
    unlistens.push(
      await portty.onList((s) => {
        // Show the list - do NOT auto-open a terminal. The user picks one.
        setSessions(s);
      }),
    );
    unlistens.push(
      await portty.onAdded((info) => {
        // Just track the session in the list. Opening a phone-created shell is
        // driven by newSession's returned id (see newSessionOrPair), not by
        // guessing here - so a session that appears for any other reason (e.g.
        // `portty share`) simply shows up without hijacking a pending create.
        const isNew = !sessions().some((s) => s.id === info.id);
        setSessions((p) =>
          p.some((s) => s.id === info.id) ? p.map((s) => (s.id === info.id ? info : s)) : [...p, info],
        );
        // Overrides are memory-only, and removal normally clears them. Keep a
        // defensive purge here too in case an event resync introduces a session
        // id without its earlier removal event reaching this WebView.
        if (isNew) {
          const current = policy();
          if (current.session_overrides[String(info.id)]) {
            const session_overrides = { ...current.session_overrides };
            delete session_overrides[String(info.id)];
            changePolicy({ ...current, session_overrides });
          }
        }
      }),
    );
    unlistens.push(
      await portty.onRemoved((id) => {
        setSessions((p) => p.filter((s) => s.id !== id));
        // Drop per-session render state so the maps don't grow unbounded.
        setHostSizes((p) => {
          const m = new Map(p);
          m.delete(id);
          return m;
        });
        setModeOverride((p) => {
          const m = new Map(p);
          m.delete(id);
          return m;
        });
        setAgentEvents((p) => {
          const m = new Map(p);
          m.delete(id);
          return m;
        });
        setPermissions((items) => items.filter((item) => item.id !== id));
        // The override dies with its session (ids are reused across host runs).
        {
          const current = policy();
          if (current.session_overrides[String(id)]) {
            const session_overrides = { ...current.session_overrides };
            delete session_overrides[String(id)];
            changePolicy({ ...current, session_overrides });
          }
        }
        if (activeId() === id) {
          // Tell the host we stopped viewing: its live forwarder holds the
          // dead session's scrollback and only a Detach/attach/pause aborts
          // it. Also clear the stale xterm buffer so nothing old flashes on
          // the next attach.
          void portty.detach();
          term?.reset();
          setActiveId(null);
          if (view() === "terminal" || view() === "agent") setView("list");
        }
      }),
    );
    unlistens.push(
      await portty.onActivity((id) => {
        setSessions((p) => p.map((s) => (s.id === id ? { ...s, has_activity: true } : s)));
      }),
    );
    unlistens.push(
      await portty.onAgentSnapshot((batch) => {
        // The host immediately replays every still-pending approval after the
        // snapshot (on attach AND on lag-resync). Clear stale cards first so
        // resolved requests do not survive a background/reconnect cycle.
        setPermissions((items) => items.filter((item) => item.id !== batch.id));
        mergeAgentBatch(batch);
      }),
    );
    unlistens.push(await portty.onAgentEvent((batch) => mergeAgentBatch(batch)));
    unlistens.push(
      await portty.onPermission((request) => {
        if (maybeAutoApprove(request)) return;
        setPermissions((items) => [
          ...items.filter((item) => !samePermission(item, request)),
          request,
        ]);
        // Ring the OS when this lands while the app is off screen. Without it a
        // merely-backgrounded phone shows nothing: the card waits behind a dark
        // screen and the agent stays blocked until someone happens to look.
        // Deliberately AFTER the auto-approve check above, so a request policy
        // already answered never buzzes a pocket. Fire-and-forget - a failed
        // notification must not interfere with answering the card.
        void notifyPendingApproval({
          appVisible: appIsVisible(),
          pendingCount: permissions().length,
        });
        // Push is only a doorbell; after launch/reconnect the host replays its
        // queued card. Open that agent directly so the card is on screen - but
        // ONLY when a notification tap actually brought us forward. Otherwise
        // stay where the user put themselves; the badge and the session dot are
        // the notice.
        if (view() === "list" && consumeWakeAttach()) attachAgent(request.id);
      }),
    );
    unlistens.push(
      await portty.onTransferProgress((progress) => {
        const total = progress.total ? ` / ${Math.round(progress.total / 1024)} KiB` : "";
        setTransferStatus(
          `${progress.direction === "upload" ? "Uploading" : "Downloading"} ${Math.round(progress.transferred / 1024)} KiB${total}`,
        );
      }),
    );
    unlistens.push(
      await portty.onTransferComplete((complete) => {
        setTransferStatus(`${complete.direction === "upload" ? "Uploaded" : "Downloaded"} ${complete.path}`);
      }),
    );
    unlistens.push(
      await portty.onTransferError((error) => setTransferStatus(`Transfer failed: ${error.message}`)),
    );
    unlistens.push(
      await portty.onPermissionResolved((resolved) => {
        // Answered somewhere - this phone (echo of our own decision), another
        // phone, or the laptop's `portty agent` chat. Dismiss the card.
        const callKey = `${resolved.id}:${resolved.tool_call_id}`;
        const wasOurs = autoDecided.has(callKey);
        autoDecided.delete(callKey);
        const pending = permissions().find(
          (item) => item.id === resolved.id && item.tool_call.tool_call_id === resolved.tool_call_id,
        );
        // Audit an EXTERNAL resolution of a card we were still showing. Our own
        // decisions already logged; cards we never had aren't ours to record.
        if (!wasOurs && pending) {
          const tier = policy().session_overrides[String(resolved.id)] ?? policy().tier;
          // A v5 host tells us the outcome + which viewer answered - record both
          // in the decision log and name them in the notice instead of a bare
          // "answered elsewhere" (older hosts leave these undefined).
          logDecision(pending, "resolved-elsewhere", tier, {
            resolution: resolved.resolution,
            by: resolved.by,
          });
          const outcome =
            resolved.resolution === "allowed"
              ? "Approved"
              : resolved.resolution === "rejected"
                ? "Rejected"
                : null;
          const where = resolved.by === "laptop" ? "on the laptop" : "on another device";
          const notice =
            resolved.by === "system" || resolved.resolution === "cancelled"
              ? "Approval dismissed - the agent ended the turn"
              : outcome
                ? `${outcome} ${where}`
                : "Approval answered on another device";
          showToast(notice);
        }
        setPermissions((items) =>
          items.filter(
            (item) =>
              !(item.id === resolved.id && item.tool_call.tool_call_id === resolved.tool_call_id),
          ),
        );
      }),
    );
    unlistens.push(
      await portty.onError((message) => {
        // Legacy host-side command error (correlated commands now reject their
        // own promise instead). Surface anything that still arrives this way.
        setStatus(message);
      }),
    );
    unlistens.push(
      await portty.onPairRevoked((host) => {
        // This is an explicit authenticated terminal state, not a transient
        // network drop. Suppress auto-reconnect and remove only the matching
        // generation's host entry (the Rust core already erased its credential).
        manualDisconnect = true;
        // The pairing is over and the credential already deleted, so this host's
        // approval history and policy go too - same reasoning as an explicit
        // removal (see forgetHostStorage).
        forgetHostStorage(host);
        if (policyHost() === host) setDecisionLog([]);
        setHostList((hosts) => hosts.filter((saved) => saved.id !== host));
        setPaired(false);
        setPaused(false);
        setSessions([]);
        // Pair ended - drop any pending approval cards for the dead pairing.
        setPermissions([]);
        setActiveId(null);
        term?.reset();
        scanner.reset();
        setStatus("pair ended by laptop");
        if (view() === "terminal" || view() === "agent") setView("list");
      }),
    );
    unlistens.push(
      await portty.onDisconnected(() => {
        // A deliberate pair/reconnect drops the old link first; that self-induced
        // `disconnected` must NOT start a competing auto-reconnect - the in-flight
        // op owns the transition and will set the final state itself.
        if (connecting()) return;
        setPaired(false);
        disconnectedAt = Date.now();
        setPaused(false);
        setSessions([]);
        // Drop pending approval cards: a tap on a dead link resolves nothing,
        // and the host replays every still-pending card after the reconnect
        // snapshot - so stale cards can't survive a drop and mis-resolve.
        setPermissions([]);
        // Echo confidence/RTT belong to the dead link; decisions sent on it
        // are void. Policy drops to the fail-closed sentinel until the next
        // connect re-selects the host.
        echo.reset();
        autoDecided = new Set();
        resetPolicyToLoading();
        setStatus("disconnected");
        if (manualDisconnect) {
          // User disconnected deliberately - respect it, no auto-reconnect.
          // Point at the one-tap recovery so a deliberate disconnect never feels
          // stranded on a re-pair form. Also cancel any already-scheduled
          // auto-retry - a stale timer firing after a deliberate disconnect would
          // reconnect against the user's intent.
          manualDisconnect = false;
          if (reconnectTimer) clearTimeout(reconnectTimer);
          setStatus("disconnected - tap Reconnect to resume");
          setActiveId(null);
          if (view() === "terminal" || view() === "agent") setView("list");
          return;
        }
        // Silent drop (doze/host restart/Wi-Fi) - reconnect automatically and
        // keep the user's place (activeId survives for the re-attach).
        reconnectAttempt = 0;
        void tryAutoReconnect();
      }),
    );
    onCleanup(() => unlistens.forEach((u) => u()));

    // Visibility transitions:
    //  - hidden  → Detach, so the host STOPS streaming to a backgrounded app
    //              (saves battery/data). It keeps buffering into its ring.
    //  - visible → if unpaired, reconnect; if paired, re-attach - which both
    //              resumes streaming AND acts as a liveness probe (a dead link
    //              fails the write, fires disconnected, and auto-reconnect runs).
    //              The host precedes the re-attach snapshot with a ScreenReset,
    //              so xterm is cleared first (no duplicated output).
    let wasHidden = document.visibilityState === "hidden";
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        wasHidden = true;
        if (connecting()) return; // a connect op is already in flight
        if (
          paired() &&
          (view() === "terminal" || view() === "agent") &&
          activeId() != null
        )
          void portty.detach();
        return;
      }
      // Ignore synthetic/duplicate visible notifications. In particular, the
      // Android biometric prompt can close with a visible event of its own.
      if (!wasHidden) return;
      wasHidden = false;
      if (connecting()) return; // a connect op is already in flight
      // A push-notification tap may have brought us forward: the wake blob
      // names WHICH host rang. Reconnect there (host switch included) so the
      // replayed approval card lands on screen.
      void (async () => {
        const wakeHost = await portty.consumePushWake().catch(() => null);
        if (wakeHost) {
          // Came forward from a notification tap - the replayed card may open.
          armWakeAttach();
          await doReconnect(wakeHost);
          return;
        }
        if (!paired()) {
          reconnectAttempt = 0;
          void tryAutoReconnect();
          return;
        }
        const id = activeId();
        if ((view() === "terminal" || view() === "agent") && id != null) {
          if (view() === "terminal") {
            // Warm resume - the buffer is intact; fetch only the missed delta.
            echo.reset();
            portty.resumeOutput(id).catch((e) => {
              if (activeId() === id && view() === "terminal") {
                setStatus(`${e}`);
                setActiveId(null);
                setView("list");
              }
            });
          } else {
            portty.attach(id).catch((e) => {
              if (activeId() === id && view() === "agent") {
                setStatus(`${e}`);
                setActiveId(null);
                setView("list");
              }
            });
          }
          // Re-attach restarts live streaming on the host, so the pause state
          // must follow - otherwise the button shows resume while output is live.
          setPaused(false);
        }
      })();
    };
    document.addEventListener("visibilitychange", onVisibility);
    onCleanup(() => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("resize", onWinResize);
      const ta = termTextarea();
      ta?.removeEventListener("focus", onTaFocus);
      ta?.removeEventListener("blur", onTaBlur);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (sweepTimer !== undefined) window.clearInterval(sweepTimer);
      window.clearTimeout(armedKillTimer);
      window.clearTimeout(armedHostRemovalTimer);
    });

    // SEC-2: auto-resume on cold start - no pasted ticket/PIN. A push
    // notification tap is the doorbell case: its wake blob names WHICH host
    // rang, so resume THAT host and let its replayed approval card land.
    // Otherwise resume the most recent host. On failure we stay on the
    // (empty) home, where "New session" opens pairing.
    setConnecting(true);
    try {
      setStatus("resuming…");
      const wakeHost = await portty.consumePushWake().catch(() => null);
      // Cold start from a notification tap - same allowance as the resume path.
      if (wakeHost) armWakeAttach();
      resetPolicyToLoading();
      await portty.reconnect(outputCb, sizeCb, wakeHost ?? undefined);
      await selectPolicyHost(wakeHost ?? undefined);
      setPaired(true);
      setStatus("paired");
    } catch {
      setStatus("not paired");
    } finally {
      setConnecting(false);
    }
  });

  return (
    <div
      class="portty-app flex h-full flex-col text-neutral-200"
      classList={{ "portty-app--term": view() === "terminal" || view() === "agent" }}
    >
      <Show when={reconnectToast()}>
        <div class="portty-reconnect-toast">Reconnected - session restored</div>
      </Show>
      {/* Status changes are only visible in the home header's pill; away from
          home they'd vanish - surface them as a transient toast instead. */}
      <Show when={statusToast() && !showsStatusInline(view())}>
        <div class="portty-reconnect-toast portty-status-toast">{statusToast()}</div>
      </Show>
      {/* ── TERMINAL ── always mounted so xterm survives view switches; hidden
          (display:none) unless we're viewing it. */}
      <div class={view() === "terminal" ? "flex h-full flex-col" : "hidden"}>
        <header class="portty-header">
          <button
            class="portty-icon-btn"
            onClick={backToList}
            title="Back to sessions"
            aria-label="Back to sessions"
          >
            <Icon name="arrow-left" />
          </button>
          <span class="portty-header-title truncate">
            {sessions().find((s) => s.id === activeId())?.title ?? "terminal"}
          </span>
          {/* Perceived keystroke latency (echo round-trip EWMA) - the same
              measurement that gates predictive echo, surfaced for LAN vs LTE
              vs relay comparison. Hidden until a first sample exists. */}
          <Show when={echoLatency() > 0}>
            <span
              class="portty-latency-chip"
              title="Measured keystroke echo latency (round trip). Predictive echo turns on above 120 ms."
            >
              {echoLatency()} ms
            </span>
          </Show>
          <div class="portty-header-actions">
            {/* Fit ↔ match toggle. Match ("1:1") renders the host's real grid -
                required for full-screen apps and Ink TUIs (Claude Code); fit
                soft-wraps at phone width for comfortable log reading. While an
                app is on the alternate screen the view matches automatically. */}
            <button
              class="portty-icon-btn portty-mode-btn"
              disabled={activeId() == null}
              onClick={toggleMode}
              title={
                renderMode() === "match"
                  ? "Matching the host's terminal width - tap to fit to phone"
                  : "Fitting to phone width - tap to match the host's terminal"
              }
              aria-label={
                renderMode() === "match"
                  ? "Switch to fit-to-phone width"
                  : "Switch to match host terminal width"
              }
            >
              {renderMode() === "match" ? "1:1" : "Fit"}
            </button>
            <button
              class="portty-icon-btn"
              onClick={() => void startDownload()}
              title="Download from host"
              aria-label="Download a file from the host"
            >
              <Icon name="download" />
            </button>
            <button
              class="portty-icon-btn"
              classList={{ "portty-kb-on": keyboardUp() }}
              onClick={toggleKeyboard}
              title={keyboardUp() ? "Hide keyboard" : "Show keyboard"}
              aria-label={keyboardUp() ? "Hide keyboard" : "Show keyboard"}
              aria-pressed={keyboardUp()}
            >
              <Icon name="keyboard" />
            </button>
            {/* Seven 44pt controls plus a title do not fit 402px, and the title
                was the thing that lost - it collapsed to 12px ("p.") on a 16 Pro
                and to nothing on an SE, so the session you were typing into was
                unnamed. The three least-frequent actions moved in here; the
                session name gets the space back. A dot marks the menu whenever
                something inside it is live (paused, or a kill armed), so state
                that used to be visible on the toolbar is not simply hidden. */}
            <button
              class="portty-icon-btn"
              classList={{ "portty-icon-btn-on": termMenu() }}
              onClick={() => setTermMenu((open) => !open)}
              title="More terminal actions"
              aria-label="More terminal actions"
              aria-expanded={termMenu()}
            >
              <Icon name="more" />
              <Show when={paused() || (activeId() != null && armedKillId() === activeId())}>
                <span class="portty-icon-live-dot" aria-hidden="true" />
              </Show>
            </button>
          </div>
        </header>

        {/* The overflow sheet. Full-width rows with words, not glyphs - once an
            action costs a second tap it should at least stop being a rebus. */}
        <Show when={termMenu()}>
          <section class="portty-term-menu" role="menu" aria-label="More terminal actions">
            <button
              role="menuitem"
              onClick={() => {
                setTermMenu(false);
                void startUpload();
              }}
            >
              <Icon name="upload" />
              Upload a file to the host
            </button>
            <button
              role="menuitem"
              disabled={activeId() == null}
              onClick={() => {
                setTermMenu(false);
                togglePause();
              }}
            >
              <Icon name={paused() ? "play" : "pause"} />
              {paused() ? "Resume live output" : "Pause live output"}
            </button>
            {/* Power ends THIS session on both sides - the shell on the host dies
                and it leaves the phone's list. Two-tap armed (red) because it's
                destructive. Link-disconnect lives on the home screen. The menu
                stays OPEN on the arming tap: closing it would hide the very
                confirmation the second tap is meant to answer. */}
            <button
              role="menuitem"
              class="portty-term-menu-danger"
              classList={{
                "portty-kill-armed": activeId() != null && armedKillId() === activeId(),
              }}
              disabled={activeId() == null}
              onClick={() => {
                if (activeId() == null) return;
                const wasArmed = armedKillId() === activeId();
                killWithConfirm(activeId()!);
                if (wasArmed) setTermMenu(false);
              }}
            >
              <Icon name="power" />
              {activeId() != null && armedKillId() === activeId()
                ? "Tap again to end this session"
                : "End this session"}
            </button>
          </section>
        </Show>

        <Show when={transferStatus()}>
          <div class="portty-transfer-status" onClick={() => setTransferStatus("")}>
            {transferStatus()}
          </div>
        </Show>

        <Show when={transferSheet()}>
          {(sheet) => (
            <section class="portty-transfer-sheet">
              {/* The sheet arrived as a bare field with no name on it, which on
                  a phone is indistinguishable from the terminal sprouting an
                  input. Say which direction the transfer goes. */}
              <h2 class="portty-sheet-title">
                <Icon name={sheet().mode === "download" ? "download" : "upload"} />
                {sheet().mode === "download" ? "Download from host" : "Upload to host"}
              </h2>
              <label>
                {sheet().mode === "download"
                  ? "Path on the host to download"
                  : "Destination path on the host"}
                <input
                  type="text"
                  value={transferPath()}
                  placeholder="~/project/file.txt"
                  autocapitalize="off"
                  autocorrect="off"
                  spellcheck={false}
                  onInput={(event) => setTransferPath(event.currentTarget.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") void submitTransfer();
                  }}
                />
              </label>
              <label class="portty-transfer-outside">
                <input
                  type="checkbox"
                  checked={transferOutside()}
                  onChange={(event) => setTransferOutside(event.currentTarget.checked)}
                />
                Allow a path outside my home folder
              </label>
              <div class="portty-transfer-actions">
                <button class="portty-btn-ghost" onClick={() => setTransferSheet(null)}>
                  Cancel
                </button>
                <button
                  class="portty-btn-primary"
                  disabled={!transferPath().trim()}
                  onClick={() => void submitTransfer()}
                >
                  {sheet().mode === "download" ? "Download" : "Upload"}
                </button>
              </div>
            </section>
          )}
        </Show>

        <div
          class="portty-term-zoom relative flex-1 p-1"
          classList={{
            "overflow-hidden": !matchActive(),
            "portty-term-pan": matchActive(),
            // Open a pan axis only where the grid actually overflows; otherwise
            // touch-action stays `none` so the drag-scroll gesture survives.
            "portty-term-pan-x": matchActive() && panX() && !panY(),
            "portty-term-pan-xy": matchActive() && panY(),
            // Mouse-reporting app: the keyboard overlay goes click-through so a
            // tap reaches xterm and is reported as a click. Select mode already
            // does the same, so don't fight it for the same overlay.
            "portty-mouse-mode": mouseMode() && !selectMode(),
            "portty-select-mode": selectMode(),
          }}
          ref={termEl}
          onPointerDown={onTermPointerDown}
          onPointerMove={onTermPointerMove}
          onPointerUp={onTermPointerEnd}
          onPointerCancel={onTermPointerEnd}
        >
          {/* Loading state during attach/resume so a slow snapshot fetch reads
              as "working", not a frozen black screen the user taps/kills.
              "Opening portal", not "attaching": attach is the wire operation's
              name, and the person waiting is not attaching to anything - they
              are getting a way through to their machine, which is the whole
              product and the reason it is called Portty. */}
          <Show when={attaching()}>
            <div class="portty-term-loading" aria-live="polite">
              <span class="portty-term-spinner" />
              opening portal…
            </div>
          </Show>
          {/* Touch-reachable scrollback. The full-cover xterm helper textarea
              (z-index 10) eats swipe gestures, so surface explicit controls that
              scroll the LOCAL buffer only. stopPropagation on pointerdown keeps a
              tap here from bubbling to the terminal focus handler (which would
              yank the keyboard up). */}
          <div class="portty-scroll-ctl" onPointerDown={(e) => e.stopPropagation()}>
            <button
              class="portty-icon-btn"
              onClick={() => scrollTermPages(-1)}
              title="Scroll up"
              aria-label="Scroll up one page"
            >
              <Icon name="chevron-up" />
            </button>
            <button
              class="portty-icon-btn"
              onClick={() => scrollTermPages(1)}
              title="Scroll down"
              aria-label="Scroll down one page"
            >
              <Icon name="chevron-down" />
            </button>
            <button
              class="portty-icon-btn"
              onClick={scrollTermToBottom}
              title="Jump to latest output"
              aria-label="Jump to latest output"
            >
              <Icon name="scroll-bottom" />
            </button>
          </div>
        </div>

        {/* Select-mode bar: docked BETWEEN the terminal and the KeyBar - never
            overlaying terminal text (an overlay chip swallowed the long-press
            on the very rows the user wanted to copy). enter/exitSelectMode
            refit xterm around the height change. */}
        <Show when={selectMode()}>
          <div class="portty-select-bar">
            <span class="portty-select-hint">Long-press text to select</span>
            <button class="portty-chip-btn" onClick={() => void copyVisibleScreen()}>
              Copy screen
            </button>
            <button class="portty-chip-btn portty-chip-btn-done" onClick={exitSelectMode}>
              Done
            </button>
          </div>
        </Show>

        {/* Docked directly above the KeyBar: the composer and the keys it needs
            (Ctrl, Esc, Tab) read as one input surface, and neither ever covers
            terminal text. */}
        {/* A box that silently vanishes reads as a bug. Say why, once, in the
            space it used to occupy - the user learns the rule instead of
            re-wondering every time they open an editor. */}
        <Show when={!commandBarVisible()}>
          <div class="portty-cmdbar-hint">
            Full-screen app - it reads single keys. Tap the screen to type.
          </div>
        </Show>
        <Show when={commandBarVisible()}>
          <CommandBar
            value={draft()}
            onInput={setDraft}
            onSubmit={submitDraft}
            onFocus={focusComposer}
            onBlur={() => setComposerFocused(false)}
            ref={(el) => (draftEl = el)}
          />
        </Show>

        <KeyBar
          ctrl={ctrl()}
          onToggleCtrl={() => setCtrl((c) => !c)}
          alt={alt()}
          onToggleAlt={() => setAlt((a) => !a)}
          selectMode={selectMode()}
          onToggleSelect={() => (selectMode() ? exitSelectMode() : enterSelectMode())}
          onPaste={() => void pasteFromClipboard()}
          expanded={keysExpanded()}
          onToggleExpanded={toggleKeysExpanded}
          onKey={(s) => {
            // The latches compose with the arrows and PgUp/PgDn - Ctrl+Left and
            // Alt+Left are word motion, the most-used editing gesture there is,
            // and they used to be unreachable: the latch was consumed and a
            // PLAIN arrow sent, so the combination failed silently.
            const modified = modifySequence(s, latches());
            clearLatches();
            if (modified) {
              // A modified cursor key is always CSI, even under DECCKM - SS3 has
              // no slot for the parameter - so skip the rewrite below.
              sendInput(modified);
              return;
            }
            // In DECCKM application-cursor mode the arrow keys are SS3-encoded
            // (ESC O A) not CSI (ESC [ A); KeyBar emits CSI, so rewrite when the
            // app requested app-mode - otherwise arrows misbehave in less/vim/
            // menus while a hardware keyboard works, a confusing inconsistency.
            sendInput(scanner.appCursorMode() ? (CURSOR_CSI_TO_SS3[s] ?? s) : s);
          }}
        />
      </div>

      <Show when={view() === "agent"}>
        <AgentView
          session={sessions().find((session) => session.id === activeId())}
          events={activeId() == null ? [] : (agentEvents().get(activeId()!) ?? [])}
          permissions={permissions().filter((request) => request.id === activeId())}
          sending={sendingPrompt()}
          stopping={stoppingAgent()}
          onBack={backToList}
          onStop={() => void cancelAgentTurn()}
          onPrompt={sendAgentPrompt}
          onSetMode={setAgentMode}
          onSetConfig={setAgentConfig}
          onAuthenticate={authenticateAgent}
          onDecision={decidePermission}
          onLearnExact={learnExactPermission}
          policy={policy()}
          decisionLog={decisionLog()}
          onPolicyChange={changePolicy}
        />
      </Show>

      {/* ── SESSION LIST (home) ── */}
      <Show when={view() === "list"}>
        <div class="flex h-full flex-col">
          <header class="portty-header">
            <img src={logo} alt="" class="portty-logo" />
            <span class="portty-brand">Portty</span>
            <span class="portty-status" title={status()}>
              <span
                class="portty-status-dot"
                data-state={statusState()}
                role="img"
                aria-label={paired() ? "Connected" : "Not connected"}
              />
            </span>
            {/* No top-level approval count here on purpose. A header badge can
                only ever jump you to ONE session - it picked the oldest - which
                is a guess about which agent you meant, and with several waiting
                it took you somewhere you did not ask to go. The waiting state
                lives on the session cards instead, where it names the agent and
                a tap is unambiguous. */}
            <Show when={bioAvailable()}>
              <button
                class="portty-icon-btn"
                title={bioOn() ? "App lock on - tap to turn off" : "App lock off - tap to turn on"}
                aria-label={bioOn() ? "App lock on, tap to turn off" : "App lock off, tap to turn on"}
                onClick={() => {
                  const next = !bioOn();
                  if (!next) {
                    // Turning the lock OFF is exactly what someone holding an
                    // unlocked phone would do first, and it was the one path that
                    // asked for nothing. Prove it is the owner, same as enabling.
                    void promptBiometric("Confirm it's you to turn OFF app lock").then((ok) => {
                      if (!ok) {
                        setStatus("app lock left ON - authentication failed");
                        return;
                      }
                      setBioOn(false);
                      setBiometricPref(false);
                      setStatus("app lock off");
                    });
                    return;
                  }
                  // Turning the lock ON proves the credential works before the
                  // UI claims protection. A pref that says "on" while the OS
                  // prompt cannot actually run is the fail-open the gate exists
                  // to prevent - so only persist it after a real unlock.
                  void promptBiometric("Confirm it's you to turn on app lock").then((ok) => {
                    if (!ok) {
                      setStatus("app lock not enabled - authentication failed");
                      return;
                    }
                    setBioOn(true);
                    setBiometricPref(true);
                    setStatus("app lock on - Portty will ask on every return");
                  });
                }}
              >
                <Icon name={bioOn() ? "lock" : "unlock"} />
              </button>
            </Show>
            {/* Disconnect drops the phone link (sessions keep running
                on the Mac; Reconnect resumes them). Home-screen only - in the
                terminal header it was one thumb-slip from session end and read
                as "turn off", which stranded users. Non-destructive, no confirm. */}
            <Show when={paired()}>
              <button
                class="portty-icon-btn"
                title="Disconnect from host (sessions keep running)"
                aria-label="Disconnect from host; sessions keep running"
                onClick={() => {
                  manualDisconnect = true;
                  void portty.disconnect();
                }}
              >
                <Icon name="disconnect" />
              </button>
            </Show>
          </header>

          {/* As soon as one laptop is saved, selecting/switching it is a
              Home-screen operation - you pick the host right here instead of
              going through "Add host" (which stays exclusively for pairing a
              computer that is not saved yet). The blank disconnected value
              ensures tapping any named host immediately starts a reconnect. */}
          <Show when={hostList().length > 0}>
            <div class="portty-host-switcher">
              <span class="portty-host-switcher-label">
                <Icon name="host" />
                Host
              </span>
              <div class="portty-host-select-wrap" ref={hostMenuWrap}>
                <button
                  type="button"
                  class="portty-host-select"
                  disabled={connecting()}
                  aria-haspopup="listbox"
                  aria-expanded={hostMenuOpen()}
                  aria-label="Switch host"
                  onClick={() => setHostMenuOpen((open) => !open)}
                >
                  {/* The same glyph as the menu rows, so the closed control and
                      the open list are visibly the same kind of thing. Hidden
                      while unpaired: "Choose a host…" is a prompt, not a
                      machine, and a computer icon in front of it would claim
                      one is selected. */}
                  <Show when={paired() && !connecting()}>
                    <Icon name="monitor" class="portty-host-select-glyph" />
                  </Show>
                  <span class="portty-host-select-value">
                    {connecting()
                      ? "Switching host…"
                      : paired()
                        ? (hostList().find((h) => h.id === policyHost())?.name ??
                          "Connected host")
                        : "Choose a host…"}
                  </span>
                  <Icon name="chevron-down" class="portty-host-select-chevron" />
                </button>
                <Show when={hostMenuOpen()}>
                  <ul class="portty-host-menu" role="listbox" aria-label="Saved hosts">
                    <For each={hostList()}>
                      {(host) => {
                        const isCurrent = () => paired() && host.id === policyHost();
                        return (
                          <li>
                            <button
                              type="button"
                              role="option"
                              aria-selected={isCurrent()}
                              class="portty-host-menu-item"
                              classList={{ "portty-host-menu-item--active": isCurrent() }}
                              onClick={() => {
                                setHostMenuOpen(false);
                                if (host.id !== policyHost()) void doReconnect(host.id);
                              }}
                            >
                              {/* Every row in this list is a machine, so it gets
                                  the machine glyph - the same one the pairing
                                  screen uses for a saved host.

                                  It replaces a coloured dot that was driven by
                                  `isCurrent`, i.e. red for "not the host you are
                                  on" rather than for anything wrong. On a list
                                  of your own computers a red dot reads as "that
                                  one is down", and the tick beside the active
                                  row already says which is which. */}
                              <Icon name="monitor" class="portty-host-menu-glyph" />
                              <span class="portty-host-menu-name">
                                {host.name ?? `${host.id.slice(0, 8)}…`}
                              </span>
                              <Show when={isCurrent()}>
                                <Icon name="check" class="portty-host-menu-check" />
                              </Show>
                            </button>
                            {/* Per-machine setting, under the machine it belongs
                                to. Only for the CONNECTED one: choosing a folder
                                means browsing the host's workspace, which needs a
                                live link - so offering it on an offline row would
                                open a browser that cannot list anything. */}
                            <Show when={isCurrent()}>
                              <button
                                type="button"
                                class="portty-host-menu-sub"
                                onClick={() => {
                                  setHostMenuOpen(false);
                                  toggleTerminalPicker();
                                }}
                              >
                                <span class="portty-host-menu-sub-label">Default folder</span>
                                <span class="portty-host-menu-sub-value">
                                  {host.default_dir
                                    ? `${ROOT_LABEL[host.default_root ?? "workspace"]} / ${host.default_dir}`
                                    : host.default_root === "home"
                                      ? ROOT_LABEL.home
                                      : "workspace root"}
                                </span>
                              </button>
                            </Show>
                          </li>
                        );
                      }}
                    </For>
                    {/* "Add host" lives here - the switcher answers "which
                        machine", so "add a new one" belongs at the foot of the
                        same list (removed from the home footer). */}
                    <li>
                      <button
                        type="button"
                        class="portty-host-menu-item portty-host-menu-add"
                        onClick={() => {
                          setHostMenuOpen(false);
                          setScanError("");
                          setScanning(false);
                          setView("pair");
                        }}
                      >
                        <span class="portty-host-menu-plus" aria-hidden="true">
                          +
                        </span>
                        <span class="portty-host-menu-name">Add host</span>
                      </button>
                    </li>
                  </ul>
                </Show>
              </div>
            </div>
          </Show>

          <div class="flex-1 overflow-y-auto p-3">
            <Show
              when={sessions().length > 0}
              fallback={
                <div class="portty-empty">
                  <div class="portty-empty-glyph">&gt;_</div>
                  <p class="portty-empty-title">No sessions yet</p>
                  <p class="portty-empty-sub">
                    <Show
                      when={paired()}
                      fallback={
                        <Show
                          when={hostList().length > 0}
                          fallback={
                            <>
                              On your computer, run <code>portty-host</code> - then tap
                              “Connect to a host” and scan the QR it prints.
                            </>
                          }
                        >
                          Tap “Reconnect” to resume your last host, or “Connect to a host” to
                          pair a new computer running <code>portty-host</code>.
                        </Show>
                      }
                    >
                      Start a shell or choose “Coding agent” below.
                    </Show>
                  </p>
                </div>
              }
            >
              <div class="flex flex-col gap-2.5">
                <For each={sessions()}>
                  {(s) => (
                    <div
                      class="portty-session-card"
                      classList={{
                        "portty-session-card--waiting": pendingFor(s.id) > 0,
                      }}
                      onClick={() => {
                        if (renamingId() !== s.id) openSession(s);
                      }}
                    >
                      <Show
                        when={renamingId() === s.id}
                        fallback={
                          <>
                            <span
                              class="portty-session-icon"
                              title={
                                s.kind === "agent"
                                  ? "Structured coding agent"
                                  : s.source === "adopted"
                                    ? "Adopted terminal (portty share)"
                                    : undefined
                              }
                            >
                              {s.kind === "agent" ? (
                                "AI"
                              ) : s.source === "adopted" ? (
                                <Icon name="switch" />
                              ) : (
                                ">_"
                              )}
                            </span>
                            <span class="portty-session-body">
                              <span class="portty-session-name">{s.title}</span>
                              {/* Amber outranks lime: "waiting on YOUR approval"
                                  is the one state worth interrupting for. */}
                              <Show
                                when={pendingFor(s.id) > 0}
                                fallback={
                                  <Show when={s.has_activity}>
                                    <span class="portty-activity-dot" title="New output" />
                                  </Show>
                                }
                              >
                                {/* The COUNT, not just a dot: one agent can stack
                                    several requests, and "3 waiting" is a
                                    different decision from "1 waiting" - it tells
                                    you whether you are answering or triaging.
                                    Not a button; the whole card is the tap
                                    target, so there is no guess about which
                                    session you meant. */}
                                <span
                                  class="portty-session-pending"
                                  title={`${pendingFor(s.id)} approval${pendingFor(s.id) === 1 ? "" : "s"} waiting for you`}
                                  aria-label={`${pendingFor(s.id)} approval${pendingFor(s.id) === 1 ? "" : "s"} waiting for you`}
                                >
                                  {pendingFor(s.id)}
                                </span>
                              </Show>
                            </span>
                            <div
                              class="portty-session-actions"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <button title="Rename" onClick={() => startRename(s)}>
                                <Icon name="edit" />
                              </button>
                              <button
                                title={
                                  armedKillId() === s.id
                                    ? "Tap again to end this session"
                                    : "End session"
                                }
                                classList={{ "portty-kill-armed": armedKillId() === s.id }}
                                onClick={() => killWithConfirm(s.id)}
                              >
                                <Icon name="power" />
                                <Show when={armedKillId() === s.id}>
                                  <span class="portty-icon-confirm-mark">?</span>
                                </Show>
                              </button>
                            </div>
                          </>
                        }
                      >
                        <input
                          class="portty-rename-input"
                          value={renameText()}
                          autofocus
                          onClick={(e) => e.stopPropagation()}
                          onInput={(e) => setRenameText(e.currentTarget.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") commitRename(s.id);
                            if (e.key === "Escape") setRenamingId(null);
                          }}
                        />
                        <div class="portty-session-actions" onClick={(e) => e.stopPropagation()}>
                          <button title="Save" onClick={() => commitRename(s.id)}>
                            <Icon name="check" />
                          </button>
                          <button title="Cancel" onClick={() => setRenamingId(null)}>
                            <Icon name="close" />
                          </button>
                        </div>
                      </Show>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>

          <div class="portty-footer">
            {/* Disconnected: resume-by-stored-token is a
                one-tap primary action - recovery must NOT look like it needs a
                fresh ticket+PIN pairing. "Connect to a host" (the pair form)
                becomes the secondary path for reaching a NEW host. First run
                is the exception: with NO saved host, Reconnect can only fail,
                so pairing is the primary action instead. */}
            <Show when={!paired() && hostList().length > 0}>
              <button class="portty-new-session-btn" onClick={() => doReconnect()}>
                Reconnect
              </button>
            </Show>
            <button
              class={
                paired() || hostList().length === 0
                  ? "portty-new-session-btn"
                  : "portty-add-host-btn"
              }
              onClick={newSessionOrPair}
              disabled={creating()}
            >
              {!paired() ? "Connect to a host" : creating() ? "Creating…" : "+ New session"}
            </button>
            <Show when={paired()}>
              {/* Opened by "+ New session" above - there is no separate
                  "somewhere else" button, because starting a shell and choosing
                  where it starts are the same action. */}
              <Show when={showTerminalPicker()}>
                <div class="portty-agent-picker">
                  <div class="portty-dir-picker">
                    {/* The sheet OPENS on your default folder, so "Open here" is
                        one tap to where you usually work and there is no separate
                        shortcut row duplicating it.

                        The star sits on the "you are here" row, beside the folder
                        it applies to: changing the default is "navigate away, tap
                        the star", which you can find by looking because you start
                        standing on the current answer. It is never disabled - at
                        the root there is simply nothing to star (the root is what
                        "no default" means), so it is hidden there and the caption
                        teaches the gesture instead. */}
                    {/* Root switcher. Only shown when this host serves more than
                        one - a single chip labelled "Workspace" would just be
                        furniture. Switching resets to that root's top level, which
                        is the only rel guaranteed to exist in it. */}
                    <Show when={terminalRoots().length > 1}>
                      <div class="portty-dir-roots" role="tablist" aria-label="Folder roots">
                        <For each={terminalRoots()}>
                          {(root) => (
                            <button
                              role="tab"
                              class="portty-dir-root"
                              classList={{ "portty-dir-root--on": dirRoot() === root }}
                              aria-selected={dirRoot() === root}
                              disabled={dirLoading()}
                              onClick={() => {
                                if (dirRoot() === root) return;
                                void browseDir("", root);
                              }}
                            >
                              {ROOT_LABEL[root]}
                            </button>
                          )}
                        </For>
                      </div>
                    </Show>

                    <FolderBrowser
                      // The folder you are standing in. Absent at the root, where
                      // there is nothing to star: the root is what "no default"
                      // means, so a star there could only ever be a no-op.
                      trailing={
                        // In a non-workspace root the top level IS starrable ("open
                        // in home"), so the star is only meaningless at the
                        // workspace root - the one place that already means
                        // "no default".
                        <Show when={dirRel() !== "" || dirRoot() !== "workspace"}>
                          <DefaultStar rel={dirRel()} />
                        </Show>
                      }
                      // …and on every folder in the list, so starring one never
                      // requires opening it first. This is what makes setting the
                      // FIRST default reachable from the root, where the row above
                      // has no star to offer.
                      entryTrailing={(rel) => <DefaultStar rel={rel()} />}
                      // An icon with no label is a guess on a touch screen -
                      // `title` needs a pointer to hover, which a phone has not
                      // got. This line has to name a gesture that exists ON SCREEN:
                      // it used to say "open a folder and tap its star" while the
                      // rows had no stars, which is a promise the UI did not keep.
                      caption={
                        <p class="portty-dir-hint">
                          {dirIsDefault()
                            ? "New terminals open here by default. Tap its star to clear it."
                            : hostDefaultDir() === "" && hostDefaultRoot() === "workspace"
                              ? "New terminals open in the workspace root. Tap any folder’s star to make it the default."
                              : `Default: ${ROOT_LABEL[hostDefaultRoot()]}${hostDefaultDir() ? ` / ${hostDefaultDir()}` : ""} — tap another folder’s star to move it.`}
                        </p>
                      }
                    />

                    <div class="portty-dir-actions">
                      <button
                        class="portty-btn-ghost"
                        onClick={closeTerminalPicker}
                        disabled={creating()}
                      >
                        Cancel
                      </button>
                      <button
                        class="portty-btn-primary"
                        onClick={() => void startTerminalIn(dirRel())}
                        disabled={creating() || dirLoading()}
                      >
                        {creating() ? "Opening…" : "Open here"}
                      </button>
                    </div>
                  </div>
                </div>
              </Show>
              <button
                class="portty-add-host-btn portty-new-agent-btn"
                onClick={() => {
                  // Mutually exclusive: both sheets browse the same signals.
                  closeTerminalPicker();
                  setShowAgentPicker((open) => !open);
                }}
                disabled={creatingAgent()}
              >
                <Show when={!creatingAgent()} fallback="Starting agent…">
                  <Icon name="bot" class="portty-btn-icon" />
                  Coding agent
                </Show>
              </button>
              <Show when={showAgentPicker()}>
                <div class="portty-agent-picker">
                  <Show
                    when={pendingProvider()}
                    fallback={
                      <>
                        {/* Availability is shown BEFORE the three taps it used
                            to take to discover it. Unknown (older host, or the
                            request failed) stays tappable - refusing an agent we
                            have no information about would be worse than letting
                            the start fail with the host's own explanation. */}
                        <For
                          each={
                            [
                              ["claude_code", "C", "Claude Code"],
                              ["open_code", "O", "OpenCode"],
                              ["codex", "X", "Codex"],
                            ] as Array<[portty.AgentProvider, string, string]>
                          }
                        >
                          {([provider, glyph, label]) => {
                            const row = () => providerState(provider);
                            const missing = () => row()?.available === false;
                            return (
                              <button
                                classList={{ "is-unavailable": missing() }}
                                disabled={missing()}
                                title={row()?.detail ?? undefined}
                                onClick={() => chooseAgentProvider(provider)}
                              >
                                <span class="portty-agent-picker-glyph">{glyph}</span> {label}
                                <Show when={missing()}>
                                  <small class="portty-agent-picker-note">not installed</small>
                                </Show>
                              </button>
                            );
                          }}
                        </For>
                        {/* Goose is wired end-to-end (AgentProvider::Goose) but
                            not shipped in this build - the host binary isn't
                            provisioned yet. Re-enable this button to expose it. */}
                      </>
                    }
                  >
                    {(provider) => (
                      <div class="portty-dir-picker">
                        {/* The path the agent will actually run in, shown before
                            you commit - the old flow gave no indication at all. */}
                        <FolderBrowser />

                        {/* Conversations for THIS directory. Shown between the
                            folders and the actions so the choice reads in order:
                            where → which conversation → or start fresh.

                            The "asking" line is not decoration: this list now
                            includes what the AGENT remembers, which means the
                            host is launching its adapter to find out. Without a
                            visible wait, a conversation appearing a beat after
                            you already tapped "Start new" reads as a bug. */}
                        <Show when={dirSessionsLoading() || dirSessions().length > 0}>
                          <div class="portty-dir-saved">
                            <h3>Resume a conversation</h3>
                            <For each={dirSessions()}>
                              {(row) => (
                                <button
                                  class="portty-dir-session"
                                  onClick={() => void resumeSaved(row)}
                                  disabled={creatingAgent()}
                                >
                                  <span class="portty-dir-session-label">
                                    {row.label ?? row.title}
                                  </span>
                                  <span class="portty-dir-session-meta">
                                    {PROVIDER_LABEL[row.provider] ?? row.provider}
                                    {/* A conversation whose agent reported no
                                        usable timestamp shows no time at all,
                                        rather than "56y ago" from a zero. */}
                                    <Show when={row.last_active_at_unix_ms > 0}>
                                      {" · "}
                                      {agoLabel(row.last_active_at_unix_ms)}
                                    </Show>
                                  </span>
                                </button>
                              )}
                            </For>
                            <Show when={dirSessionsLoading()}>
                              <p class="portty-dir-saved-note">
                                Asking {PROVIDER_LABEL[provider()] ?? provider()} what it
                                remembers here…
                              </p>
                            </Show>
                          </div>
                        </Show>

                        <div class="portty-dir-actions">
                          <button
                            class="portty-btn-ghost"
                            onClick={() => setPendingProvider(null)}
                            disabled={creatingAgent()}
                          >
                            Back
                          </button>
                          <button
                            class="portty-btn-primary"
                            onClick={() => void startAgent(provider(), dirRel())}
                            disabled={creatingAgent() || dirLoading()}
                          >
                            {/* "Start here" while the probe is still out would be
                                a claim there is nothing to resume, made before
                                the answer arrived. Say "Start new" until it is
                                actually known to be false. */}
                            {creatingAgent()
                              ? "Starting…"
                              : dirSessionsLoading() || dirSessions().length > 0
                                ? "Start new"
                                : "Start here"}
                          </button>
                        </div>
                      </div>
                    )}
                  </Show>
                </div>
              </Show>
              {/* "Add host" moved into the host dropdown (the switcher owns
                  machine management now). The first-run "Connect to a host"
                  primary button above still covers the zero-host case, where no
                  dropdown exists yet. */}
            </Show>
          </div>
        </div>
      </Show>

      {/* ── PAIR ── */}
      <Show when={view() === "pair"}>
        <div class="flex h-full flex-col">
          <header class="portty-header">
            <button
              class="portty-icon-btn"
              onClick={() => {
                setScanning(false);
                setView("list");
              }}
              title="Back"
            >
              <Icon name="arrow-left" />
            </button>
            <span class="portty-header-title">Pair with a host</span>
          </header>

          {/* min-h-0 + overflow: with saved hosts + the ticket form + the soft
              keyboard up, the Pair button must stay reachable by scrolling. */}
          <div class="mx-auto flex w-full max-w-md min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-5">
            <Show
              when={scanning()}
              fallback={
                <>
                  {/* Host picker: saved laptops resume by stored token - one tap,
                      no PIN. The ticket+PIN form below is only for NEW laptops. */}
                  <Show when={hostList().length > 0}>
                    <div class="portty-card flex flex-col gap-2">
                      <p class="portty-hint">Saved hosts - tap to connect (no PIN needed):</p>
                      <For each={hostList()}>
                        {(h) => (
                          <div class="portty-saved-host-row">
                            <Show
                              when={renamingHostId() === h.id}
                              fallback={
                                <>
                                  <button
                                    class="portty-btn-ghost portty-saved-host-connect"
                                    onClick={() => doReconnect(h.id)}
                                  >
                                    <Icon name="monitor" />
                                    <span>
                                      {h.name ?? `${h.id.slice(0, 8)}…`}
                                      {h.is_last ? " · last used" : ""}
                                    </span>
                                  </button>
                                  <button
                                    class="portty-host-row-btn"
                                    onClick={() => startHostRename(h)}
                                    title="Rename this host (on this phone only)"
                                    aria-label={`Rename ${h.name ?? "saved host"}`}
                                  >
                                    <Icon name="edit" />
                                  </button>
                                  <button
                                    class="portty-host-row-btn"
                                    classList={{ "portty-host-row-btn--armed": armedHostRemoval() === h.id }}
                                    onClick={() => void removeHostWithConfirm(h)}
                                    title={
                                      armedHostRemoval() === h.id
                                        ? "Tap again to remove this saved host"
                                        : "Remove saved host"
                                    }
                                    aria-label={
                                      armedHostRemoval() === h.id
                                        ? `Confirm removal of ${h.name ?? "saved host"}`
                                        : `Remove ${h.name ?? "saved host"}`
                                    }
                                  >
                                    {armedHostRemoval() === h.id ? "Remove?" : <Icon name="close" />}
                                  </button>
                                </>
                              }
                            >
                              {/* The placeholder doubles as the hint: it shows what
                                  an empty field falls back to (the hostname). */}
                              <input
                                class="portty-rename-input"
                                value={hostRenameText()}
                                autofocus
                                maxLength={MAX_HOST_NAME_LEN}
                                placeholder={h.announced_name ?? "Name this host"}
                                aria-label={`Name for ${h.announced_name ?? "this host"}`}
                                onInput={(e) => setHostRenameText(e.currentTarget.value)}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") void commitHostRename(h);
                                  if (e.key === "Escape") setRenamingHostId(null);
                                }}
                              />
                              <button
                                class="portty-host-row-btn"
                                onClick={() => void commitHostRename(h)}
                                title="Save name"
                                aria-label="Save host name"
                              >
                                <Icon name="check" />
                              </button>
                              <button
                                class="portty-host-row-btn"
                                onClick={() => setRenamingHostId(null)}
                                title="Cancel"
                                aria-label="Cancel renaming host"
                              >
                                <Icon name="close" />
                              </button>
                            </Show>
                          </div>
                        )}
                      </For>
                      <Show when={hostList().length > 1}>
                        <button
                          class="portty-forget-all-btn"
                          classList={{
                            "portty-forget-all-btn--armed": armedHostRemoval() === ALL_HOSTS,
                          }}
                          onClick={() => void removeAllHostsWithConfirm()}
                        >
                          {armedHostRemoval() === ALL_HOSTS
                            ? "Tap again to forget all hosts"
                            : "Forget all saved hosts…"}
                        </button>
                      </Show>
                    </div>
                  </Show>
                  <p class="portty-hint">
                    On your host run <code>portty-host</code>. Scan the QR, paste the ticket, or - if
                    the ticket's too long to send by hand - type the NodeId + the six-word phrase it
                    printed. Then confirm the code that appears, on the computer.
                  </p>
                  <div class="portty-card flex flex-col gap-3">
                    {/* Labels stay visible after typing - placeholder-only
                        fields turn into anonymous boxes once filled. */}
                    <label class="portty-field">
                      Setup code from your computer
                      <textarea
                        class="portty-input portty-input--mono"
                        rows="2"
                        placeholder="NodeId (64 hex) or portty1:…"
                        value={ticket()}
                        onInput={(e) => setTicket(e.currentTarget.value)}
                        autocapitalize="off"
                        autocorrect="off"
                        autocomplete="off"
                        spellcheck={false}
                      />
                    </label>
                    {/* A bare NodeId carries no secret, so the phrase is the
                        credential and pairing cannot proceed without it. */}
                    <Show when={/^[0-9a-fA-F]{64}$/.test(ticket().trim())}>
                      <label class="portty-field">
                        6-word phrase
                        <input
                          class="portty-input portty-input--mono"
                          placeholder="raven-quartz-mellow-pixel-ridge-onyx"
                          value={phrase()}
                          onInput={(e) => setPhrase(e.currentTarget.value)}
                          autocapitalize="off"
                          autocorrect="off"
                          autocomplete="off"
                          spellcheck={false}
                        />
                      </label>
                    </Show>
                    <button
                      class="portty-btn-primary"
                      onClick={doPair}
                      disabled={connecting() || !canPair()}
                    >
                      {connecting() ? "Connecting…" : "Pair"}
                    </button>
                    {/* The host will not finish pairing until a human there
                        confirms this code, so it has to stay on screen for the
                        whole wait - not flash past. */}
                    <Show when={pairCode()}>
                      <div class="portty-pair-code" role="status" aria-live="polite">
                        <p class="portty-pair-code__label">
                          Check this matches the code on your computer, then confirm it there.
                        </p>
                        <p
                          class="portty-pair-code__digits"
                          aria-label={`Pairing code ${pairCode().split("").join(" ")}`}
                        >
                          {pairCode().slice(0, 3)} {pairCode().slice(3)}
                        </p>
                        <p class="portty-pair-code__warn">
                          If the codes differ, reject it there. Something is between this phone and
                          that machine.
                        </p>
                      </div>
                    </Show>
                  </div>
                  <div class="flex items-center gap-3">
                    <button
                      class="portty-btn-ghost portty-btn-with-icon"
                      disabled={connecting()}
                      onClick={() => {
                        setScanError("");
                        setScanning(true);
                      }}
                    >
                      <Icon name="qr-code" />
                      Scan QR
                    </button>
                    <Show when={hostList().length > 0}>
                      <button
                        class="portty-link flex-1 text-center"
                        onClick={() => doReconnect()}
                        disabled={connecting()}
                      >
                        {connecting() ? "Connecting…" : "Reconnect"}
                      </button>
                    </Show>
                  </div>
                  <Show when={scanError()}>
                    <p class="text-xs" style={{ color: "var(--red)" }}>
                      {scanError()}
                    </p>
                  </Show>
                  <p class="portty-hint">{status()}</p>
                </>
              }
            >
              <QrScanner
                onResult={(t) => {
                  setTicket(t);
                  setScanning(false);
                }}
                onError={(m) => {
                  setScanError(m);
                  setScanning(false);
                }}
                onCancel={() => setScanning(false)}
              />
            </Show>
          </div>
        </div>
      </Show>
    </div>
  );
}
