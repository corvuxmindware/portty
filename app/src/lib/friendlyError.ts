// Plain words for errors.
//
// What the core and the computer report is developer text: "transport: io:
// connection lost", "command timed out", "cannot open upload: No such file or
// directory (os error 2)". People need to know what happened and what to do
// next. Pairing and reconnecting already fail with a structured
// `{ kind, message, detail }` worked out from the typed Rust error
// (src-tauri/src/connect_error.rs); this module passes that through and maps
// the errors that still arrive as flat strings.
//
// Every message is one or two short sentences that end with a next step.
// Commands are wrapped in backticks; `ErrorNote` shows them as code.
//
// `detail` keeps the technical text for support, behind "Details". It goes
// through `redactDetail` first, so a pairing code, key, token, long id, link,
// address or file path never reaches the screen even if one slipped into an
// error upstream.

/** Where the error came from - the same words mean different things in each. */
export type ErrorContext =
  /** Pairing with a new computer. */
  | "pair"
  /** Reconnecting to a saved computer. */
  | "reconnect"
  /** Opening, ending or renaming a session. */
  | "session"
  /** Talking to a coding agent. */
  | "agent"
  | "upload"
  | "download"
  | "general";

export interface FriendlyError {
  /** A stable name for what went wrong (drives retries and tests). */
  kind: string;
  /** One or two short sentences: what happened, then what to do. */
  message: string;
  /** Technical text for support, already redacted. Empty when there is none. */
  detail: string;
}

/** Reconnect failures that trying again by itself cannot fix: someone has to
 *  update a program, pair again, or tidy a saved computer. Retrying these only
 *  delays the one message that says what to do. */
const NEEDS_THE_PERSON = new Set([
  "version",
  "rejected",
  "revoked",
  "wrong_host",
  "saved_damaged",
  "no_saved_host",
  "host_not_saved",
]);

/** Whether an automatic reconnect should keep trying after this failure. */
export const worthRetrying = (error: FriendlyError): boolean => !NEEDS_THE_PERSON.has(error.kind);

/** Whether the reconnect Portty tries by itself at launch should explain its
 *  failure. Only when someone has to act, or for the likely out-of-date
 *  computer program: a computer that is simply off reads as "Not connected"
 *  until the person taps Reconnect, and nothing is saved on a first run. */
export const worthShowingAtLaunch = (error: FriendlyError): boolean =>
  error.kind !== "no_saved_host" && (!worthRetrying(error) || error.kind === "maybe_old_host");

const MAX_DETAIL_CHARS = 600;

/**
 * Strip anything sensitive or identifying from technical text before it is
 * shown: pairing codes and phrases, links, file paths, long ids and keys, and
 * network addresses. Over-redacting a support note costs nothing; leaking a
 * secret into one is the thing this guards against.
 */
export function redactDetail(text: string): string {
  let out = text
    // Pairing tickets (`portty1:…`, `portty3:…`) and any other link or URI.
    .replace(/\bportty\d*:\S+/gi, "[pairing code]")
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, "[link]")
    // Six-word manual pairing phrases.
    .replace(/\b[a-z]+(?:-[a-z]+){5}\b/g, "[phrase]")
    // Windows paths, with or without the `\\?\` prefix, and UNC shares. A
    // Windows path cannot contain ':' after its drive, so stopping there keeps
    // the error text that follows ("…: Access is denied").
    .replace(/(?:\\\\\?\\)?[A-Za-z]:[\\/][^:\r\n"'<>|]*/g, "[path]")
    .replace(/\\\\[^\s\\:]+\\[^:\r\n"'<>|]*/g, "[path]")
    // Home-relative and absolute Unix paths, wherever a path can start.
    .replace(/(^|[\s'"(=,])~?\/[^:\r\n"')]*/g, "$1[path]")
    // Long hex or base32/base64 runs: device ids, keys, tokens.
    .replace(/\b[0-9a-f]{24,}\b/gi, "[id]")
    .replace(/\b[A-Za-z0-9_-]{40,}\b/g, "[id]")
    // IPv4 and IPv6 addresses, with any port.
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, "[address]")
    .replace(/\[?\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b\]?(?::\d+)?/gi, "[address]")
    // A six-digit comparison code standing on its own.
    .replace(/\b\d{6}\b/g, "[code]")
    .trim();
  if (out.length > MAX_DETAIL_CHARS) out = `${out.slice(0, MAX_DETAIL_CHARS)}…`;
  return out;
}

/** The error's own text, whatever shape it arrived in. */
function rawText(error: unknown): string {
  if (error === undefined || error === null) return "";
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object") {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  try {
    return JSON.stringify(error) ?? String(error);
  } catch {
    return String(error);
  }
}

/** A pair/reconnect failure from the core, already in plain words. */
function isStructured(error: unknown): error is { kind: string; message: string; detail?: unknown } {
  if (!error || typeof error !== "object") return false;
  const shaped = error as { kind?: unknown; message?: unknown };
  return typeof shaped.kind === "string" && typeof shaped.message === "string";
}

const isTransfer = (context: ErrorContext) => context === "upload" || context === "download";

type Rule = {
  test: RegExp;
  kind: string;
  /** Only for these contexts; every context when absent. */
  only?: ErrorContext[];
  message: (context: ErrorContext) => string;
};

const RUN_PAIR_AGAIN = "Run `portty pair` on your computer again and scan the new QR code.";
const PAIR_AGAIN =
  "Pair again: run `portty pair` on your computer and scan the new QR code.";

// First match wins, so specific rules sit above general ones.
const RULES: Rule[] = [
  {
    test: /already in progress/i,
    kind: "busy",
    message: () => "Portty is already connecting. Wait a moment, then try again.",
  },
  {
    test: /\bnot paired\b/i,
    kind: "not_connected",
    message: () => "You're not connected to your computer. Reconnect, then try again.",
  },
  {
    test: /connection busy/i,
    kind: "busy_link",
    message: () =>
      "The connection to your computer is busy or slow. Wait a moment, then try again.",
  },

  // ── Transfers ──
  {
    test: /outside the host user's home|outside .*home/i,
    kind: "outside_home",
    only: ["upload", "download"],
    message: () =>
      "That path is outside your home folder on the computer. Tick “Allow a path outside my home folder” if you meant it, then try again.",
  },
  {
    test: /at most \d+ file transfers/i,
    kind: "too_many_transfers",
    only: ["upload", "download"],
    message: () => "Too many transfers at once. Wait for one to finish, then try again.",
  },
  {
    test: /changed during download/i,
    kind: "file_changed",
    only: ["upload", "download"],
    message: () => "The file changed on your computer while it was downloading. Try again.",
  },
  {
    test: /checksum|verification|declared size|oversized file chunk/i,
    kind: "corrupted",
    only: ["upload", "download"],
    message: () => "The file didn't arrive intact. Try again.",
  },
  {
    test: /size limit|may not exceed|too large|too big|exceeds/i,
    kind: "too_big",
    only: ["upload", "download"],
    message: () => "That file is too big to transfer.",
  },
  {
    test: /different host/i,
    kind: "host_switched",
    only: ["upload", "download"],
    message: () =>
      "The transfer stopped because you switched to another computer. Start it again.",
  },
  {
    test: /no longer available|start (it|the transfer) again/i,
    kind: "transfer_interrupted",
    only: ["upload", "download"],
    message: () => "The transfer was interrupted. Start it again.",
  },
  {
    test: /already active/i,
    kind: "transfer_running",
    only: ["upload", "download"],
    message: () => "That transfer is already running.",
  },
  {
    test: /not a regular file/i,
    kind: "not_a_file",
    only: ["upload", "download"],
    message: (context) =>
      context === "upload"
        ? "That isn't a file Portty can send. Choose a file, not a folder."
        : "That path is a folder, not a file. Enter the path of a file.",
  },
  {
    test: /read-only file system|os error 30\b/i,
    kind: "read_only",
    only: ["upload", "download"],
    message: () => "Portty can't save to that place. Choose another folder.",
  },
  {
    test: /no space|not enough space|disk (is )?full|os error (28|112)\b/i,
    kind: "no_space",
    only: ["upload", "download"],
    message: () => "There isn't enough free space. Free some up, then try again.",
  },
  {
    test: /permission denied|access is denied|os error (13|5)\b/i,
    kind: "no_permission",
    only: ["upload", "download"],
    message: () =>
      "Portty isn't allowed to use that file. Check its permissions, or choose another file.",
  },
  {
    test: /no such file|cannot find|not found|os error (2|3)\b/i,
    kind: "file_missing",
    only: ["upload", "download"],
    message: (context) =>
      context === "upload"
        ? "Portty couldn't open that file on this phone. Choose it again, then try again."
        : "That file isn't on your computer. Check the path, then try again.",
  },

  // ── Sessions ──
  {
    test: /no longer available|no longer exists|session not found|unknown session/i,
    kind: "session_gone",
    only: ["session", "agent", "general"],
    message: () => "That session has ended. Pick another one or start a new one.",
  },

  // ── Pairing words, in case a pairing error ever arrives flattened ──
  {
    test: /UnsupportedVersion|protocol version \d+ unsupported/i,
    kind: "version",
    message: () =>
      "This app and your computer have different versions of Portty. Update both to the newest version (check the computer with `portty --version`), then try again.",
  },
  {
    test: /\bRevoked\b|pair revoked|pair ended/i,
    kind: "revoked",
    message: () =>
      "Your computer removed this phone. To use it again, pair again: run `portty pair` on your computer and scan the new QR code.",
  },
  {
    test: /\bWrongPin\b|\bPairingClosed\b/,
    kind: "rejected",
    only: ["reconnect"],
    message: () => `Your computer no longer accepts this phone's saved pairing. ${PAIR_AGAIN}`,
  },
  {
    test: /\bWrongPin\b/,
    kind: "code_rejected",
    message: () => `This pairing code didn't work. It may be old or mistyped. ${RUN_PAIR_AGAIN}`,
  },
  {
    test: /\bPairingClosed\b/,
    kind: "code_expired",
    message: () => `This pairing code has expired or was already used. ${RUN_PAIR_AGAIN}`,
  },
  {
    test: /\bRateLimited\b/,
    kind: "rate_limited",
    message: () => "Your computer paused after too many tries. Wait a few minutes, then try again.",
  },
  {
    test: /\bCancelled\b/,
    kind: "declined",
    message: () =>
      "Pairing was declined or timed out on your computer. Run `portty pair` on your computer again, scan the new QR code, and type y there when the codes match.",
  },
  {
    test: /iroh transport: (connect|open_bi)|no addressing information|unable to connect/i,
    kind: "unreachable",
    message: () =>
      "Can't reach your computer. Check that both devices are online and that `portty-host` is running on the computer. Then try again.",
  },

  // ── The link itself ──
  {
    test: /timed out/i,
    kind: "timeout",
    message: () =>
      "Your computer didn't answer in time. Check that both devices are online, then try again.",
  },
  {
    test: /connection (closed|lost)|peer closed|closed before|disconnected during|phone disconnected/i,
    kind: "lost",
    message: (context) =>
      isTransfer(context)
        ? "Lost the connection to your computer. Reconnect, then start the transfer again."
        : "Lost the connection to your computer. Reconnect, then try again.",
  },
];

const FALLBACK: Record<ErrorContext, string> = {
  pair: "Couldn't pair with your computer. Try again.",
  reconnect: "Couldn't connect to your computer. Try again.",
  session: "That didn't work on your computer. Try again.",
  agent: "The agent couldn't do that. Try again.",
  upload: "The upload didn't work. Try again.",
  download: "The download didn't work. Try again.",
  general: "Something went wrong. Try again.",
};

/** Wrapping prefixes the core or the host adds around the real reason. */
const NOISE_PREFIXES = [
  /^(pair|reconnect) failed( - re-pair)?:\s*/i,
  /^could not (start agent|resume|create session|list [a-z]+|open that folder):\s*/i,
  /^acp:\s*/i,
  /^error:\s*/i,
];

/** The computer's own explanation, when it is already a readable sentence -
 *  "OpenCode is not installed on this host" says more than any generic line
 *  could. Technical text (OS error codes, wire names, paths) is not. */
function readableReason(raw: string): string | null {
  let text = raw.trim();
  for (let changed = true; changed; ) {
    changed = false;
    for (const prefix of NOISE_PREFIXES) {
      const next = text.replace(prefix, "");
      if (next !== text) {
        text = next.trim();
        changed = true;
      }
    }
  }
  if (!text || text.length > 140) return null;
  // OS error codes, Rust paths, braces, slashes, hex and snake_case names are
  // a developer's words, not a person's.
  if (/os error|\(\d+\)|::|[{}[\]\\/]|0x[0-9a-f]|\b[a-z]+_[a-z_]+\b/i.test(text)) return null;
  if (redactDetail(text) !== text) return null;
  const sentence = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(sentence) ? sentence : `${sentence}.`;
}

/**
 * Turn any error into plain words with a next step.
 *
 * `fallback` replaces the context's generic line when nothing more specific is
 * known (for example "Couldn't send your message."); the computer's own reason
 * is added when it is readable, and otherwise kept for Details.
 */
export function friendlyError(
  error: unknown,
  context: ErrorContext = "general",
  fallback?: string,
): FriendlyError {
  if (isStructured(error)) {
    const detail = typeof error.detail === "string" ? redactDetail(error.detail) : "";
    return { kind: error.kind, message: error.message, detail };
  }
  const raw = rawText(error).trim();
  const detail = redactDetail(raw);
  for (const rule of RULES) {
    if (rule.only && !rule.only.includes(context)) continue;
    if (rule.test.test(raw)) return { kind: rule.kind, message: rule.message(context), detail };
  }
  const reason = readableReason(raw);
  const lead = fallback ?? FALLBACK[context];
  if (reason) {
    // "Couldn't start OpenCode. OpenCode is not installed on this host."
    const base = lead.replace(/\s*Try again\.$/, "");
    return { kind: "failed", message: `${base} ${reason}`, detail };
  }
  const message = fallback ? `${fallback.replace(/\s*Try again\.$/, "")} Try again.` : lead;
  return { kind: "failed", message, detail };
}

/** Which phone this is, for naming the right settings screen. */
export type Platform = "android" | "ios" | "other";

export function detectPlatform(
  userAgent: string = typeof navigator === "undefined" ? "" : navigator.userAgent,
  maxTouchPoints: number = typeof navigator === "undefined" ? 0 : navigator.maxTouchPoints,
): Platform {
  if (/android/i.test(userAgent)) return "android";
  if (/iphone|ipad|ipod/i.test(userAgent)) return "ios";
  // iPadOS asks for desktop sites and says "Macintosh"; the touch screen gives
  // it away.
  if (/macintosh/i.test(userAgent) && maxTouchPoints > 1) return "ios";
  return "other";
}

const PASTE_INSTEAD = "Paste the pairing code from `portty pair` instead";

/**
 * Plain words for a camera that would not start, by the reason the browser
 * gives (`DOMException.name`). Each one offers pasting the code, which always
 * works, and says how to fix the camera where that is up to the person.
 */
export function cameraErrorMessage(error: unknown, platform: Platform = detectPlatform()): string {
  const name =
    error && typeof error === "object" && typeof (error as { name?: unknown }).name === "string"
      ? (error as { name: string }).name
      : "";
  switch (name) {
    case "NotAllowedError":
    case "PermissionDeniedError":
    case "SecurityError": {
      const where =
        platform === "android"
          ? "allow Camera in Settings → Apps → Portty → Permissions"
          : platform === "ios"
            ? "allow Camera in Settings → Portty → Camera"
            : "allow camera access for Portty in your settings";
      return `Portty can't use the camera. ${PASTE_INSTEAD}, or ${where}.`;
    }
    case "NotFoundError":
    case "DevicesNotFoundError":
    case "OverconstrainedError":
    case "ConstraintNotSatisfiedError":
      return `No camera was found on this device. ${PASTE_INSTEAD}.`;
    case "NotReadableError":
    case "TrackStartError":
    case "AbortError":
      return `The camera is busy or not working. Close other apps that use it and try again, or ${PASTE_INSTEAD.charAt(0).toLowerCase()}${PASTE_INSTEAD.slice(1)}.`;
    default:
      return `Portty couldn't start the camera. ${PASTE_INSTEAD}, or try again.`;
  }
}

/** For a device with no camera API at all. */
export const NO_CAMERA_MESSAGE = `This device has no camera Portty can use. ${PASTE_INSTEAD}.`;
