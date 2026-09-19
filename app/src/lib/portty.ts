// Tauri command + event wrappers for the Portty core.
import { invoke, Channel } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type SessionKind = "shell" | "agent";
export type SessionSource = "spawned" | "adopted";

export interface SessionInfo {
  id: number;
  title: string;
  kind: SessionKind;
  source: SessionSource;
  has_activity: boolean;
}

export type AgentProvider = "claude_code" | "open_code" | "codex" | "goose";
export type AgentToolKind =
  | "read"
  | "edit"
  | "delete"
  | "move"
  | "search"
  | "execute"
  | "think"
  | "fetch"
  | "other";
export type AgentToolStatus = "pending" | "in_progress" | "completed" | "failed";
export type AgentPlanStatus = "pending" | "in_progress" | "completed";

export interface AgentPlanEntry {
  content: string;
  status: AgentPlanStatus;
}

export interface AgentCommand {
  name: string;
  description: string;
  input_hint: string | null;
}

export interface AgentMode {
  id: string;
  name: string;
  description: string | null;
}

export type AgentConfigValue = { select: string } | { boolean: boolean };

export interface AgentConfigChoice {
  value: string;
  name: string;
  description: string | null;
  group: string | null;
}

export interface AgentConfigOption {
  id: string;
  name: string;
  description: string | null;
  category: string | null;
  current_value: AgentConfigValue;
  choices: AgentConfigChoice[];
}

export interface AgentAuthMethod {
  id: string;
  name: string;
  description: string | null;
}

export type AgentEvent =
  | { type: "session_started"; provider: AgentProvider }
  | { type: "user_message"; text: string }
  | { type: "turn_started" }
  | { type: "message_chunk"; text: string }
  | { type: "thought_chunk"; text: string }
  | {
      type: "tool_call";
      tool_call_id: string;
      title: string;
      kind: AgentToolKind;
      status: AgentToolStatus;
      detail: string | null;
    }
  | {
      type: "tool_call_update";
      tool_call_id: string;
      title: string | null;
      kind: AgentToolKind | null;
      status: AgentToolStatus | null;
      detail: string | null;
    }
  | { type: "plan"; entries: AgentPlanEntry[] }
  | { type: "turn_finished"; stop_reason: string }
  | { type: "error"; message: string }
  | { type: "available_commands"; commands: AgentCommand[] }
  | { type: "mode_state"; current_mode_id: string; available_modes: AgentMode[] }
  | { type: "config_options"; options: AgentConfigOption[] }
  | { type: "session_info"; title: string | null }
  | { type: "replaying"; active: boolean }
  | { type: "auth_required"; methods: AgentAuthMethod[] }
  | { type: "usage"; used_tokens: number; max_tokens: number; cost: string | null };

export interface AgentTimelineEvent {
  seq: number;
  event: AgentEvent;
}

export interface AgentEventBatch {
  id: number;
  events: AgentTimelineEvent[];
}

export type PermissionOptionKind =
  | "allow_once"
  | "allow_always"
  | "reject_once"
  | "reject_always";

export interface AgentPermission {
  id: number;
  tool_call: { tool_call_id: string; title: string };
  options: Array<{ option_id: string; name: string; kind: PermissionOptionKind }>;
  category?: PermissionCategory;
  /** Connection generation that raised this card. Session ids and tool-call ids
   *  are host-local, so the decision carries this back and the core refuses to
   *  answer a card minted by a different (e.g. replaced) host. */
  connection: number;
  /** How broad the agent's sandbox root is for this card's session. Optional on
   *  the type only so an absent value is representable; the policy engine treats
   *  anything other than `"project"` as broad and refuses to auto-approve reads. */
  workspace_scope?: WorkspaceScope;
}

/** How broad the agent's ACP file sandbox root is, as reported by the host.
 *
 *  `"broad"` means the root is the home directory, an ancestor of it, or a
 *  filesystem root - so confinement bounds almost nothing and "readonly" would
 *  otherwise mean "read anything I own". */
export type WorkspaceScope = "project" | "broad";

export type PolicyTier = "readonly" | "edits" | "yolo";
export type PermissionCategory =
  | "read"
  | "write"
  | "execute"
  | "network"
  | "destructive"
  | "unknown";

export interface ExactAllowRule {
  category: Exclude<PermissionCategory, "unknown">;
  /** Byte-for-byte ACP tool title; never case-folded or whitespace-normalized. */
  title: string;
  /** Canonical compact JSON of the ACP tool's raw input. */
  input: string;
}

export interface ApprovalPolicy {
  tier: PolicyTier;
  /** Process-local only: session ids are reused after a host restart. */
  session_overrides: Record<string, PolicyTier>;
  /** Exact tool titles that override the tier and always prompt. */
  prompt_exceptions: string[];
  /** Explicit category + title + canonical raw-input grants. */
  exact_allow_rules: ExactAllowRule[];
}

/** How an approval decision was reached - so the audit log is complete, not
 * just the auto-approvals. */
export type DecisionSource =
  | "auto"
  | "manual-allow"
  | "manual-reject"
  | "learned-exact"
  | "resolved-elsewhere";

export interface DecisionLogEntry {
  at: string;
  session_id: number;
  tool_call_id: string;
  title: string;
  category: PermissionCategory;
  policy: PolicyTier | "exact";
  /** How the decision was made. Optional so entries stored before this field
   * existed still deserialize (render treats a missing source as "auto"). */
  source?: DecisionSource;
  /** Canonical tool input (the command/args/path) at decision time, for review.
   * Optional for the same backward-compat reason; null when unavailable. */
  input?: string | null;
  /** For a "resolved-elsewhere" entry: what the other viewer decided and which
   * viewer it was (v5+ host). Optional - absent on older entries / older hosts. */
  resolution?: "allowed" | "rejected" | "cancelled";
  resolved_by?: "phone" | "laptop" | "system";
}

export interface TransferProgress {
  id: number;
  direction: "download" | "upload";
  transferred: number;
  total: number | null;
  path: string;
}

export interface TransferComplete {
  id: number;
  direction: "download" | "upload";
  path: string;
}

// ── Commands ────────────────────────────────────────────────────────
// `pair` takes a binary Channel for output: the core pushes
// [kind][8-byte LE session id][payload] per message, avoiding the JSON
// byte-array bloat while keeping one ORDERED path for output (`kind=0`),
// reset (`kind=1`), and the authoritative PTY size (`kind=2` - 2-byte LE
// cols + rows; on attach the host sends reset → size → snapshot, and
// match-width mode must apply the size before the snapshot bytes).
/// `secretPhrase` is the manual-entry alternative to a full ticket: paste just
/// the host's NodeId as `ticket` and pass the 6-word phrase it printed here
/// instead of pasting the whole `portty1:...` blob. Ignored when `ticket` is
/// already a full ticket (it carries its own secret).
///
/// There is no PIN. The secret in the ticket/QR/phrase is the whole first-pair
/// credential, and the human check moved to AFTER the exchange: `onPairCode`
/// fires with a 6-digit code that must match the one the host prints, and the
/// promise does not resolve until someone confirms it there. Pairing without a
/// secret is rejected outright rather than falling back to anything weaker.

export type OutputCb = (id: number, data: Uint8Array | null) => void;
export type SizeCb = (id: number, cols: number, rows: number) => void;

/**
 * Bound on a terminal dimension taken from the host.
 *
 * The host is authenticated but not trusted with the phone's memory: `cols` and
 * `rows` arrive as u16, so a hostile or buggy paired host can say 65535x65535
 * and xterm.js will try to allocate a ~4-billion-cell buffer. There is no real
 * terminal anywhere near this - a 5K display at a tiny font is a few hundred
 * columns - so clamping costs nothing legitimate.
 *
 * Clamped rather than rejected: a session whose size is implausible should still
 * render at a sane size, not vanish.
 */
export const MAX_TERMINAL_DIMENSION = 1000;

/** Lower bound. xterm.js requires at least one cell in each axis, and a zero
 *  from a truncated or malicious frame would otherwise divide-by-zero the
 *  match-width font calculation. */
export const MIN_TERMINAL_DIMENSION = 1;

/** Clamp one host-supplied dimension into a renderable range.
 *
 *  Every non-finite input collapses to the MINIMUM, +Infinity included. This
 *  number decides an allocation and the only way to get a non-finite one is
 *  corrupt input, so the safe direction is small. */
export const clampTerminalDimension = (value: number): number => {
  if (!Number.isFinite(value)) return MIN_TERMINAL_DIMENSION;
  return Math.min(MAX_TERMINAL_DIMENSION, Math.max(MIN_TERMINAL_DIMENSION, Math.floor(value)));
};

const outputChannel = (onOutput: OutputCb, onSize: SizeCb): Channel => {
  const ch = new Channel();
  ch.onmessage = (msg: unknown) => {
    // Tauri delivers raw bytes as an ArrayBuffer (webview) - normalize to a
    // Uint8Array and peel off the kind + 8-byte id prefix.
    const all = msg instanceof ArrayBuffer ? new Uint8Array(msg) : new Uint8Array(msg as number[]);
    if (all.length < 9) return;
    const view = new DataView(all.buffer, all.byteOffset);
    const id = Number(view.getBigUint64(1, true));
    if (all[0] === 1) onOutput(id, null);
    else if (all[0] === 0) onOutput(id, all.subarray(9));
    // Clamp HERE, at the single point where host-supplied dimensions enter the
    // app, so no consumer has to remember to. Everything downstream - the size
    // map, the match-width font maths, term.resize - sees bounded values.
    else if (all[0] === 2 && all.length >= 13)
      onSize(
        id,
        clampTerminalDimension(view.getUint16(9, true)),
        clampTerminalDimension(view.getUint16(11, true)),
      );
  };
  return ch;
};

/// Tauri event carrying the pairing comparison code. Fires once, mid-handshake,
/// while the host waits for a human to confirm it.
export const PAIR_CODE_EVENT = "portty://pair-code";

export const pair = (
  ticket: string,
  onOutput: OutputCb,
  onSize: SizeCb,
  secretPhrase?: string,
): Promise<void> =>
  invoke<void>("pair", {
    ticket,
    secretPhrase: secretPhrase ?? null,
    onOutput: outputChannel(onOutput, onSize),
  });

/// Resume a saved host by the stored token - no ticket or code. `host` (a
/// device-id hex from `listHosts`) picks a SPECIFIC saved laptop; omitted = most
/// recent. Rejects if nothing is saved or the token was rejected (then re-pair).
export const reconnect = (onOutput: OutputCb, onSize: SizeCb, host?: string): Promise<void> =>
  invoke<void>("reconnect", { onOutput: outputChannel(onOutput, onSize), host: host ?? null });

/// One saved laptop (host picker). `id` is the full device-id hex. `name` is
/// what to display - the nickname the user set, else the hostname the host
/// announced (null when it never sent a real one). `announced_name` is that
/// hostname alone: the placeholder while renaming, and what clearing restores.
export interface SavedHost {
  id: string;
  name: string | null;
  announced_name: string | null;
  is_renamed: boolean;
  is_last: boolean;
  /** The folder new terminals open in, relative to `default_root`.
   *  `null` means none chosen - the workspace root itself. */
  default_dir: string | null;
  /** Which root `default_dir` is relative to. `null` whenever it is. */
  default_root: TerminalRoot | null;
}

/** A directory tree the phone may open a terminal in.
 *
 *  The host declares which it serves ({@link listTerminalRoots}) - the operator can
 *  turn the non-workspace ones off - and every path stays RELATIVE to one of them,
 *  so the wire never carries an absolute path.
 *
 *  Terminals only. An agent's directory is also its file-access sandbox root, so
 *  {@link newAgentIn} stays workspace-relative by construction. */
export type TerminalRoot = "workspace" | "home";
/// The laptops this phone can resume by stored token.
export const listHosts = () => invoke<SavedHost[]>("list_hosts");
/// Rename a saved laptop. Cosmetic and phone-local: nothing is sent to the host,
/// so it works offline and another phone paired to the same laptop is unaffected.
/// An empty name clears the nickname, restoring the announced hostname. Resolves
/// with the nickname as stored (trimmed, capped), or null if it was cleared.
export const renameHost = (host: string, name: string) =>
  invoke<string | null>("rename_host", { host, name });
/// Set the folder new terminals open in for one saved laptop. Phone-local and per
/// host, like `renameHost`: nothing is sent to the host, so it works offline and
/// another phone paired to the same laptop keeps its own choice. `rel` is
/// workspace-relative; `""` clears it (back to the workspace root). Resolves with
/// the value as stored, or null once cleared.
///
/// A preference, not a permission - the host re-resolves and re-confines whatever
/// it is handed, so a stale value can only be refused.
export const setHostDefaultDir = (host: string, root: TerminalRoot, rel: string) =>
  invoke<string | null>("set_host_default_dir", { host, root, rel });
/// Forget a laptop locally and, when reachable, obtain a durable host-side
/// revocation acknowledgement before closing the link.
export interface RemoveHostResult {
  disconnected: boolean;
  remote_revoked: boolean;
}
export const removeHost = (host: string) =>
  invoke<RemoveHostResult>("remove_host", { host });

// Correlated commands: these resolve on the host's ack and REJECT (with the
// host's message) if the command failed - no more silent no-ops.
export const attach = (id: number) => invoke<void>("attach", { id });
/// Warm re-attach: resume the session's output strictly after the last seq
/// this phone rendered - no repaint. The HOST falls back to reset + full
/// snapshot on its own when the boundary aged out, so callers need no
/// fallback logic. Use `attach` when the local terminal buffer is empty.
export const resumeOutput = (id: number) => invoke<void>("resume_output", { id });
export const detach = () => invoke<void>("detach");

/** Open a link in the system browser instead of navigating the app's webview
 *  away from the SPA (#53). Rust validates the scheme (http/https only). */
export const openExternal = (url: string) => invoke<void>("open_external_url", { url });
/// Freeze live output for the viewed session (scroll/read without the cursor
/// jumping; saves cellular data). Host keeps buffering; `resumeStream` replays.
export const pauseStream = () => invoke<void>("pause_stream");
export const resumeStream = () => invoke<void>("resume_stream");
export const input = (id: number, data: string) => invoke<void>("input", { id, data });
/// Create a shell on the host; resolves with the NEW session's id so the caller
/// opens exactly it (no guessing from the next `portty://added`). The shell is
/// born at the host's FIXED size - the phone renders around it (fit/match modes)
/// and never drives the PTY size.
export const newSession = (title?: string) => invoke<number>("new_session", { title });
/**
 * Create a shell in a CHOSEN workspace directory, browsed with
 * {@link listWorkspaceDirs} - the same listing the agent picker uses.
 *
 * `rel` is workspace-relative; `""` means the workspace root, which is what a
 * plain {@link newSession} already opens now. Pass the host's RESOLVED `rel` from
 * the listing rather than composing a path here.
 *
 * Unlike {@link newAgentIn}, a deeper pick is NOT a narrower sandbox - a shell
 * can `cd` anywhere its user can reach. It chooses where you start, nothing more.
 */
export const newSessionIn = (rel: string, title?: string) =>
  invoke<number>("new_session_in", { rel, title: title ?? null });

/** Which folder roots this host serves for terminals.
 *
 *  Ask, don't assume: the operator can restrict them, and an older host does not
 *  know the request at all - callers treat a rejection as `["workspace"]`, which is
 *  exactly what every host did before v10. */
export const listTerminalRoots = () => invoke<TerminalRoot[]>("list_terminal_roots");

/** Browse directories inside a chosen root. `rel` is relative to it; `""` is the
 *  root itself. The host re-resolves and re-checks containment, so a phone still
 *  cannot name a path outside the root it asked for. */
export const listDirsIn = (root: TerminalRoot, rel: string) =>
  invoke<WorkspaceListing>("list_dirs_in", { root, rel });

/** Create a shell in `rel` inside `root`. */
export const newSessionInRoot = (root: TerminalRoot, rel: string, title?: string) =>
  invoke<number>("new_session_in_root", { root, rel, title: title ?? null });
export const newAgent = (provider: AgentProvider, title?: string) =>
  invoke<number>("new_agent", { provider, title: title ?? null });

/** One level of the host's workspace tree. `rel` is the RESOLVED path relative
 *  to the workspace root; `""` is the root itself. */
export interface WorkspaceListing {
  rel: string;
  names: string[];
}

/**
 * Browse the directories an agent may be started in.
 *
 * Everything is relative to the host's workspace root and the host re-checks
 * containment, so the phone can never name a path outside it - `..` is refused
 * rather than resolved. To go up, ask for a SHORTER `rel`.
 */
export const listWorkspaceDirs = (rel: string) =>
  invoke<WorkspaceListing>("list_workspace_dirs", { rel });

/** Start an agent in a chosen directory. That directory becomes the agent's cwd
 *  AND its file-access sandbox root, so a deeper pick is strictly narrower. */
export const newAgentIn = (provider: AgentProvider, rel: string, title?: string) =>
  invoke<number>("new_agent_in", { provider, rel, title: title ?? null });

/** One saved conversation the host can reopen. */
export interface AgentSessionRow {
  acp_session_id: string;
  provider: AgentProvider;
  title: string;
  /** The conversation's first prompt, when one was recorded - far better than a
   *  title for telling two sessions apart. */
  label: string | null;
  last_active_at_unix_ms: number;
}
export interface AgentSessionListing {
  rel: string;
  sessions: AgentSessionRow[];
}

/** Whether one agent can actually be launched on the host. */
export interface AgentProviderRow {
  provider: AgentProvider;
  available: boolean;
  /** Why not, and what to do about it. Null when available. */
  detail: string | null;
}

/** Which agents this host can launch. Asked when the picker opens so a missing
 *  adapter is visible up front rather than discovered by failing. */
export const listAgentProviders = () => invoke<AgentProviderRow[]>("list_agent_providers", {});

/** Saved conversations for one workspace directory, newest first - Portty's own
 *  cache only. Superseded by `listAgentSessionsFor`; kept for callers with no
 *  provider in hand. */
export const listAgentSessions = (rel: string) =>
  invoke<AgentSessionListing>("list_agent_sessions", { rel });

/** Every conversation one agent can continue in a directory: the ones Portty
 *  started AND the ones started with that agent's own CLI on the laptop.
 *
 *  Slow on purpose - the host launches the agent's ACP adapter to ask it - so
 *  call this beside the folder listing rather than in front of it. */
export const listAgentSessionsFor = (rel: string, provider: AgentProvider) =>
  invoke<AgentSessionListing>("list_agent_sessions_for", { rel, provider });

/** Reopen one specific saved conversation. The host recovers which agent owns it
 *  from its own cache, so the provider is deliberately not sent. */
export const resumeAgentSession = (rel: string, acpSessionId: string) =>
  invoke<number>("resume_agent_session", { rel, acpSessionId });
export const agentPrompt = (id: number, text: string) =>
  invoke<void>("agent_prompt", { id, text });
export const agentCancel = (id: number) => invoke<void>("agent_cancel", { id });
export const agentSetMode = (id: number, modeId: string) =>
  invoke<void>("agent_set_mode", { id, modeId });
export const agentSetConfig = (id: number, configId: string, value: AgentConfigValue) =>
  invoke<void>("agent_set_config", { id, configId, value });
export const agentAuthenticate = (id: number, methodId: string) =>
  invoke<void>("agent_authenticate", { id, methodId });
/** Answer one approval card. `connection` comes from the card itself - the core
 *  rejects a decision aimed at a link that is no longer the current one. */
export const permissionDecision = (
  request: AgentPermission,
  optionId: string | null,
) =>
  invoke<void>("permission_decision", {
    id: request.id,
    toolCallId: request.tool_call.tool_call_id,
    optionId,
    connection: request.connection,
  });
export const downloadFile = (
  remotePath: string,
  localPath: string,
  allowOutsideHome = false,
) => invoke<number>("download_file", { remotePath, localPath, allowOutsideHome });
export const uploadFile = (
  localPath: string,
  remotePath: string,
  allowOutsideHome = false,
) => invoke<number>("upload_file", { localPath, remotePath, allowOutsideHome });
export const kill = (id: number) => invoke<void>("kill", { id });
/// Give a session a custom name. The host re-sends the list (→ `portty://list`).
export const rename = (id: number, title: string) => invoke<void>("rename", { id, title });
export const disconnect = () => invoke<void>("disconnect");
/// Consume the wake blob a tapped push notification left behind (if any):
/// resolves with the paired host's device-id hex to reconnect to, or null.
export const consumePushWake = () => invoke<string | null>("consume_push_wake");
/// Manual push-registration seam (the automatic path reads the native token
/// file on every connect). Registers with the CURRENTLY connected host.
export const registerPush = (provider: "apns" | "fcm", token: string) =>
  invoke<void>("register_push", { provider, token });

// ── Events (from the Rust core) ─────────────────────────────────────
/**
 * The agent approval log, stored by the Tauri core in an owner-only,
 * backup-excluded file instead of WebView localStorage.
 *
 * Shaped as a `DecisionLogStorage` so `lib/decisionLog.ts` keeps one code path
 * for reading, redacting and writing, whichever side the bytes land on. The key
 * it is handed already encodes the host; the core validates and re-derives its
 * own filename rather than trusting a path from here.
 */
export const decisionLogStore = {
  getItem: (key: string): Promise<string | null> =>
    invoke<string>("decision_log_load", { host: hostFromDecisionKey(key) }).catch(() => null),
  setItem: (key: string, value: string): Promise<void> =>
    invoke<void>("decision_log_save", { host: hostFromDecisionKey(key), entries: value }).catch(
      () => undefined,
    ),
};

/** Drop a host's stored approval log - called when the host is forgotten. */
export const forgetDecisionLog = (host: string): Promise<void> =>
  invoke<void>("decision_log_forget", { host }).catch(() => undefined);

/** The storage interface is key-based; the core wants the host id. Kept in one
 *  place so the key format lives only in `lib/decisionLog.ts`. */
const hostFromDecisionKey = (key: string): string => key.slice(key.lastIndexOf(":") + 1);

/// The pairing comparison code, delivered mid-handshake. Subscribe BEFORE
/// calling `pair` - the event fires as soon as the proof is sent, which can be
/// well before `pair` resolves.
export function onPairCode(cb: (code: string) => void): Promise<UnlistenFn> {
  return listen<string>(PAIR_CODE_EVENT, (e) => cb(e.payload));
}

export function onList(cb: (sessions: SessionInfo[]) => void): Promise<UnlistenFn> {
  return listen<SessionInfo[]>("portty://list", (e) => cb(e.payload));
}
export function onAdded(cb: (info: SessionInfo) => void): Promise<UnlistenFn> {
  return listen<SessionInfo>("portty://added", (e) => cb(e.payload));
}
export function onRemoved(cb: (id: number) => void): Promise<UnlistenFn> {
  return listen<number>("portty://removed", (e) => cb(e.payload));
}
export function onActivity(cb: (id: number) => void): Promise<UnlistenFn> {
  return listen<number>("portty://activity", (e) => cb(e.payload));
}
export function onDisconnected(cb: () => void): Promise<UnlistenFn> {
  return listen("portty://disconnected", () => cb());
}
export function onPairRevoked(cb: (host: string) => void): Promise<UnlistenFn> {
  return listen<{ host: string }>("portty://pair-revoked", (e) => cb(e.payload.host));
}
/** A command the host could not carry out (e.g. session limit hit). */
export function onError(cb: (message: string) => void): Promise<UnlistenFn> {
  return listen<string>("portty://error", (e) => cb(e.payload));
}
export function onAgentSnapshot(cb: (batch: AgentEventBatch) => void): Promise<UnlistenFn> {
  return listen<AgentEventBatch>("portty://agent-snapshot", (e) => cb(e.payload));
}
export function onAgentEvent(cb: (batch: AgentEventBatch) => void): Promise<UnlistenFn> {
  return listen<AgentEventBatch>("portty://agent-event", (e) => cb(e.payload));
}
export function onPermission(cb: (request: AgentPermission) => void): Promise<UnlistenFn> {
  return listen<AgentPermission>("portty://permission", (e) => cb(e.payload));
}
/** How the host answered a pending approval, so a dismissed card can say what
 * happened and who did it. `resolution`/`by` are present only from a v5+ host. */
export interface PermissionResolvedInfo {
  id: number;
  tool_call_id: string;
  resolution?: "allowed" | "rejected" | "cancelled";
  by?: "phone" | "laptop" | "system";
}
export function onPermissionResolved(
  cb: (resolved: PermissionResolvedInfo) => void,
): Promise<UnlistenFn> {
  return listen<PermissionResolvedInfo>("portty://permission-resolved", (e) => cb(e.payload));
}
export function onTransferProgress(cb: (progress: TransferProgress) => void): Promise<UnlistenFn> {
  return listen<TransferProgress>("portty://transfer-progress", (e) => cb(e.payload));
}
export function onTransferComplete(cb: (complete: TransferComplete) => void): Promise<UnlistenFn> {
  return listen<TransferComplete>("portty://transfer-complete", (e) => cb(e.payload));
}
export function onTransferError(
  cb: (error: { id: number; message: string }) => void,
): Promise<UnlistenFn> {
  return listen<{ id: number; message: string }>("portty://transfer-error", (e) => cb(e.payload));
}
