//! Portty wire frames.
//!
//! Postcard-encoded. **Append-only wire contract** - see the `change-protocol`
//! skill. Postcard tags variants by declaration order, so:
//!   - never reorder variants
//!   - never remove variants (rename `Deprecated_…` instead)
//!   - add new variants at the END
//!
//! These frames are the real Rust↔Rust wire protocol for the iroh P2P pipe
//! (host ↔ Tauri app core). The browser local-proof uses a JSON harness over
//! WebSocket instead - see `crates/host`.

use serde::{Deserialize, Serialize};

pub mod relay;

/// Stable handle for a terminal session on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// Stable handle for one file transfer. The initiating phone chooses it, which
/// makes retries and reconnect resumes idempotent at the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferId(pub u64);

/// File-transfer chunks use the same granularity as PTY reads. Keeping them
/// small bounds memory on slow/mobile links and lets retries start at a precise
/// sequence boundary.
pub const FILE_CHUNK_BYTES: usize = 16 * 1024;

/// What's running in the session. `Shell` is the floor; `Agent` is the shipped
/// structured ACP ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKind {
    Shell,
    Agent,
}

/// How a session came to exist, so the phone can badge adopted terminals.
///
/// Introduced in PROTOCOL_VERSION 2 (a new field on `SessionInfo` is a
/// wire-breaking change - see the `change-protocol` skill).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionSource {
    /// The host daemon spawned this shell itself (the classic path).
    Spawned,
    /// A `portty share` relay in another process owns the PTY; the host adopted it.
    Adopted,
}

/// Snapshot of a session for list rendering. `has_activity` is true when the
/// session has produced output no viewer has seen yet - drives the activity dot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub title: String,
    pub kind: SessionKind,
    pub source: SessionSource,
    pub has_activity: bool,
}

// ── agent ceiling (ACP) ───────────────────────────────────────────────
// Introduced as part of the PROTOCOL_VERSION 2 schema by appending new variants
// at the end of `Frame`. Append-only declaration order preserves every existing
// tag, but it is not capability negotiation: future schema additions still
// require a protocol-version bump before either peer emits them.

/// The kind of choice an approval card offers. Mirrors ACP's
/// `PermissionOptionKind`, flattened for the phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionOptionKind {
    AllowOnce,
    AllowAlways,
    RejectOnce,
    RejectAlways,
}

/// One tappable choice on an approval card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionOption {
    /// Stable id echoed back in `PermissionDecision` (e.g. "allow-once").
    pub option_id: String,
    /// Human-readable label for the button.
    pub name: String,
    pub kind: PermissionOptionKind,
}

/// A tool call the agent wants to make, shown as a card. `Shell` sessions
/// never produce this - it's the ACP ceiling only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallCard {
    /// The agent's tool-call id; the phone echoes it in `PermissionDecision`
    /// so the host can match the reply to the pending ACP `request_permission`.
    pub tool_call_id: String,
    /// Short title for the card (e.g. "Run: rm -rf build/").
    pub title: String,
}

/// Agent implementations Portty knows how to launch on the host. The phone
/// selects a preset; it never sends an arbitrary command line to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProvider {
    ClaudeCode,
    OpenCode,
    Codex,
    /// Goose's native `goose acp` stdio server.
    Goose,
}

/// Coarse tool categories used by the mobile timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentToolKind {
    Read,
    Edit,
    Delete,
    Move,
    Search,
    Execute,
    Think,
    Fetch,
    Other,
}

/// Vendor-neutral permission categories used by the phone's fail-closed policy
/// engine. `Unknown` is intentionally explicit and is never auto-approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCategory {
    Read,
    Write,
    Execute,
    Network,
    Destructive,
    Unknown,
}

/// How broad the agent's workspace root is - the directory `sandboxed_acp_path`
/// confines every ACP file read to.
///
/// A FACT the host reports, not a decision. Approval policy stays phone-side;
/// this exists because only the host knows where the sandbox root actually is,
/// and the phone cannot judge "is a blanket read approval meaningful here?"
/// without it.
///
/// The distinction matters because the shipped service files used to set
/// `PORTTY_WORKSPACE` to the home directory. The sandbox was doing its job -
/// canonical realpath, symlink rejection, containment - around a root that
/// contained everything the user owns, so "readonly" silently meant "read
/// anything of mine" instead of "read this project".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceScope {
    /// A specific project directory. Blanket read approval is meaningful.
    Project,
    /// The home directory, an ancestor of it, or a filesystem root - so the
    /// sandbox bounds almost nothing. Also what an indeterminate root reports,
    /// because the phone must fail closed when the scope is unclear.
    Broad,
}

/// Which OS push service delivers the wake-up doorbell for this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushProvider {
    Apns,
    Fcm,
}

/// Lifecycle state of a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentToolStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// Lifecycle state of one plan item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPlanStatus {
    Pending,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPlanEntry {
    pub content: String,
    pub status: AgentPlanStatus,
}

/// One slash command advertised by an ACP agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCommand {
    pub name: String,
    pub description: String,
    /// Human-readable input hint (for example `task description`).
    pub input_hint: Option<String>,
}

/// One resumable conversation the host has cached for a workspace directory.
///
/// Introduced in PROTOCOL_VERSION 7. The host already persisted all of this to
/// resume the NEWEST conversation automatically; this exposes the same records
/// so the phone can pick a different one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionSummary {
    /// The agent's own session id - opaque to the phone, and the only thing it
    /// sends back to resume. The host re-derives provider and cwd from its own
    /// cache rather than trusting either over the wire.
    pub acp_session_id: String,
    pub provider: AgentProvider,
    pub title: String,
    /// First prompt of the conversation, when one was recorded - far better than
    /// a title for telling two sessions apart.
    pub label: Option<String>,
    pub last_active_at_unix_ms: u64,
}

/// Whether one coding agent can actually start on this host right now.
///
/// Introduced in PROTOCOL_VERSION 7. Answers the question the phone used to
/// discover only by failing three taps deep: is the adapter installed?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProviderAvailability {
    pub provider: AgentProvider,
    pub available: bool,
    /// Why not, and what to do about it. `None` when available.
    pub detail: Option<String>,
}

/// One selectable ACP session mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMode {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

/// Value of an ACP session configuration option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentConfigValue {
    Select(String),
    Boolean(bool),
}

/// One choice inside an ACP select configuration option. `group` preserves
/// grouped model lists without forcing clients to understand ACP internals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfigChoice {
    pub value: String,
    pub name: String,
    pub description: Option<String>,
    pub group: Option<String>,
}

/// Provider-neutral session configuration option rendered by Portty clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfigOption {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// ACP semantic category (`model`, `mode`, `thought_level`, ...).
    pub category: Option<String>,
    pub current_value: AgentConfigValue,
    pub choices: Vec<AgentConfigChoice>,
}

/// Authentication method advertised during ACP initialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthMethod {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

/// Provider-neutral events rendered by the clean mobile agent feed. These are
/// deliberately smaller than ACP's full schema: the host normalizes provider
/// details while preserving the useful human-facing text and lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentEvent {
    SessionStarted {
        provider: AgentProvider,
    },
    UserMessage {
        text: String,
    },
    TurnStarted,
    MessageChunk {
        text: String,
    },
    ThoughtChunk {
        text: String,
    },
    ToolCall {
        tool_call_id: String,
        title: String,
        kind: AgentToolKind,
        status: AgentToolStatus,
        detail: Option<String>,
    },
    ToolCallUpdate {
        tool_call_id: String,
        title: Option<String>,
        kind: Option<AgentToolKind>,
        status: Option<AgentToolStatus>,
        detail: Option<String>,
    },
    Plan {
        entries: Vec<AgentPlanEntry>,
    },
    TurnFinished {
        stop_reason: String,
    },
    Error {
        message: String,
    },
    /// Reducer state: replaces the full advertised slash-command list.
    AvailableCommands {
        commands: Vec<AgentCommand>,
    },
    /// Reducer state: replaces the available modes and active mode.
    ModeState {
        current_mode_id: String,
        available_modes: Vec<AgentMode>,
    },
    /// Reducer state: authoritative full ACP configuration state.
    ConfigOptions {
        options: Vec<AgentConfigOption>,
    },
    /// The ACP agent changed the human-facing conversation title.
    SessionInfo {
        title: Option<String>,
    },
    /// History replay is in progress while a cached ACP session is loaded.
    Replaying {
        active: bool,
    },
    /// The agent requires authentication before it can create the session.
    AuthRequired {
        methods: Vec<AgentAuthMethod>,
    },
    /// Reducer state: latest context-window usage, plus the cumulative session
    /// cost when the agent reports one (pre-formatted, e.g. `1.23 USD`).
    Usage {
        used_tokens: u64,
        max_tokens: u64,
        cost: Option<String>,
    },
}

/// Sequence-tagged history item. Snapshots and live delivery can overlap at an
/// attach boundary; `seq` lets the phone de-duplicate without dropping updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTimelineEvent {
    pub seq: u64,
    pub event: AgentEvent,
}

/// A directory tree the phone may open a TERMINAL in.
///
/// The host declares which of these it actually serves
/// ([`RequestKind::ListTerminalRoots`]), so a root the operator turned off is
/// never offered - and a request naming a disabled root is refused, not quietly
/// served. Inside a root, `rel` is resolved and containment-checked by the host
/// exactly as [`RequestKind::ListWorkspaceDirs`] always was: the wire still never
/// carries an absolute path, and the phone still never does arithmetic the host
/// trusts.
///
/// Deliberately NOT reachable from agent sessions. For an agent the chosen
/// directory is also its ACP file-access sandbox root, so
/// [`RequestKind::NewAgentSessionIn`] stays workspace-relative and an agent cannot
/// be started outside the workspace BY CONSTRUCTION - not by a check someone has
/// to remember to keep.
///
/// Why this is not a widening for terminals: a paired phone can already open a
/// shell and run `ls /`, and there is no read-only pairing tier. What these roots
/// add is convenient enumeration, which is why they stop at the terminal path.
///
/// Append-only, like every enum on this wire.
/// Introduced in PROTOCOL_VERSION 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalRoot {
    /// `PORTTY_WORKSPACE`, else the daemon's launch directory. The only root that
    /// existed before v10, and the one every `rel` was implicitly relative to.
    Workspace,
    /// The user's home directory.
    Home,
}

/// A phone→host command that expects a correlated reply (`Frame::CommandResult`
/// echoing the `req_id`). This is the request/response layer: the phone knows
/// whether the specific command succeeded and, for `NewSession`, gets the new
/// session's id back - so it opens exactly that session instead of guessing from
/// the next `SessionAdded`. Fire-and-forget commands (Input/Resize/Detach/Pause/
/// Resume) are intentionally NOT here - acking every keystroke is pointless.
///
/// Introduced in PROTOCOL_VERSION 2 (pure append).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestKind {
    NewSession {
        cwd: Option<String>,
        title: Option<String>,
    },
    Attach {
        id: SessionId,
    },
    KillSession {
        id: SessionId,
    },
    RenameSession {
        id: SessionId,
        title: String,
    },
    /// `NewSession` that carries the creating viewer's terminal size, so the
    /// shell is BORN at the right dimensions instead of 24×80-then-jump on the
    /// first attach+resize (full-screen apps briefly rendered at the wrong
    /// size, and shells reprinted their prompt on the corrective WINCH).
    ///
    /// Appended after `RenameSession` (pure append - an old host fails to
    /// decode only the frames that carry it, same as any version skew).
    NewSessionSized {
        cwd: Option<String>,
        title: Option<String>,
        cols: u16,
        rows: u16,
    },
    /// Start one of Portty's allow-listed coding-agent presets in the host
    /// workspace. Appended after every existing request kind.
    NewAgentSession {
        provider: AgentProvider,
        title: Option<String>,
    },
    /// Send one complete user prompt to an agent session.
    AgentPrompt {
        id: SessionId,
        text: String,
    },
    /// Cancel only the active ACP turn; keep the conversation session alive.
    AgentCancel {
        id: SessionId,
    },
    AgentSetMode {
        id: SessionId,
        mode_id: String,
    },
    AgentSetConfigOption {
        id: SessionId,
        config_id: String,
        value: AgentConfigValue,
    },
    AgentAuthenticate {
        id: SessionId,
        method_id: String,
    },

    // ── chosen agent workspace (v6, pure append) ─────────────────────
    /// List the directories the phone may start an agent in.
    ///
    /// `rel` is a path RELATIVE to the host's workspace root, `""` meaning the
    /// root itself. Relative by construction so the wire can never carry an
    /// absolute path the host would have to argue with; the host resolves and
    /// re-checks containment regardless (never trust the phone's arithmetic).
    /// Introduced in PROTOCOL_VERSION 6. Appended after `AgentAuthenticate`.
    ListWorkspaceDirs {
        rel: String,
    },
    /// Start a coding agent in a CHOSEN directory instead of the daemon's launch
    /// directory.
    ///
    /// `rel` is relative to the workspace root, as above; the chosen directory
    /// becomes both the agent's cwd AND its ACP file-access sandbox root, so
    /// picking a subdirectory strictly NARROWS what the agent can reach. The
    /// older [`RequestKind::NewAgentSession`] stays frozen for the wire record
    /// and keeps meaning "the workspace root".
    /// Introduced in PROTOCOL_VERSION 6.
    NewAgentSessionIn {
        provider: AgentProvider,
        title: Option<String>,
        rel: String,
    },

    // ── resumable conversations (v7, pure append) ────────────────────
    /// List the cached conversations for one workspace directory, newest first.
    /// `rel` is workspace-relative exactly as in [`RequestKind::ListWorkspaceDirs`].
    /// Introduced in PROTOCOL_VERSION 7.
    ListAgentSessions {
        rel: String,
    },
    /// Continue one specific cached conversation rather than whichever was most
    /// recent. The host looks the id up in its own cache to recover the provider
    /// and directory, so a phone cannot resume a conversation into a workspace it
    /// did not belong to. Introduced in PROTOCOL_VERSION 7.
    ResumeAgentSession {
        rel: String,
        acp_session_id: String,
    },
    /// Which coding agents this host can actually launch. Answered with
    /// [`Frame::AgentProviders`]. Introduced in PROTOCOL_VERSION 7.
    ListAgentProviders,

    // ── chosen terminal directory (v9, pure append) ───────────────────
    /// Open a SHELL in a chosen directory instead of the workspace root.
    ///
    /// `rel` is workspace-relative exactly as in
    /// [`RequestKind::ListWorkspaceDirs`], so the terminal picker reuses that
    /// listing wholesale and one resolver (`workspace::resolve_within`) stays
    /// authoritative for both pickers.
    ///
    /// [`RequestKind::NewSession`] and [`RequestKind::NewSessionSized`] stay
    /// frozen and keep meaning "the workspace root". Their `cwd: Option<String>`
    /// is a leftover the phone has never populated and must not start
    /// populating - an absolute path chosen by the phone is exactly what `rel`
    /// exists to avoid, and the host would have to argue with it.
    ///
    /// Note what confinement does and does not buy here. For
    /// [`RequestKind::NewAgentSessionIn`] the chosen directory is a real security
    /// boundary: it becomes the agent's ACP file-access sandbox root, so picking
    /// deeper strictly narrows reach. A shell has no such property - it can `cd`
    /// anywhere its user can reach the moment it opens. So this bound is about
    /// predictable UX and a single trusted resolver, NOT a containment claim.
    ///
    /// Introduced in PROTOCOL_VERSION 9. Appended after `ListAgentProviders`.
    NewSessionIn {
        title: Option<String>,
        rel: String,
    },

    // ── terminal roots beyond the workspace (v10, pure append) ────────
    /// Which [`TerminalRoot`]s this host serves. Answered with
    /// [`Frame::TerminalRoots`].
    ///
    /// The phone asks rather than assuming, because the operator can turn the
    /// non-workspace roots off (`PORTTY_TERMINAL_ROOTS=workspace`) and offering a
    /// root the host will refuse is worse than not offering it.
    /// Introduced in PROTOCOL_VERSION 10.
    ListTerminalRoots,
    /// List directories inside a chosen root - the generalisation of
    /// [`RequestKind::ListWorkspaceDirs`] from one root to the declared set.
    ///
    /// `rel` is relative to `root`, never absolute. Answered with
    /// [`Frame::WorkspaceDirs`], which carries the host's RESOLVED `rel`; the root
    /// is implied by the request the phone correlated with.
    /// Introduced in PROTOCOL_VERSION 10.
    ListDirsIn {
        root: TerminalRoot,
        rel: String,
    },
    /// Open a shell in `rel` inside `root`.
    ///
    /// [`RequestKind::NewSessionIn`] stays frozen and keeps meaning "relative to
    /// the workspace", which is exactly `NewSessionInRoot` with
    /// [`TerminalRoot::Workspace`] - kept for the wire record and for older phones.
    /// Introduced in PROTOCOL_VERSION 10.
    NewSessionInRoot {
        root: TerminalRoot,
        rel: String,
        title: Option<String>,
    },

    // ── conversations the AGENT remembers (v11, pure append) ──────────
    /// Every conversation `provider` can continue in `rel`, newest first: the
    /// ones Portty started AND the ones the agent's own CLI started on the
    /// laptop.
    ///
    /// [`RequestKind::ListAgentSessions`] stays frozen and keeps its
    /// Portty-cache-only meaning for the wire record. It is also provider-blind,
    /// which is exactly what this cannot be: asking an agent what it remembers
    /// costs an adapter launch, so the phone names the ONE provider whose picker
    /// it is standing in rather than making the host start four of them.
    ///
    /// Answered with the same [`Frame::AgentSessions`], because a row is the same
    /// row whichever store it came from, and continuing one is still
    /// [`RequestKind::ResumeAgentSession`] - the host looks the id up in its own
    /// records to recover the provider either way, so the phone still cannot
    /// name one.
    ///
    /// Introduced in PROTOCOL_VERSION 11. Appended after `NewSessionInRoot`.
    ListAgentSessionsFor {
        rel: String,
        provider: AgentProvider,
    },
}

/// The result of a [`RequestKind`], correlated to the request by `req_id`
/// (see `Frame::CommandResult`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandOutcome {
    /// Success. `session` is the affected/created session where meaningful - for
    /// `NewSession` it's the new shell's id (the phone opens exactly it).
    Ok { session: Option<SessionId> },
    /// Failure with a human-readable reason to surface to the user.
    Error { message: String },
}

/// What happened to a resolved approval, so a dismissed card can say the
/// outcome instead of just vanishing. Carried by [`Frame::AgentPermissionResolvedInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionResolution {
    /// A presented option was selected (approved).
    Allowed,
    /// A viewer explicitly declined the request.
    Rejected,
    /// Withdrawn without a viewer decision - the agent exited or the turn ended.
    Cancelled,
}

/// Which viewer answered a pending approval. Deliberately coarse - the exact
/// device name is never put on the wire. Carried by
/// [`Frame::AgentPermissionResolvedInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionResolver {
    /// A paired phone tapped the card.
    Phone,
    /// The laptop `portty agent` chat answered.
    Laptop,
    /// No viewer answered - the agent exited or the turn ended first.
    System,
}

/// The wire frame enum. Direction noted per variant.
///
/// Introduced in PROTOCOL_VERSION 1.
#[derive(Clone, Serialize, Deserialize)]
pub enum Frame {
    // ── session list / lifecycle (host → phone) ─────────────────────
    /// Full snapshot of all sessions. Sent on attach and whenever the set changes.
    SessionList {
        sessions: Vec<SessionInfo>,
    },
    /// A session was created.
    SessionAdded {
        info: SessionInfo,
    },
    /// A session ended.
    SessionRemoved {
        id: SessionId,
    },

    // ── attach / detach (phone → host) ──────────────────────────────
    /// Phone is now viewing this session - stream it live (scrollback + bytes).
    Attach {
        id: SessionId,
    },
    /// Phone stopped viewing (switched away / backgrounded). Switching = Detach + Attach.
    Detach,

    // ── data flow ───────────────────────────────────────────────────
    /// phone → host: keystrokes / taps written into the PTY.
    Input {
        id: SessionId,
        bytes: Vec<u8>,
    },
    /// host → phone: PTY bytes for the ACTIVE session only.
    Output {
        id: SessionId,
        bytes: Vec<u8>,
    },
    /// host → phone: a non-viewed session produced output (tiny - drives the dot).
    ActivityBlip {
        id: SessionId,
    },

    // ── pty control (phone → host) ──────────────────────────────────
    /// Resize the PTY (rotation / soft keyboard popped).
    Resize {
        id: SessionId,
        cols: u16,
        rows: u16,
    },

    // ── session management (phone → host) ───────────────────────────
    /// Create a new shell session in this cwd.
    NewSession {
        cwd: Option<String>,
        title: Option<String>,
    },
    /// Destroy a session.
    KillSession {
        id: SessionId,
    },

    // ── agent ceiling (ACP) - PROTOCOL_VERSION 2, pure append ──────────
    /// host → phone: the agent wants to run an action and needs the user to
    /// approve/deny. Show an approval card. Only for `SessionKind::Agent`.
    RequestPermission {
        id: SessionId,
        tool_call: ToolCallCard,
        options: Vec<PermissionOption>,
    },
    /// phone → host: the user's decision to a `RequestPermission`.
    /// `option_id = Some(choice)` = approved/selected; `None` = cancelled.
    /// `tool_call_id` matches the card so the host replies to the right ACP request.
    PermissionDecision {
        tool_call_id: String,
        option_id: Option<String>,
    },

    // ── live-stream control (phone → host) - PROTOCOL_VERSION 2, pure append ──
    /// Stop streaming live `Output` for the actively-viewed session, but keep it
    /// "viewed" (don't switch away or send `ActivityBlip`). Lets the user scroll
    /// and read without the cursor jumping, and saves bandwidth on cellular. The
    /// host keeps buffering into the ring; a following `ResumeStream` replays the
    /// scrollback snapshot and resumes live output.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 13). Append-only tag.
    PauseStream,
    /// Resume live `Output` after a `PauseStream`. The host re-sends the current
    /// scrollback snapshot (so the user sees recent history) then streams live.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 14). Append-only tag.
    ResumeStream,

    // ── session rename (phone → host) - PROTOCOL_VERSION 2, pure append ──
    /// phone → host: give a session a custom name (e.g. "chinky"). The host
    /// updates the title and re-broadcasts the session set (a fresh
    /// `SessionList`) so every viewer sees the new name. No-op if `id` is gone.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 15). Append-only tag.
    RenameSession {
        id: SessionId,
        title: String,
    },

    // ── command feedback (host → phone) - PROTOCOL_VERSION 2, pure append ──
    /// host → phone: a phone-issued command could not be carried out (e.g. the
    /// session limit was hit on `NewSession`, or a `RenameSession`/`KillSession`
    /// targeted a session that no longer exists). The phone surfaces `message`.
    /// Without this, such failures were silently dropped.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 16). Append-only tag.
    CommandError {
        message: String,
    },

    // ── screen resync (host → phone) - PROTOCOL_VERSION 2, pure append ──
    /// host → phone: clear the client terminal for `id` NOW, because a full
    /// scrollback snapshot is about to follow (attach/switch, resume after pause,
    /// or recovery from a dropped-output lag). Without an explicit reset the
    /// client would render the snapshot ON TOP of existing content - duplicating
    /// old output and corrupting full-screen apps. The phone calls `term.reset()`
    /// on receipt for the active session.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 17). Append-only tag.
    ///
    /// `generation` (v5) identifies the host process lifetime that produced this
    /// screen. The phone stores it alongside the session's last-seen seq and
    /// echoes it in [`Frame::OutputResume`]; a mismatch on reconnect means the
    /// host restarted, so a delta resume would corrupt the screen and the host
    /// sends a fresh full attach instead.
    ScreenReset {
        id: SessionId,
        generation: u64,
    },

    // ── request/response correlation (PROTOCOL_VERSION 2, pure append) ──
    /// phone → host: a command that expects a reply, tagged with a phone-chosen
    /// `req_id`. See [`RequestKind`]. The host answers with `CommandResult`.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 18). Append-only tag.
    Request {
        req_id: u64,
        kind: RequestKind,
    },
    /// host → phone: the outcome of a `Request`, echoing its `req_id` so the
    /// phone can resolve exactly that pending command.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 19). Append-only tag.
    CommandResult {
        req_id: u64,
        outcome: CommandOutcome,
    },

    // ── authoritative PTY size (host → phone) - PROTOCOL_VERSION 2, pure append ──
    /// host → phone: the session's REAL PTY dimensions. The phone never drives
    /// the PTY size anymore (fixed-size model): spawned sessions are born at the
    /// host's fixed size, adopted sessions follow the laptop terminal. This frame
    /// tells the phone what that size is, so its match-width render mode can set
    /// its own terminal to the same grid (cursor math is only correct when both
    /// sides agree on cols). Sent on attach (between `ScreenReset` and the
    /// scrollback snapshot) and whenever an adopted session's laptop resizes.
    ///
    /// Introduced in PROTOCOL_VERSION 2 (index 20). Append-only tag.
    SessionSize {
        id: SessionId,
        cols: u16,
        rows: u16,
    },

    // ── structured agent feed (host → phone), pure append ─────────────
    /// Bounded replay sent whenever the phone opens/resumes an agent session.
    AgentSnapshot {
        id: SessionId,
        events: Vec<AgentTimelineEvent>,
    },
    /// One live normalized ACP update for the actively viewed agent session.
    AgentTimeline {
        id: SessionId,
        event: AgentTimelineEvent,
    },
    /// phone → host: session-scoped approval decision. ACP tool-call ids are
    /// only guaranteed unique inside one session; this avoids cross-resolving
    /// two agents that happen to reuse the same id. The older unscoped
    /// `PermissionDecision` remains supported for compatibility.
    AgentPermissionDecision {
        id: SessionId,
        tool_call_id: String,
        option_id: Option<String>,
    },
    /// host → phone: a pending approval was answered by SOME viewer - this
    /// phone, another phone, or a laptop `portty agent` chat. Every other
    /// viewer dismisses its card, so dual-control approvals stay in sync.
    /// Index 24, pure append.
    AgentPermissionResolved {
        id: SessionId,
        tool_call_id: String,
    },

    // ── resumable output + file transfer (pure append) ───────────────
    /// Sequence-tagged authoritative output. New clients use this in place of
    /// `Output`; the legacy variant remains frozen for older peers.
    SequencedOutput {
        id: SessionId,
        seq: u64,
        bytes: Vec<u8>,
    },
    /// Ask the host to replay output strictly after `after_seq`. If the ring no
    /// longer contains that boundary - OR `generation` no longer matches the
    /// host's current lifetime (a restart) - the host sends `ScreenReset` plus a
    /// fresh snapshot instead of a delta.
    ///
    /// `generation` (v5) is the value from the `ScreenReset` that established the
    /// screen this phone is resuming; 0 if the phone never saw one.
    OutputResume {
        id: SessionId,
        after_seq: u64,
        generation: u64,
    },
    /// Download a file. Paths outside the host user's home are rejected unless
    /// the user explicitly opted in for this request.
    FileGetReq {
        id: TransferId,
        path: String,
        start_seq: u64,
        allow_outside_home: bool,
    },
    /// Begin an atomic upload. Bytes land in a sibling temporary file and are
    /// renamed to `path` only after size and checksum verification.
    FilePutReq {
        id: TransferId,
        path: String,
        size: u64,
        mode: Option<u32>,
        allow_outside_home: bool,
    },
    FileChunk {
        id: TransferId,
        seq: u64,
        bytes: Vec<u8>,
    },
    /// BLAKE3 digest of the complete file. This semantic changed at wire
    /// protocol v4; v3 peers are rejected before file frames are exchanged.
    FileDone {
        id: TransferId,
        size: u64,
        checksum: [u8; 32],
    },
    FileErr {
        id: TransferId,
        reason: String,
    },
    /// Retry from a chunk boundary rather than restarting unrelated transfers.
    FileRetry {
        id: TransferId,
        from_seq: u64,
    },

    // ── policy-aware approvals (pure append) ─────────────────────────
    /// Category-bearing replacement for `RequestPermission`. Unknown ACP tool
    /// kinds map to `Unknown`, which the phone always prompts for.
    PolicyPermissionRequest {
        id: SessionId,
        tool_call: ToolCallCard,
        options: Vec<PermissionOption>,
        category: PermissionCategory,
        /// How broad the sandbox root is for the session that raised this card.
        ///
        /// Per-request rather than announced once per session on purpose: a card
        /// carries its own scope, so there is no window in which the phone holds
        /// a card but not the fact it needs to judge it. Added in v8, alongside
        /// the field it exists to gate.
        workspace_scope: WorkspaceScope,
    },

    // ── async push registration (pure append) ────────────────────────
    /// phone → host: register this device for wake-up pushes. The host stores
    /// the registration and forwards it to its configured push relay. The
    /// `sealed_wake_blob` is ciphertext the PHONE created (keyed by a secret
    /// that never leaves the phone); the host and relay store and forward it
    /// opaquely, and the phone decrypts it on notification receipt to learn
    /// which paired host rang the doorbell. Index 34, pure append.
    PushRegister {
        provider: PushProvider,
        token: String,
        sealed_wake_blob: Vec<u8>,
    },
    /// host → phone: outcome of a `PushRegister` (e.g. "no relay configured").
    /// Index 35, pure append.
    PushRegisterAck {
        ok: bool,
        detail: Option<String>,
    },

    // ── generation-bound pair revocation (pure append) ──────────────
    /// phone → host: revoke only the currently authenticated phone's pair.
    /// The host ignores any external target and binds this to the connection's
    /// QUIC-authenticated DeviceId. Index 36.
    UnpairSelf {
        request_id: u64,
        pair_id: [u8; 16],
    },
    /// host → phone: acknowledgement emitted only after the durable tombstone
    /// commit. Index 37.
    UnpairResult {
        request_id: u64,
        pair_id: [u8; 16],
        committed: bool,
        detail: Option<String>,
    },
    /// host → phone: the laptop revoked this exact pair generation. This rides
    /// the existing authenticated sealed channel; the phone deletes local state
    /// only when `pair_id` matches its current record. Index 38.
    PairRevoked {
        pair_id: [u8; 16],
        event_id: [u8; 16],
    },

    // ── richer approval resolution (v5, pure append) ─────────────────
    /// host → phone: like [`Frame::AgentPermissionResolved`] (index 24) but also
    /// names the outcome and which viewer answered, so a dismissed card can show
    /// "Rejected on the laptop" instead of silently vanishing. A v5 host sends
    /// THIS in place of index 24; index 24 stays frozen for the wire record.
    /// Index 39.
    AgentPermissionResolvedInfo {
        id: SessionId,
        tool_call_id: String,
        resolution: PermissionResolution,
        by: PermissionResolver,
    },

    // ── chosen agent workspace (v6, pure append) ─────────────────────
    /// host → phone: the immediate subdirectories of `rel`, answering
    /// [`RequestKind::ListWorkspaceDirs`].
    ///
    /// Only directories are listed - the picker chooses a working directory, and
    /// file names in a workspace can themselves be sensitive.
    ///
    /// `req_id` correlates to the `Frame::Request` that asked, exactly like
    /// `CommandResult`; two listings in flight are told apart by this and not by
    /// `rel`, which is only an echo of the RESOLVED path (`""` marks the
    /// workspace root, where the phone hides its "up" affordance since there is
    /// nothing above it to reach). Index 40.
    WorkspaceDirs {
        req_id: u64,
        rel: String,
        /// Immediate child directory NAMES (not paths), sorted, never `..`.
        names: Vec<String>,
    },

    // ── resumable conversations (v7, pure append) ────────────────────
    /// host → phone: cached conversations for `rel`, newest first, answering
    /// [`RequestKind::ListAgentSessions`]. Correlated by `req_id` like every
    /// other request/response pair. Index 41.
    AgentSessions {
        req_id: u64,
        rel: String,
        sessions: Vec<AgentSessionSummary>,
    },
    /// host → phone: adapter availability per provider. Index 42.
    AgentProviders {
        req_id: u64,
        providers: Vec<AgentProviderAvailability>,
    },
    /// host → phone: which [`TerminalRoot`]s this host serves, answering
    /// [`RequestKind::ListTerminalRoots`]. Index 43.
    ///
    /// Carries the roots and nothing else - no paths. The phone labels them
    /// itself, so a listing frame never has to disclose where home or the
    /// workspace actually live.
    /// Introduced in PROTOCOL_VERSION 10.
    TerminalRoots {
        req_id: u64,
        roots: Vec<TerminalRoot>,
    },
}

/// Redacting `Debug`.
///
/// Deliberately NOT derived. A frame carries the most sensitive data in the
/// product: `Input` is the user's keystrokes (including passwords typed into a
/// shell), `Output`/`SequencedOutput` is their terminal, `FileChunk` is file
/// contents, `PushRegister` holds a push token, and paths and titles are their
/// own business. One `tracing::debug!(?frame)` anywhere - in this repo or in a
/// fork - would put all of that in a log file, so the type simply cannot print
/// it. Structure (ids, sequence numbers, sizes, flags) is kept, because that is
/// what a log is actually for.
///
/// The match is exhaustive on purpose: a new variant will not compile until
/// someone has decided what of it is safe to show.
impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SessionList { sessions } => write!(f, "SessionList {{ sessions: {} }}", sessions.len()),
            Self::SessionAdded { info: _ } => f.write_str("SessionAdded"),
            Self::SessionRemoved { id } => write!(f, "SessionRemoved {{ id: {:?} }}", id),
            Self::Attach { id } => write!(f, "Attach {{ id: {:?} }}", id),
            Self::Detach => f.write_str("Detach"),
            Self::Input { id, bytes } => write!(f, "Input {{ id: {:?}, bytes: {} bytes }}", id, bytes.len()),
            Self::Output { id, bytes } => write!(f, "Output {{ id: {:?}, bytes: {} bytes }}", id, bytes.len()),
            Self::ActivityBlip { id } => write!(f, "ActivityBlip {{ id: {:?} }}", id),
            Self::Resize { id, cols, rows } => write!(f, "Resize {{ id: {:?}, cols: {:?}, rows: {:?} }}", id, cols, rows),
            Self::NewSession { cwd, title } => write!(f, "NewSession {{ cwd: {}, title: {} }}", cwd.as_ref().map_or("none".to_string(), |v| format!("{} chars", v.len())), title.as_ref().map_or("none".to_string(), |v| format!("{} chars", v.len()))),
            Self::KillSession { id } => write!(f, "KillSession {{ id: {:?} }}", id),
            Self::RequestPermission { id, tool_call: _, options } => write!(f, "RequestPermission {{ id: {:?}, options: {} }}", id, options.len()),
            Self::PermissionDecision { tool_call_id, option_id } => write!(f, "PermissionDecision {{ tool_call_id: {:?}, option_id: {:?} }}", tool_call_id, option_id),
            Self::PauseStream => f.write_str("PauseStream"),
            Self::ResumeStream => f.write_str("ResumeStream"),
            Self::RenameSession { id, title } => write!(f, "RenameSession {{ id: {:?}, title: {} chars }}", id, title.len()),
            Self::CommandError { message } => write!(f, "CommandError {{ message: {} chars }}", message.len()),
            Self::ScreenReset { id, generation } => write!(f, "ScreenReset {{ id: {:?}, generation: {:?} }}", id, generation),
            Self::Request { req_id, kind: _ } => write!(f, "Request {{ req_id: {:?} }}", req_id),
            Self::CommandResult { req_id, outcome: _ } => write!(f, "CommandResult {{ req_id: {:?} }}", req_id),
            Self::SessionSize { id, cols, rows } => write!(f, "SessionSize {{ id: {:?}, cols: {:?}, rows: {:?} }}", id, cols, rows),
            Self::AgentSnapshot { id, events } => write!(f, "AgentSnapshot {{ id: {:?}, events: {} }}", id, events.len()),
            Self::AgentTimeline { id, event: _ } => write!(f, "AgentTimeline {{ id: {:?} }}", id),
            Self::AgentPermissionDecision { id, tool_call_id, option_id } => write!(f, "AgentPermissionDecision {{ id: {:?}, tool_call_id: {:?}, option_id: {:?} }}", id, tool_call_id, option_id),
            Self::AgentPermissionResolved { id, tool_call_id } => write!(f, "AgentPermissionResolved {{ id: {:?}, tool_call_id: {:?} }}", id, tool_call_id),
            Self::SequencedOutput { id, seq, bytes } => write!(f, "SequencedOutput {{ id: {:?}, seq: {:?}, bytes: {} bytes }}", id, seq, bytes.len()),
            Self::OutputResume { id, after_seq, generation } => write!(f, "OutputResume {{ id: {:?}, after_seq: {:?}, generation: {:?} }}", id, after_seq, generation),
            Self::FileGetReq { id, path, start_seq, allow_outside_home } => write!(f, "FileGetReq {{ id: {:?}, path: {} chars, start_seq: {:?}, allow_outside_home: {:?} }}", id, path.len(), start_seq, allow_outside_home),
            Self::FilePutReq { id, path, size, mode, allow_outside_home } => write!(f, "FilePutReq {{ id: {:?}, path: {} chars, size: {:?}, mode: {:?}, allow_outside_home: {:?} }}", id, path.len(), size, mode, allow_outside_home),
            Self::FileChunk { id, seq, bytes } => write!(f, "FileChunk {{ id: {:?}, seq: {:?}, bytes: {} bytes }}", id, seq, bytes.len()),
            Self::FileDone { id, size, checksum: _ } => write!(f, "FileDone {{ id: {:?}, size: {:?} }}", id, size),
            Self::FileErr { id, reason } => write!(f, "FileErr {{ id: {:?}, reason: {} chars }}", id, reason.len()),
            Self::FileRetry { id, from_seq } => write!(f, "FileRetry {{ id: {:?}, from_seq: {:?} }}", id, from_seq),
            Self::PolicyPermissionRequest { id, tool_call: _, options, category, workspace_scope } => write!(f, "PolicyPermissionRequest {{ id: {:?}, options: {}, category: {:?}, workspace_scope: {:?} }}", id, options.len(), category, workspace_scope),
            Self::PushRegister { provider, token, sealed_wake_blob } => write!(f, "PushRegister {{ provider: {:?}, token: {} bytes, sealed_wake_blob: {} bytes }}", provider, token.len(), sealed_wake_blob.len()),
            Self::PushRegisterAck { ok, detail } => write!(f, "PushRegisterAck {{ ok: {:?}, detail: {} }}", ok, detail.as_ref().map_or("none".to_string(), |v| format!("{} chars", v.len()))),
            Self::UnpairSelf { request_id, pair_id: _ } => write!(f, "UnpairSelf {{ request_id: {:?} }}", request_id),
            Self::UnpairResult { request_id, pair_id: _, committed, detail } => write!(f, "UnpairResult {{ request_id: {:?}, committed: {:?}, detail: {} }}", request_id, committed, detail.as_ref().map_or("none".to_string(), |v| format!("{} chars", v.len()))),
            Self::PairRevoked { pair_id: _, event_id: _ } => f.write_str("PairRevoked"),
            Self::AgentPermissionResolvedInfo { id, tool_call_id, resolution, by } => write!(f, "AgentPermissionResolvedInfo {{ id: {:?}, tool_call_id: {:?}, resolution: {:?}, by: {:?} }}", id, tool_call_id, resolution, by),
            // Directory names describe the host's filesystem layout - counted,
            // never printed, same as every other path in this impl.
            Self::WorkspaceDirs { req_id, rel, names } => write!(f, "WorkspaceDirs {{ req_id: {:?}, rel: {} chars, names: {} }}", req_id, rel.len(), names.len()),
            // Labels are the user's own first prompts - counted, never printed.
            Self::AgentSessions { req_id, rel, sessions } => write!(f, "AgentSessions {{ req_id: {:?}, rel: {} chars, sessions: {} }}", req_id, rel.len(), sessions.len()),
            Self::AgentProviders { req_id, providers } => write!(f, "AgentProviders {{ req_id: {:?}, providers: {} }}", req_id, providers.len()),
            // Root KINDS, not paths - safe to print in full, and useful when
            // diagnosing why a phone was not offered a root.
            Self::TerminalRoots { req_id, roots } => write!(f, "TerminalRoots {{ req_id: {:?}, roots: {:?} }}", req_id, roots),
        }
    }
}

/// Which authenticated peer is permitted to send a frame.
///
/// This is deliberately an exhaustive match instead of another comment-only
/// convention: adding a Frame variant now fails to compile until its direction
/// is classified. File-transfer data/control is bidirectional because the same
/// variants serve uploads and downloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    PhoneToHost,
    HostToPhone,
    Bidirectional,
}

impl FrameDirection {
    pub const fn allows_phone_to_host(self) -> bool {
        matches!(self, Self::PhoneToHost | Self::Bidirectional)
    }

    pub const fn allows_host_to_phone(self) -> bool {
        matches!(self, Self::HostToPhone | Self::Bidirectional)
    }
}

impl Frame {
    pub const fn direction(&self) -> FrameDirection {
        match self {
            Self::SessionList { .. }
            | Self::SessionAdded { .. }
            | Self::SessionRemoved { .. }
            | Self::Output { .. }
            | Self::ActivityBlip { .. }
            | Self::RequestPermission { .. }
            | Self::CommandError { .. }
            | Self::ScreenReset { .. }
            | Self::CommandResult { .. }
            | Self::SessionSize { .. }
            | Self::AgentSnapshot { .. }
            | Self::AgentTimeline { .. }
            | Self::AgentPermissionResolved { .. }
            | Self::AgentPermissionResolvedInfo { .. }
            | Self::SequencedOutput { .. }
            | Self::PolicyPermissionRequest { .. }
            | Self::PushRegisterAck { .. }
            | Self::UnpairResult { .. }
            | Self::PairRevoked { .. }
            | Self::WorkspaceDirs { .. }
            | Self::AgentSessions { .. }
            | Self::AgentProviders { .. }
            | Self::TerminalRoots { .. } => FrameDirection::HostToPhone,

            Self::Attach { .. }
            | Self::Detach
            | Self::Input { .. }
            | Self::Resize { .. }
            | Self::NewSession { .. }
            | Self::KillSession { .. }
            | Self::PermissionDecision { .. }
            | Self::PauseStream
            | Self::ResumeStream
            | Self::RenameSession { .. }
            | Self::Request { .. }
            | Self::AgentPermissionDecision { .. }
            | Self::OutputResume { .. }
            | Self::FileGetReq { .. }
            | Self::FilePutReq { .. }
            | Self::PushRegister { .. }
            | Self::UnpairSelf { .. } => FrameDirection::PhoneToHost,

            Self::FileChunk { .. }
            | Self::FileDone { .. }
            | Self::FileErr { .. }
            | Self::FileRetry { .. } => FrameDirection::Bidirectional,
        }
    }
}

pub fn encode(frame: &Frame) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(frame)
}

pub fn decode(bytes: &[u8]) -> Result<Frame, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_directions_are_enforced_as_part_of_the_schema() {
        assert_eq!(
            Frame::SessionList { sessions: vec![] }.direction(),
            FrameDirection::HostToPhone
        );
        assert_eq!(Frame::Detach.direction(), FrameDirection::PhoneToHost);
        assert_eq!(
            Frame::FileRetry {
                id: TransferId(1),
                from_seq: 0,
            }
            .direction(),
            FrameDirection::Bidirectional
        );
        assert!(!Frame::Detach.direction().allows_host_to_phone());
        assert!(!Frame::SessionList { sessions: vec![] }
            .direction()
            .allows_phone_to_host());
    }

    #[test]
    fn roundtrip_output() {
        let f = Frame::Output {
            id: SessionId(7),
            bytes: vec![1, 2, 3, 4],
        };
        let back = decode(&encode(&f).unwrap()).unwrap();
        match back {
            Frame::Output { id, bytes } => {
                assert_eq!(id, SessionId(7));
                assert_eq!(bytes, vec![1, 2, 3, 4]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_session_list() {
        let f = Frame::SessionList {
            sessions: vec![SessionInfo {
                id: SessionId(1),
                title: "bash".into(),
                kind: SessionKind::Shell,
                source: SessionSource::Spawned,
                has_activity: false,
            }],
        };
        let back = decode(&encode(&f).unwrap()).unwrap();
        match back {
            Frame::SessionList { sessions } => assert_eq!(sessions.len(), 1),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_adopted_source() {
        // A `portty share` terminal reports as Adopted - the badge the phone shows.
        let f = Frame::SessionAdded {
            info: SessionInfo {
                id: SessionId(3),
                title: "share".into(),
                kind: SessionKind::Shell,
                source: SessionSource::Adopted,
                has_activity: true,
            },
        };
        let back = decode(&encode(&f).unwrap()).unwrap();
        match back {
            Frame::SessionAdded { info } => {
                assert_eq!(info.source, SessionSource::Adopted);
                assert!(info.has_activity);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ping_sized_frame_is_tiny() {
        // The lightest frame should be a handful of bytes (postcard tags by index).
        let f = Frame::Detach;
        assert!(encode(&f).unwrap().len() <= 2);
    }

    // ── agent ceiling (ACP) frames ────────────────────────────────────
    #[test]
    fn roundtrip_request_permission() {
        let f = Frame::RequestPermission {
            id: SessionId(5),
            tool_call: ToolCallCard {
                tool_call_id: "call_001".into(),
                title: "Run: git push --force".into(),
            },
            options: vec![
                PermissionOption {
                    option_id: "allow-once".into(),
                    name: "Allow once".into(),
                    kind: PermissionOptionKind::AllowOnce,
                },
                PermissionOption {
                    option_id: "reject-once".into(),
                    name: "Reject".into(),
                    kind: PermissionOptionKind::RejectOnce,
                },
            ],
        };
        let back = decode(&encode(&f).unwrap()).unwrap();
        match back {
            Frame::RequestPermission {
                id,
                tool_call,
                options,
            } => {
                assert_eq!(id, SessionId(5));
                assert_eq!(tool_call.tool_call_id, "call_001");
                assert_eq!(tool_call.title, "Run: git push --force");
                assert_eq!(options.len(), 2);
                assert_eq!(options[0].kind, PermissionOptionKind::AllowOnce);
                assert_eq!(options[1].kind, PermissionOptionKind::RejectOnce);
                assert_eq!(options[1].option_id, "reject-once");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_permission_decision() {
        // selected (approved)
        let selected = Frame::PermissionDecision {
            tool_call_id: "call_001".into(),
            option_id: Some("allow-once".into()),
        };
        match decode(&encode(&selected).unwrap()).unwrap() {
            Frame::PermissionDecision {
                tool_call_id,
                option_id,
            } => {
                assert_eq!(tool_call_id, "call_001");
                assert_eq!(option_id.as_deref(), Some("allow-once"));
            }
            _ => panic!("wrong variant"),
        }
        // cancelled
        let cancelled = Frame::PermissionDecision {
            tool_call_id: "call_001".into(),
            option_id: None,
        };
        match decode(&encode(&cancelled).unwrap()).unwrap() {
            Frame::PermissionDecision {
                tool_call_id,
                option_id,
            } => {
                assert_eq!(tool_call_id, "call_001");
                assert!(option_id.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn agent_frames_append_after_existing_variants() {
        // postcard tags enum variants by declaration index (a single byte while
        // we have <128 variants). The wire schema is PINNED to these tags:
        // reordering, inserting, or removing a variant shifts them and MUST be
        // accompanied by a PROTOCOL_VERSION bump (see frame.rs). These asserts
        // are the tripwire - if one fires, either restore the declaration order
        // or bump PROTOCOL_VERSION so mixed builds fail closed (#35).
        assert_eq!(encode(&Frame::Detach).unwrap()[0], 4); // Detach == index 4
        let rp = encode(&Frame::RequestPermission {
            id: SessionId(0),
            tool_call: ToolCallCard {
                tool_call_id: "x".into(),
                title: "t".into(),
            },
            options: vec![],
        })
        .unwrap();
        assert_eq!(rp[0], 11, "RequestPermission must stay at index 11");
        let pd = encode(&Frame::PermissionDecision {
            tool_call_id: "x".into(),
            option_id: None,
        })
        .unwrap();
        assert_eq!(pd[0], 12, "PermissionDecision must stay at index 12");
        // Frozen: v5's last variant. It is no longer the highest, but its tag is
        // part of the wire record and must never move.
        let v5_last = encode(&Frame::AgentPermissionResolvedInfo {
            id: SessionId(0),
            tool_call_id: "x".into(),
            resolution: PermissionResolution::Allowed,
            by: PermissionResolver::Phone,
        })
        .unwrap();
        assert_eq!(
            v5_last[0], 39,
            "AgentPermissionResolvedInfo must stay at index 39; a change here means the \
             Frame schema moved and PROTOCOL_VERSION must be bumped"
        );
        // Pin the HIGHEST current variant. Its tag equals (variant count - 1), so
        // ANY insertion / removal / reorder anywhere before it moves this byte -
        // one assert guards the whole appended range (13..=40) that #35 flagged as
        // version-unattributed.
        let v6_last = encode(&Frame::WorkspaceDirs {
            req_id: 0,
            rel: String::new(),
            names: vec![],
        })
        .unwrap();
        assert_eq!(v6_last[0], 40, "WorkspaceDirs must stay at index 40");
        let v7_sessions = encode(&Frame::AgentSessions {
            req_id: 0,
            rel: String::new(),
            sessions: vec![],
        })
        .unwrap();
        assert_eq!(v7_sessions[0], 41, "AgentSessions must stay at index 41");
        let latest = encode(&Frame::AgentProviders {
            req_id: 0,
            providers: vec![],
        })
        .unwrap();
        assert_eq!(
            latest[0], 42,
            "AgentProviders must stay at index 42; a change here means the Frame schema \
             moved and PROTOCOL_VERSION must be bumped"
        );
        let v10_last = encode(&Frame::TerminalRoots {
            req_id: 0,
            roots: vec![],
        })
        .unwrap();
        assert_eq!(
            v10_last[0], 43,
            "TerminalRoots must stay at index 43; a change here means the Frame schema \
             moved and PROTOCOL_VERSION must be bumped"
        );
    }

    /// v10's appends, and the roots enum's own tags.
    ///
    /// `TerminalRoot` is a NEW enum, so its order is only a contract from here on -
    /// pinning it now is what makes that true, rather than discovering later that
    /// someone inserted a root above `Home` and silently re-pointed every stored
    /// default on every phone.
    #[test]
    fn terminal_roots_append_after_the_chosen_directory_create() {
        assert_eq!(
            postcard::to_allocvec(&TerminalRoot::Workspace).unwrap()[0],
            0,
            "Workspace must stay at index 0 - it is what every pre-v10 rel meant"
        );
        assert_eq!(postcard::to_allocvec(&TerminalRoot::Home).unwrap()[0], 1);

        // The frozen predecessor: v9's create keeps its tag.
        let frozen = postcard::to_allocvec(&RequestKind::NewSessionIn {
            title: None,
            rel: String::new(),
        })
        .unwrap();
        assert_eq!(frozen[0], 16, "NewSessionIn must stay at index 16");

        assert_eq!(
            postcard::to_allocvec(&RequestKind::ListTerminalRoots).unwrap()[0],
            17,
            "ListTerminalRoots must stay at index 17"
        );
        let list = postcard::to_allocvec(&RequestKind::ListDirsIn {
            root: TerminalRoot::Home,
            rel: "code".into(),
        })
        .unwrap();
        assert_eq!(list[0], 18, "ListDirsIn must stay at index 18");
        let open = postcard::to_allocvec(&RequestKind::NewSessionInRoot {
            root: TerminalRoot::Home,
            rel: "code/app".into(),
            title: Some("api".into()),
        })
        .unwrap();
        assert_eq!(open[0], 19, "NewSessionInRoot must stay at index 19");

        match postcard::from_bytes::<RequestKind>(&open).unwrap() {
            RequestKind::NewSessionInRoot { root, rel, title } => {
                assert_eq!(root, TerminalRoot::Home);
                assert_eq!(rel, "code/app");
                assert_eq!(title.as_deref(), Some("api"));
            }
            _ => panic!("wrong variant"),
        }
        match postcard::from_bytes::<RequestKind>(&list).unwrap() {
            RequestKind::ListDirsIn { root, rel } => {
                assert_eq!(root, TerminalRoot::Home);
                assert_eq!(rel, "code");
            }
            _ => panic!("wrong variant"),
        }

        // The roots reply is host→phone only, and carries no paths.
        let reply = Frame::TerminalRoots {
            req_id: 7,
            roots: vec![TerminalRoot::Workspace, TerminalRoot::Home],
        };
        assert_eq!(reply.direction(), FrameDirection::HostToPhone);
        assert!(!reply.direction().allows_phone_to_host());
        match decode(&encode(&reply).unwrap()).unwrap() {
            Frame::TerminalRoots { req_id, roots } => {
                assert_eq!(req_id, 7);
                assert_eq!(roots, vec![TerminalRoot::Workspace, TerminalRoot::Home]);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// v11's append, and the two frozen requests it must not disturb.
    ///
    /// `ListAgentSessionsFor` is a SECOND way to ask a question `ListAgentSessions`
    /// already answers, so the risk here is not a missing tag - it is someone
    /// deciding the old one is redundant and deleting it. It is not redundant: it
    /// is the wire record, and a phone built before v11 has no other way to ask.
    #[test]
    fn agent_owned_session_listing_appends_after_the_root_create() {
        // The frozen predecessors: v10's highest request, and the v7 listing this
        // one widens rather than replaces.
        assert_eq!(
            postcard::to_allocvec(&RequestKind::NewSessionInRoot {
                root: TerminalRoot::Home,
                rel: String::new(),
                title: None,
            })
            .unwrap()[0],
            19,
            "NewSessionInRoot must stay at index 19"
        );
        assert_eq!(
            postcard::to_allocvec(&RequestKind::ListAgentSessions { rel: String::new() }).unwrap()
                [0],
            13,
            "ListAgentSessions must stay at index 13 - v11 widens it, it does not \
             replace it, and a pre-v11 phone can only ask this way"
        );

        let listing = postcard::to_allocvec(&RequestKind::ListAgentSessionsFor {
            rel: "app".into(),
            provider: AgentProvider::OpenCode,
        })
        .unwrap();
        assert_eq!(
            listing[0], 20,
            "ListAgentSessionsFor must stay at index 20; a change here means the \
             RequestKind schema moved and PROTOCOL_VERSION must be bumped"
        );
        match postcard::from_bytes::<RequestKind>(&listing).unwrap() {
            RequestKind::ListAgentSessionsFor { rel, provider } => {
                assert_eq!(rel, "app");
                assert_eq!(provider, AgentProvider::OpenCode);
            }
            _ => panic!("wrong variant"),
        }

        // It rides the EXISTING reply, so the answer's direction and shape are
        // already pinned elsewhere - what matters is that no new frame appeared to
        // carry it.
        let reply = Frame::AgentSessions {
            req_id: 3,
            rel: "app".into(),
            sessions: Vec::new(),
        };
        assert_eq!(reply.direction(), FrameDirection::HostToPhone);
    }

    #[test]
    fn workspace_picker_requests_append_after_agent_authenticate() {
        // v6. The frozen predecessor first: `NewAgentSession` keeps meaning "the
        // workspace root", so its tag must not drift when the chosen-directory
        // variant lands beside it.
        let frozen = postcard::to_allocvec(&RequestKind::NewAgentSession {
            provider: AgentProvider::ClaudeCode,
            title: None,
        })
        .unwrap();
        assert_eq!(frozen[0], 5, "NewAgentSession's existing tag must not move");

        let list =
            postcard::to_allocvec(&RequestKind::ListWorkspaceDirs { rel: String::new() }).unwrap();
        assert_eq!(list[0], 11, "ListWorkspaceDirs must stay at index 11");

        let start = postcard::to_allocvec(&RequestKind::NewAgentSessionIn {
            provider: AgentProvider::ClaudeCode,
            title: None,
            rel: "project-portty".into(),
        })
        .unwrap();
        assert_eq!(start[0], 12, "NewAgentSessionIn must stay at index 12");

        match postcard::from_bytes::<RequestKind>(&start).unwrap() {
            RequestKind::NewAgentSessionIn {
                provider,
                title,
                rel,
            } => {
                assert_eq!(provider, AgentProvider::ClaudeCode);
                assert!(title.is_none());
                assert_eq!(rel, "project-portty");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn acp_control_variants_are_append_only_and_round_trip() {
        assert_eq!(postcard::to_allocvec(&AgentProvider::Codex).unwrap()[0], 2);
        assert_eq!(postcard::to_allocvec(&AgentProvider::Goose).unwrap()[0], 3);

        let legacy = postcard::to_allocvec(&RequestKind::AgentPrompt {
            id: SessionId(1),
            text: "hello".into(),
        })
        .unwrap();
        assert_eq!(legacy[0], 6, "AgentPrompt's existing tag must not move");

        let request = RequestKind::AgentSetConfigOption {
            id: SessionId(9),
            config_id: "model".into(),
            value: AgentConfigValue::Boolean(true),
        };
        let encoded = postcard::to_allocvec(&request).unwrap();
        assert_eq!(encoded[0], 9);
        assert!(matches!(
            postcard::from_bytes::<RequestKind>(&encoded).unwrap(),
            RequestKind::AgentSetConfigOption {
                id: SessionId(9),
                value: AgentConfigValue::Boolean(true),
                ..
            }
        ));

        let usage = AgentEvent::Usage {
            used_tokens: 12_000,
            max_tokens: 200_000,
            cost: Some("0.42 USD".into()),
        };
        let encoded = postcard::to_allocvec(&usage).unwrap();
        assert_eq!(encoded[0], 16, "Usage must stay appended at tag 16");
        assert_eq!(postcard::from_bytes::<AgentEvent>(&encoded).unwrap(), usage);
    }

    #[test]
    fn roundtrip_session_size() {
        let f = Frame::SessionSize {
            id: SessionId(9),
            cols: 160,
            rows: 48,
        };
        match decode(&encode(&f).unwrap()).unwrap() {
            Frame::SessionSize { id, cols, rows } => {
                assert_eq!(id, SessionId(9));
                assert_eq!((cols, rows), (160, 48));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn session_size_appends_after_command_result() {
        // SessionSize MUST sit at index 20 - after CommandResult (19). An older
        // peer that only knows 0..=19 never produces it and fails gracefully
        // (unknown tag) if it receives one.
        let f = encode(&Frame::SessionSize {
            id: SessionId(0),
            cols: 0,
            rows: 0,
        })
        .unwrap();
        assert_eq!(f[0], 20, "SessionSize must stay at index 20");
    }

    #[test]
    fn roundtrip_pause_resume_stream() {
        let pause = decode(&encode(&Frame::PauseStream).unwrap()).unwrap();
        assert!(matches!(pause, Frame::PauseStream));
        let resume = decode(&encode(&Frame::ResumeStream).unwrap()).unwrap();
        assert!(matches!(resume, Frame::ResumeStream));
    }

    #[test]
    fn roundtrip_structured_agent_timeline() {
        let f = Frame::AgentTimeline {
            id: SessionId(42),
            event: AgentTimelineEvent {
                seq: 7,
                event: AgentEvent::ToolCall {
                    tool_call_id: "tool-1".into(),
                    title: "Run cargo test".into(),
                    kind: AgentToolKind::Execute,
                    status: AgentToolStatus::InProgress,
                    detail: Some("cargo test".into()),
                },
            },
        };
        match decode(&encode(&f).unwrap()).unwrap() {
            Frame::AgentTimeline { id, event } => {
                assert_eq!(id, SessionId(42));
                assert_eq!(event.seq, 7);
                assert!(matches!(event.event, AgentEvent::ToolCall { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn structured_agent_frames_are_appended() {
        let snapshot = Frame::AgentSnapshot {
            id: SessionId(0),
            events: vec![],
        };
        assert_eq!(encode(&snapshot).unwrap()[0], 21);
        let live = Frame::AgentTimeline {
            id: SessionId(0),
            event: AgentTimelineEvent {
                seq: 0,
                event: AgentEvent::TurnStarted,
            },
        };
        assert_eq!(encode(&live).unwrap()[0], 22);
        let decision = Frame::AgentPermissionDecision {
            id: SessionId(1),
            tool_call_id: "tool".into(),
            option_id: None,
        };
        assert_eq!(encode(&decision).unwrap()[0], 23);
        let resolved = Frame::AgentPermissionResolved {
            id: SessionId(1),
            tool_call_id: "tool".into(),
        };
        assert_eq!(encode(&resolved).unwrap()[0], 24);
        // v5 append: the richer resolution frame sits at index 39, leaving the
        // frozen index-24 variant untouched for the wire record.
        let resolved_info = Frame::AgentPermissionResolvedInfo {
            id: SessionId(1),
            tool_call_id: "tool".into(),
            resolution: PermissionResolution::Rejected,
            by: PermissionResolver::Laptop,
        };
        assert_eq!(encode(&resolved_info).unwrap()[0], 39);
    }

    #[test]
    fn stream_control_frames_append_after_acp() {
        // PauseStream / ResumeStream MUST sit at indices 13/14 - after the ACP
        // frames (11/12). An older peer that only knows 0..=12 never produces
        // them and fails gracefully (unknown tag) if it receives one.
        assert_eq!(
            encode(&Frame::PauseStream).unwrap()[0],
            13,
            "PauseStream must stay at index 13"
        );
        assert_eq!(
            encode(&Frame::ResumeStream).unwrap()[0],
            14,
            "ResumeStream must stay at index 14"
        );
    }
}

#[cfg(test)]
mod golden {
    //! Golden wire vectors - the exact postcard bytes for representative v1/v2
    //! frames. Unlike the tag-index guards above, these pin the FULL byte layout
    //! (fields, varint widths, string/vec framing), so ANY change to the wire
    //! format - not just variant reordering - trips a test. If one of these
    //! fails, the on-wire protocol changed: bump `PROTOCOL_VERSION` and update
    //! the vector deliberately, don't just re-baseline it.
    use super::*;

    fn assert_golden(frame: &Frame, want: &[u8]) {
        let got = encode(frame).unwrap();
        assert_eq!(got.as_slice(), want, "wire format changed for {frame:?}");
        // And it must round-trip back to an equal-shaped frame.
        assert!(decode(want).is_ok(), "golden bytes must decode");
    }

    #[test]
    fn golden_v1_frames() {
        assert_golden(&Frame::Detach, &[0x04]);
        assert_golden(&Frame::Attach { id: SessionId(1) }, &[0x03, 0x01]);
        assert_golden(
            &Frame::Input {
                id: SessionId(2),
                bytes: vec![0xDE, 0xAD],
            },
            &[0x05, 0x02, 0x02, 0xde, 0xad],
        );
        assert_golden(
            &Frame::Output {
                id: SessionId(7),
                bytes: vec![1, 2, 3, 4],
            },
            &[0x06, 0x07, 0x04, 0x01, 0x02, 0x03, 0x04],
        );
        assert_golden(
            &Frame::Resize {
                id: SessionId(1),
                cols: 80,
                rows: 24,
            },
            &[0x08, 0x01, 0x50, 0x18],
        );
        assert_golden(
            &Frame::NewSession {
                cwd: None,
                title: Some("x".into()),
            },
            &[0x09, 0x00, 0x01, 0x01, 0x78],
        );
        assert_golden(&Frame::KillSession { id: SessionId(9) }, &[0x0a, 0x09]);
        assert_golden(
            &Frame::SessionAdded {
                info: SessionInfo {
                    id: SessionId(1),
                    title: "bash".into(),
                    kind: SessionKind::Shell,
                    source: SessionSource::Spawned,
                    has_activity: false,
                },
            },
            &[0x01, 0x01, 0x04, 0x62, 0x61, 0x73, 0x68, 0x00, 0x00, 0x00],
        );
    }

    #[test]
    fn golden_v2_frames() {
        assert_golden(
            &Frame::PermissionDecision {
                tool_call_id: "c".into(),
                option_id: Some("a".into()),
            },
            &[0x0c, 0x01, 0x63, 0x01, 0x01, 0x61],
        );
        assert_golden(
            &Frame::RenameSession {
                id: SessionId(3),
                title: "hi".into(),
            },
            &[0x0f, 0x03, 0x02, 0x68, 0x69],
        );
        assert_golden(
            &Frame::SessionSize {
                id: SessionId(3),
                cols: 160,
                rows: 48,
            },
            // tag 20, id 3, cols 160 (2-byte varint), rows 48
            &[0x14, 0x03, 0xa0, 0x01, 0x30],
        );
    }

    #[test]
    fn golden_v6_frames() {
        // Workspace root listing: tag 40, req_id 1, rel "" (len 0), name "src".
        assert_golden(
            &Frame::WorkspaceDirs {
                req_id: 1,
                rel: String::new(),
                names: vec!["src".into()],
            },
            &[0x28, 0x01, 0x00, 0x01, 0x03, 0x73, 0x72, 0x63],
        );
        // A nested listing with no children - the empty vec must still frame.
        assert_golden(
            &Frame::WorkspaceDirs {
                req_id: 7,
                rel: "a/b".into(),
                names: vec![],
            },
            &[0x28, 0x07, 0x03, 0x61, 0x2f, 0x62, 0x00],
        );
    }

    #[test]
    fn golden_v7_frames() {
        // tag 41, req_id 2, rel "app", one summary: id "s1", provider 0
        // (ClaudeCode), title "t", label None, last_active 5.
        assert_golden(
            &Frame::AgentSessions {
                req_id: 2,
                rel: "app".into(),
                sessions: vec![AgentSessionSummary {
                    acp_session_id: "s1".into(),
                    provider: AgentProvider::ClaudeCode,
                    title: "t".into(),
                    label: None,
                    last_active_at_unix_ms: 5,
                }],
            },
            &[
                0x29, 0x02, 0x03, 0x61, 0x70, 0x70, 0x01, 0x02, 0x73, 0x31, 0x00, 0x01, 0x74, 0x00,
                0x05,
            ],
        );
        // A directory with no cached conversations still has to frame cleanly -
        // the phone renders "no saved conversations" from exactly this.
        assert_golden(
            &Frame::AgentSessions {
                req_id: 9,
                rel: String::new(),
                sessions: vec![],
            },
            &[0x29, 0x09, 0x00, 0x00],
        );
    }

    #[test]
    fn resume_requests_append_after_the_workspace_picker() {
        let list =
            postcard::to_allocvec(&RequestKind::ListAgentSessions { rel: String::new() }).unwrap();
        assert_eq!(list[0], 13, "ListAgentSessions must stay at index 13");
        let resume = postcard::to_allocvec(&RequestKind::ResumeAgentSession {
            rel: "app".into(),
            acp_session_id: "abc".into(),
        })
        .unwrap();
        assert_eq!(resume[0], 14, "ResumeAgentSession must stay at index 14");
        match postcard::from_bytes::<RequestKind>(&resume).unwrap() {
            RequestKind::ResumeAgentSession {
                rel,
                acp_session_id,
            } => {
                assert_eq!(rel, "app");
                assert_eq!(acp_session_id, "abc");
            }
            _ => panic!("wrong variant"),
        }
    }

    /// v9's append, plus the frozen predecessor it lands behind.
    ///
    /// `ListAgentProviders` was the highest `RequestKind` and nothing pinned it -
    /// the tripwire pattern used everywhere else in this module had simply not
    /// been extended to it, so an insertion anywhere in `RequestKind` could have
    /// shifted the whole appended range unnoticed. Pinning it here closes that as
    /// well as guarding the new variant.
    #[test]
    fn chosen_terminal_directory_appends_after_list_agent_providers() {
        let frozen = postcard::to_allocvec(&RequestKind::ListAgentProviders).unwrap();
        assert_eq!(
            frozen[0], 15,
            "ListAgentProviders must stay at index 15; a change here means the RequestKind \
             schema moved and PROTOCOL_VERSION must be bumped"
        );

        let open = postcard::to_allocvec(&RequestKind::NewSessionIn {
            title: Some("api".into()),
            rel: "crates/host".into(),
        })
        .unwrap();
        assert_eq!(open[0], 16, "NewSessionIn must stay at index 16");

        match postcard::from_bytes::<RequestKind>(&open).unwrap() {
            RequestKind::NewSessionIn { title, rel } => {
                assert_eq!(title.as_deref(), Some("api"));
                assert_eq!(rel, "crates/host");
            }
            _ => panic!("wrong variant"),
        }

        // The workspace root is the empty rel, and a titleless open is the
        // ordinary case (the host names the session). Both must survive the trip.
        let root = postcard::to_allocvec(&RequestKind::NewSessionIn {
            title: None,
            rel: String::new(),
        })
        .unwrap();
        match postcard::from_bytes::<RequestKind>(&root).unwrap() {
            RequestKind::NewSessionIn { title, rel } => {
                assert!(title.is_none());
                assert!(rel.is_empty());
            }
            _ => panic!("wrong variant"),
        }

        // The frozen `NewSession` keeps its tag AND its unused `cwd`. The phone
        // has never sent a path there and `NewSessionIn` is why it never will.
        let legacy = postcard::to_allocvec(&RequestKind::NewSession {
            cwd: None,
            title: None,
        })
        .unwrap();
        assert_eq!(legacy[0], 0, "NewSession must stay at index 0");
    }

    #[test]
    fn screen_reset_stays_at_index_17() {
        let bytes = encode(&Frame::ScreenReset {
            id: SessionId(0),
            generation: 7,
        })
        .unwrap();
        assert_eq!(bytes[0], 17, "ScreenReset must stay at index 17");
        assert!(matches!(decode(&bytes).unwrap(), Frame::ScreenReset { .. }));
    }

    #[test]
    fn request_and_result_indices_and_roundtrip() {
        // Appended after ScreenReset (17). Guard the indices…
        let req = encode(&Frame::Request {
            req_id: 42,
            kind: RequestKind::NewSession {
                cwd: None,
                title: Some("dev".into()),
            },
        })
        .unwrap();
        assert_eq!(req[0], 18, "Request must stay at index 18");
        let res = encode(&Frame::CommandResult {
            req_id: 42,
            outcome: CommandOutcome::Ok {
                session: Some(SessionId(7)),
            },
        })
        .unwrap();
        assert_eq!(res[0], 19, "CommandResult must stay at index 19");

        // …and round-trip the correlation id + payload.
        match decode(&req).unwrap() {
            Frame::Request { req_id, kind } => {
                assert_eq!(req_id, 42);
                assert!(matches!(kind, RequestKind::NewSession { .. }));
            }
            _ => panic!("wrong variant"),
        }
        match decode(&res).unwrap() {
            Frame::CommandResult { req_id, outcome } => {
                assert_eq!(req_id, 42);
                assert!(matches!(
                    outcome,
                    CommandOutcome::Ok {
                        session: Some(SessionId(7))
                    }
                ));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn command_error_stays_at_index_16() {
        // Appended after RenameSession (15). Older peers never produce it and
        // fail gracefully (unknown tag) on receipt.
        let bytes = encode(&Frame::CommandError {
            message: "x".into(),
        })
        .unwrap();
        assert_eq!(bytes[0], 16, "CommandError must stay at index 16");
        assert!(matches!(
            decode(&bytes).unwrap(),
            Frame::CommandError { .. }
        ));
    }

    #[test]
    fn rename_session_stays_at_index_15() {
        // The appended v2 rename frame (the review flagged it as unguarded). An
        // older peer that only knows 0..=14 must never produce it and fails
        // gracefully (unknown tag) if it receives one.
        assert_eq!(
            encode(&Frame::RenameSession {
                id: SessionId(0),
                title: String::new(),
            })
            .unwrap()[0],
            15,
            "RenameSession must stay at index 15"
        );
    }

    #[test]
    fn file_frames_roundtrip_and_remain_chunk_bounded() {
        let frame = Frame::FileChunk {
            id: TransferId(44),
            seq: 7,
            bytes: vec![0xa5; FILE_CHUNK_BYTES],
        };
        match decode(&encode(&frame).unwrap()).unwrap() {
            Frame::FileChunk { id, seq, bytes } => {
                assert_eq!(id, TransferId(44));
                assert_eq!(seq, 7);
                assert_eq!(bytes.len(), FILE_CHUNK_BYTES);
            }
            _ => panic!("wrong file frame"),
        }
    }

    /// The scope must survive the wire intact, and `Broad` must be the value a
    /// caller reaches for when it does not know - the phone refuses blanket read
    /// approval on `Broad`, so an accidental `Project` is the unsafe direction.
    #[test]
    fn workspace_scope_round_trips_on_the_permission_card() {
        for scope in [WorkspaceScope::Project, WorkspaceScope::Broad] {
            let frame = Frame::PolicyPermissionRequest {
                id: SessionId(7),
                tool_call: ToolCallCard {
                    tool_call_id: "t".into(),
                    title: "Read file".into(),
                },
                options: Vec::new(),
                category: PermissionCategory::Read,
                workspace_scope: scope,
            };
            let back: Frame = postcard::from_bytes(&encode(&frame).unwrap()).unwrap();
            match back {
                Frame::PolicyPermissionRequest {
                    workspace_scope, ..
                } => {
                    assert_eq!(workspace_scope, scope);
                }
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    /// The scope is not a credential, but a debug line that omitted it would hide
    /// exactly the fact that explains why a card prompted.
    #[test]
    fn permission_card_debug_names_the_scope_without_the_tool_call() {
        let rendered = format!(
            "{:?}",
            Frame::PolicyPermissionRequest {
                id: SessionId(1),
                tool_call: ToolCallCard {
                    tool_call_id: "secret-id".into(),
                    title: "Read /home/u/.ssh/id_rsa".into(),
                },
                options: Vec::new(),
                category: PermissionCategory::Read,
                workspace_scope: WorkspaceScope::Broad,
            }
        );
        assert!(rendered.contains("Broad"), "{rendered}");
        assert!(!rendered.contains("id_rsa"), "{rendered}");
    }

    #[test]
    fn new_frames_are_appended_after_existing_contract() {
        assert_eq!(
            encode(&Frame::SequencedOutput {
                id: SessionId(0),
                seq: 0,
                bytes: Vec::new(),
            })
            .unwrap()[0],
            25
        );
        assert_eq!(
            encode(&Frame::PolicyPermissionRequest {
                id: SessionId(0),
                tool_call: ToolCallCard {
                    tool_call_id: String::new(),
                    title: String::new(),
                },
                options: Vec::new(),
                category: PermissionCategory::Unknown,
                workspace_scope: WorkspaceScope::Broad,
            })
            .unwrap()[0],
            33
        );
    }

    #[test]
    fn file_frames_stay_at_indices_27_through_32() {
        // A swap among the six file variants would keep every other golden pin
        // green while corrupting live transfers - pin each one individually.
        let id = TransferId(0);
        assert_eq!(
            encode(&Frame::FileGetReq {
                id,
                path: String::new(),
                start_seq: 0,
                allow_outside_home: false,
            })
            .unwrap()[0],
            27
        );
        assert_eq!(
            encode(&Frame::FilePutReq {
                id,
                path: String::new(),
                size: 0,
                mode: None,
                allow_outside_home: false,
            })
            .unwrap()[0],
            28
        );
        assert_eq!(
            encode(&Frame::FileChunk {
                id,
                seq: 0,
                bytes: Vec::new(),
            })
            .unwrap()[0],
            29
        );
        assert_eq!(
            encode(&Frame::FileDone {
                id,
                size: 0,
                checksum: [0; 32],
            })
            .unwrap()[0],
            30
        );
        assert_eq!(
            encode(&Frame::FileErr {
                id,
                reason: String::new(),
            })
            .unwrap()[0],
            31
        );
        assert_eq!(
            encode(&Frame::FileRetry { id, from_seq: 0 }).unwrap()[0],
            32
        );
    }

    #[test]
    fn push_frames_stay_at_indices_34_and_35() {
        let bytes = encode(&Frame::PushRegister {
            provider: PushProvider::Apns,
            token: String::new(),
            sealed_wake_blob: Vec::new(),
        })
        .unwrap();
        assert_eq!(bytes[0], 34, "PushRegister must stay at index 34");
        assert!(matches!(
            decode(&bytes).unwrap(),
            Frame::PushRegister {
                provider: PushProvider::Apns,
                ..
            }
        ));
        assert_eq!(
            encode(&Frame::PushRegisterAck {
                ok: true,
                detail: None,
            })
            .unwrap()[0],
            35,
            "PushRegisterAck must stay at index 35"
        );
    }

    #[test]
    fn revocation_frames_are_appended_and_generation_bound() {
        assert_eq!(
            encode(&Frame::UnpairSelf {
                request_id: 7,
                pair_id: [1; 16],
            })
            .unwrap()[0],
            36
        );
        assert_eq!(
            encode(&Frame::UnpairResult {
                request_id: 7,
                pair_id: [1; 16],
                committed: true,
                detail: None,
            })
            .unwrap()[0],
            37
        );
        let revoked = Frame::PairRevoked {
            pair_id: [1; 16],
            event_id: [2; 16],
        };
        let bytes = encode(&revoked).unwrap();
        assert_eq!(bytes[0], 38);
        assert!(matches!(
            decode(&bytes).unwrap(),
            Frame::PairRevoked { pair_id, .. } if pair_id == [1; 16]
        ));
    }

    /// `Frame` must never print its payloads. One `tracing::debug!(?frame)` in
    /// this repo or a fork would otherwise write keystrokes, terminal output, or
    /// file contents into a log file.
    #[test]
    fn frame_debug_redacts_every_payload() {
        let secrets: &[(Frame, &str)] = &[
            (
                Frame::Input {
                    id: SessionId(1),
                    bytes: b"sudo hunter2".to_vec(),
                },
                "hunter2",
            ),
            (
                Frame::Output {
                    id: SessionId(1),
                    bytes: b"BEGIN PRIVATE KEY".to_vec(),
                },
                "PRIVATE KEY",
            ),
            (
                Frame::SequencedOutput {
                    id: SessionId(1),
                    seq: 4,
                    bytes: b"ssh-rsa AAAA".to_vec(),
                },
                "ssh-rsa",
            ),
            (
                Frame::FileChunk {
                    id: TransferId(1),
                    seq: 0,
                    bytes: b"AWS_SECRET_ACCESS_KEY=x".to_vec(),
                },
                "AWS_SECRET",
            ),
            (
                Frame::PushRegister {
                    provider: PushProvider::Apns,
                    token: "apns-device-token".into(),
                    sealed_wake_blob: vec![7; 8],
                },
                "apns-device-token",
            ),
            (
                Frame::FileGetReq {
                    id: TransferId(1),
                    path: "/home/u/.ssh/id_ed25519".into(),
                    start_seq: 0,
                    allow_outside_home: true,
                },
                "id_ed25519",
            ),
            (
                Frame::RenameSession {
                    id: SessionId(1),
                    title: "customer-db-prod".into(),
                },
                "customer-db-prod",
            ),
            (
                Frame::CommandError {
                    message: "/etc/shadow: permission denied".into(),
                },
                "shadow",
            ),
        ];
        for (frame, leaked) in secrets {
            let rendered = format!("{frame:?}");
            assert!(
                !rendered.contains(leaked),
                "Debug leaked {leaked:?}: {rendered}"
            );
        }

        // Structure IS kept - that is what makes the logs worth having.
        assert_eq!(
            format!(
                "{:?}",
                Frame::Input {
                    id: SessionId(9),
                    bytes: vec![0; 12]
                }
            ),
            "Input { id: SessionId(9), bytes: 12 bytes }"
        );
        assert_eq!(format!("{:?}", Frame::Detach), "Detach");
    }
}
