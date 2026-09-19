//! PTY session manager.
//!
//! The host owns N terminal sessions as first-class objects. A session has one
//! of two backends:
//!   - **Pty** - the host spawned the shell and owns the PTY (the classic path).
//!   - **Adopted** - a `portty` relay in ANOTHER process owns the PTY; the host
//!     proxies input/resize/kill to it over the local relay pipe and receives
//!     its output. This is how "run `portty share` in any terminal" works.
//!
//! Either way the manager is **transport-agnostic** and NEVER parses terminal
//! bytes - it is a dumb byte pipe (terminal byte-pipe rule). The local proof wires it
//! to a WebSocket (main.rs); the iroh pipe wires it to `Transport<Frame>`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use agent_client_protocol as acp;
use agent_client_protocol::schema::v1::{
    AuthenticateRequest, BooleanConfigOptionCapabilities, CancelNotification, ClientCapabilities,
    ClientSessionCapabilities, ContentBlock, CreateTerminalRequest, CreateTerminalResponse,
    FileSystemCapabilities, Implementation, InitializeRequest, KillTerminalRequest,
    KillTerminalResponse, ListSessionsRequest, LoadSessionRequest, NewSessionResponse,
    PermissionOptionKind as AcpPermissionOptionKind, PlanEntryStatus as AcpPlanEntryStatus,
    PromptRequest, ReadTextFileRequest, ReadTextFileResponse, ReleaseTerminalRequest,
    ReleaseTerminalResponse, RequestPermissionOutcome, RequestPermissionRequest,
    RequestPermissionResponse, ResumeSessionRequest, SelectedPermissionOutcome, SessionConfigKind,
    SessionConfigOption as AcpSessionConfigOption, SessionConfigOptionCategory,
    SessionConfigOptionValue, SessionConfigOptionsCapabilities, SessionConfigSelectOptions,
    SessionModeState, SessionNotification, SessionUpdate, SetSessionConfigOptionRequest,
    SetSessionModeRequest, TerminalExitStatus, TerminalOutputRequest, TerminalOutputResponse,
    ToolCallStatus as AcpToolCallStatus, ToolKind as AcpToolKind, WaitForTerminalExitRequest,
    WaitForTerminalExitResponse, WriteTextFileRequest, WriteTextFileResponse,
};
use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::{AcpAgent, AcpAgentConfig};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, OwnedSemaphorePermit, Semaphore};

use portty_protocol::relay::HostToRelay;
use portty_protocol::{
    AgentAuthMethod, AgentCommand, AgentConfigChoice, AgentConfigOption, AgentConfigValue,
    AgentEvent, AgentMode, AgentPlanEntry, AgentPlanStatus, AgentProvider,
    AgentProviderAvailability, AgentSessionSummary, AgentTimelineEvent, AgentToolKind,
    AgentToolStatus, PermissionCategory, PermissionOption, PermissionOptionKind,
    PermissionResolution, PermissionResolver, SessionId, SessionInfo, SessionKind, SessionSource,
    ToolCallCard, WorkspaceScope,
};

/// Default cap per-session scrollback. 256 KiB gives a phone coming online
/// several thousand lines of catch-up (e.g. the tail of a training run) while
/// staying cheap even with many sessions (64 × 256 KiB = 16 MiB worst case).
/// Override at runtime with `PORTTY_SCROLLBACK_BYTES` (clamped to 4 KiB..4 MiB).
pub const DEFAULT_SCROLLBACK_BYTES: usize = 256 * 1024;

/// Read the per-session scrollback cap from `PORTTY_SCROLLBACK_BYTES`, clamped
/// to a sane 4 KiB..4 MiB window; defaults to 256 KiB. Snapshots are CHUNKED
/// into multiple wire frames on attach (see `SNAPSHOT_CHUNK_BYTES` in
/// iroh_serve), so the cap is no longer bound to MAX_FRAME_BYTES - the upper
/// bound is purely a RAM guard. Read once.
pub fn scrollback_cap_from_env() -> usize {
    const MIN: usize = 4 * 1024;
    const MAX: usize = 4 * 1024 * 1024;
    std::env::var("PORTTY_SCROLLBACK_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(MIN, MAX))
        .unwrap_or(DEFAULT_SCROLLBACK_BYTES)
}

/// Hard cap on concurrent sessions. Each session preallocates a scrollback ring
/// and spawns tasks/a process, so an unbounded count is a resource-exhaustion
/// vector: a paired client could otherwise create PTYs until the host falls
/// over. Override with `PORTTY_MAX_SESSIONS` (clamped 1..1024). Read per-spawn.
pub const DEFAULT_MAX_SESSIONS: usize = 64;

fn max_sessions() -> usize {
    std::env::var("PORTTY_MAX_SESSIONS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(1, 1024))
        .unwrap_or(DEFAULT_MAX_SESSIONS)
}

/// Cap on a session title's length (bytes). A client sets titles freely
/// (spawn/rename), so bound them to keep the session list small and bounded.
const MAX_TITLE_BYTES: usize = 256;

/// Agent history is replayed on attach just like terminal scrollback, but as
/// structured cards. Bound it independently so a verbose model cannot grow the
/// daemon forever while the phone is asleep.
const MAX_AGENT_HISTORY_BYTES: usize = 512 * 1024;
const MAX_AGENT_EVENT_TEXT_BYTES: usize = 64 * 1024;
const MAX_AGENT_PROMPT_BYTES: usize = 64 * 1024;
const AGENT_PROMPT_QUEUE: usize = 16;
const MAX_AGENT_SHORT_TEXT_BYTES: usize = 1024;
const MAX_AGENT_PLAN_ENTRIES: usize = 64;
const MAX_AGENT_COMMANDS: usize = 32;
const MAX_AGENT_MODES: usize = 32;
const MAX_AGENT_CONFIG_OPTIONS: usize = 16;
/// Per option, not shared: a provider-rich model list must not starve the
/// mode picker after it.
const MAX_AGENT_CONFIG_CHOICES: usize = 64;
const MAX_AGENT_AUTH_METHODS: usize = 8;
const MAX_PERMISSION_OPTIONS: usize = 32;
const MAX_ACP_TEXT_FILE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_ACP_TERMINAL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_ACP_TERMINAL_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACP_TERMINALS: usize = 32;
const ACP_EVENT_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
const ACP_EVENT_SEGMENTS: u64 = 8;
/// Host-wide disk ceiling for raw ACP diagnostics. Per-session rotation alone
/// allowed the default 64 sessions to retain 2 GiB (64 * 8 * 4 MiB). The
/// janitor reserves one segment for every live logger, then removes the oldest
/// closed segments across every session so normal operation stays within this
/// single 256 MiB budget.
const ACP_EVENT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ACP_CACHE_BYTES: usize = 8 * 1024 * 1024;
const LEGACY_MODEL_CONFIG_ID: &str = "portty.legacy_model";

/// Whole budget for one ACP `session/list` probe, adapter launch included.
///
/// The probe starts a real adapter process, and some of them are `npx`
/// shims that resolve a package before saying a word. The phone is waiting on a
/// folder tap, so the answer is bounded rather than correct-eventually: past this
/// the probe is abandoned and the picker shows Portty's own cache alone.
const ACP_SESSION_LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
/// Pages of `session/list` to follow. `nextCursor` is the agent's to hand out and
/// the spec asks clients to treat it as opaque, which means a buggy or hostile
/// adapter can hand back a cycle of them - so the walk is bounded by count, not
/// by trusting the agent to terminate it.
const MAX_ACP_SESSION_LIST_PAGES: usize = 8;
/// Conversations offered for one directory. The picker is a list you thumb
/// through on a phone; past this it is an archive, and an archive needs search,
/// not a longer list.
const MAX_LISTED_AGENT_SESSIONS: usize = 50;
/// How long one probe's answer is reused for the same provider and directory.
///
/// The picker is navigated, not read once: up, into a sibling, back. Without
/// this, every one of those taps launches the agent's adapter again to be told
/// the same thing, which is both slow for the person tapping and a way for a
/// paired phone to keep the host spawning processes. Short enough that a chat
/// you just started shows up when you back out to look for it.
const ACP_SESSION_LIST_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// Directories whose probe answers are held at once. Small: this exists to make
/// backtracking cheap, not to be an offline index.
const MAX_MEMOIZED_PROBES: usize = 8;
/// How long a listing waits for the one probe slot before answering from the
/// cache alone.
///
/// Probes are serialized, so without a bound the queue is unbounded in both depth
/// and time: taps on several folders each wait out the ones ahead, and the phone
/// gives up on its own budget long before the host stops launching adapters for
/// answers nobody is still reading. Kept well inside that budget so a queued
/// listing degrades to a short answer rather than to a timeout.
const ACP_PROBE_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Conversations remembered from probes so `ResumeAgentSession` can look one up.
/// Deliberately larger than one listing (you browse several folders before you
/// tap) and deliberately in RAM: these are things the AGENT persists, and Portty
/// mirroring them to disk would be a second copy to keep honest and to leak.
const MAX_DISCOVERED_ACP_SESSIONS: usize = 256;

/// Fixed birth size for daemon-owned PTYs (fixed-size model). Viewers never
/// resize a session; the phone's match-width mode follows THIS size instead
/// (`Frame::SessionSize`). 160×48 keeps a desktop-comfortable width while a
/// phone in landscape can still render it at a readable font. Override with
/// `PORTTY_PTY_COLS` / `PORTTY_PTY_ROWS` (clamped to sane terminal bounds).
pub const DEFAULT_PTY_COLS: u16 = 160;
pub const DEFAULT_PTY_ROWS: u16 = 48;

/// The daemon's fixed PTY size, from env or the defaults above. Read per-spawn.
pub fn fixed_pty_size() -> (u16, u16) {
    let read = |var: &str, default: u16, min: u16, max: u16| {
        std::env::var(var)
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .map(|n| n.clamp(min, max))
            .unwrap_or(default)
    };
    (
        read("PORTTY_PTY_COLS", DEFAULT_PTY_COLS, 20, 500),
        read("PORTTY_PTY_ROWS", DEFAULT_PTY_ROWS, 10, 200),
    )
}

/// Bounded depth of the per-adopted-session control channel (host → relay:
/// Input/Resize/Kill). Bounded rather than unbounded so a stalled relay can't
/// let control messages accumulate without limit; these are human-paced, so the
/// queue effectively never fills against a live relay (drop-on-full otherwise).
pub const ADOPTED_CTRL_QUEUE: usize = 1024;

/// Truncate a title to `MAX_TITLE_BYTES` on a UTF-8 char boundary.
fn clamp_title(mut title: String) -> String {
    if title.len() > MAX_TITLE_BYTES {
        let mut end = MAX_TITLE_BYTES;
        while !title.is_char_boundary(end) {
            end -= 1;
        }
        title.truncate(end);
    }
    title
}

/// Async notifications about the session SET changing (not per-byte output).
/// The WebSocket layer forwards these so the client list stays live.
#[derive(Debug, Clone)]
pub enum ManagerEvent {
    Added(SessionInfo),
    Removed(SessionId),
    Activity(SessionId),
    /// An agent (ACP) session needs the user to approve an action. The transport
    /// layer turns this into a `Frame::RequestPermission` for the phone.
    AgentPermission {
        id: SessionId,
        tool_call: ToolCallCard,
        options: Vec<PermissionOption>,
        category: PermissionCategory,
        /// How broad this session's ACP sandbox root is. Travels WITH the card
        /// rather than being looked up when the frame is built, so the value the
        /// phone judges by is the one that was in force when the agent asked.
        workspace_scope: WorkspaceScope,
    },
    /// One normalized ACP update. The transport only forwards this for the
    /// actively viewed session; the bounded history is replayed on attach.
    AgentTimeline {
        id: SessionId,
        event: AgentTimelineEvent,
    },
    /// The session's authoritative PTY size changed (an adopted session's
    /// laptop terminal was resized, or the local-proof browser resized a
    /// session). The transport layer forwards it as `Frame::SessionSize` so a
    /// phone in match-width mode follows.
    Resized {
        id: SessionId,
        cols: u16,
        rows: u16,
    },
    /// A pending approval was answered by SOME viewer (phone tap or laptop
    /// `portty agent` keypress). Every other viewer dismisses its card.
    /// `resolution`/`by` let the phone show what happened and who answered.
    AgentPermissionResolved {
        id: SessionId,
        tool_call_id: String,
        resolution: PermissionResolution,
        by: PermissionResolver,
    },
}

pub struct Session {
    id: SessionId,
    inner: Arc<SessionInner>,
}

#[derive(Debug)]
pub struct OutputChunk {
    pub seq: u64,
    pub bytes: Arc<Vec<u8>>,
}

/// `delta_since_and_subscribe` result: the retained chunks strictly after the
/// requested boundary, the checkpoint seq they run through, and the live
/// receiver obtained under the same lock (no gap, no duplication).
pub type OutputDelta = (
    Vec<Arc<OutputChunk>>,
    u64,
    broadcast::Receiver<Arc<OutputChunk>>,
);

/// How a session's I/O is backed.
enum Backend {
    /// The host spawned the shell and owns the PTY.
    Pty {
        /// Kept alive so `resize` works from any thread, and `take`n by `kill` to
        /// close the PTY.
        ///
        /// `Option` because closing it is the ONLY thing that unblocks the
        /// blocking reader on Windows. Killing the child is enough on Unix - the
        /// slave is already dropped, so the master reader sees EOF - but a
        /// ConPTY stays open until the master handle goes, since conhost holds
        /// the pipe regardless of whether the child is alive. Measured: after
        /// `child.kill()` the reader was still blocked 8s later, and returned
        /// the instant the master dropped. That deadlocked `kill`: the reader
        /// waits for EOF, EOF needs the master dropped, and the master was held
        /// by the `Arc<SessionInner>` that the reader task itself owns.
        master: StdMutex<Option<Box<dyn portable_pty::MasterPty + Send>>>,
        writer: StdMutex<Box<dyn std::io::Write + Send>>,
        child: StdMutex<Option<Box<dyn portable_pty::Child + Send + Sync>>>,
    },
    /// A `portty` relay owns the PTY in its own process; proxy control to it.
    Adopted { to_relay: mpsc::Sender<HostToRelay> },
    /// An ACP agent session (the ceiling). `handle` holds the pending-permission
    /// map and the prompt channel, shared with the ACP driver task.
    Acp { handle: Arc<AcpHandle> },
}

/// Live state for an ACP agent session, shared between the driver task (runs the
/// ACP connection) and the manager (routes phone decisions in).
struct AcpHandle {
    /// Pending `session/request_permission`s keyed by tool_call_id. The oneshot
    /// resolves `Some(option_id)` (approve) or `None` (cancel) when the phone
    /// replies. StdMutex: the section is a tiny map op and is NEVER held across
    /// an await - the driver awaits the receiver after inserting + dropping the guard.
    pending: StdMutex<HashMap<String, PendingAgentPermission>>,
    /// User/control commands inbound from phones and laptop clients.
    command_tx: mpsc::Sender<AcpCommand>,
    /// Bounded structured replay for phone attach/resume.
    history: StdMutex<AgentHistory>,
    next_seq: AtomicU64,
    /// Killing an agent session must also stop the ACP process/driver, not just
    /// hide its registry entry.
    driver: StdMutex<Option<tokio::task::AbortHandle>>,
    /// The agent-side ACP session id this driver currently owns. Spawning
    /// consults it so two live Portty sessions never resume the same ACP
    /// conversation and cross-wire their feeds.
    acp_session_id: StdMutex<Option<String>>,
    /// How broad THIS session's sandbox root is, fixed when the session was
    /// created. Per-session rather than host-wide because the phone's directory
    /// picker can narrow the root, and a session started in `~/code/app` deserves
    /// a different answer from one started in `~`. Reported on every approval
    /// card so the phone can refuse blanket read approval inside a broad root.
    workspace_scope: WorkspaceScope,
}

#[derive(Default)]
struct AgentHistory {
    events: VecDeque<AgentTimelineEvent>,
    /// Reducer-style updates must survive history pruning so late attachers
    /// always receive commands/mode/config/title/auth state.
    sticky: HashMap<StickyAgentEvent, AgentTimelineEvent>,
    bytes: usize,
}

impl AgentHistory {
    fn push(&mut self, event: AgentTimelineEvent) {
        self.bytes = self.bytes.saturating_add(agent_event_size(&event));
        // Clone only for the rare sticky kinds - message/thought chunks are
        // the hot path and carry the payload text.
        if let Some(kind) = sticky_agent_event(&event.event) {
            self.sticky.insert(kind, event.clone());
        }
        self.events.push_back(event);
        while self.bytes > MAX_AGENT_HISTORY_BYTES && self.events.len() > 1 {
            if let Some(old) = self.events.pop_front() {
                self.bytes = self.bytes.saturating_sub(agent_event_size(&old));
            }
        }
    }

    fn snapshot(&self) -> Vec<AgentTimelineEvent> {
        let mut events: Vec<_> = self.events.iter().cloned().collect();
        for event in self.sticky.values() {
            if !events.iter().any(|candidate| candidate.seq == event.seq) {
                events.push(event.clone());
            }
        }
        events.sort_by_key(|event| event.seq);
        events
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum StickyAgentEvent {
    Commands,
    Mode,
    Config,
    SessionInfo,
    Replaying,
    Auth,
    Usage,
}

enum AcpCommand {
    Prompt(String),
    Cancel,
    SetMode {
        mode_id: String,
        response: Option<oneshot::Sender<Result<(), String>>>,
    },
    SetConfig {
        config_id: String,
        value: AgentConfigValue,
        response: Option<oneshot::Sender<Result<(), String>>>,
    },
    Authenticate(String),
}

impl AcpCommand {
    fn take_responder(&mut self) -> Option<oneshot::Sender<Result<(), String>>> {
        match self {
            AcpCommand::SetMode { response, .. } | AcpCommand::SetConfig { response, .. } => {
                response.take()
            }
            _ => None,
        }
    }
}

struct AcpTerminals {
    workspace: PathBuf,
    next_id: AtomicU64,
    active: StdMutex<HashMap<String, Arc<AcpTerminal>>>,
    /// Includes released terminals so session teardown can still stop them.
    controls: StdMutex<Vec<mpsc::Sender<TerminalControl>>>,
}

struct AcpTerminal {
    state: StdMutex<AcpTerminalState>,
    changed: tokio::sync::Notify,
    control: mpsc::Sender<TerminalControl>,
}

#[derive(Default)]
struct AcpTerminalState {
    output: String,
    truncated: bool,
    output_limit: usize,
    exit_status: Option<TerminalExitStatus>,
}

enum TerminalControl {
    Kill,
}

struct AcpEventLogger {
    dir: PathBuf,
    segment: u64,
    bytes: u64,
    file: Option<std::io::BufWriter<std::fs::File>>,
    active_path: Option<PathBuf>,
}

/// Paths with an open writer in this process. The janitor holds this mutex
/// while enumerating/removing files so it never unlinks another live session's
/// current segment (which is especially important on Unix, where that would
/// otherwise succeed while the writer kept appending to an invisible inode).
static ACTIVE_ACP_EVENT_LOGS: OnceLock<StdMutex<HashSet<PathBuf>>> = OnceLock::new();

type AcpDebugCallback = Arc<dyn Fn(&str, acp::LineDirection) + Send + Sync + 'static>;

struct TrackedAcpAgent {
    agent: AcpAgent,
    closed: tokio::sync::watch::Sender<bool>,
    debug: Option<AcpDebugCallback>,
}

impl acp::ConnectTo<acp::Client> for TrackedAcpAgent {
    async fn connect_to(self, client: impl acp::ConnectTo<acp::Agent>) -> acp::Result<()> {
        let result = connect_tracked_acp_process(self.agent, self.debug, client).await;
        let _ = self.closed.send(true);
        result
    }
}

/// ACP's stock subprocess guard uses SIGKILL immediately. Portty instead gives
/// an adapter a five-second window to flush and tear down before escalating to a
/// hard kill. On Unix we nudge it with SIGTERM; on Windows (no SIGTERM) the
/// window lets the adapter notice its stdio pipes closed (EOF) and exit on its
/// own. Either way a well-behaved adapter exits promptly and the wait returns
/// early - only a hung adapter waits the full five seconds.
struct GracefulAcpChild(Option<async_process::Child>);

struct ForceKillAcpChild(Option<async_process::Child>);

impl Drop for ForceKillAcpChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
        }
    }
}

impl GracefulAcpChild {
    async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let result = self
            .0
            .as_mut()
            .expect("child is present while waiting")
            .status()
            .await;
        if result.is_ok() {
            self.0.take();
        }
        result
    }
}

impl Drop for GracefulAcpChild {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        #[cfg(unix)]
        {
            let pid = child.id();
            // SAFETY: pid comes from this live Child. Failure means it already
            // exited; status() below reaps it either way.
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(reap_acp_child_after_grace(child));
            } else {
                let _ = child.kill();
            }
        }
        #[cfg(not(unix))]
        {
            // No SIGTERM on Windows; the reaper's grace window lets the adapter
            // exit on stdio EOF (its pipes close as this guard drops) before we
            // force-kill (#47), instead of the previous immediate kill.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(reap_acp_child_after_grace(child));
            } else {
                let _ = child.kill();
            }
        }
    }
}

async fn reap_acp_child_after_grace(child: async_process::Child) {
    let mut child = ForceKillAcpChild(Some(child));
    let exited = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        child.0.as_mut().expect("guard owns child").status(),
    )
    .await;
    if !matches!(exited, Ok(Ok(_))) {
        let process = child.0.as_mut().expect("guard owns child");
        let _ = process.kill();
        let _ = process.status().await;
    }
    // A completed/reaped child no longer needs the force-kill drop guard.
    child.0.take();
}

async fn connect_tracked_acp_process(
    agent: AcpAgent,
    debug: Option<AcpDebugCallback>,
    client: impl acp::ConnectTo<acp::Agent>,
) -> acp::Result<()> {
    use futures_util::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use futures_util::StreamExt as _;

    let (child_stdin, child_stdout, child_stderr, child) = agent.spawn_process()?;
    let (stderr_tx, stderr_rx) = tokio::sync::oneshot::channel::<String>();

    let stderr_debug = debug.clone();
    let stderr_future = async move {
        let mut lines = BufReader::new(child_stderr).lines();
        let mut collected = String::new();
        while let Some(result) = lines.next().await {
            if let Ok(line) = result {
                if let Some(callback) = &stderr_debug {
                    callback(&line, acp::LineDirection::Stderr);
                }
                if collected.len() < MAX_AGENT_EVENT_TEXT_BYTES {
                    if !collected.is_empty() {
                        collected.push('\n');
                    }
                    collected.push_str(&line);
                    collected = clamp_agent_text(collected);
                }
            }
        }
        let _ = stderr_tx.send(collected);
    };

    let incoming: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = std::io::Result<String>> + Send>,
    > = if let Some(callback) = debug.clone() {
        Box::pin(BufReader::new(child_stdout).lines().inspect(move |result| {
            if let Ok(line) = result {
                callback(line, acp::LineDirection::Stdout);
            }
        }))
    } else {
        Box::pin(BufReader::new(child_stdout).lines())
    };

    let outgoing: std::pin::Pin<
        Box<dyn futures_util::Sink<String, Error = std::io::Error> + Send>,
    > = if let Some(callback) = debug {
        Box::pin(futures_util::sink::unfold(
            (child_stdin, callback),
            async move |(mut writer, callback), line: String| {
                callback(&line, acp::LineDirection::Stdin);
                let mut bytes = line.into_bytes();
                bytes.push(b'\n');
                writer.write_all(&bytes).await?;
                Ok::<_, std::io::Error>((writer, callback))
            },
        ))
    } else {
        Box::pin(futures_util::sink::unfold(
            child_stdin,
            async move |mut writer, line: String| {
                let mut bytes = line.into_bytes();
                bytes.push(b'\n');
                writer.write_all(&bytes).await?;
                Ok::<_, std::io::Error>(writer)
            },
        ))
    };

    let protocol =
        acp::ConnectTo::<acp::Client>::connect_to(acp::Lines::new(outgoing, incoming), client);
    let child_monitor = monitor_acp_child(GracefulAcpChild(Some(child)), stderr_rx);
    let main_race = async {
        match futures_util::future::select(Box::pin(protocol), Box::pin(child_monitor)).await {
            futures_util::future::Either::Left((result, _))
            | futures_util::future::Either::Right((result, _)) => result,
        }
    };
    match futures_util::future::select(Box::pin(main_race), Box::pin(stderr_future)).await {
        futures_util::future::Either::Left((result, _)) => result,
        futures_util::future::Either::Right(((), protocol)) => protocol.await,
    }
}

async fn monitor_acp_child(
    mut child: GracefulAcpChild,
    stderr_rx: tokio::sync::oneshot::Receiver<String>,
) -> acp::Result<()> {
    let status = child
        .wait()
        .await
        .map_err(acp::Error::into_internal_error)?;
    if status.success() {
        return Ok(());
    }
    let stderr = stderr_rx.await.unwrap_or_default();
    let message = if stderr.is_empty() {
        format!("ACP adapter exited with {status}")
    } else {
        format!("ACP adapter exited with {status}: {stderr}")
    };
    Err(acp::Error::internal_error().data(message))
}

/// Which conversation a spawn should adopt.
///
/// Replaces a `fresh: bool`, which could not express "continue THIS one" and
/// would have needed a second `Option` beside it - a pair that can encode the
/// nonsense state "fresh, but also resume something".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentResume {
    /// Continue whichever conversation in this directory was most recent.
    Latest,
    /// Start a brand-new conversation, ignoring the cache.
    Fresh,
    /// Continue one specific conversation the phone picked.
    Session(String),
}

/// A conversation the AGENT remembers, learned from an ACP `session/list` probe
/// rather than from Portty's own resume cache.
///
/// Not serde: this never reaches disk. It exists so `ResumeAgentSession` can
/// recover the provider for an id the phone tapped, and the provider must keep
/// coming from a record the HOST wrote - the phone naming it is exactly the
/// mix-up `resume_agent_session` refuses to allow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscoveredAcpSession {
    provider: AgentProvider,
    cwd: PathBuf,
    acp_session_id: String,
    title: String,
    /// `None` when the agent reported no usable timestamp - which the phone
    /// renders as "no time" rather than as 1970.
    last_active_at_unix_ms: Option<u64>,
}

/// Bounded FIFO of conversations seen in probes, so a resume can look one up.
///
/// A miss is not a failure mode worth engineering around: the phone always lists
/// before it resumes, so the only way to miss is a host restart in between, and
/// the answer to that ("re-open the picker") is one tap.
#[derive(Debug, Default)]
struct DiscoveredAcpSessions(VecDeque<DiscoveredAcpSession>);

impl DiscoveredAcpSessions {
    /// Keyed by PROVIDER as well as directory and id. Two agents inventing the
    /// same id string in one folder is unlikely, but the entry's whole job is to
    /// say which agent owns the conversation - keying it on less than that would
    /// let a later listing overwrite the answer with a different agent's.
    fn remember(&mut self, sessions: &[DiscoveredAcpSession]) {
        for session in sessions {
            self.0.retain(|entry| {
                !(entry.provider == session.provider
                    && entry.cwd == session.cwd
                    && entry.acp_session_id == session.acp_session_id)
            });
            self.0.push_back(session.clone());
        }
        while self.0.len() > MAX_DISCOVERED_ACP_SESSIONS {
            self.0.pop_front();
        }
    }

    /// Matched on BOTH cwd and id, exactly like the on-disk cache: the phone
    /// names an id, the workspace resolver supplies the directory.
    ///
    /// Ambiguity resolves to nothing. If two providers really did report the same
    /// id here there is no way to tell which one the tap meant, and starting the
    /// wrong agent against someone else's conversation is worse than the phone
    /// being told the conversation is no longer saved.
    fn find(&self, cwd: &std::path::Path, acp_session_id: &str) -> Option<&DiscoveredAcpSession> {
        let mut matches = self
            .0
            .iter()
            .filter(|entry| entry.cwd == cwd && entry.acp_session_id == acp_session_id);
        let first = matches.next()?;
        match matches.any(|other| other.provider != first.provider) {
            true => None,
            false => Some(first),
        }
    }
}

/// One provider's recent answer for one directory, so backtracking through the
/// folder picker does not relaunch its adapter (see [`ACP_SESSION_LIST_TTL`]).
#[derive(Debug, Clone)]
struct ProbeMemo {
    provider: AgentProvider,
    cwd: PathBuf,
    taken_at: std::time::Instant,
    sessions: Vec<DiscoveredAcpSession>,
}

#[derive(Debug, Default)]
struct ProbeMemos(VecDeque<ProbeMemo>);

impl ProbeMemos {
    fn get(
        &self,
        provider: AgentProvider,
        cwd: &std::path::Path,
        now: std::time::Instant,
    ) -> Option<Vec<DiscoveredAcpSession>> {
        self.0
            .iter()
            .find(|memo| {
                memo.provider == provider
                    && memo.cwd == cwd
                    && now.duration_since(memo.taken_at) < ACP_SESSION_LIST_TTL
            })
            .map(|memo| memo.sessions.clone())
    }

    fn store(&mut self, memo: ProbeMemo) {
        self.0
            .retain(|entry| !(entry.provider == memo.provider && entry.cwd == memo.cwd));
        self.0.push_back(memo);
        while self.0.len() > MAX_MEMOIZED_PROBES {
            self.0.pop_front();
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedAcpSession {
    provider: AgentProvider,
    cwd: PathBuf,
    acp_session_id: String,
    title: String,
    first_prompt_label: Option<String>,
    last_active_at_unix_ms: u64,
    desired_mode: Option<String>,
    desired_config: HashMap<String, AgentConfigValue>,
}

/// Compatibility envelope for pre-config-options ACP agents. The current 1.x
/// schema intentionally removed `models`, so Portty captures that optional
/// legacy field without downgrading the rest of the SDK.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, acp::JsonRpcRequest)]
#[request(
    method = "session/new",
    response = CompatibleNewSessionResponse,
    crate = acp
)]
#[serde(rename_all = "camelCase")]
struct CompatibleNewSessionRequest {
    cwd: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional_directories: Vec<PathBuf>,
    mcp_servers: Vec<serde_json::Value>,
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    meta: Option<serde_json::Value>,
}

impl CompatibleNewSessionRequest {
    fn new(cwd: &std::path::Path) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            additional_directories: Vec::new(),
            mcp_servers: Vec::new(),
            meta: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, acp::JsonRpcResponse)]
#[response(crate = acp)]
#[serde(rename_all = "camelCase")]
struct CompatibleNewSessionResponse {
    #[serde(flatten)]
    current: NewSessionResponse,
    #[serde(default)]
    models: Option<LegacyModelState>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyModelState {
    current_model_id: String,
    #[serde(default)]
    available_models: Vec<LegacyModelInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyModelInfo {
    model_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, acp::JsonRpcRequest)]
#[request(
    method = "session/set_model",
    response = LegacySetSessionModelResponse,
    crate = acp
)]
#[serde(rename_all = "camelCase")]
struct LegacySetSessionModelRequest {
    session_id: acp::schema::v1::SessionId,
    model_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, acp::JsonRpcResponse)]
#[response(crate = acp)]
struct LegacySetSessionModelResponse {}

struct AcpBootstrap {
    session_id: acp::schema::v1::SessionId,
    modes: Option<SessionModeState>,
    config_options: Option<Vec<AcpSessionConfigOption>>,
    legacy_models: Option<LegacyModelState>,
}

/// The two ACP ways to reopen an existing conversation.
///
/// They differ in one respect that matters to a phone: `session/load` replays the
/// transcript as `session/update` notifications, `session/resume` does not. Both
/// restore the agent's context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcpReopen {
    /// `session/load` - restores context AND replays the transcript.
    Load,
    /// `session/resume` - restores context only.
    Resume,
}

impl AcpReopen {
    fn supported(self, capabilities: &acp::schema::v1::AgentCapabilities) -> bool {
        match self {
            Self::Load => capabilities.load_session,
            Self::Resume => capabilities.session_capabilities.resume.is_some(),
        }
    }
}

/// Which reopen call to try first, given whether this driver has already replayed.
///
/// **The trap this exists to name.** The obvious input here is "is the timeline
/// empty" - and it is wrong. `spawn_agent_provider` pushes a `SessionStarted`
/// card into history before the driver task is spawned, and that card is not
/// sticky, so an emptiness test reads `false` on the first connect of every
/// provider-backed session. Wiring the order to it silently disables the replay
/// in production while still passing on the provider-less test spawn - which is
/// exactly how it shipped broken once. Ask about replaying, not about the
/// timeline.
fn acp_reopen_order(replayed: bool) -> [AcpReopen; 2] {
    if replayed {
        // The phone already holds every card, and replayed copies arrive with
        // fresh seqs it cannot dedupe.
        [AcpReopen::Resume, AcpReopen::Load]
    } else {
        // The only way a conversation the LAPTOP started ever reaches the phone.
        [AcpReopen::Load, AcpReopen::Resume]
    }
}

/// What either reopen call tells the driver. The two responses are distinct
/// types carrying the same two fields Portty reads.
struct AcpReopenResponse {
    modes: Option<SessionModeState>,
    config_options: Option<Vec<AcpSessionConfigOption>>,
}

static ACP_CACHE_LOCK: std::sync::OnceLock<StdMutex<()>> = std::sync::OnceLock::new();
const MAX_CACHED_ACP_SESSIONS: usize = 64;

struct PendingAgentPermission {
    responder: oneshot::Sender<Option<String>>,
    tool_call: ToolCallCard,
    options: Vec<PermissionOption>,
    category: PermissionCategory,
}

/// Seq-tagged scrollback ring. Chunk boundaries are preserved so a
/// reconnecting viewer can be served exactly the output after its last-seen
/// sequence number (`delta_since`) instead of a full reset + snapshot.
#[derive(Default)]
struct ScrollbackRing {
    chunks: VecDeque<Arc<OutputChunk>>,
    bytes: usize,
    /// Smallest seq from which the ring holds COMPLETE output onward. Usually
    /// the front chunk's seq; one greater when the front chunk had to be
    /// truncated to respect the byte cap (its remaining bytes are partial, so
    /// a delta may not start inside it).
    min_full_seq: u64,
}

impl ScrollbackRing {
    /// Append one broadcast chunk, then evict from the front to stay within
    /// `cap`. Whole chunks are evicted first; if a single oversized chunk still
    /// busts the cap (tiny caps), its front is trimmed and `min_full_seq`
    /// advances past it so `delta_since` stays truthful.
    fn push(&mut self, chunk: Arc<OutputChunk>, cap: usize) {
        self.bytes += chunk.bytes.len();
        self.chunks.push_back(chunk);
        while self.bytes > cap && self.chunks.len() > 1 {
            if let Some(old) = self.chunks.pop_front() {
                self.bytes -= old.bytes.len();
                self.min_full_seq = old.seq + 1;
            }
        }
        if self.bytes > cap {
            if let Some(front) = self.chunks.front_mut() {
                let excess = self.bytes - cap;
                let trimmed: Vec<u8> = front.bytes[excess..].to_vec();
                self.bytes -= excess;
                self.min_full_seq = front.seq + 1;
                *front = Arc::new(OutputChunk {
                    seq: front.seq,
                    bytes: Arc::new(trimmed),
                });
            }
        }
    }

    /// Every retained byte, oldest first (attach snapshots).
    fn concat(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bytes);
        for c in &self.chunks {
            out.extend_from_slice(&c.bytes);
        }
        out
    }

    /// Chunks strictly after `after_seq`, or `None` when that boundary has
    /// aged out of the ring (caller falls back to reset + full snapshot).
    fn since(&self, after_seq: u64) -> Option<Vec<Arc<OutputChunk>>> {
        if after_seq + 1 < self.min_full_seq {
            return None;
        }
        Some(
            self.chunks
                .iter()
                .filter(|c| c.seq > after_seq)
                .cloned()
                .collect(),
        )
    }
}

struct SessionInner {
    id: SessionId,
    title: StdMutex<String>,
    kind: SessionKind,
    source: SessionSource,
    /// Which coding-agent preset backs an ACP session (`None` for shells and
    /// the raw test spawn). Lets `portty agent <provider>` join the newest
    /// live session of the SAME provider instead of guessing by title.
    provider: Option<AgentProvider>,
    backend: Backend,
    scrollback: StdMutex<ScrollbackRing>,
    /// Per-session scrollback ring cap (bytes). Copied from the manager at spawn.
    cap: usize,
    output_tx: broadcast::Sender<Arc<OutputChunk>>,
    next_output_seq: AtomicU64,
    has_unseen_activity: AtomicBool,
    events_tx: broadcast::Sender<ManagerEvent>,
    /// The session's ONE authoritative PTY size (fixed-size model). Spawned
    /// sessions are born at the daemon's fixed size and stay there; adopted
    /// sessions follow the laptop terminal (`RelayToHost::SizeChanged`).
    /// Viewers never drive it - the phone's match-width mode follows it via
    /// `Frame::SessionSize`.
    size: StdMutex<(u16, u16)>,
}

impl SessionInner {
    /// Feed program output into scrollback ring + broadcast + activity flag.
    /// Shared by the local PTY reader and the adopted-session pipe reader.
    fn push_output(&self, bytes: &[u8]) {
        let chunk = Arc::new(OutputChunk {
            seq: self.next_output_seq.fetch_add(1, Ordering::Relaxed),
            bytes: Arc::new(bytes.to_vec()),
        });
        let was_unseen = {
            let mut sb = self.scrollback.lock().unwrap();
            // The ring shares the broadcast chunk's allocation; eviction is by
            // whole chunks (single drain-like pass, no per-byte pops).
            sb.push(chunk.clone(), self.cap);
            let was_unseen = self.has_unseen_activity.swap(true, Ordering::Relaxed);
            // Keep the same lock through publication. A subscriber that takes a
            // snapshot under this lock therefore sees the chunk in exactly one
            // place: either the snapshot or its new receiver, never both.
            let _ = self.output_tx.send(chunk);
            was_unseen
        };
        // Only fire an Activity event on the seen → unseen transition. A noisy
        // background build produces one blip until the user looks at it again,
        // instead of an event per output chunk (which floods the client link).
        if !was_unseen {
            let _ = self.events_tx.send(ManagerEvent::Activity(self.id));
        }
    }

    fn push_agent_event(&self, event: AgentEvent) {
        let Backend::Acp { handle } = &self.backend else {
            return;
        };
        let event = AgentTimelineEvent {
            seq: handle.next_seq.fetch_add(1, Ordering::Relaxed),
            event,
        };
        {
            let mut history = handle.history.lock().unwrap();
            history.push(event.clone());
        }
        let was_unseen = self.has_unseen_activity.swap(true, Ordering::Relaxed);
        let _ = self
            .events_tx
            .send(ManagerEvent::AgentTimeline { id: self.id, event });
        if !was_unseen {
            let _ = self.events_tx.send(ManagerEvent::Activity(self.id));
        }
    }
}

fn sticky_agent_event(event: &AgentEvent) -> Option<StickyAgentEvent> {
    match event {
        AgentEvent::AvailableCommands { .. } => Some(StickyAgentEvent::Commands),
        AgentEvent::ModeState { .. } => Some(StickyAgentEvent::Mode),
        AgentEvent::ConfigOptions { .. } => Some(StickyAgentEvent::Config),
        AgentEvent::SessionInfo { .. } => Some(StickyAgentEvent::SessionInfo),
        AgentEvent::Replaying { .. } => Some(StickyAgentEvent::Replaying),
        AgentEvent::AuthRequired { .. } => Some(StickyAgentEvent::Auth),
        AgentEvent::Usage { .. } => Some(StickyAgentEvent::Usage),
        _ => None,
    }
}

fn clamp_agent_text(mut text: String) -> String {
    if text.len() > MAX_AGENT_EVENT_TEXT_BYTES {
        const SUFFIX: &str = "\n… truncated by Portty …";
        let mut end = MAX_AGENT_EVENT_TEXT_BYTES.saturating_sub(SUFFIX.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(SUFFIX);
    }
    text
}

fn clamp_agent_short_text(mut text: String) -> String {
    if text.len() > MAX_AGENT_SHORT_TEXT_BYTES {
        const SUFFIX: &str = "…";
        let mut end = MAX_AGENT_SHORT_TEXT_BYTES.saturating_sub(SUFFIX.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(SUFFIX);
    }
    text
}

fn agent_event_size(event: &AgentTimelineEvent) -> usize {
    // Debug formatting allocates, but it over-counts postcard's compact
    // encoding (field names, quotes, escapes), which is exactly what a pruning
    // bound wants: the wire snapshot stays comfortably under the byte budget.
    32 + format!("{:?}", event.event).len()
}

/// Resolve `cmd` against `dirs`, returning the first candidate that exists.
///
/// Windows launchers ship as scripts (`npx` is `npx.cmd`), so the common
/// executable extensions are probed too. **Order is load-bearing:** npm installs
/// BOTH an extension-less Unix shim and a `.cmd` beside each other, and Windows
/// cannot execute the extension-less one - so real executables are tried first
/// and the bare name last (which is what matches a `cmd` that already carries
/// its own extension).
///
/// Split from `resolve_on_path` so the ordering is testable without mutating the
/// process-wide PATH.
fn resolve_in_dirs(cmd: &str, dirs: impl Iterator<Item = PathBuf>) -> Option<PathBuf> {
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".com", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    dirs.into_iter().find_map(|dir| {
        exts.iter()
            .map(|ext| dir.join(format!("{cmd}{ext}")))
            .find(|candidate| candidate.is_file())
    })
}

/// Resolve `cmd` to a concrete path on the host's PATH.
fn resolve_on_path(cmd: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    resolve_in_dirs(
        cmd,
        std::env::split_paths(&paths)
            .collect::<Vec<_>>()
            .into_iter(),
    )
}

/// True when `cmd` resolves on the host's PATH.
fn command_on_path(cmd: &str) -> bool {
    resolve_on_path(cmd).is_some()
}

/// Opt-in launcher command for the Claude ACP adapter (see [`AdapterLaunch`]).
pub const CLAUDE_ADAPTER_SPEC_VAR: &str = "PORTTY_CLAUDE_ACP_COMMAND";
/// Opt-in launcher command for the Codex ACP adapter (see [`AdapterLaunch`]).
pub const CODEX_ADAPTER_SPEC_VAR: &str = "PORTTY_CODEX_ACP_COMMAND";

/// How to start one provider's ACP adapter, and what to tell the user when we
/// cannot.
///
/// **Why there is no built-in `npx` fallback.** Starting an agent is a request
/// from a paired phone, and the adapter runs unsandboxed as the host user with
/// the host's credentials. A silent `npx -y <pkg>@latest` fallback therefore let
/// a remote tap download and execute whatever that package publishes *next* - a
/// compromised release or registry account becomes host code execution, with no
/// review, no pinning, and nobody at the laptop. So a missing adapter is an
/// error, and the escape hatch is deliberately local and explicit: the laptop
/// owner sets the provider's env var to the exact command they vetted, e.g.
///
/// ```text
/// PORTTY_CODEX_ACP_COMMAND='npx -y @agentclientprotocol/codex-acp@0.4.1'
/// ```
struct AdapterLaunch {
    /// Executable that must resolve before we promise the phone a session.
    required: String,
    /// Remedy shown when `required` is missing.
    hint: String,
    /// Full launcher command, parsed by `acp_agent_from_spec`.
    spec: String,
    default_title: &'static str,
}

/// How a provider's adapter is resolved.
///
/// A seam, not a feature: in production this is always [`adapter_launch_for`].
/// Tests replace it because a provider otherwise resolves to whatever REAL
/// adapter is on the machine's PATH - so a test that drives the agent lifecycle
/// would launch Claude Code or Codex for real on any developer's machine that had
/// one installed. With the seam they point the provider at
/// `crates/acp-probe/mock_agent.py` and the same code path runs against a
/// deterministic fixture.
type AdapterResolver =
    Arc<dyn Fn(AgentProvider) -> crate::error::HostResult<AdapterLaunch> + Send + Sync>;

fn default_adapter_resolver() -> AdapterResolver {
    Arc::new(adapter_launch_for)
}

/// How each provider is launched.
///
/// Extracted so the availability check and the actual spawn resolve through ONE
/// path. Two copies would drift, and the failure mode of drift here is the
/// picker cheerfully offering an agent that then refuses to start.
fn adapter_launch_for(provider: AgentProvider) -> crate::error::HostResult<AdapterLaunch> {
    match provider {
        AgentProvider::ClaudeCode => {
            AdapterLaunch::resolve("claude-agent-acp", CLAUDE_ADAPTER_SPEC_VAR, "Claude Code")
        }
        AgentProvider::Codex => {
            AdapterLaunch::resolve("codex-acp", CODEX_ADAPTER_SPEC_VAR, "Codex")
        }
        AgentProvider::OpenCode => AdapterLaunch::installed(
            "opencode",
            "opencode acp",
            "install the OpenCode CLI on the host",
            "OpenCode",
        ),
        AgentProvider::Goose => AdapterLaunch::installed(
            "goose",
            "goose acp",
            "install and configure Goose on the host",
            "Goose",
        ),
    }
}

/// Can this provider start right now? Same resolution the spawn uses, so an
/// agent shown as available is one that will actually launch.
///
/// `command_available` shells out to a login shell, so this belongs off the
/// runtime - callers wrap it in `spawn_blocking`.
fn provider_readiness(provider: AgentProvider) -> Option<String> {
    match adapter_launch_for(provider) {
        Err(error) => Some(error.to_string()),
        Ok(launch) if !command_available(&launch.required) => Some(format!(
            "`{}` was not found on this host - {}",
            launch.required, launch.hint
        )),
        Ok(_) => None,
    }
}

impl AdapterLaunch {
    /// A provider launched by a CLI the user installed themselves.
    fn installed(
        required: &str,
        spec: &str,
        hint: &str,
        default_title: &'static str,
    ) -> crate::error::HostResult<Self> {
        Ok(Self {
            required: required.to_string(),
            hint: hint.to_string(),
            spec: spec.to_string(),
            default_title,
        })
    }

    /// Prefer the locally installed adapter binary; otherwise use the owner's
    /// opt-in command, and if there is none, fail with both remedies.
    fn resolve(
        adapter: &str,
        spec_var: &str,
        default_title: &'static str,
    ) -> crate::error::HostResult<Self> {
        if command_available(adapter) {
            return Self::installed(
                adapter,
                adapter,
                "reinstall the adapter on the host",
                default_title,
            );
        }
        let hint = format!(
            "install `{adapter}` on the host, or set {spec_var} to the exact \
             version-pinned launcher command you want Portty to run"
        );
        let Some(spec) = std::env::var(spec_var)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Err(crate::error::HostError::Acp(format!(
                "no ACP adapter for this agent on this host - {hint}"
            )));
        };
        // An owner-supplied command is trusted, but an unpinned one still means
        // "run whatever the registry serves today". Say so once, out loud.
        if spec.contains("@latest") || spec.contains("@next") {
            tracing::warn!(
                var = spec_var,
                "ACP adapter command is not version-pinned; a phone request will \
                 execute whatever that tag resolves to today"
            );
        }
        let required = spec
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        Ok(Self {
            required,
            hint,
            spec,
            default_title,
        })
    }
}

/// Map a client's answer to an approval onto two things: the option id forwarded
/// to the adapter, and the resolution reported to every other viewer (which also
/// becomes their decision-log entry).
///
/// Two rules, and the second one is why this is a function:
///
/// 1. Only an option the agent actually OFFERED is forwarded. A client echoing an
///    id that was never in the options (bug or tampering) must not drive the agent
///    down an un-presented branch, so that becomes a cancel.
/// 2. The reported resolution comes from the chosen option's KIND, not from
///    "an id was supplied". ACP offers REJECT options as ids too, so tapping
///    "Deny" used to be broadcast to the other viewers - and written into their
///    logs - as "Allowed", while the adapter correctly received the rejection. An
///    audit trail that says the opposite of what happened is worse than none.
fn permission_outcome(
    option_id: Option<String>,
    options: &[PermissionOption],
) -> (Option<String>, PermissionResolution) {
    let kind = option_id.as_ref().and_then(|id| {
        options
            .iter()
            .find(|option| &option.option_id == id)
            .map(|option| option.kind)
    });
    match (option_id, kind) {
        (Some(id), Some(PermissionOptionKind::AllowOnce | PermissionOptionKind::AllowAlways)) => {
            (Some(id), PermissionResolution::Allowed)
        }
        (Some(id), Some(PermissionOptionKind::RejectOnce | PermissionOptionKind::RejectAlways)) => {
            (Some(id), PermissionResolution::Rejected)
        }
        (Some(_), None) => {
            tracing::warn!(
                "ignoring permission decision with an option id the agent never offered"
            );
            (None, PermissionResolution::Cancelled)
        }
        // No option at all: an outright reject from the viewer.
        (None, _) => (None, PermissionResolution::Rejected),
    }
}

fn command_available(cmd: &str) -> bool {
    #[cfg(unix)]
    {
        resolve_login_shell_program(cmd).is_some()
    }
    #[cfg(not(unix))]
    {
        command_on_path(cmd)
    }
}

/// Resolve a bare program name to a spawnable path, consulting the user's
/// login-shell PATH (nvm/Homebrew/asdf) when the daemon's own PATH misses.
/// Bounded (10s per probe). Only SUCCESSFUL resolutions are memoized - a
/// negative cache would make "install the adapter, then retry" keep failing
/// for the daemon's lifetime.
#[cfg(unix)]
fn resolve_login_shell_program(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        return Some(PathBuf::from(cmd));
    }
    if command_on_path(cmd) {
        // The daemon's PATH already finds it; normal exec lookup will too.
        return Some(PathBuf::from(cmd));
    }
    static CACHE: std::sync::OnceLock<StdMutex<HashMap<String, PathBuf>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| StdMutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().unwrap().get(cmd) {
        return Some(hit.clone());
    }
    let resolved = probe_login_shell_program(cmd);
    if let Some(path) = &resolved {
        cache.lock().unwrap().insert(cmd.to_string(), path.clone());
    }
    resolved
}

/// `command -v` under `$SHELL -l`, with a hard deadline. Profile banners may
/// precede the answer on stdout, so the LAST absolute-path line wins.
#[cfg(unix)]
fn probe_login_shell_program(cmd: &str) -> Option<PathBuf> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let mut child = std::process::Command::new(shell)
        .args(["-l", "-c", "command -v -- \"$1\"", "portty", cmd])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        let _ = stdout.read_to_string(&mut out);
        out
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let out = reader.join().ok()?;
                return out
                    .lines()
                    .rev()
                    .map(str::trim)
                    .find(|line| line.starts_with('/'))
                    .map(PathBuf::from);
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                tracing::warn!(cmd, "login-shell PATH probe timed out");
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
}

/// The interactive shell to spawn, as (program, args). On Unix it is a LOGIN
/// shell: a daemon started by launchd/systemd inherits a bare environment, so
/// without `-l` a phone-spawned shell would miss the user's PATH and profile.
/// A login shell re-reads the profile so it behaves like a real terminal (#21).
/// Returned split so the choice is unit-testable.
#[cfg(unix)]
fn login_shell_argv() -> (String, Vec<String>) {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    (shell, vec!["-l".into()])
}

#[cfg(unix)]
fn login_shell_command() -> CommandBuilder {
    let (shell, args) = login_shell_argv();
    let mut cmd = CommandBuilder::new(shell);
    cmd.args(args);
    cmd
}

/// Windows has no login-shell concept; the default program inherits the user
/// environment of whatever started the daemon.
#[cfg(windows)]
fn login_shell_command() -> CommandBuilder {
    CommandBuilder::new_default_prog()
}

/// The directory a shell opens in when its caller does not name one.
///
/// **portable_pty does not inherit the daemon's cwd.** Spawn a PTY with no `cwd`
/// and it starts in the user's HOME (`%USERPROFILE%` on Windows), so leaving this
/// to the default silently ignored BOTH `PORTTY_WORKSPACE` and the directory
/// `portty-host` was launched from. Every phone path sends `None` -
/// `RequestKind::NewSession`, `NewSessionSized`, and the legacy
/// `Frame::NewSession` all do - so every phone terminal opened at "root" instead
/// of the project, which is exactly what `workspace_dir`'s own doc comment warns
/// about. The agent spawn and the local browser proof each applied
/// `workspace_dir()` themselves and so looked correct, which is why the proof
/// never surfaced it.
///
/// Defaulting here rather than at each call site means a future caller cannot
/// reintroduce it by forgetting.
///
/// Canonicalized to match the agent spawn, and because `workspace_dir()` falls
/// back to `"."`. `None` means "leave portable_pty's default alone": the workspace
/// is unresolvable (launch dir deleted under us), and a terminal that opens in the
/// wrong place still beats refusing to open one - `cmd.cwd()` with a path that no
/// longer exists fails the spawn outright.
fn default_shell_cwd() -> Option<PathBuf> {
    let workspace = crate::iroh_serve::workspace_dir();
    match std::fs::canonicalize(&workspace) {
        Ok(dir) => Some(dir),
        Err(error) => {
            tracing::warn!(
                workspace = ?workspace,
                error = %error,
                "could not resolve the workspace directory; the shell will open in the \
                 platform default instead"
            );
            None
        }
    }
}

/// Resolve the adapter's program name to a spawnable path, consulting the user's
/// login-shell PATH (nvm/Homebrew/asdf) when the daemon's own PATH misses.
#[cfg(unix)]
fn resolve_agent_program(cmd: &str) -> Option<PathBuf> {
    resolve_login_shell_program(cmd)
}

#[cfg(not(unix))]
fn resolve_agent_program(cmd: &str) -> Option<PathBuf> {
    windows_spawnable_program(cmd)
}

/// Give a bare program name the file extension Windows refuses to look for.
///
/// `CreateProcess` searches PATH but only ever appends `.exe` - it does NOT
/// honour PATHEXT. npm installs its launchers as `.cmd` shims, so a bare
/// `opencode` (or the `npx` in an owner-supplied `PORTTY_*_ACP_COMMAND`, or an
/// agent asking to run `npm test`) fails with **"program not found"** even though
/// the readiness check found `opencode.cmd` a moment earlier. Handed the full
/// path WITH its extension it works: `std::process::Command` recognises
/// `.cmd`/`.bat` and routes them through `cmd.exe` using the argument quoting
/// from the CVE-2024-24576 fix.
///
/// `None` means "spawn the name as given" - either it is already a path the
/// caller spelled out, or nothing on PATH matches and the OS should produce its
/// own not-found error rather than us inventing one.
///
/// Shared by the adapter spawn and the ACP terminal spawn so the two cannot
/// drift into disagreeing about what is runnable. **Resolution grants nothing
/// new:** every caller could already run PATH programs, and only the PROGRAM is
/// rewritten - never the arguments, the cwd, or the environment.
#[cfg(not(unix))]
fn windows_spawnable_program(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('\\') || cmd.contains('/') {
        // Already a path - the caller spelled it out, leave it alone.
        return None;
    }
    resolve_on_path(cmd)
}

/// Unix needs nothing here: `execvp` already walks PATH, and the login-shell
/// probe that [`resolve_agent_program`] uses is deliberately NOT applied to
/// agent-requested terminals - it is bounded at 10s per miss and memoizes only
/// hits, so an agent could burn a blocking thread per bogus command name.
#[cfg(unix)]
fn windows_spawnable_program(_cmd: &str) -> Option<PathBuf> {
    None
}

/// Build the ACP subprocess command. The program name is resolved to a concrete
/// path, but the adapter is spawned DIRECTLY - a `$SHELL -l -c` wrapper would
/// let profile stdout corrupt the JSON-RPC stream (verified: a `.zprofile` echo
/// lands before the first frame) and re-target kill signals at the shell instead
/// of the adapter.
///
/// Resolution does not widen the trust boundary: `spec` still comes from an
/// allow-listed provider preset or the owner's own env var, and only the PROGRAM
/// is rewritten - never the arguments.
fn acp_agent_from_spec(spec: &str) -> crate::error::HostResult<AcpAgent> {
    let agent = AcpAgent::from_str(spec)
        .map_err(|error| crate::error::HostError::Acp(error.to_string()))?;
    let config = agent.into_config();
    let program = config.command().to_string_lossy().to_string();
    let Some(resolved) = resolve_agent_program(&program) else {
        return Ok(AcpAgent::new(config));
    };
    // `AcpAgentConfig` exposes only consuming builders and getters - there is no
    // field setter - so swapping the program means rebuilding the config, which
    // means carrying the args and env across by hand. The contract above is that
    // ONLY the program changes, so both are copied verbatim; dropping either
    // would silently launch the adapter with different arguments or a different
    // environment than the preset asked for.
    //
    // The old `McpServer::Stdio` match is gone with it: in agent-client-protocol
    // 2.0 an `AcpAgent` is by definition a subprocess launch, so there is no
    // longer a non-stdio variant to skip over.
    let rebuilt = AcpAgentConfig::new(resolved)
        .args(config.arguments().iter().cloned())
        .envs(
            config
                .environment()
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
    Ok(AcpAgent::new(rebuilt))
}

impl AcpEventLogger {
    fn new(session_id: SessionId) -> std::io::Result<Self> {
        Self::new_in(&crate::app_data_dir(), session_id)
    }

    fn new_in(data_dir: &std::path::Path, session_id: SessionId) -> std::io::Result<Self> {
        let root = data_dir.join("acp-events");
        let dir = root.join(session_id.0.to_string());
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let segment = (0..ACP_EVENT_SEGMENTS)
            .filter_map(|segment| {
                let modified = std::fs::metadata(dir.join(format!("events-{segment:02}.ndjson")))
                    .ok()?
                    .modified()
                    .ok()?;
                Some((modified, segment))
            })
            .max_by_key(|(modified, _)| *modified)
            .map_or(0, |(_, segment)| segment);
        let mut logger = Self {
            dir,
            segment,
            bytes: 0,
            file: None,
            active_path: None,
        };
        // A Portty session can respawn its adapter several times. Reopening the
        // tap must preserve frames already written by the previous process.
        logger.open_segment(true)?;
        if logger.bytes >= ACP_EVENT_SEGMENT_BYTES {
            logger.rotate_segment()?;
        }
        prune_acp_event_log_files(&root, ACP_EVENT_TOTAL_BYTES, ACP_EVENT_SEGMENT_BYTES)?;
        Ok(logger)
    }

    fn open_segment(&mut self, append: bool) -> std::io::Result<()> {
        let path = self.dir.join(format!("events-{:02}.ndjson", self.segment));
        let active_logs = ACTIVE_ACP_EVENT_LOGS.get_or_init(Default::default);
        let mut active = active_logs.lock().unwrap();
        let is_new_logger = self.active_path.is_none();
        let max_live_loggers = (ACP_EVENT_TOTAL_BYTES / ACP_EVENT_SEGMENT_BYTES) as usize;
        if is_new_logger && active.len() >= max_live_loggers {
            return Err(std::io::Error::other(
                "host-wide ACP event-log budget has no free live segment",
            ));
        }
        if self.active_path.as_ref() != Some(&path) && active.contains(&path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "ACP event segment already has a live writer",
            ));
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(&path)?;
        self.bytes = if append { file.metadata()?.len() } else { 0 };
        self.file = Some(std::io::BufWriter::new(file));
        if let Some(previous) = self.active_path.replace(path.clone()) {
            active.remove(&previous);
        }
        active.insert(path);
        Ok(())
    }

    fn rotate_segment(&mut self) -> std::io::Result<()> {
        if let Some(mut file) = self.file.take() {
            let _ = file.flush();
        }
        self.segment = (self.segment + 1) % ACP_EVENT_SEGMENTS;
        self.open_segment(false)?;
        prune_acp_event_log_files(
            self.dir.parent().unwrap_or(&self.dir),
            ACP_EVENT_TOTAL_BYTES,
            ACP_EVENT_SEGMENT_BYTES,
        )?;
        Ok(())
    }

    fn write_frame(&mut self, line: &str, direction: acp::LineDirection) -> std::io::Result<()> {
        let direction = match direction {
            acp::LineDirection::Stdin => "client_to_agent",
            acp::LineDirection::Stdout => "agent_to_client",
            acp::LineDirection::Stderr => "agent_stderr",
        };
        let at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        // One escape pass: the frame is the only field needing JSON quoting.
        // Building a serde_json::Value here would copy and encode every
        // streamed chunk twice on the hot path.
        let mut encoded = format!(
            "{{\"at_unix_ms\":{at_unix_ms},\"direction\":\"{direction}\",\"frame\":{}}}",
            serde_json::to_string(line)?,
        )
        .into_bytes();
        // A single provider line must not punch through the segment/global
        // ceiling. Preserve its timestamp, direction, and byte count while
        // omitting only the pathological raw payload.
        if encoded.len() as u64 + 1 > ACP_EVENT_SEGMENT_BYTES {
            encoded = format!(
                "{{\"at_unix_ms\":{at_unix_ms},\"direction\":\"{direction}\",\"frame\":null,\"frame_omitted_bytes\":{}}}",
                line.len(),
            )
            .into_bytes();
        }
        let record_bytes = encoded.len() as u64 + 1;
        if self.bytes > 0 && self.bytes.saturating_add(record_bytes) > ACP_EVENT_SEGMENT_BYTES {
            self.rotate_segment()?;
        }
        let file = self.file.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "ACP event log is closed")
        })?;
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.flush()?;
        self.bytes = self.bytes.saturating_add(record_bytes);
        Ok(())
    }
}

impl Drop for AcpEventLogger {
    fn drop(&mut self) {
        self.file.take();
        if let Some(path) = self.active_path.take() {
            ACTIVE_ACP_EVENT_LOGS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .remove(&path);
        }
    }
}

#[derive(Debug)]
struct AcpEventLogFile {
    path: PathBuf,
    bytes: u64,
    modified: std::time::SystemTime,
}

fn is_acp_event_segment(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.strip_prefix("events-")
        .and_then(|name| name.strip_suffix(".ndjson"))
        .and_then(|segment| segment.parse::<u64>().ok())
        .is_some_and(|segment| segment < ACP_EVENT_SEGMENTS)
}

/// Remove oldest closed segments across all sessions. Space for each active
/// writer to grow to a complete segment is reserved up front, so a burst from
/// many concurrent agents cannot temporarily recreate the old 2 GiB bound.
fn prune_acp_event_log_files(
    root: &std::path::Path,
    total_budget: u64,
    segment_bytes: u64,
) -> std::io::Result<u64> {
    let active_logs = ACTIVE_ACP_EVENT_LOGS.get_or_init(Default::default);
    let active = active_logs.lock().unwrap();
    prune_acp_event_log_files_with_active(root, total_budget, segment_bytes, &active)
}

fn prune_acp_event_log_files_with_active(
    root: &std::path::Path,
    total_budget: u64,
    segment_bytes: u64,
    active: &HashSet<PathBuf>,
) -> std::io::Result<u64> {
    let mut files = Vec::new();
    let sessions = match std::fs::read_dir(root) {
        Ok(sessions) => sessions,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    for session in sessions {
        let session = session?;
        if !session.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(session.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_file() || !is_acp_event_segment(&entry.path()) {
                continue;
            }
            let metadata = entry.metadata()?;
            files.push(AcpEventLogFile {
                path: entry.path(),
                bytes: metadata.len(),
                modified: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
            });
        }
    }

    let mut total = files.iter().map(|file| file.bytes).sum::<u64>();
    let reserved_growth = files
        .iter()
        .filter(|file| active.contains(&file.path))
        .map(|file| segment_bytes.saturating_sub(file.bytes.min(segment_bytes)))
        .sum::<u64>();
    let retained_now = total_budget.saturating_sub(reserved_growth);
    files.sort_by_key(|file| file.modified);
    for file in files {
        if total <= retained_now {
            break;
        }
        if active.contains(&file.path) {
            continue;
        }
        match std::fs::remove_file(&file.path) {
            Ok(()) => total = total.saturating_sub(file.bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                total = total.saturating_sub(file.bytes);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(total)
}

/// Startup janitor for segments left by prior host processes. Live loggers also
/// invoke the same host-wide janitor whenever they open or rotate a segment.
pub fn prune_acp_event_logs(data_dir: &std::path::Path) -> std::io::Result<u64> {
    prune_acp_event_log_files(
        &data_dir.join("acp-events"),
        ACP_EVENT_TOTAL_BYTES,
        ACP_EVENT_SEGMENT_BYTES,
    )
}

/// Raw ACP transcript logging: OPT-IN via `PORTTY_ACP_EVENT_LOG=1`.
///
/// The log is a verbatim copy of the JSON-RPC stream in both directions, so it
/// contains whole prompts, the file contents the agent read, tool arguments,
/// and adapter stderr - i.e. whatever secrets happened to be in the workspace or
/// the conversation. That is exactly what you want while debugging an adapter and
/// exactly what you do not want written to disk by default on every agent
/// session. The files are owner-only and bounded, but up to 256 MiB of plaintext
/// transcript retained silently is a much bigger footprint than a diagnostic
/// needs. Default off; the operator turns it on for the run they are debugging.
/// Pure half of the gate, so the default-off decision is testable without
/// mutating a process-wide env var under parallel tests. Anything that is not an
/// explicit opt-in - unset, empty, `0`, `false`, a typo - means no transcript.
fn acp_event_log_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let value = value.trim();
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
}

fn acp_event_debug(session_id: SessionId) -> Option<AcpDebugCallback> {
    if !acp_event_log_enabled(std::env::var("PORTTY_ACP_EVENT_LOG").ok().as_deref()) {
        return None;
    }
    let logger = match AcpEventLogger::new(session_id) {
        Ok(logger) => Arc::new(StdMutex::new(logger)),
        Err(error) => {
            tracing::warn!(session = session_id.0, %error, "could not create ACP event log");
            return None;
        }
    };
    Some(Arc::new(move |line, direction| {
        if let Err(error) = logger.lock().unwrap().write_frame(line, direction) {
            tracing::debug!(session = session_id.0, %error, "could not append ACP event frame");
        }
    }))
}

fn acp_cache_path() -> PathBuf {
    crate::app_data_dir().join("acp-sessions.json")
}

fn read_acp_cache_unlocked() -> Vec<CachedAcpSession> {
    let path = acp_cache_path();
    if std::fs::metadata(&path).is_ok_and(|metadata| metadata.len() > MAX_ACP_CACHE_BYTES as u64) {
        tracing::warn!("ignoring oversized ACP session cache");
        return Vec::new();
    }
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_acp_cache_unlocked(mut entries: Vec<CachedAcpSession>) -> std::io::Result<()> {
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_active_at_unix_ms));
    entries.truncate(MAX_CACHED_ACP_SESSIONS);
    let path = acp_cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let bytes = loop {
        let bytes = serde_json::to_vec_pretty(&entries)?;
        if bytes.len() <= MAX_ACP_CACHE_BYTES || entries.len() <= 1 {
            break bytes;
        }
        entries.pop();
    };
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn cached_acp_session(
    provider: Option<AgentProvider>,
    cwd: &std::path::Path,
) -> Option<CachedAcpSession> {
    let provider = provider?;
    let _guard = ACP_CACHE_LOCK
        .get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap();
    read_acp_cache_unlocked()
        .into_iter()
        .filter(|entry| entry.provider == provider && entry.cwd == cwd)
        .max_by_key(|entry| entry.last_active_at_unix_ms)
}

/// Every cached conversation for one workspace directory, newest first.
///
/// Same store the automatic "resume the newest" path reads - this just stops
/// throwing the rest away. Scoped to `cwd`, so a conversation is only ever
/// offered inside the directory it belongs to.
fn list_cached_acp_sessions(cwd: &std::path::Path) -> Vec<CachedAcpSession> {
    let _guard = ACP_CACHE_LOCK
        .get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap();
    select_sessions_for_cwd(read_acp_cache_unlocked(), cwd)
}

/// Pure selection, split from the IO so it is testable without touching the
/// process-global `PORTTY_DATA_DIR` that the real cache path derives from.
fn select_sessions_for_cwd(
    entries: Vec<CachedAcpSession>,
    cwd: &std::path::Path,
) -> Vec<CachedAcpSession> {
    let mut entries: Vec<CachedAcpSession> = entries
        .into_iter()
        .filter(|entry| entry.cwd == cwd)
        .collect();
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_active_at_unix_ms));
    entries
}

/// Pure counterpart of [`cached_acp_session_by_id`]. Matches on BOTH cwd and id.
fn select_session_by_id(
    entries: Vec<CachedAcpSession>,
    cwd: &std::path::Path,
    acp_session_id: &str,
) -> Option<CachedAcpSession> {
    entries
        .into_iter()
        .find(|entry| entry.cwd == cwd && entry.acp_session_id == acp_session_id)
}

/// One specific cached conversation, looked up by the agent's own session id.
///
/// Matched on `cwd` as well as the id: the phone names an id, but the directory
/// comes from the workspace resolver, so a conversation can never be resumed
/// into a workspace it did not belong to even if the id were guessed.
fn cached_acp_session_by_id(
    cwd: &std::path::Path,
    acp_session_id: &str,
) -> Option<CachedAcpSession> {
    let _guard = ACP_CACHE_LOCK
        .get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap();
    select_session_by_id(read_acp_cache_unlocked(), cwd, acp_session_id)
}

/// Gather the persistable view of a session (cheap: brief history lock, no IO).
fn build_cached_acp_session(
    provider: Option<AgentProvider>,
    cwd: &std::path::Path,
    acp_session_id: &acp::schema::v1::SessionId,
    inner: &SessionInner,
) -> Option<CachedAcpSession> {
    if cfg!(test) && std::env::var_os("PORTTY_ACP_SESSION_CACHE").is_none() {
        return None;
    }
    let provider = provider?;
    let mut desired_mode = None;
    let mut desired_config = HashMap::new();
    let mut first_prompt_label = None;
    if let Backend::Acp { handle } = &inner.backend {
        let history = handle.history.lock().unwrap();
        if let Some(event) = history.sticky.get(&StickyAgentEvent::Mode) {
            if let AgentEvent::ModeState {
                current_mode_id, ..
            } = &event.event
            {
                desired_mode = Some(current_mode_id.clone());
            }
        }
        if let Some(event) = history.sticky.get(&StickyAgentEvent::Config) {
            if let AgentEvent::ConfigOptions { options } = &event.event {
                desired_config.extend(
                    options
                        .iter()
                        .map(|option| (option.id.clone(), option.current_value.clone())),
                );
            }
        }
        first_prompt_label = history.events.iter().find_map(|event| match &event.event {
            AgentEvent::UserMessage { text } => Some(clamp_cache_label(text)),
            _ => None,
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Some(CachedAcpSession {
        provider,
        cwd: cwd.to_path_buf(),
        acp_session_id: acp_session_id.to_string(),
        title: inner.title.lock().unwrap().clone(),
        first_prompt_label,
        last_active_at_unix_ms: now,
        desired_mode,
        desired_config,
    })
}

/// Blocking half of persistence: merge one entry into the cache file. An
/// earlier first-prompt label wins - it names the conversation's origin.
fn write_cached_acp_session(mut cached: CachedAcpSession) {
    let _guard = ACP_CACHE_LOCK
        .get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap();
    let mut entries = read_acp_cache_unlocked();
    let original_first_prompt = entries
        .iter()
        .find(|entry| {
            entry.provider == cached.provider && entry.acp_session_id == cached.acp_session_id
        })
        .and_then(|entry| entry.first_prompt_label.clone());
    entries.retain(|entry| {
        !(entry.provider == cached.provider && entry.acp_session_id == cached.acp_session_id)
    });
    cached.first_prompt_label = original_first_prompt.or(cached.first_prompt_label);
    entries.push(cached);
    if let Err(error) = write_acp_cache_unlocked(entries) {
        tracing::debug!(%error, "could not persist ACP session cache");
    }
}

/// Persist from the async driver: state capture is synchronous, the file IO
/// runs on the blocking pool so streaming turns never stall on disk.
fn persist_tracked_acp_session(
    provider: Option<AgentProvider>,
    cwd: &std::path::Path,
    acp_session_id: &acp::schema::v1::SessionId,
    inner: &SessionInner,
    tracked: &StdMutex<Option<CachedAcpSession>>,
) {
    if let Some(cached) = build_cached_acp_session(provider, cwd, acp_session_id, inner) {
        *tracked.lock().unwrap() = Some(cached.clone());
        tokio::task::spawn_blocking(move || write_cached_acp_session(cached));
    }
}

fn prune_cached_acp_session(provider: Option<AgentProvider>, session_id: &str) {
    let Some(provider) = provider else { return };
    let _guard = ACP_CACHE_LOCK
        .get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap();
    let mut entries = read_acp_cache_unlocked();
    entries.retain(|entry| !(entry.provider == provider && entry.acp_session_id == session_id));
    let _ = write_acp_cache_unlocked(entries);
}

fn clamp_cache_label(text: &str) -> String {
    let mut label = text.lines().next().unwrap_or_default().trim().to_string();
    if label.len() > 80 {
        let mut end = 80 - "…".len();
        while !label.is_char_boundary(end) {
            end -= 1;
        }
        label.truncate(end);
        label.push('…');
    }
    label
}

/// Ask one provider's adapter which conversations it remembers in `cwd`.
///
/// This is the whole point of the v11 listing: Portty's own cache only ever knew
/// about conversations Portty spawned, so a chat started with the agent's CLI in
/// the laptop terminal was invisible from the phone even though the SAME adapter
/// could resume it. `session/list` is the agent's own answer to "what have I got
/// here", and the phone is entitled to the same answer the laptop gets.
///
/// Every failure - no adapter, no `session/list` capability, auth required, a
/// hung launch, a malformed page - degrades to "nothing extra", never to an
/// error. A probe failure that propagated would take Portty's own cached
/// conversations down with it, which is strictly worse than the status quo it is
/// meant to improve.
///
/// The connection deliberately advertises NO client capabilities: no filesystem,
/// no terminals, no permission handler. A listing must not be able to turn into
/// an agent doing work, and an adapter that tries gets a method-not-found instead
/// of a file.
async fn probe_agent_sessions(
    resolver: AdapterResolver,
    provider: AgentProvider,
    cwd: PathBuf,
) -> Vec<DiscoveredAcpSession> {
    // Resolving the launcher shells out to a login shell on a PATH miss and can
    // block for seconds - and being synchronous, the timeout below cannot
    // interrupt it. Off the runtime, exactly as `spawn_agent_provider` does it.
    let resolved = tokio::task::spawn_blocking(move || {
        resolver(provider).and_then(|launch| acp_agent_from_spec(&launch.spec))
    })
    .await;
    let agent = match resolved {
        Ok(Ok(agent)) => agent,
        Ok(Err(error)) => {
            tracing::debug!(?provider, %error, "no adapter to ask for saved conversations");
            return Vec::new();
        }
        Err(error) => {
            tracing::debug!(?provider, %error, "could not resolve the adapter to ask");
            return Vec::new();
        }
    };
    // The tracked wrapper is what applies Portty's SIGTERM-then-kill guard, so
    // the probe cannot leave an adapter behind when the timeout fires.
    let (closed_tx, _closed_rx) = tokio::sync::watch::channel(false);
    let agent = TrackedAcpAgent {
        agent,
        closed: closed_tx,
        debug: None,
    };
    // The spelling the AGENT will recognise, which is not always the resolver's
    // (see `agent_facing_path`). This is what its own `cwd` filter matches on.
    let probe_cwd = agent_facing_path(&cwd);
    let probe = acp::Client.builder().name("portty-host").connect_with(
        agent,
        async move |cx: acp::ConnectionTo<acp::Agent>| {
            let init = cx
                .send_request(InitializeRequest::new(ProtocolVersion::V1).client_info(
                    Implementation::new("portty-host", env!("CARGO_PKG_VERSION")),
                ))
                .block_task()
                .await?;
            if init.agent_capabilities.session_capabilities.list.is_none() {
                return Ok(Vec::new());
            }
            let mut rows: Vec<acp::schema::v1::SessionInfo> = Vec::new();
            let mut cursor: Option<String> = None;
            for _ in 0..MAX_ACP_SESSION_LIST_PAGES {
                let page = cx
                    .send_request(
                        ListSessionsRequest::new()
                            .cwd(probe_cwd.clone())
                            .cursor(cursor.take()),
                    )
                    .block_task()
                    .await?;
                // Truncated to the remaining budget BEFORE it is taken: an
                // adapter that answers one page with a hundred thousand rows must
                // not get them all allocated first.
                let room = MAX_LISTED_AGENT_SESSIONS.saturating_sub(rows.len());
                rows.extend(page.sessions.into_iter().take(room));
                if rows.len() >= MAX_LISTED_AGENT_SESSIONS {
                    break;
                }
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            Ok(rows)
        },
    );
    let listed = match tokio::time::timeout(ACP_SESSION_LIST_TIMEOUT, probe).await {
        Ok(Ok(listed)) => listed,
        Ok(Err(error)) => {
            // Code and first line only. An adapter's failure carries its stderr,
            // and stderr is where agent CLIs put auth failures, tokens in URLs,
            // and absolute paths.
            tracing::debug!(
                ?provider,
                code = ?error.code,
                detail = first_line(&error.message),
                "agent could not list its saved conversations"
            );
            return Vec::new();
        }
        Err(_) => {
            tracing::info!(
                ?provider,
                "gave up waiting for the agent's saved conversations"
            );
            return Vec::new();
        }
    };
    let real_cwd = cwd.clone();
    tokio::task::spawn_blocking(move || {
        discovered_from_session_infos(provider, &real_cwd, listed, &canonical_or_none)
    })
    .await
    .unwrap_or_default()
}

/// The first line of an adapter's error, bounded.
///
/// Walks back to a char boundary rather than slicing at the byte: the text is an
/// agent's error message, so it is arbitrary UTF-8, and `&line[..200]` panics
/// outright when byte 200 lands mid-character.
fn first_line(text: &str) -> &str {
    let line = text.lines().next().unwrap_or_default();
    let mut end = line.len().min(200);
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    &line[..end]
}

/// The spelling of `path` to hand an agent.
///
/// `workspace::resolve_within` canonicalizes, and on Windows that yields the
/// verbatim form (`\\?\C:\w\app`). Adapters record and match a process working
/// directory (`C:\w\app`), so handing them the verbatim spelling means their own
/// `cwd` filter matches nothing and the whole listing silently comes back empty.
/// Unix has no such form and this is the identity there.
/// Only `VerbatimDisk` is unwrapped. A `VerbatimUNC` path has no plain spelling
/// that means the same thing, so it is left exactly as it is rather than
/// rewritten into something that might point somewhere else.
fn agent_facing_path(path: &std::path::Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
        use std::path::{Component, Prefix};

        const VERBATIM: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
        if let Some(Component::Prefix(prefix)) = path.components().next() {
            if matches!(prefix.kind(), Prefix::VerbatimDisk(_)) {
                // Through UTF-16, not `to_string_lossy`: a Windows path need not
                // be valid Unicode, and the lossy form would hand the agent a
                // path with U+FFFD where its real bytes used to be.
                let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
                if wide.starts_with(VERBATIM) {
                    return PathBuf::from(OsString::from_wide(&wide[VERBATIM.len()..]));
                }
            }
        }
    }
    path.to_path_buf()
}

/// `Path::canonicalize`, with any failure meaning "no answer".
///
/// Injected into [`discovered_from_session_infos`] so the trust rules stay
/// testable without touching the filesystem.
fn canonical_or_none(path: &std::path::Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

/// Pure half of the probe: what the host is willing to believe from a listing.
///
/// Split out so the trust rules are testable without an adapter. The `cwd` check
/// is the load-bearing one - the request already filtered by directory, but the
/// filter is the AGENT's, and the directory is a confinement boundary the
/// workspace resolver owns. An adapter that returns a conversation from somewhere
/// else does not get to have it offered.
///
/// Compared through `canonicalize`, not as strings: `cwd` came from the resolver
/// and is already canonical, while the agent reports whatever spelling its own
/// process had - a symlinked project root on macOS, a non-verbatim drive path on
/// Windows. String equality there is not stricter, just wrong in a direction that
/// silently empties the list. A path that will not resolve is dropped, so the
/// comparison still fails closed.
fn discovered_from_session_infos(
    provider: AgentProvider,
    cwd: &std::path::Path,
    listed: Vec<acp::schema::v1::SessionInfo>,
    canonicalize: &dyn Fn(&std::path::Path) -> Option<PathBuf>,
) -> Vec<DiscoveredAcpSession> {
    let target = canonicalize(cwd).unwrap_or_else(|| cwd.to_path_buf());
    let mut seen = HashSet::new();
    listed
        .into_iter()
        .filter(|info| canonicalize(&info.cwd).is_some_and(|reported| reported == target))
        .filter_map(|info| {
            let acp_session_id = info.session_id.to_string();
            // Dropped, never truncated: a shortened id is a DIFFERENT id, and
            // resuming it would either miss or hit the wrong conversation. The
            // bound matters because 50 unbounded ids can push the reply past
            // MAX_FRAME_BYTES, which drops the phone's whole connection rather
            // than failing the listing.
            if acp_session_id.is_empty()
                || acp_session_id.len() > MAX_AGENT_SHORT_TEXT_BYTES
                || !seen.insert(acp_session_id.clone())
            {
                return None;
            }
            let title = info
                .title
                .as_deref()
                .map(str::trim)
                .filter(|title| !title.is_empty())
                .map(clamp_cache_label)
                .unwrap_or_else(|| "conversation".to_string());
            Some(DiscoveredAcpSession {
                provider,
                // The RESOLVER's path, never the agent's - so a row can only ever
                // be resumed into the directory the workspace resolver produced.
                cwd: cwd.to_path_buf(),
                acp_session_id,
                title,
                last_active_at_unix_ms: info.updated_at.as_deref().and_then(unix_ms_from_rfc3339),
            })
        })
        .take(MAX_LISTED_AGENT_SESSIONS)
        .collect()
}

/// `2026-08-06T06:53:09.852Z` → milliseconds since the epoch.
///
/// ACP says "ISO 8601 timestamp", which is a family, not a format. Portty parses
/// the RFC 3339 subset every adapter actually emits (JavaScript's
/// `toISOString()`, plus a numeric offset) and returns `None` for anything else.
/// `None` beats a guess: an unparseable timestamp defaulting to "now" would sort
/// a stale conversation to the top of the picker, and defaulting to the epoch
/// would tell you it was last touched in 1970. The phone shows neither.
fn unix_ms_from_rfc3339(text: &str) -> Option<u64> {
    let text = text.trim();
    let bytes = text.as_bytes();
    if bytes.len() < 20 || (bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ') {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = text.get(range)?;
        if !slice.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59
        // A leap second (:60) is a real timestamp, not a malformed one.
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    let mut millis = 0i64;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits: String = fraction.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        // Pad/truncate to exactly milliseconds; extra precision is dropped, not
        // rounded - a picker sorts by the second, not the microsecond.
        let mut padded = digits.clone();
        padded.truncate(3);
        while padded.len() < 3 {
            padded.push('0');
        }
        millis = padded.parse::<i64>().ok()?;
        rest = &rest[1 + digits.len()..];
    }
    let offset_minutes = match rest.as_bytes().first() {
        Some(b'Z') | Some(b'z') if rest.len() == 1 => 0,
        Some(sign @ (b'+' | b'-')) if rest.len() == 6 && rest.as_bytes()[3] == b':' => {
            let hours: i64 = rest.get(1..3)?.parse().ok()?;
            let minutes: i64 = rest.get(4..6)?.parse().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = hours * 60 + minutes;
            if *sign == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        // No zone is not "assume UTC" - it is an unknown instant, and the picker
        // is better off saying nothing than sorting on a guess.
        _ => return None,
    };
    let days = days_from_civil(year, month as u32, day as u32);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset_minutes * 60;
    let millis = seconds.checked_mul(1000)?.checked_add(millis)?;
    u64::try_from(millis).ok()
}

/// Fold what Portty cached together with what the agent remembers into the one
/// list the picker shows.
///
/// Pure, because the interesting decisions are all judgement calls worth pinning
/// in tests:
///
/// - **The cache wins on identity.** Its row carries the conversation's first
///   prompt, which tells two chats apart far better than an auto-generated title.
/// - **The agent wins on recency.** Portty's timestamp is when Portty last
///   persisted the conversation; the agent's is when the conversation was last
///   touched, including from the laptop, which is the whole reason the row is
///   here.
/// - **Unknown time sorts last, as 0.** Not as "now" - see [`unix_ms_from_rfc3339`].
fn merge_agent_sessions(
    provider: AgentProvider,
    cached: Vec<CachedAcpSession>,
    discovered: Vec<DiscoveredAcpSession>,
) -> Vec<AgentSessionSummary> {
    let mut rows: Vec<AgentSessionSummary> = cached
        .into_iter()
        .filter(|entry| entry.provider == provider)
        .map(|entry| AgentSessionSummary {
            acp_session_id: entry.acp_session_id,
            provider: entry.provider,
            title: entry.title,
            label: entry.first_prompt_label,
            last_active_at_unix_ms: entry.last_active_at_unix_ms,
        })
        .collect();
    for entry in discovered {
        match rows
            .iter_mut()
            .find(|row| row.acp_session_id == entry.acp_session_id)
        {
            Some(row) => {
                row.last_active_at_unix_ms = row
                    .last_active_at_unix_ms
                    .max(entry.last_active_at_unix_ms.unwrap_or_default());
            }
            None => rows.push(AgentSessionSummary {
                acp_session_id: entry.acp_session_id,
                provider: entry.provider,
                title: entry.title,
                // No first prompt to show: Portty never watched this conversation
                // happen, so the agent's title is the best name there is.
                label: None,
                last_active_at_unix_ms: entry.last_active_at_unix_ms.unwrap_or_default(),
            }),
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.last_active_at_unix_ms));
    rows.truncate(MAX_LISTED_AGENT_SESSIONS);
    rows
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`). Portty needs one date conversion and no calendar, so this
/// is a dozen lines instead of a dependency.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

impl Session {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            id: self.id,
            title: self.inner.title.lock().unwrap().clone(),
            kind: self.inner.kind,
            source: self.inner.source,
            has_activity: self.inner.has_unseen_activity.load(Ordering::Relaxed),
        }
    }

    /// Bytes the viewer sees on attach (recent scrollback). Cheap copy of the ring.
    #[cfg(test)]
    pub fn scrollback_snapshot(&self) -> Vec<u8> {
        self.inner.scrollback.lock().unwrap().concat()
    }

    /// Atomically snapshot scrollback AND subscribe to live output, with no gap:
    /// every byte lands in exactly one of the two. `push_output` takes the same
    /// scrollback lock *before* it broadcasts, so while we hold it here a
    /// concurrent write can't slip between the snapshot and the subscription -
    /// output produced during attach is therefore never lost (nor duplicated).
    pub fn snapshot_and_subscribe(&self) -> (Vec<u8>, u64, broadcast::Receiver<Arc<OutputChunk>>) {
        let sb = self.inner.scrollback.lock().unwrap();
        let snap = sb.concat();
        let through_seq = self
            .inner
            .next_output_seq
            .load(Ordering::Relaxed)
            .saturating_sub(1);
        let rx = self.inner.output_tx.subscribe();
        // Mark seen under the same boundary: output before this point is in the
        // snapshot; output after it will set unseen again and enter `rx`.
        self.mark_seen();
        drop(sb);
        (snap, through_seq, rx)
    }

    /// Atomically collect the output chunks strictly after `after_seq` AND
    /// subscribe to live output (same lock discipline as
    /// `snapshot_and_subscribe`). Returns `None` when the boundary has aged out
    /// of the ring - or lies in the future, e.g. a stale client talking to a
    /// restarted host - in which case the caller must fall back to a full
    /// reset + snapshot attach. Output seqs start at 1, so `after_seq == 0`
    /// means "seen nothing yet" and is served as a from-the-start delta.
    pub fn delta_since_and_subscribe(&self, after_seq: u64) -> Option<OutputDelta> {
        let sb = self.inner.scrollback.lock().unwrap();
        let through_seq = self
            .inner
            .next_output_seq
            .load(Ordering::Relaxed)
            .saturating_sub(1);
        if after_seq > through_seq {
            return None;
        }
        let chunks = sb.since(after_seq)?;
        let rx = self.inner.output_tx.subscribe();
        self.mark_seen();
        drop(sb);
        Some((chunks, through_seq, rx))
    }

    pub fn mark_seen(&self) {
        self.inner
            .has_unseen_activity
            .store(false, Ordering::Relaxed);
    }

    /// Bounded structured history for an ACP session. Returns `None` for a
    /// terminal, which keeps the terminal byte path completely separate.
    pub fn agent_snapshot(&self) -> Option<Vec<AgentTimelineEvent>> {
        let Backend::Acp { handle } = &self.inner.backend else {
            return None;
        };
        let history = handle.history.lock().unwrap();
        let events = history.snapshot();
        drop(history);
        self.mark_seen();
        Some(events)
    }

    /// How broad this session's ACP sandbox root is.
    ///
    /// `Broad` for anything that is not an agent session: there are no approval
    /// cards there, and an unknown scope must never read as the permissive one.
    pub fn agent_workspace_scope(&self) -> WorkspaceScope {
        match &self.inner.backend {
            Backend::Acp { handle } => handle.workspace_scope,
            _ => WorkspaceScope::Broad,
        }
    }

    /// Approval cards currently blocking this agent. Attach replays these so a
    /// phone reconnect/background cycle cannot strand a turn forever.
    pub fn agent_permissions(
        &self,
    ) -> Vec<(ToolCallCard, Vec<PermissionOption>, PermissionCategory)> {
        let Backend::Acp { handle } = &self.inner.backend else {
            return Vec::new();
        };
        handle
            .pending
            .lock()
            .unwrap()
            .values()
            .map(|pending| {
                (
                    pending.tool_call.clone(),
                    pending.options.clone(),
                    pending.category,
                )
            })
            .collect()
    }

    /// Is this approval card still waiting for an answer? Drives the push
    /// doorbell's graced re-check: a card answered during the grace window
    /// must not ring the user's pocket.
    pub fn agent_permission_pending(&self, tool_call_id: &str) -> bool {
        let Backend::Acp { handle } = &self.inner.backend else {
            return false;
        };
        handle.pending.lock().unwrap().contains_key(tool_call_id)
    }

    /// Does this session have ANY approval still waiting? Used by the doorbell's
    /// post-lag reconciliation: after the event broadcast drops messages, the
    /// agent may be blocked on a permission we never saw, so we re-check the
    /// source of truth instead of trusting the (lossy) event stream.
    pub fn has_pending_permission(&self) -> bool {
        let Backend::Acp { handle } = &self.inner.backend else {
            return false;
        };
        !handle.pending.lock().unwrap().is_empty()
    }

    /// Rename the session (phone gave it a custom title). Cheap lock swap; the
    /// next `info()` / `list()` reflects it.
    pub fn set_title(&self, title: String) {
        *self.inner.title.lock().unwrap() = title;
    }

    /// Push external output into this session (adopted sessions: bytes arriving
    /// from the relay pipe). PTY-backed sessions fill their ring via the reader
    /// task instead and don't call this.
    pub fn push_output(&self, bytes: &[u8]) {
        self.inner.push_output(bytes);
    }

    /// Write keystrokes into the session (input from the phone/browser).
    pub fn write_input(&self, bytes: &[u8]) -> std::io::Result<()> {
        match &self.inner.backend {
            Backend::Pty { writer, .. } => {
                let mut w = writer.lock().unwrap();
                w.write_all(bytes)?;
                w.flush()?;
                Ok(())
            }
            Backend::Adopted { to_relay } => to_relay
                .try_send(HostToRelay::Input(bytes.to_vec()))
                .map_err(|e| {
                    // Callers swallow this error (input is fire-and-forget), so
                    // a dropped keystroke must at least be visible in the log.
                    tracing::warn!(
                        id = self.id().0,
                        "input dropped: relay control queue {}",
                        if matches!(e, tokio::sync::mpsc::error::TrySendError::Full(_)) {
                            "full"
                        } else {
                            "closed"
                        }
                    );
                    broken_pipe()
                }),
            // Agent sessions take whole prompts (see `agent_prompt`), not raw keystrokes.
            Backend::Acp { .. } => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "agent sessions take prompts, not raw keystrokes",
            )),
        }
    }

    /// The session's authoritative PTY size (what the phone's match-width mode
    /// should render at).
    pub fn size(&self) -> (u16, u16) {
        *self.inner.size.lock().unwrap()
    }

    /// Record a new authoritative size reported by the process that owns the
    /// PTY (an adopted session's relay after a laptop resize). Does NOT resize
    /// anything - the owner already did - it just updates the record and
    /// broadcasts `ManagerEvent::Resized` so viewers follow. No-op if unchanged.
    pub fn set_size(&self, cols: u16, rows: u16) {
        {
            let mut size = self.inner.size.lock().unwrap();
            if *size == (cols, rows) {
                return;
            }
            *size = (cols, rows);
        }
        let _ = self.inner.events_tx.send(ManagerEvent::Resized {
            id: self.id,
            cols,
            rows,
        });
    }

    /// Resize a HOST-OWNED PTY. Only the local-proof browser calls this (a dev
    /// tool with a single viewer); the phone path ignores viewer resizes - the
    /// fixed-size model makes the PTY size authoritative, not viewer-driven.
    /// Adopted sessions refuse: their laptop terminal is the sole size owner.
    pub fn resize(&self, cols: u16, rows: u16) -> std::io::Result<()> {
        if self.size() == (cols, rows) {
            return Ok(()); // no-op resizes would still raise SIGWINCH (prompt spam)
        }
        match &self.inner.backend {
            Backend::Pty { master, .. } => {
                let guard = master.lock().unwrap();
                // `kill` closed the PTY. Say so rather than reporting success for
                // a resize that reached nothing.
                let master = guard.as_ref().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "session PTY is closed")
                })?;
                master
                    .resize(PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                drop(guard);
                self.set_size(cols, rows);
                Ok(())
            }
            // The laptop terminal owns an adopted session's size.
            Backend::Adopted { .. } => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "adopted sessions are sized by their own terminal",
            )),
            // No PTY behind an agent session - nothing to resize.
            Backend::Acp { .. } => Ok(()),
        }
    }

    /// Send a user message (prompt) to an agent session. Shells don't take prompts.
    pub fn agent_prompt(&self, text: String) -> std::io::Result<()> {
        if text.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "agent prompt cannot be empty",
            ));
        }
        if text.len() > MAX_AGENT_PROMPT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "agent prompt is too large",
            ));
        }
        match &self.inner.backend {
            Backend::Acp { handle } => {
                let command = self.agent_command_for_text(&text)?;
                handle
                    .command_tx
                    .try_send(command)
                    .map_err(|error| match error {
                        mpsc::error::TrySendError::Full(_) => std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "agent prompt queue is full",
                        ),
                        // The driver is gone (agent exited/crashed) but the
                        // session is kept so its final error card stays
                        // readable - tell the user what to do, not "pipe".
                        mpsc::error::TrySendError::Closed(_) => std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "the agent has exited - close this session and start a new one",
                        ),
                    })?;
                // Portty-local /mode and /model commands are controls rather
                // than conversation messages. Other slash commands remain
                // ordinary prompts, exactly as ACP specifies.
                if !is_portty_control_command(&text) {
                    self.inner.push_agent_event(AgentEvent::UserMessage {
                        text: clamp_agent_text(text),
                    });
                }
                Ok(())
            }
            _ => Err(broken_pipe()),
        }
    }

    fn agent_command_for_text(&self, text: &str) -> std::io::Result<AcpCommand> {
        let trimmed = text.trim();
        let Backend::Acp { handle } = &self.inner.backend else {
            return Err(broken_pipe());
        };
        if trimmed == "/mode" {
            let modes = self.mode_choice_summary();
            return Err(invalid_agent_control(&format!(
                "usage: /mode <mode-id>{modes}"
            )));
        }
        if let Some(value) = trimmed.strip_prefix("/mode ").map(str::trim) {
            if value.is_empty() {
                let modes = self.mode_choice_summary();
                return Err(invalid_agent_control(&format!(
                    "usage: /mode <mode-id>{modes}"
                )));
            }
            validate_agent_control_id(value, "mode id")?;
            return Ok(AcpCommand::SetMode {
                mode_id: value.to_string(),
                response: None,
            });
        }
        if trimmed == "/model" {
            let models = self.model_choice_summary();
            return Err(invalid_agent_control(&format!(
                "usage: /model <model-id>{models}"
            )));
        }
        if let Some(value) = trimmed.strip_prefix("/model ").map(str::trim) {
            if value.is_empty() {
                let models = self.model_choice_summary();
                return Err(invalid_agent_control(&format!(
                    "usage: /model <model-id>{models}"
                )));
            }
            validate_agent_control_id(value, "model id")?;
            let history = handle.history.lock().unwrap();
            let model = history
                .sticky
                .get(&StickyAgentEvent::Config)
                .and_then(|event| {
                    let AgentEvent::ConfigOptions { options } = &event.event else {
                        return None;
                    };
                    options
                        .iter()
                        .find(|option| option.category.as_deref() == Some("model"))
                        .map(|option| option.id.clone())
                });
            return model
                .map(|config_id| AcpCommand::SetConfig {
                    config_id,
                    value: AgentConfigValue::Select(value.to_string()),
                    response: None,
                })
                .ok_or_else(|| {
                    invalid_agent_control("this agent did not advertise model switching")
                });
        }
        if let Some(command_text) = trimmed.strip_prefix('/') {
            let name = command_text
                .split_once(char::is_whitespace)
                .map_or(command_text, |(name, _)| name);
            // Only command-shaped names are gated. Text like `/tmp/build.log
            // explain` or `/etc. the rest` is an ordinary prompt that happens
            // to start with a path - send it to the agent untouched.
            let command_shaped = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':'));
            if command_shaped {
                let history = handle.history.lock().unwrap();
                // None = the agent never advertised a command list (yet) -
                // forward like the pre-gate builds did, both for adapters that
                // don't publish commands and for the startup window before the
                // advertisement arrives. Only a known list rejects unknowns.
                let advertised =
                    history
                        .sticky
                        .get(&StickyAgentEvent::Commands)
                        .and_then(|event| match &event.event {
                            AgentEvent::AvailableCommands { commands } => {
                                Some(commands.iter().any(|command| command.name == name))
                            }
                            _ => None,
                        });
                if advertised == Some(false) {
                    return Err(invalid_agent_control(
                        "unknown slash command for this agent",
                    ));
                }
            }
        }
        Ok(AcpCommand::Prompt(text.to_string()))
    }

    /// `\navailable: a, b, c` for the /mode usage error, or empty when the
    /// agent never advertised modes.
    fn mode_choice_summary(&self) -> String {
        let Backend::Acp { handle } = &self.inner.backend else {
            return String::new();
        };
        let history = handle.history.lock().unwrap();
        let Some(event) = history.sticky.get(&StickyAgentEvent::Mode) else {
            return String::new();
        };
        let AgentEvent::ModeState {
            available_modes, ..
        } = &event.event
        else {
            return String::new();
        };
        summarize_choices(available_modes.iter().map(|mode| mode.id.as_str()))
    }

    /// `\navailable: a, b, c` for the /model usage error, or empty when the
    /// agent has no model option.
    fn model_choice_summary(&self) -> String {
        let Backend::Acp { handle } = &self.inner.backend else {
            return String::new();
        };
        let history = handle.history.lock().unwrap();
        let Some(event) = history.sticky.get(&StickyAgentEvent::Config) else {
            return String::new();
        };
        let AgentEvent::ConfigOptions { options } = &event.event else {
            return String::new();
        };
        let Some(model) = options
            .iter()
            .find(|option| option.category.as_deref() == Some("model"))
        else {
            return String::new();
        };
        summarize_choices(model.choices.iter().map(|choice| choice.value.as_str()))
    }

    /// Cancel the running turn without destroying its ACP conversation.
    pub fn agent_cancel(&self) -> std::io::Result<()> {
        self.send_agent_command(AcpCommand::Cancel)
    }

    pub async fn agent_set_mode(&self, mode_id: String) -> std::io::Result<()> {
        validate_agent_control_id(&mode_id, "mode id")?;
        let (response, receiver) = oneshot::channel();
        self.send_agent_command(AcpCommand::SetMode {
            mode_id,
            response: Some(response),
        })?;
        await_agent_control(receiver).await
    }

    pub async fn agent_set_config(
        &self,
        config_id: String,
        value: AgentConfigValue,
    ) -> std::io::Result<()> {
        validate_agent_control_id(&config_id, "config id")?;
        if let AgentConfigValue::Select(value) = &value {
            validate_agent_control_id(value, "config value")?;
        }
        let (response, receiver) = oneshot::channel();
        self.send_agent_command(AcpCommand::SetConfig {
            config_id,
            value,
            response: Some(response),
        })?;
        await_agent_control(receiver).await
    }

    /// Set the provider's advertised model option without requiring a caller
    /// to know its provider-specific configuration id.
    pub async fn agent_set_model(&self, model_id: String) -> std::io::Result<()> {
        validate_agent_control_id(&model_id, "model id")?;
        let config_id = {
            let Backend::Acp { handle } = &self.inner.backend else {
                return Err(broken_pipe());
            };
            let history = handle.history.lock().unwrap();
            history
                .sticky
                .get(&StickyAgentEvent::Config)
                .and_then(|event| {
                    let AgentEvent::ConfigOptions { options } = &event.event else {
                        return None;
                    };
                    options
                        .iter()
                        .find(|option| option.category.as_deref() == Some("model"))
                        .map(|option| option.id.clone())
                })
                .ok_or_else(|| {
                    invalid_agent_control("this agent did not advertise a model setting")
                })?
        };
        self.agent_set_config(config_id, AgentConfigValue::Select(model_id))
            .await
    }

    pub fn agent_authenticate(&self, method_id: String) -> std::io::Result<()> {
        validate_agent_control_id(&method_id, "authentication method id")?;
        self.send_agent_command(AcpCommand::Authenticate(method_id))
    }

    fn send_agent_command(&self, command: AcpCommand) -> std::io::Result<()> {
        let Backend::Acp { handle } = &self.inner.backend else {
            return Err(broken_pipe());
        };
        handle
            .command_tx
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "agent command queue is full",
                ),
                mpsc::error::TrySendError::Closed(_) => std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the agent has exited - close this session and start a new one",
                ),
            })
    }

    /// Resolve a pending agent permission request (from the phone's
    /// `PermissionDecision` or the laptop chat's `AgentDecision`).
    ///
    /// See [`permission_outcome`] for how an answer maps onto what the adapter is
    /// told and what other viewers are told.
    /// `Some(option_id)` = approve; `None` = reject. `by` names the viewer that
    /// answered so the other viewers can say what happened.
    /// No-op if this session has no matching pending request.
    pub fn resolve_permission(
        &self,
        tool_call_id: &str,
        option_id: Option<String>,
        by: PermissionResolver,
    ) {
        if let Backend::Acp { handle } = &self.inner.backend {
            if let Some(pending) = handle.pending.lock().unwrap().remove(tool_call_id) {
                let (decision, resolution) = permission_outcome(option_id, &pending.options);
                let _ = pending.responder.send(decision);
                // Tell every OTHER viewer the card is answered - with a phone
                // and a laptop chat on one session, the deciding device must
                // dismiss the card on the other one.
                let _ = self
                    .inner
                    .events_tx
                    .send(ManagerEvent::AgentPermissionResolved {
                        id: self.id,
                        tool_call_id: tool_call_id.to_string(),
                        resolution,
                        by,
                    });
            }
        }
    }

    /// Which coding-agent preset backs this session (`None` for shells).
    pub fn provider(&self) -> Option<AgentProvider> {
        self.inner.provider
    }

    /// True while the ACP driver still consumes prompts (the agent process is
    /// running). Dead-but-listed agent sessions return false.
    pub fn agent_alive(&self) -> bool {
        match &self.inner.backend {
            Backend::Acp { handle } => !handle.command_tx.is_closed(),
            _ => false,
        }
    }
}

async fn await_agent_control(
    receiver: oneshot::Receiver<Result<(), String>>,
) -> std::io::Result<()> {
    match tokio::time::timeout(std::time::Duration::from_secs(30), receiver).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(message))) => Err(std::io::Error::other(message)),
        Ok(Err(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "agent connection ended before the setting changed",
        )),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "agent setting change timed out",
        )),
    }
}

fn is_portty_control_command(text: &str) -> bool {
    let text = text.trim_start();
    text == "/mode" || text.starts_with("/mode ") || text == "/model" || text.starts_with("/model ")
}

fn invalid_agent_control(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

/// Render `\navailable: a, b, c (+N more)` for a usage error; empty when
/// there is nothing to offer. Capped so the error stays a readable one-liner.
fn summarize_choices<'a>(choices: impl Iterator<Item = &'a str>) -> String {
    const MAX_LISTED: usize = 12;
    let mut listed: Vec<&str> = Vec::new();
    let mut extra = 0usize;
    for choice in choices {
        if listed.len() < MAX_LISTED {
            listed.push(choice);
        } else {
            extra += 1;
        }
    }
    if listed.is_empty() {
        return String::new();
    }
    let mut summary = format!("\navailable: {}", listed.join(", "));
    if extra > 0 {
        summary.push_str(&format!(" (+{extra} more)"));
    }
    summary
}

fn validate_agent_control_id(value: &str, label: &str) -> std::io::Result<()> {
    if value.is_empty() || value.len() > MAX_AGENT_SHORT_TEXT_BYTES {
        return Err(invalid_agent_control(&format!(
            "{label} must be 1..={MAX_AGENT_SHORT_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn broken_pipe() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "relay is gone")
}

#[derive(Clone)]
pub struct SessionManager {
    next_id: Arc<Mutex<u64>>,
    sessions: Arc<Mutex<HashMap<SessionId, SessionEntry>>>,
    events_tx: broadcast::Sender<ManagerEvent>,
    scrollback_cap: Arc<usize>,
    /// Concurrent-session cap, resolved once at construction (see `max_sessions`).
    max_sessions: usize,
    /// Atomic admission gate shared by phone, browser, and local relay callers.
    session_slots: Arc<Semaphore>,
    /// Conversations learned from ACP `session/list` probes, so a resume can
    /// recover the provider for an id that was never in the on-disk cache.
    discovered: Arc<StdMutex<DiscoveredAcpSessions>>,
    /// Recent probe answers, so navigating the folder picker does not relaunch an
    /// adapter per tap.
    probes: Arc<StdMutex<ProbeMemos>>,
    /// One adapter probe at a time, host-wide. The serve loop hands each listing
    /// to its own task so a slow agent cannot freeze the phone's terminal, which
    /// removes the accidental serialization that awaiting inline used to provide -
    /// without this, a burst of folder taps is a burst of adapter processes.
    probe_slots: Arc<Semaphore>,
    /// Always [`adapter_launch_for`] in production; see [`AdapterResolver`].
    adapter_resolver: AdapterResolver,
}

/// The permit lives in the registry rather than in `Session`: removing a session
/// returns capacity immediately even if an output forwarder still holds an Arc.
struct SessionEntry {
    session: Arc<Session>,
    _permit: OwnedSemaphorePermit,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::new_with_cap(DEFAULT_SCROLLBACK_BYTES)
    }

    /// Build a manager with a custom per-session scrollback cap (bytes). Clamped
    /// upstream by `scrollback_cap_from_env`; used directly when tests want a
    /// known cap.
    pub fn new_with_cap(cap: usize) -> Self {
        Self::new_with_limits(cap, max_sessions())
    }

    fn new_with_limits(cap: usize, max_sessions: usize) -> Self {
        let (events_tx, _) = broadcast::channel(64);
        Self {
            next_id: Arc::new(Mutex::new(1)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            events_tx,
            scrollback_cap: Arc::new(cap),
            max_sessions,
            session_slots: Arc::new(Semaphore::new(max_sessions)),
            discovered: Arc::new(StdMutex::new(DiscoveredAcpSessions::default())),
            probes: Arc::new(StdMutex::new(ProbeMemos::default())),
            probe_slots: Arc::new(Semaphore::new(1)),
            adapter_resolver: default_adapter_resolver(),
        }
    }

    /// A manager whose providers resolve to `resolver` instead of to the
    /// adapters installed on this machine. See [`AdapterResolver`].
    #[cfg(test)]
    fn new_with_adapter_resolver(resolver: AdapterResolver) -> Self {
        Self {
            adapter_resolver: resolver,
            ..Self::new()
        }
    }

    pub async fn list(&self) -> Vec<SessionInfo> {
        self.sessions
            .lock()
            .await
            .values()
            .map(|entry| entry.session.info())
            .collect()
    }

    pub async fn get(&self, id: SessionId) -> Option<Arc<Session>> {
        self.sessions
            .lock()
            .await
            .get(&id)
            .map(|entry| entry.session.clone())
    }

    /// The most recently created LIVE agent session for `provider`, if any.
    /// `portty agent` joins it so the laptop chat and the phone drive ONE
    /// conversation instead of spawning a parallel agent.
    pub async fn newest_live_agent(&self, provider: AgentProvider) -> Option<Arc<Session>> {
        self.sessions
            .lock()
            .await
            .iter()
            .filter(|(_, entry)| {
                entry.session.provider() == Some(provider) && entry.session.agent_alive()
            })
            .max_by_key(|(id, _)| id.0)
            .map(|(_, entry)| entry.session.clone())
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ManagerEvent> {
        self.events_tx.subscribe()
    }

    /// Is an approval card still unanswered? (See `Session::agent_permission_pending`.)
    pub async fn agent_permission_pending(&self, id: SessionId, tool_call_id: &str) -> bool {
        match self.get(id).await {
            Some(session) => session.agent_permission_pending(tool_call_id),
            None => false,
        }
    }

    /// Is ANY agent session holding an unanswered approval? The doorbell falls
    /// back to this after a broadcast lag, when a dropped `AgentPermission`
    /// could otherwise leave a locked phone unrung with no further event coming.
    pub async fn any_agent_permission_pending(&self) -> bool {
        self.sessions
            .lock()
            .await
            .values()
            .any(|entry| entry.session.has_pending_permission())
    }

    async fn next_id(&self) -> SessionId {
        let mut n = self.next_id.lock().await;
        let v = *n;
        *n += 1;
        SessionId(v)
    }

    /// Atomically reserve a session slot across every creation path. The permit
    /// is inserted with the session, or returned automatically on any failure.
    fn reserve_capacity(&self) -> crate::error::HostResult<OwnedSemaphorePermit> {
        self.session_slots.clone().try_acquire_owned().map_err(|_| {
            crate::error::HostError::Limit(format!(
                "session limit reached ({}); close a session first",
                self.max_sessions
            ))
        })
    }

    /// Spawn a new shell session the host owns. `cwd=None` → the daemon's cwd.
    /// The PTY is BORN at the daemon's fixed size (see [`fixed_pty_size`]) and
    /// stays there - viewers render around it, they never resize it.
    pub async fn spawn_shell(
        &self,
        cwd: Option<PathBuf>,
        title: Option<String>,
    ) -> crate::error::HostResult<SessionId> {
        let permit = self.reserve_capacity()?;
        let id = self.next_id().await;

        let (cols, rows) = fixed_pty_size();
        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| crate::error::HostError::Pty(e.to_string()))?;
        let master = pair.master;
        let slave = pair.slave;

        let mut cmd = login_shell_command();
        // Defence in depth: the daemon already takes the relay bearer secrets out
        // of its own environment on startup (see push::push_secret_env), so this
        // covers a build or code path where that has not run yet. A phone
        // terminal must not be able to read them out of `env`.
        for key in crate::push::PUSH_SECRET_ENV_VARS {
            cmd.env_remove(key);
        }
        // This session is already portal-connected - the daemon owns its PTY.
        // Without this, a `portty install` profile hook in the user's shell rc
        // would see a fresh interactive shell and `exec portty share`, self-
        // wrapping the phone-spawned session into a duplicate adopted one.
        cmd.env("PORTTY_RELAY", "1");
        // `None` means "wherever the workspace is", NOT "wherever portable_pty
        // feels like" - see `default_shell_cwd`.
        if let Some(cwd) = cwd.or_else(default_shell_cwd) {
            cmd.cwd(cwd);
        }
        let child = slave
            .spawn_command(cmd)
            .map_err(|e| crate::error::HostError::Pty(e.to_string()))?;
        let reader = master
            .try_clone_reader()
            .map_err(|e| crate::error::HostError::Pty(e.to_string()))?;
        let writer = master
            .take_writer()
            .map_err(|e| crate::error::HostError::Pty(e.to_string()))?;
        drop(slave); // closing the slave lets EOF propagate to the master reader

        let (output_tx, _) = broadcast::channel::<Arc<OutputChunk>>(256);
        let inner = Arc::new(SessionInner {
            id,
            title: StdMutex::new(clamp_title(title.unwrap_or_else(|| "shell".into()))),
            kind: SessionKind::Shell,
            source: SessionSource::Spawned,
            provider: None,
            backend: Backend::Pty {
                master: StdMutex::new(Some(master)),
                writer: StdMutex::new(writer),
                child: StdMutex::new(Some(child)),
            },
            scrollback: StdMutex::new(ScrollbackRing::default()),
            cap: *self.scrollback_cap,
            output_tx,
            next_output_seq: AtomicU64::new(1),
            has_unseen_activity: AtomicBool::new(false),
            events_tx: self.events_tx.clone(),
            size: StdMutex::new((cols, rows)),
        });
        let session = Arc::new(Session {
            id,
            inner: inner.clone(),
        });
        self.sessions.lock().await.insert(
            id,
            SessionEntry {
                session: session.clone(),
                _permit: permit,
            },
        );

        // Reader task: blocking drain → scrollback + broadcast. When it returns
        // (child exited → master reader EOF), reap + remove the session.
        let manager = self.clone();
        tokio::spawn(async move {
            tokio::task::spawn_blocking(move || drain_reader(inner, reader))
                .await
                .ok();
            manager.remove_dead(id).await;
        });

        let _ = self.events_tx.send(ManagerEvent::Added(session.info()));
        Ok(id)
    }

    /// Register a terminal owned by a `portty` relay in another process. Output
    /// arrives via `session.push_output`; input/kill go out on `to_relay`.
    /// `cols`/`rows` is the relay's LOCAL terminal size - the authoritative size
    /// for the session's lifetime (updated by `RelayToHost::SizeChanged`).
    /// Returns the id and the session handle (the pipe handler drives it).
    pub async fn register_adopted(
        &self,
        title: String,
        cols: u16,
        rows: u16,
        to_relay: mpsc::Sender<HostToRelay>,
    ) -> crate::error::HostResult<(SessionId, Arc<Session>)> {
        let permit = self.reserve_capacity()?;
        let id = self.next_id().await;
        let (output_tx, _) = broadcast::channel::<Arc<OutputChunk>>(256);
        let inner = Arc::new(SessionInner {
            id,
            title: StdMutex::new(clamp_title(title)),
            kind: SessionKind::Shell,
            source: SessionSource::Adopted,
            provider: None,
            backend: Backend::Adopted { to_relay },
            scrollback: StdMutex::new(ScrollbackRing::default()),
            cap: *self.scrollback_cap,
            output_tx,
            next_output_seq: AtomicU64::new(1),
            has_unseen_activity: AtomicBool::new(false),
            events_tx: self.events_tx.clone(),
            size: StdMutex::new((cols, rows)),
        });
        let session = Arc::new(Session { id, inner });
        self.sessions.lock().await.insert(
            id,
            SessionEntry {
                session: session.clone(),
                _permit: permit,
            },
        );
        let _ = self.events_tx.send(ManagerEvent::Added(session.info()));
        Ok((id, session))
    }

    /// Spawn an ACP agent session (the ceiling). `spec` is an agent command
    /// string parsed by `AcpAgent::from_str` (e.g. `"npx -y
    /// @agentclientprotocol/codex-acp"`, or later a preset name from a registry).
    /// The agent must be authenticated in the host's environment - creds are
    /// inherited, not handled here (deferred sub-step).
    ///
    /// **Windows note:** `spec` is shell-tokenized, so backslashes are treated
    /// as escapes. Use forward slashes in any path inside `spec`
    /// (e.g. `python C:/path/to/agent.py`, not `C:\path\to\agent.py`).
    #[cfg(test)]
    pub async fn spawn_agent(
        &self,
        spec: &str,
        title: Option<String>,
        provider: Option<AgentProvider>,
    ) -> crate::error::HostResult<SessionId> {
        let agent = acp_agent_from_spec(spec)?;
        let cwd = std::env::current_dir()?;
        // `Latest` preserves the old `fresh: false` behaviour exactly.
        self.spawn_agent_with(agent, title, provider, cwd, AgentResume::Latest)
            .await
    }

    /// Adapter availability for every provider, so the phone can show which
    /// agents this host can actually launch instead of finding out by failing.
    pub async fn agent_provider_availability(&self) -> Vec<AgentProviderAvailability> {
        tokio::task::spawn_blocking(|| {
            [
                AgentProvider::ClaudeCode,
                AgentProvider::OpenCode,
                AgentProvider::Codex,
                AgentProvider::Goose,
            ]
            .into_iter()
            .map(|provider| {
                let detail = provider_readiness(provider);
                AgentProviderAvailability {
                    provider,
                    available: detail.is_none(),
                    detail,
                }
            })
            .collect()
        })
        .await
        .unwrap_or_default()
    }

    /// Every conversation cached for `cwd`, newest first, for the phone's picker.
    ///
    /// Read-only and off the runtime - the cache lives on disk, and this runs on
    /// the request loop that also pumps terminal output to the phone.
    pub async fn list_agent_sessions(&self, cwd: PathBuf) -> Vec<AgentSessionSummary> {
        tokio::task::spawn_blocking(move || {
            list_cached_acp_sessions(&cwd)
                .into_iter()
                .map(|entry| AgentSessionSummary {
                    acp_session_id: entry.acp_session_id,
                    provider: entry.provider,
                    title: entry.title,
                    label: entry.first_prompt_label,
                    last_active_at_unix_ms: entry.last_active_at_unix_ms,
                })
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    /// Every conversation `provider` can continue in `cwd`, newest first: the
    /// ones Portty cached AND the ones the agent itself remembers.
    ///
    /// Provider-scoped because the second half costs an adapter launch (see
    /// [`probe_agent_sessions`]), and because a picker you entered by choosing
    /// Claude Code should not offer to resume an OpenCode chat - tapping that row
    /// would correctly start OpenCode, which is not what the screen promised.
    pub async fn list_agent_sessions_for(
        &self,
        provider: AgentProvider,
        cwd: PathBuf,
    ) -> Vec<AgentSessionSummary> {
        let cache_cwd = cwd.clone();
        let cached = tokio::task::spawn_blocking(move || list_cached_acp_sessions(&cache_cwd))
            .await
            .unwrap_or_default();
        // The CACHE half is always re-read - it is a file, it is cheap, and it is
        // where a conversation started from this phone a moment ago appears. Only
        // the adapter launch is memoized.
        //
        // Each memo read is bound before its `match`, not inside it: a match
        // scrutinee's temporaries live for the whole match, which would hold this
        // std mutex across the probe's `.await`.
        let memoized = self.memoized_probe(provider, &cwd);
        let discovered = match memoized {
            Some(memoized) => memoized,
            None => {
                // One adapter at a time host-wide, and only for so long: a listing
                // that cannot get the slot answers from the cache rather than
                // queueing past the point where the phone is still listening.
                let Ok(Ok(_slot)) =
                    tokio::time::timeout(ACP_PROBE_QUEUE_WAIT, self.probe_slots.acquire()).await
                else {
                    tracing::debug!(
                        ?provider,
                        "another agent listing is still running; answering from the cache"
                    );
                    return merge_agent_sessions(provider, cached, Vec::new());
                };
                // Re-checked now that the slot is ours: two taps on the same
                // folder both miss above, and the second must use what the first
                // just learned rather than launching the adapter again.
                match self.memoized_probe(provider, &cwd) {
                    Some(memoized) => memoized,
                    None => {
                        let fresh = probe_agent_sessions(
                            self.adapter_resolver.clone(),
                            provider,
                            cwd.clone(),
                        )
                        .await;
                        self.probes.lock().unwrap().store(ProbeMemo {
                            provider,
                            cwd,
                            taken_at: std::time::Instant::now(),
                            sessions: fresh.clone(),
                        });
                        fresh
                    }
                }
            }
        };
        // Remembered BEFORE the merge drops duplicates: the index exists so a
        // resume can recover the provider, and that is just as true for an id the
        // cache already knew about.
        self.discovered.lock().unwrap().remember(&discovered);
        merge_agent_sessions(provider, cached, discovered)
    }

    fn memoized_probe(
        &self,
        provider: AgentProvider,
        cwd: &std::path::Path,
    ) -> Option<Vec<DiscoveredAcpSession>> {
        self.probes
            .lock()
            .unwrap()
            .get(provider, cwd, std::time::Instant::now())
    }

    /// The record behind one resumable id, from the disk cache or - for a
    /// conversation Portty never started - from the last probe.
    ///
    /// One lookup for both entry points, so "which agent owns this id" is decided
    /// in exactly one place. Nothing here reads the phone's request beyond the id
    /// itself; `cwd` is whatever the workspace resolver produced.
    async fn resumable_conversation(
        &self,
        cwd: &std::path::Path,
        acp_session_id: &str,
    ) -> Option<CachedAcpSession> {
        let lookup_cwd = cwd.to_path_buf();
        let lookup_id = acp_session_id.to_string();
        let cached =
            tokio::task::spawn_blocking(move || cached_acp_session_by_id(&lookup_cwd, &lookup_id))
                .await
                .ok()
                .flatten();
        cached.or_else(|| {
            let discovered = self.discovered.lock().unwrap();
            let entry = discovered.find(cwd, acp_session_id)?;
            // Deliberately no desired mode or config: those describe how Portty
            // last drove a conversation, and it never drove this one. The agent's
            // own state stands.
            Some(CachedAcpSession {
                provider: entry.provider,
                cwd: entry.cwd.clone(),
                acp_session_id: entry.acp_session_id.clone(),
                title: entry.title.clone(),
                first_prompt_label: None,
                last_active_at_unix_ms: entry.last_active_at_unix_ms.unwrap_or_default(),
                desired_mode: None,
                desired_config: HashMap::new(),
            })
        })
    }

    /// Reopen one specific saved conversation.
    ///
    /// The provider comes from the HOST's record - the disk cache, or the index
    /// of what the last probe saw - never from the phone: the id and the
    /// directory identify the conversation, and the record already knows which
    /// agent owns it. Resuming a Claude conversation into OpenCode because the
    /// phone said so would be a silent data mix-up.
    pub async fn resume_agent_session(
        &self,
        cwd: PathBuf,
        acp_session_id: String,
    ) -> crate::error::HostResult<SessionId> {
        let entry = self
            .resumable_conversation(&cwd, &acp_session_id)
            .await
            .ok_or_else(|| {
                crate::error::HostError::Acp(
                    "that conversation is no longer saved on this host".into(),
                )
            })?;
        self.spawn_agent_provider(
            entry.provider,
            Some(entry.title.clone()),
            AgentResume::Session(acp_session_id),
            Some(cwd),
        )
        .await
    }

    /// Launch an allow-listed coding agent. Credentials are inherited from the
    /// host environment, matching how the same CLI runs in the laptop terminal.
    /// `fresh` starts a brand-new conversation; otherwise the driver resumes
    /// the provider's most recent cached ACP session in this workspace (unless
    /// a live Portty session already owns it).
    ///
    /// `cwd` is the directory the phone chose, already resolved and proved to be
    /// inside the workspace by `crate::workspace` - this never re-derives it, so
    /// there is exactly one place that decides what is reachable. `None` means
    /// the workspace root, which is what the frozen `NewAgentSession` request
    /// (and the laptop CLI) still ask for.
    ///
    /// Whatever lands here becomes the agent's cwd AND its ACP file-access
    /// sandbox root (see `run_acp_session`), so a narrower choice is strictly
    /// less reachable filesystem, never more.
    pub async fn spawn_agent_provider(
        &self,
        provider: AgentProvider,
        title: Option<String>,
        resume: AgentResume,
        cwd: Option<PathBuf>,
    ) -> crate::error::HostResult<SessionId> {
        // Preflight the launcher binary. The actual spawn happens later inside
        // the driver task (after the session already exists), so without this
        // check a missing runtime creates a dead session that still holds a
        // capacity slot - and every retry from the phone piles up another one.
        // `command_available` shells out (login shell), so it runs off-loop.
        let resolver = self.adapter_resolver.clone();
        let preflight = tokio::task::spawn_blocking(move || {
            let launch = resolver(provider)?;
            if !command_available(&launch.required) {
                return Err(crate::error::HostError::Acp(format!(
                    "`{}` was not found on this host - {}",
                    launch.required, launch.hint
                )));
            }
            let cwd = match cwd {
                Some(chosen) => chosen,
                None => std::fs::canonicalize(crate::iroh_serve::workspace_dir())?,
            };
            Ok((launch.spec, launch.default_title, cwd))
        })
        .await
        .map_err(|error| crate::error::HostError::Acp(error.to_string()))?;
        let (spec, default_title, cwd) = preflight?;
        let agent = acp_agent_from_spec(&spec)?;
        self.spawn_agent_with(
            agent,
            Some(title.unwrap_or_else(|| default_title.into())),
            Some(provider),
            cwd,
            resume,
        )
        .await
    }

    async fn spawn_agent_with(
        &self,
        agent: AcpAgent,
        title: Option<String>,
        provider: Option<AgentProvider>,
        cwd: PathBuf,
        resume: AgentResume,
    ) -> crate::error::HostResult<SessionId> {
        // Seed conversation resume BEFORE the driver exists: a fresh spawn
        // never resumes. The cache read is blocking IO, so it happens off the
        // runtime; the live-ownership check happens LATER, inside the same
        // sessions-lock scope that registers this session, so two overlapping
        // spawns cannot both adopt one cached conversation.
        let cached = match (&resume, provider) {
            (AgentResume::Fresh, _) | (_, None) => None,
            (AgentResume::Latest, Some(_)) => {
                let seed_provider = provider;
                let seed_cwd = cwd.clone();
                tokio::task::spawn_blocking(move || cached_acp_session(seed_provider, &seed_cwd))
                    .await
                    .unwrap_or_default()
            }
            (AgentResume::Session(id), Some(_)) => {
                // Looked up by (cwd, id) - the phone names the id, the workspace
                // resolver supplies the directory. A miss resumes NOTHING rather
                // than silently falling back to the newest conversation, which
                // would hand the user a different chat than the one they tapped.
                //
                // Both stores, because a conversation the agent's own CLI started
                // is resumable without ever having been in Portty's cache.
                self.resumable_conversation(&cwd, id).await
            }
        };
        let permit = self.reserve_capacity()?;
        let id = self.next_id().await;
        let (command_tx, command_rx) = mpsc::channel::<AcpCommand>(AGENT_PROMPT_QUEUE);
        let handle = Arc::new(AcpHandle {
            pending: StdMutex::new(HashMap::new()),
            command_tx,
            history: StdMutex::new(AgentHistory::default()),
            next_seq: AtomicU64::new(1),
            driver: StdMutex::new(None),
            acp_session_id: StdMutex::new(None),
            // Classified from the SAME cwd the ACP file sandbox confines to, so
            // the scope the phone sees always describes the root actually in
            // force for this session.
            workspace_scope: crate::workspace::workspace_scope(&cwd),
        });
        let (output_tx, _) = broadcast::channel::<Arc<OutputChunk>>(256);
        let inner = Arc::new(SessionInner {
            id,
            title: StdMutex::new(clamp_title(title.unwrap_or_else(|| "agent".into()))),
            kind: SessionKind::Agent,
            source: SessionSource::Spawned,
            provider,
            backend: Backend::Acp {
                handle: handle.clone(),
            },
            scrollback: StdMutex::new(ScrollbackRing::default()),
            cap: *self.scrollback_cap,
            output_tx,
            next_output_seq: AtomicU64::new(1),
            has_unseen_activity: AtomicBool::new(false),
            events_tx: self.events_tx.clone(),
            // No PTY behind an agent session - report the fixed size for
            // uniformity (the phone renders agent output as cards anyway).
            size: StdMutex::new(fixed_pty_size()),
        });
        let session = Arc::new(Session { id, inner });
        let resume = {
            let mut sessions = self.sessions.lock().await;
            // Ownership check + registration are atomic: a cached conversation
            // already owned by a live driver must not be attached twice (two
            // adapters would cross-drive one ACP conversation). Reserving the
            // id on the new handle before the lock drops closes the window
            // where a second spawn could pass the same check.
            let resume = match cached {
                Some(cached) => {
                    let already_live = sessions.values().any(|entry| {
                        entry.session.inner.provider == provider
                            && matches!(
                                &entry.session.inner.backend,
                                Backend::Acp { handle }
                                    if handle.acp_session_id.lock().unwrap().as_deref()
                                        == Some(cached.acp_session_id.as_str())
                            )
                    });
                    if already_live {
                        tracing::info!(
                            acp_session = %cached.acp_session_id,
                            "cached ACP conversation is already live; starting fresh"
                        );
                        None
                    } else {
                        *handle.acp_session_id.lock().unwrap() =
                            Some(cached.acp_session_id.clone());
                        Some(cached)
                    }
                }
                None => None,
            };
            sessions.insert(
                id,
                SessionEntry {
                    session: session.clone(),
                    _permit: permit,
                },
            );
            resume
        };
        let _ = self.events_tx.send(ManagerEvent::Added(session.info()));
        if let Some(provider) = provider {
            session
                .inner
                .push_agent_event(AgentEvent::SessionStarted { provider });
        }

        // Drive the ACP connection until the agent exits or the session is
        // killed. The session is deliberately NOT removed when the driver ends:
        // the timeline (including the final "Agent connection ended" card) must
        // stay readable on the phone until the user closes it - removal would
        // navigate the phone away and drop the explanation. RAM stays bounded:
        // dead sessions count against `max_sessions` like live ones, and the
        // spawn preflight above keeps doomed sessions from piling up.
        let driver_handle = handle.clone();
        let inner = session.inner.clone();
        let task = tokio::spawn(async move {
            run_acp_session(agent, driver_handle, inner, id, cwd, command_rx, resume).await;
        });
        *handle.driver.lock().unwrap() = Some(task.abort_handle());
        Ok(id)
    }

    /// Route a LEGACY unscoped phone `PermissionDecision` (the frame carries no
    /// SessionId) to the agent session holding this pending `tool_call_id`.
    ///
    /// ACP tool-call ids are only guaranteed unique WITHIN one session, so with
    /// no SessionId we resolve ONLY when exactly one agent session holds the id.
    /// If two sessions happen to share it we refuse rather than approve an action
    /// in a session the user never saw. Modern clients send the session-scoped
    /// `AgentPermissionDecision` and route via `get(id)` instead.
    /// `Some` = approve, `None` = cancel.
    pub async fn resolve_permission(
        &self,
        tool_call_id: &str,
        option_id: Option<String>,
        by: PermissionResolver,
    ) {
        let sessions = self.sessions.lock().await;
        let mut holders = sessions.values().filter(|entry| {
            matches!(entry.session.inner.backend, Backend::Acp { .. })
                && entry.session.agent_permission_pending(tool_call_id)
        });
        let Some(entry) = holders.next() else {
            return; // no agent session has this pending id - no-op
        };
        if holders.next().is_some() {
            tracing::warn!(
                "ignoring unscoped PermissionDecision: tool_call_id is pending in multiple \
                 sessions; the client should send a session-scoped AgentPermissionDecision"
            );
            return;
        }
        entry
            .session
            .resolve_permission(tool_call_id, option_id, by);
    }

    /// Client-initiated rename. Returns true if the session exists and was
    /// renamed. The caller re-sends the session list so the phone re-renders.
    pub async fn rename(&self, id: SessionId, title: String) -> bool {
        match self.sessions.lock().await.get(&id) {
            Some(entry) => {
                entry.session.set_title(clamp_title(title));
                true
            }
            None => false,
        }
    }

    /// Client-initiated kill. Returns true if a session was removed.
    pub async fn kill(&self, id: SessionId) -> bool {
        let mut sessions = self.sessions.lock().await;
        let Some(entry) = sessions.get(&id) else {
            return false;
        };
        // Adopted sessions: deliver Kill BEFORE removing the entry. try_send
        // used to be fire-and-forget - on a full control queue (wedged relay
        // writer) the Kill was silently dropped, the session vanished from the
        // phone's list, and `true` (success) was reported while the `portty
        // share` shell kept running invisibly on the host. Failing honestly
        // keeps the session listed so the user can retry.
        if let Backend::Adopted { to_relay } = &entry.session.inner.backend {
            use tokio::sync::mpsc::error::TrySendError;
            match to_relay.try_send(HostToRelay::Kill) {
                // Closed = the relay is already gone; removal below is correct
                // (remove_dead may race us, which get/remove handles fine).
                Ok(()) | Err(TrySendError::Closed(_)) => {}
                Err(TrySendError::Full(_)) => {
                    tracing::warn!(
                        id = id.0,
                        "kill not delivered: relay control queue full; keeping session"
                    );
                    return false;
                }
            }
        }
        let entry = sessions.remove(&id).expect("checked above");
        drop(sessions);
        let session = entry.session;
        match &session.inner.backend {
            Backend::Pty { child, master, .. } => {
                if let Some(child) = child.lock().unwrap().as_mut() {
                    let _ = child.kill();
                }
                // Then close the PTY, in this order. The kill alone leaves the
                // blocking reader parked forever on Windows (see `Backend::Pty`),
                // which leaks the reader thread and its conhost for the life of
                // the daemon and stops `remove_dead` from ever reaping. Dropping
                // the master gives the reader EOF on every platform, so this is
                // not `cfg`'d: one teardown path, exercised everywhere.
                let closed = master.lock().unwrap().take();
                drop(closed);
            }
            // Kill already delivered above (or the relay is gone).
            Backend::Adopted { .. } => {}
            Backend::Acp { handle } => {
                if let Some(driver) = handle.driver.lock().unwrap().take() {
                    driver.abort();
                }
                // Dropping pending responders cancels any approval currently
                // waiting on the phone.
                handle.pending.lock().unwrap().clear();
                // An explicit kill discards the conversation: pruning the
                // cache means the next spawn starts fresh instead of resuming
                // a chat the user just threw away. (Host restarts don't kill,
                // so continuity across restarts is unaffected.)
                let provider = session.inner.provider;
                if let Some(acp_session_id) = handle.acp_session_id.lock().unwrap().take() {
                    tokio::task::spawn_blocking(move || {
                        prune_cached_acp_session(provider, &acp_session_id);
                    });
                }
            }
        }
        let _ = self.events_tx.send(ManagerEvent::Removed(id));
        true
    }

    /// A session ended (PTY reader hit EOF, or a relay disconnected). Reap + remove.
    pub async fn remove_dead(&self, id: SessionId) {
        if let Some(entry) = self.sessions.lock().await.remove(&id) {
            let session = entry.session;
            if let Backend::Pty { child, .. } = &session.inner.backend {
                if let Some(child) = child.lock().unwrap().as_mut() {
                    let _ = child.wait();
                }
            }
            let _ = self.events_tx.send(ManagerEvent::Removed(id));
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking read loop: PTY master reader → capped scrollback ring + broadcast.
fn drain_reader(inner: Arc<SessionInner>, mut reader: Box<dyn Read + Send>) {
    // 16 KiB: a PTY delivers whatever is buffered in one read, so a bigger
    // buffer means 4× fewer lock/broadcast/frame cycles under heavy output.
    // Shared with file transfer so both stream at the same granularity.
    let mut buf = [0u8; portty_protocol::FILE_CHUNK_BYTES];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break, // EOF or read error → session is done
            Ok(n) => inner.push_output(&buf[..n]),
        }
    }
}

impl AcpTerminals {
    fn new(workspace: PathBuf) -> Self {
        Self {
            workspace,
            next_id: AtomicU64::new(1),
            active: StdMutex::new(HashMap::new()),
            controls: StdMutex::new(Vec::new()),
        }
    }

    fn create(&self, request: CreateTerminalRequest) -> acp::Result<CreateTerminalResponse> {
        let mut controls = self.controls.lock().unwrap();
        // Reclaim completed processes before enforcing the per-session limit.
        // Released-but-running terminals deliberately remain counted.
        controls.retain(|control| !control.is_closed());
        if controls.len() >= MAX_ACP_TERMINALS {
            return Err(acp::Error::invalid_params().data(format!(
                "Portty allows at most {MAX_ACP_TERMINALS} ACP terminals per session"
            )));
        }
        drop(controls);
        let cwd = request.cwd.unwrap_or_else(|| self.workspace.clone());
        let cwd = sandboxed_acp_path(&self.workspace, &cwd, false)?;
        if !cwd.is_dir() {
            return Err(acp::Error::invalid_params().data("terminal cwd is not a directory"));
        }
        let limit = request
            .output_byte_limit
            .map(|value| value.min(MAX_ACP_TERMINAL_OUTPUT_BYTES as u64) as usize)
            .unwrap_or(DEFAULT_ACP_TERMINAL_OUTPUT_BYTES);
        // Same Windows trap as the adapter spawn: an agent asking to run `npm
        // test` would get "program not found" because npm's launcher is
        // `npm.cmd`. Resolution is a no-op on unix and adds no capability - the
        // sandboxed `cwd` above and the phone-side approval are what gate this.
        let program = windows_spawnable_program(&request.command)
            .unwrap_or_else(|| PathBuf::from(&request.command));
        let mut command = tokio::process::Command::new(program);
        command
            .args(request.args)
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        for variable in request.env {
            command.env(variable.name, variable.value);
        }
        // Same reasoning as the phone shell: never hand the relay bearer secrets
        // to an agent-requested command. Applied last so it also wins over an
        // adapter that tries to re-add one through `request.env`.
        for key in crate::push::PUSH_SECRET_ENV_VARS {
            command.env_remove(key);
        }
        let mut child = command.spawn().map_err(acp::Error::into_internal_error)?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (control, mut control_rx) = mpsc::channel(2);
        let terminal = Arc::new(AcpTerminal {
            state: StdMutex::new(AcpTerminalState {
                output_limit: limit,
                ..AcpTerminalState::default()
            }),
            changed: tokio::sync::Notify::new(),
            control: control.clone(),
        });
        if let Some(stdout) = stdout {
            tokio::spawn(capture_terminal_output(stdout, terminal.clone()));
        }
        if let Some(stderr) = stderr {
            tokio::spawn(capture_terminal_output(stderr, terminal.clone()));
        }
        let actor_terminal = terminal.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    status = child.wait() => {
                        let exit_status = match status {
                            Ok(status) => terminal_exit_status(status),
                            Err(error) => TerminalExitStatus::new().signal(error.to_string()),
                        };
                        actor_terminal.state.lock().unwrap().exit_status = Some(exit_status);
                        actor_terminal.changed.notify_waiters();
                        break;
                    }
                    control = control_rx.recv() => {
                        match control {
                            Some(TerminalControl::Kill) => {
                                let _ = child.start_kill();
                            }
                            None => {
                                let _ = child.start_kill();
                            }
                        }
                    }
                }
            }
        });

        let id = format!(
            "portty-terminal-{}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        self.active.lock().unwrap().insert(id.clone(), terminal);
        self.controls.lock().unwrap().push(control);
        Ok(CreateTerminalResponse::new(id))
    }

    fn get(&self, id: &acp::schema::v1::TerminalId) -> acp::Result<Arc<AcpTerminal>> {
        self.active
            .lock()
            .unwrap()
            .get(&id.to_string())
            .cloned()
            .ok_or_else(|| acp::Error::resource_not_found(Some(id.to_string())))
    }

    fn output(&self, request: TerminalOutputRequest) -> acp::Result<TerminalOutputResponse> {
        let terminal = self.get(&request.terminal_id)?;
        let state = terminal.state.lock().unwrap();
        Ok(
            TerminalOutputResponse::new(state.output.clone(), state.truncated)
                .exit_status(state.exit_status.clone()),
        )
    }

    fn kill(&self, request: KillTerminalRequest) -> acp::Result<KillTerminalResponse> {
        let terminal = self.get(&request.terminal_id)?;
        terminal
            .control
            .try_send(TerminalControl::Kill)
            .map_err(acp::Error::into_internal_error)?;
        Ok(KillTerminalResponse::new())
    }

    fn release(&self, request: ReleaseTerminalRequest) -> acp::Result<ReleaseTerminalResponse> {
        self.active
            .lock()
            .unwrap()
            .remove(&request.terminal_id.to_string())
            .ok_or_else(|| acp::Error::resource_not_found(Some(request.terminal_id.to_string())))?;
        // Deliberately do not kill: ACP defines release as resource-handle
        // disposal, distinct from terminal/kill.
        Ok(ReleaseTerminalResponse::new())
    }

    async fn wait(
        &self,
        request: WaitForTerminalExitRequest,
    ) -> acp::Result<WaitForTerminalExitResponse> {
        let terminal = self.get(&request.terminal_id)?;
        loop {
            let notified = terminal.changed.notified();
            if let Some(status) = terminal.state.lock().unwrap().exit_status.clone() {
                return Ok(WaitForTerminalExitResponse::new(status));
            }
            notified.await;
        }
    }
}

impl Drop for AcpTerminals {
    fn drop(&mut self) {
        for control in self.controls.lock().unwrap().drain(..) {
            let _ = control.try_send(TerminalControl::Kill);
        }
    }
}

async fn capture_terminal_output<R>(mut reader: R, terminal: Arc<AcpTerminal>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut bytes = [0u8; 8192];
    let mut pending_utf8 = Vec::new();
    loop {
        let count = match reader.read(&mut bytes).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let text = decode_terminal_utf8(&mut pending_utf8, &bytes[..count], false);
        let mut state = terminal.state.lock().unwrap();
        append_terminal_output(&mut state, &text);
        drop(state);
        terminal.changed.notify_waiters();
    }
    let text = decode_terminal_utf8(&mut pending_utf8, &[], true);
    if !text.is_empty() {
        let mut state = terminal.state.lock().unwrap();
        append_terminal_output(&mut state, &text);
        drop(state);
        terminal.changed.notify_waiters();
    }
}

fn decode_terminal_utf8(pending: &mut Vec<u8>, bytes: &[u8], eof: bool) -> String {
    pending.extend_from_slice(bytes);
    let mut decoded = String::new();
    let mut consumed = 0;
    while consumed < pending.len() {
        match std::str::from_utf8(&pending[consumed..]) {
            Ok(text) => {
                decoded.push_str(text);
                consumed = pending.len();
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0 {
                    decoded.push_str(
                        std::str::from_utf8(&pending[consumed..consumed + valid])
                            .expect("valid_up_to is valid UTF-8"),
                    );
                    consumed += valid;
                }
                match error.error_len() {
                    Some(invalid) => {
                        decoded.push(char::REPLACEMENT_CHARACTER);
                        consumed += invalid;
                    }
                    None => break,
                }
            }
        }
    }
    if consumed > 0 {
        pending.drain(..consumed);
    }
    if eof && !pending.is_empty() {
        decoded.push_str(&String::from_utf8_lossy(pending));
        pending.clear();
    }
    decoded
}

fn append_terminal_output(state: &mut AcpTerminalState, text: &str) {
    state.output.push_str(text);
    if state.output.len() > state.output_limit {
        let mut remove = state.output.len() - state.output_limit;
        while remove < state.output.len() && !state.output.is_char_boundary(remove) {
            remove += 1;
        }
        state.output.drain(..remove);
        state.truncated = true;
    }
}

fn terminal_exit_status(status: std::process::ExitStatus) -> TerminalExitStatus {
    // Only the `#[cfg(unix)]` block below reassigns this (signal decoding).
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut mapped = TerminalExitStatus::new().exit_code(status.code().map(|code| code as u32));
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            mapped = mapped.signal(format!("SIG{signal}"));
        }
    }
    mapped
}

fn sandboxed_acp_path(
    workspace: &std::path::Path,
    requested: &std::path::Path,
    allow_missing_leaf: bool,
) -> acp::Result<PathBuf> {
    if !requested.is_absolute() {
        return Err(acp::Error::invalid_params().data("ACP file path must be absolute"));
    }
    let root = std::fs::canonicalize(workspace).map_err(acp::Error::into_internal_error)?;
    let resolved = match std::fs::canonicalize(requested) {
        Ok(path) => path,
        Err(error) if allow_missing_leaf && error.kind() == std::io::ErrorKind::NotFound => {
            let parent = requested.parent().ok_or_else(|| {
                acp::Error::invalid_params().data("ACP file path has no parent directory")
            })?;
            let parent = std::fs::canonicalize(parent).map_err(acp::Error::into_internal_error)?;
            let name = requested.file_name().ok_or_else(|| {
                acp::Error::invalid_params().data("ACP file path has no file name")
            })?;
            let resolved = parent.join(name);
            // canonicalize(requested) said NotFound, so anything that still
            // lstat()s here is a DANGLING symlink - following it on create
            // would write outside the canonicalized tree.
            if resolved.symlink_metadata().is_ok() {
                return Err(acp::Error::invalid_params()
                    .data("ACP file path is a symlink to a missing target"));
            }
            resolved
        }
        Err(error) => return Err(acp::Error::into_internal_error(error)),
    };
    if !resolved.starts_with(&root) {
        return Err(acp::Error::invalid_params().data(format!(
            "ACP file access is restricted to {}",
            root.display()
        )));
    }
    Ok(resolved)
}

fn read_acp_text_file(
    workspace: &std::path::Path,
    request: ReadTextFileRequest,
) -> acp::Result<ReadTextFileResponse> {
    let path = sandboxed_acp_path(workspace, &request.path, false)?;
    let metadata = std::fs::metadata(&path).map_err(acp::Error::into_internal_error)?;
    if metadata.len() > MAX_ACP_TEXT_FILE_BYTES {
        return Err(acp::Error::invalid_params().data(format!(
            "file exceeds Portty's {} byte ACP read limit",
            MAX_ACP_TEXT_FILE_BYTES
        )));
    }
    let content = std::fs::read_to_string(path).map_err(acp::Error::into_internal_error)?;
    let line = request.line.unwrap_or(1).max(1) as usize;
    let limit = request.limit.map(|value| value as usize);
    let mut chunks = content.split_inclusive('\n').skip(line - 1);
    let selected: String = match limit {
        Some(limit) => chunks.by_ref().take(limit).collect(),
        None => chunks.collect(),
    };
    Ok(ReadTextFileResponse::new(selected))
}

fn write_acp_text_file(
    workspace: &std::path::Path,
    request: WriteTextFileRequest,
) -> acp::Result<WriteTextFileResponse> {
    if request.content.len() as u64 > MAX_ACP_TEXT_FILE_BYTES {
        return Err(acp::Error::invalid_params().data(format!(
            "content exceeds Portty's {} byte ACP write limit",
            MAX_ACP_TEXT_FILE_BYTES
        )));
    }
    let path = sandboxed_acp_path(workspace, &request.path, true)?;
    std::fs::write(path, request.content).map_err(acp::Error::into_internal_error)?;
    Ok(WriteTextFileResponse::new())
}

/// Drive one ACP agent connection: initialize, create a session, pump prompts,
/// and normalize streamed text/thought/tool/plan updates into the mobile feed.
/// Permission requests still block until the phone selects an ACP option.
async fn run_acp_session(
    agent: AcpAgent,
    handle: Arc<AcpHandle>,
    inner: Arc<SessionInner>,
    id: SessionId,
    cwd: PathBuf,
    command_rx: mpsc::Receiver<AcpCommand>,
    resume: Option<CachedAcpSession>,
) {
    let config = agent.config().clone();
    let mut first_agent = Some(agent);
    let command_rx = Arc::new(Mutex::new(command_rx));
    // Pin reconnects to this Portty session's ACP id. The seed is resolved at
    // spawn time (fresh flag + live double-attach guard); looking up "latest
    // by provider/cwd" on every respawn could cross-wire two concurrent chats.
    let resume_state = Arc::new(StdMutex::new(resume));
    // Prompts accepted while a turn streams. Held OUTSIDE the connection so an
    // adapter crash does not silently destroy messages the timeline already
    // echoed - the respawned connection sends them.
    let queued_prompts = Arc::new(StdMutex::new(VecDeque::<String>::new()));
    // Set when the command channel closes (session teardown): a clean adapter
    // exit respawns, but teardown must not.
    let teardown = Arc::new(AtomicBool::new(false));
    // Has this driver already replayed the conversation into the timeline?
    //
    // Deliberately NOT "is the timeline empty": `spawn_agent_provider` pushes a
    // `SessionStarted` card before this task even starts, so an emptiness test is
    // false on the first connect of every real session and the replay would never
    // happen (it would only ever fire on the provider-less test spawn). Track the
    // thing being asked about instead of a proxy for it.
    let replayed = Arc::new(AtomicBool::new(false));
    let mut ever_established = false;
    let mut retry_delay_secs = 1u64;
    let mut failed_attempts = 0u32;
    loop {
        let connect_started = std::time::Instant::now();
        let agent = first_agent
            .take()
            .unwrap_or_else(|| AcpAgent::new(config.clone()));
        let h = handle.clone();
        let ev = inner.events_tx.clone();
        let permission_feed = inner.clone();
        let notification_feed = inner.clone();
        let notification_session = Arc::new(StdMutex::new(None::<String>));
        let connection_notification_session = notification_session.clone();
        let connection_feed = inner.clone();
        let connection_commands = command_rx.clone();
        let connection_resume_state = resume_state.clone();
        let connection_handle = handle.clone();
        let connection_queued = queued_prompts.clone();
        let connection_teardown = teardown.clone();
        let connection_replayed = replayed.clone();
        let connection_cwd = cwd.clone();
        let read_root = cwd.clone();
        let write_root = cwd.clone();
        let terminals = Arc::new(AcpTerminals::new(cwd.clone()));
        let create_terminals = terminals.clone();
        let output_terminals = terminals.clone();
        let kill_terminals = terminals.clone();
        let release_terminals = terminals.clone();
        let wait_terminals = terminals.clone();
        let established = Arc::new(AtomicBool::new(false));
        let connection_established = established.clone();
        let (connection_closed_tx, mut connection_closed) = tokio::sync::watch::channel(false);
        let agent = TrackedAcpAgent {
            agent,
            closed: connection_closed_tx,
            debug: acp_event_debug(id),
        };
        let res = acp::Client
        .builder()
        .name("portty-host")
        // Register the reducer before session/new. Some agents publish their
        // command list before that request resolves. Handle this notification
        // untyped first so a future SessionUpdate variant is skipped instead
        // of failing the entire ACP connection during deserialization.
        .on_receive_dispatch(
            async move |dispatch: acp::Dispatch, _cx| {
                match dispatch {
                    acp::Dispatch::Notification(notification)
                        if notification.method() == "session/update" =>
                    {
                        match serde_json::from_value::<SessionNotification>(notification.params) {
                            Ok(notification) => {
                                let expected = notification_session.lock().unwrap().clone();
                                if expected.as_deref().is_none_or(|session_id| {
                                    session_id == notification.session_id.to_string()
                                }) {
                                    reduce_session_update(&notification_feed, notification.update);
                                } else {
                                    tracing::debug!(
                                        session_id = %notification.session_id,
                                        "skipping ACP update for another session"
                                    );
                                }
                            }
                            Err(error) => tracing::debug!(
                                %error,
                                "skipping unsupported ACP session update"
                            ),
                        }
                        Ok(acp::Handled::Yes)
                    }
                    message => Ok(acp::Handled::No {
                        message,
                        retry: false,
                    }),
                }
            },
            acp::on_receive_dispatch!(),
        )
        // The agent calls session/request_permission (a server→client request).
        // We surface it as a ManagerEvent and block on the phone's decision.
        //
        // SCOPE - what approval cards are and are not. This call is the adapter
        // ASKING; it is not a gate the adapter has to pass. The adapter is an
        // ordinary child process running as the host user (see
        // `connect_tracked_acp_process`), so it can read and write files and
        // start commands through its own OS access without ever sending this
        // request, and the tool kind/title it reports here are its own claims.
        // Approval cards are therefore consent UX over a cooperative agent -
        // good against an agent doing something the user didn't intend, not a
        // sandbox against an adapter that has been compromised or is hostile.
        // Enforcing that would need OS-level confinement plus a capability
        // broker for privileged operations, which Portty does not have yet.
        // Only install adapters you trust as much as your own shell.
        .on_receive_request(
            async move |req: RequestPermissionRequest, responder, _cx| {
                let tool_call_id = req.tool_call.tool_call_id.to_string();
                if tool_call_id.len() > MAX_AGENT_SHORT_TEXT_BYTES {
                    tracing::warn!("rejecting ACP permission with oversized tool-call id");
                    // The auto-deny must be visible: a silently refused tool
                    // call reads as the agent inexplicably giving up.
                    permission_feed.push_agent_event(AgentEvent::Error {
                        message: "Denied a permission request with an oversized id".into(),
                    });
                    return responder.respond(RequestPermissionResponse::new(
                        RequestPermissionOutcome::Cancelled,
                    ));
                }
                let card = ToolCallCard {
                    tool_call_id: tool_call_id.clone(),
                    title: req
                        .tool_call
                        .fields
                        .title
                        .clone()
                        .map(clamp_agent_short_text)
                        .unwrap_or_else(|| "agent action".into()),
                };
                let options: Vec<PermissionOption> = req
                    .options
                    .iter()
                    .take(MAX_PERMISSION_OPTIONS)
                    .filter_map(|o| {
                        let option_id = o.option_id.to_string();
                        (option_id.len() <= MAX_AGENT_SHORT_TEXT_BYTES).then(|| PermissionOption {
                            option_id,
                            name: clamp_agent_short_text(o.name.clone()),
                            kind: map_perm_kind(o.kind),
                        })
                    })
                    .collect();
                if options.is_empty() && !req.options.is_empty() {
                    // Every option id was unrepresentable - an approval card
                    // with nothing to approve would strand the agent behind an
                    // un-answerable prompt for the full TTL.
                    tracing::warn!("rejecting ACP permission whose options all had oversized ids");
                    permission_feed.push_agent_event(AgentEvent::Error {
                        message: "Denied a permission request with unrepresentable options".into(),
                    });
                    return responder.respond(RequestPermissionResponse::new(
                        RequestPermissionOutcome::Cancelled,
                    ));
                }
                let category = req
                    .tool_call
                    .fields
                    .kind
                    .map(map_tool_kind)
                    .map(permission_category)
                    .unwrap_or(PermissionCategory::Unknown);
                let (tx, rx) = oneshot::channel();
                if let Ok(mut pending) = h.pending.lock() {
                    pending.insert(
                        tool_call_id.clone(),
                        PendingAgentPermission {
                            responder: tx,
                            tool_call: card.clone(),
                            options: options.clone(),
                            category,
                        },
                    );
                }
                let _ = ev.send(ManagerEvent::AgentPermission {
                    id,
                    tool_call: card,
                    options,
                    category,
                    // The scope fixed for this session at creation - the same
                    // root `sandboxed_acp_path` enforces against.
                    workspace_scope: h.workspace_scope,
                });
                // Block until the phone replies (None if cancelled or dropped).
                let ttl_secs = std::env::var("PORTTY_APPROVAL_TTL_SECS")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(24 * 60 * 60)
                    .clamp(60, 7 * 24 * 60 * 60);
                let decision = tokio::time::timeout(std::time::Duration::from_secs(ttl_secs), rx)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .flatten();
                // Resolve normally removes this entry; timeout/disconnect needs
                // explicit cleanup so stale cards are not replayed forever.
                if let Ok(mut pending) = h.pending.lock() {
                    pending.remove(&tool_call_id);
                }
                let outcome = match decision {
                    Some(opt) => {
                        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(opt))
                    }
                    None => RequestPermissionOutcome::Cancelled,
                };
                responder.respond(RequestPermissionResponse::new(outcome))
            },
            acp::on_receive_request!(),
        )
        // File IO runs on the blocking pool and responds asynchronously - the
        // reactor also pumps session/update frames to the phone, and an agent
        // in a heavy read/edit pass must not stutter the visible stream.
        .on_receive_request(
            async move |request: ReadTextFileRequest, responder, _cx| {
                let root = read_root.clone();
                tokio::spawn(async move {
                    let result =
                        tokio::task::spawn_blocking(move || read_acp_text_file(&root, request))
                            .await
                            .unwrap_or_else(|error| Err(acp::Error::into_internal_error(error)));
                    let _ = responder.respond_with_result(result);
                });
                Ok(())
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: WriteTextFileRequest, responder, _cx| {
                let root = write_root.clone();
                tokio::spawn(async move {
                    let result =
                        tokio::task::spawn_blocking(move || write_acp_text_file(&root, request))
                            .await
                            .unwrap_or_else(|error| Err(acp::Error::into_internal_error(error)));
                    let _ = responder.respond_with_result(result);
                });
                Ok(())
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: CreateTerminalRequest, responder, _cx| {
                responder.respond_with_result(create_terminals.create(request))
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: TerminalOutputRequest, responder, _cx| {
                responder.respond_with_result(output_terminals.output(request))
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: KillTerminalRequest, responder, _cx| {
                responder.respond_with_result(kill_terminals.kill(request))
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: ReleaseTerminalRequest, responder, _cx| {
                responder.respond_with_result(release_terminals.release(request))
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: WaitForTerminalExitRequest, responder, _cx| {
                let terminals = wait_terminals.clone();
                tokio::spawn(async move {
                    let result = terminals.wait(request).await;
                    let _ = responder.respond_with_result(result);
                });
                Ok(())
            },
            acp::on_receive_request!(),
        )
        .connect_with(agent, async move |cx: acp::ConnectionTo<acp::Agent>| {
            let inner = connection_feed;
            let handle = connection_handle;
            let cwd = connection_cwd;
            let capabilities = ClientCapabilities::new()
                .fs(FileSystemCapabilities::new().read_text_file(true).write_text_file(true))
                .terminal(true)
                .session(ClientSessionCapabilities::new().config_options(
                    SessionConfigOptionsCapabilities::new()
                        .boolean(BooleanConfigOptionCapabilities::new()),
                ));
            let init = cx
                .send_request(
                    InitializeRequest::new(ProtocolVersion::V1)
                        .client_capabilities(capabilities)
                        .client_info(Implementation::new(
                            "portty-host",
                            env!("CARGO_PKG_VERSION"),
                        )),
                )
                .block_task()
                .await?;
            let cached = connection_resume_state.lock().unwrap().clone();
            let mut bootstrap: Option<AcpBootstrap> = None;
            if let Some(cached) = &cached {
                let cached_id = acp::schema::v1::SessionId::new(cached.acp_session_id.clone());
                // WHICH of the two reopen calls comes first is the difference
                // between seeing the conversation and taking Portty's word that it
                // is there. `session/resume` restores the agent's context and
                // replays NOTHING; `session/load` replays the transcript as
                // session/update notifications, which is how the timeline gets
                // filled. So: replay on the first connect (which is the only way a
                // conversation the LAPTOP started ever reaches the phone), and
                // prefer the cheaper resume afterwards - a mid-chat adapter crash
                // reconnects to a phone that already holds every card, and the
                // replayed copies would arrive with fresh seqs it cannot dedupe.
                let attempts = acp_reopen_order(connection_replayed.load(Ordering::Relaxed));
                let mut load_says_forgotten = false;
                for attempt in attempts {
                    if bootstrap.is_some() || !attempt.supported(&init.agent_capabilities) {
                        continue;
                    }
                    match reopen_acp_session(
                        attempt,
                        &cx,
                        &cached_id,
                        &cwd,
                        &init,
                        &inner,
                        &connection_commands,
                        &mut connection_closed,
                    )
                    .await?
                    {
                        Some(response) => {
                            if attempt == AcpReopen::Load {
                                connection_replayed.store(true, Ordering::Relaxed);
                            }
                            bootstrap = Some(AcpBootstrap {
                                session_id: cached_id.clone(),
                                modes: response.modes,
                                config_options: response.config_options,
                                legacy_models: None,
                            });
                        }
                        // Only `load` is authoritative about a forgotten
                        // conversation - `resume` failing may just mean the agent
                        // wants the fuller call.
                        None => load_says_forgotten |= attempt == AcpReopen::Load,
                    }
                }
                // Evicted only when NOTHING reopened it. Pruning the moment
                // `load` failed would delete a live conversation's cache entry in
                // the case where `resume` then succeeded.
                if load_says_forgotten && bootstrap.is_none() {
                    prune_cached_acp_session(inner.provider, &cached.acp_session_id);
                }
            }
            let bootstrap = match bootstrap {
                Some(bootstrap) => bootstrap,
                None => {
                    if cached.is_some() {
                        // Losing the old conversation must be visible - a
                        // context-free "resumed" chat is worse than a stated
                        // fresh start.
                        inner.push_agent_event(AgentEvent::Error {
                            message: "Could not resume the previous conversation - starting a fresh one".into(),
                        });
                    }
                    let new_request = CompatibleNewSessionRequest::new(&cwd);
                    let response = match cx.send_request(new_request.clone()).block_task().await {
                        Ok(response) => response,
                        Err(error)
                            if error.code == acp::ErrorCode::AuthRequired
                                && !init.auth_methods.is_empty() =>
                        {
                            authenticate_acp_interactively(
                                &cx,
                                &init.auth_methods,
                                &inner,
                                &connection_commands,
                                &mut connection_closed,
                            )
                            .await?;
                            cx.send_request(new_request).block_task().await?
                        }
                        Err(error) => return Err(error),
                    };
                    // Nothing was replayed, but from here the phone WILL see
                    // every card this driver produces - so a later reconnect must
                    // not treat the conversation as unseen and load it back in.
                    // Without this the common case breaks: start a chat from the
                    // phone, chat, adapter crashes, and the reconnect replays the
                    // whole transcript into a timeline that already holds it, with
                    // fresh seqs the phone cannot dedupe.
                    connection_replayed.store(true, Ordering::Relaxed);
                    AcpBootstrap {
                        session_id: response.current.session_id,
                        modes: response.current.modes,
                        config_options: response.current.config_options,
                        legacy_models: response.models,
                    }
                }
            };
            let session_id = bootstrap.session_id;
            if session_id.to_string().len() > MAX_AGENT_SHORT_TEXT_BYTES {
                return Err(acp::Error::invalid_params().data("ACP session id is too large"));
            }
            *connection_notification_session.lock().unwrap() = Some(session_id.to_string());
            *handle.acp_session_id.lock().unwrap() = Some(session_id.to_string());
            if let Some(modes) = bootstrap.modes {
                inner.push_agent_event(map_mode_state(modes));
            }
            let had_config_options = bootstrap.config_options.is_some();
            let mut mapped_config = bootstrap
                .config_options
                .map(map_config_options)
                .unwrap_or_default();
            if !mapped_config
                .iter()
                .any(|option| option.category.as_deref() == Some("model"))
            {
                if let Some(models) = bootstrap.legacy_models {
                    mapped_config.push(map_legacy_model_option(models));
                }
            }
            if had_config_options || !mapped_config.is_empty() {
                inner.push_agent_event(AgentEvent::ConfigOptions {
                    options: mapped_config,
                });
            }

            // Reapply the user's desired settings after resume/load or after a
            // cached id had to fall back to a fresh session.
            if let Some(cached) = &cached {
                if let Some(mode) = &cached.desired_mode {
                    if let Err(error) = apply_acp_control(
                        &cx,
                        &session_id,
                        AcpCommand::SetMode {
                            mode_id: mode.clone(),
                            response: None,
                        },
                        &handle,
                        &inner,
                    )
                    .await
                    {
                        tracing::debug!(session = id.0, %error, "could not replay desired ACP mode");
                    }
                }
                for (config_id, value) in &cached.desired_config {
                    if let Err(error) = apply_acp_control(
                        &cx,
                        &session_id,
                        AcpCommand::SetConfig {
                            config_id: config_id.clone(),
                            value: value.clone(),
                            response: None,
                        },
                        &handle,
                        &inner,
                    )
                    .await
                    {
                        tracing::debug!(session = id.0, %error, config_id, "could not replay desired ACP config");
                    }
                }
            }
            persist_tracked_acp_session(
                inner.provider,
                &cwd,
                &session_id,
                &inner,
                &connection_resume_state,
            );
            connection_established.store(true, Ordering::Release);

            loop {
                let queued = connection_queued.lock().unwrap().pop_front();
                let command = if let Some(prompt) = queued {
                    Some(AcpCommand::Prompt(prompt))
                } else {
                    recv_acp_command_or_closed(
                        &connection_commands,
                        &mut connection_closed,
                    )
                    .await?
                };
                let Some(command) = command else {
                    connection_teardown.store(true, Ordering::Release);
                    break;
                };
                match command {
                    AcpCommand::Prompt(prompt) => {
                        inner.push_agent_event(AgentEvent::TurnStarted);
                        // Keep the prompt across attempts: if the agent demands
                        // (re)login mid-turn, we re-authenticate and re-send the SAME
                        // prompt once, instead of dropping it and making the user
                        // retype (#45). Bounded to a single retry - an agent that
                        // still says AuthRequired after a successful login is broken
                        // and must surface as an error, not loop.
                        let mut reauthed = false;
                        'turn: loop {
                        let request = PromptRequest::new(
                            session_id.clone(),
                            vec![ContentBlock::from(prompt.clone())],
                        );
                        let turn = cx.send_request(request).block_task();
                        tokio::pin!(turn);
                        loop {
                            tokio::select! {
                                result = &mut turn => {
                                    match result {
                                        Ok(response) => inner.push_agent_event(AgentEvent::TurnFinished {
                                            stop_reason: format!("{:?}", response.stop_reason),
                                        }),
                                        Err(error) if error.code == acp::ErrorCode::RequestCancelled => {
                                            inner.push_agent_event(AgentEvent::TurnFinished {
                                                stop_reason: "cancelled".into(),
                                            });
                                        }
                                        Err(error)
                                            if error.code == acp::ErrorCode::AuthRequired
                                                && !init.auth_methods.is_empty()
                                                && !reauthed =>
                                        {
                                            // Re-login interactively (shows the auth
                                            // card, waits for the user's method), then
                                            // retry this exact prompt.
                                            match authenticate_acp_interactively(
                                                &cx,
                                                &init.auth_methods,
                                                &inner,
                                                &connection_commands,
                                                &mut connection_closed,
                                            )
                                            .await
                                            {
                                                Ok(()) => {
                                                    reauthed = true;
                                                    continue 'turn;
                                                }
                                                Err(_) => {
                                                    inner.push_agent_event(AgentEvent::Error {
                                                        message: "Authentication was cancelled; your message was not sent".into(),
                                                    });
                                                    inner.push_agent_event(AgentEvent::TurnFinished {
                                                        stop_reason: "error".into(),
                                                    });
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            // Agents can require (re)login mid-conversation -
                                            // show the auth card, not just an opaque error.
                                            // (Reached when re-auth already ran once.)
                                            if error.code == acp::ErrorCode::AuthRequired
                                                && !init.auth_methods.is_empty()
                                            {
                                                inner.push_agent_event(AgentEvent::AuthRequired {
                                                    methods: map_auth_methods(&init.auth_methods),
                                                });
                                            }
                                            inner.push_agent_event(AgentEvent::Error {
                                                message: clamp_agent_text(error.to_string()),
                                            });
                                            inner.push_agent_event(AgentEvent::TurnFinished {
                                                stop_reason: "error".into(),
                                            });
                                        }
                                    }
                                    persist_tracked_acp_session(
                                        inner.provider,
                                        &cwd,
                                        &session_id,
                                        &inner,
                                        &connection_resume_state,
                                    );
                                    break 'turn;
                                }
                                next = recv_acp_command_or_closed(
                                    &connection_commands,
                                    &mut connection_closed,
                                ) => {
                                    let Some(next) = next? else {
                                        connection_teardown.store(true, Ordering::Release);
                                        cancel_pending_permissions(&handle, &inner);
                                        cx.send_notification(CancelNotification::new(session_id.clone()))?;
                                        let _ = turn.await;
                                        return Ok(());
                                    };
                                    match next {
                                        AcpCommand::Prompt(prompt) => {
                                            connection_queued.lock().unwrap().push_back(prompt);
                                        }
                                        other => {
                                            // Stopping the turn also discards prompts
                                            // queued behind it - cancel means "stop
                                            // what I lined up", not "run the rest".
                                            if matches!(other, AcpCommand::Cancel) {
                                                connection_queued.lock().unwrap().clear();
                                            }
                                            apply_acp_control_with_feedback(
                                                &cx,
                                                &session_id,
                                                other,
                                                &handle,
                                                &inner,
                                            )
                                            .await;
                                            persist_tracked_acp_session(
                                                inner.provider,
                                                &cwd,
                                                &session_id,
                                                &inner,
                                                &connection_resume_state,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        }
                    }
                    other => {
                        apply_acp_control_with_feedback(
                            &cx,
                            &session_id,
                            other,
                            &handle,
                            &inner,
                        )
                        .await;
                        persist_tracked_acp_session(
                            inner.provider,
                            &cwd,
                            &session_id,
                            &inner,
                            &connection_resume_state,
                        );
                    }
                }
            }
            Ok(())
        })
        .await;
        if established.load(Ordering::Acquire) {
            ever_established = true;
        }
        // A user-initiated teardown never respawns, regardless of how the
        // connection future settled.
        if teardown.load(Ordering::Acquire) {
            break;
        }
        // A connection that lived a while (or was healthy long enough to set
        // up) earns the backoff back; rapid-fire failures escalate and - for
        // an adapter that reliably dies - eventually stop, so a broken login
        // or crashing native module doesn't respawn every 30s forever.
        const HEALTHY_UPTIME: std::time::Duration = std::time::Duration::from_secs(60);
        const MAX_FAILED_ATTEMPTS: u32 = 5;
        if connect_started.elapsed() >= HEALTHY_UPTIME {
            failed_attempts = 0;
            retry_delay_secs = 1;
        } else {
            failed_attempts += 1;
        }
        if failed_attempts >= MAX_FAILED_ATTEMPTS {
            tracing::warn!(session = id.0, "ACP adapter keeps failing; giving up");
            inner.push_agent_event(AgentEvent::Error {
                message: format!(
                    "The agent keeps crashing shortly after starting ({MAX_FAILED_ATTEMPTS} attempts) - close this session and check the adapter installation"
                ),
            });
            cancel_pending_permissions(&handle, &inner);
            break;
        }
        match res {
            Ok(()) if ever_established => {
                tracing::warn!(session = id.0, "ACP adapter exited; respawning adapter");
                inner.push_agent_event(AgentEvent::Error {
                    message: format!(
                        "Agent connection closed; reconnecting in {retry_delay_secs}s"
                    ),
                });
                cancel_pending_permissions(&handle, &inner);
                tokio::time::sleep(std::time::Duration::from_secs(retry_delay_secs)).await;
                retry_delay_secs = (retry_delay_secs * 2).min(30);
            }
            Ok(()) => break,
            Err(error) if ever_established => {
                tracing::warn!(%error, session = id.0, "ACP connection lost; respawning adapter");
                inner.push_agent_event(AgentEvent::Error {
                    message: clamp_agent_text(format!(
                        "Agent connection lost; reconnecting in {retry_delay_secs}s: {error}"
                    )),
                });
                cancel_pending_permissions(&handle, &inner);
                tokio::time::sleep(std::time::Duration::from_secs(retry_delay_secs)).await;
                retry_delay_secs = (retry_delay_secs * 2).min(30);
            }
            Err(error) => {
                tracing::warn!(%error, session = id.0, "ACP agent session ended during setup");
                inner.push_agent_event(AgentEvent::Error {
                    message: clamp_agent_text(format!("Agent connection ended: {error}")),
                });
                break;
            }
        }
    }
}

/// Surface the agent's auth methods, block until the user picks one, and run
/// `authenticate`. Non-auth commands received meanwhile are rejected with a
/// hint; cancel/teardown aborts. On success the auth card is cleared.
/// Reopen `session_id` with one of the two ACP calls, authenticating once if the
/// agent asks.
///
/// `Ok(None)` means "this agent no longer has that conversation" - the caller
/// falls through to the other call or to a fresh session. A real protocol error
/// still propagates: an adapter that is broken must not look like an agent with
/// a clean memory.
#[allow(clippy::too_many_arguments)]
async fn reopen_acp_session(
    how: AcpReopen,
    cx: &acp::ConnectionTo<acp::Agent>,
    session_id: &acp::schema::v1::SessionId,
    cwd: &std::path::Path,
    init: &acp::schema::v1::InitializeResponse,
    inner: &SessionInner,
    commands: &Arc<Mutex<mpsc::Receiver<AcpCommand>>>,
    closed: &mut tokio::sync::watch::Receiver<bool>,
) -> acp::Result<Option<AcpReopenResponse>> {
    // The replay banner brackets the load only. It is what stops the phone from
    // reading a burst of replayed cards as a live turn, and a resume has nothing
    // to bracket.
    if how == AcpReopen::Load {
        inner.push_agent_event(AgentEvent::Replaying { active: true });
    }
    let mut attempt = send_acp_reopen(how, cx, session_id, cwd).await;
    if matches!(&attempt, Err(error) if error.code == acp::ErrorCode::AuthRequired)
        && !init.auth_methods.is_empty()
    {
        // The banner comes down for the duration: authenticating is an
        // interactive prompt on the phone, not part of the replay.
        if how == AcpReopen::Load {
            inner.push_agent_event(AgentEvent::Replaying { active: false });
        }
        authenticate_acp_interactively(cx, &init.auth_methods, inner, commands, closed).await?;
        if how == AcpReopen::Load {
            inner.push_agent_event(AgentEvent::Replaying { active: true });
        }
        attempt = send_acp_reopen(how, cx, session_id, cwd).await;
    }
    if how == AcpReopen::Load {
        inner.push_agent_event(AgentEvent::Replaying { active: false });
    }
    match attempt {
        Ok(response) => Ok(Some(response)),
        Err(error) if acp_reconnect_fallback_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn send_acp_reopen(
    how: AcpReopen,
    cx: &acp::ConnectionTo<acp::Agent>,
    session_id: &acp::schema::v1::SessionId,
    cwd: &std::path::Path,
) -> acp::Result<AcpReopenResponse> {
    match how {
        AcpReopen::Load => cx
            .send_request(LoadSessionRequest::new(session_id.clone(), cwd))
            .block_task()
            .await
            .map(|response| AcpReopenResponse {
                modes: response.modes,
                config_options: response.config_options,
            }),
        AcpReopen::Resume => cx
            .send_request(ResumeSessionRequest::new(session_id.clone(), cwd))
            .block_task()
            .await
            .map(|response| AcpReopenResponse {
                modes: response.modes,
                config_options: response.config_options,
            }),
    }
}

async fn authenticate_acp_interactively(
    cx: &acp::ConnectionTo<acp::Agent>,
    init_methods: &[acp::schema::v1::AuthMethod],
    inner: &SessionInner,
    commands: &Arc<Mutex<mpsc::Receiver<AcpCommand>>>,
    closed: &mut tokio::sync::watch::Receiver<bool>,
) -> acp::Result<()> {
    inner.push_agent_event(AgentEvent::AuthRequired {
        methods: map_auth_methods(init_methods),
    });
    let method_id = loop {
        match recv_acp_command_or_closed(commands, closed).await? {
            Some(AcpCommand::Authenticate(method_id)) => break method_id,
            Some(AcpCommand::Cancel) | None => {
                return Err(acp::Error::request_cancelled());
            }
            Some(_) => inner.push_agent_event(AgentEvent::Error {
                message: "Authenticate this agent before sending commands".into(),
            }),
        }
    };
    cx.send_request(AuthenticateRequest::new(method_id))
        .block_task()
        .await?;
    inner.push_agent_event(AgentEvent::AuthRequired {
        methods: Vec::new(),
    });
    Ok(())
}

async fn recv_acp_command_or_closed(
    receiver: &Arc<Mutex<mpsc::Receiver<AcpCommand>>>,
    closed: &mut tokio::sync::watch::Receiver<bool>,
) -> acp::Result<Option<AcpCommand>> {
    if *closed.borrow() {
        return Err(acp::Error::internal_error().data("ACP adapter process exited"));
    }
    tokio::select! {
        command = async { receiver.lock().await.recv().await } => Ok(command),
        changed = closed.changed() => {
            match changed {
                Ok(()) if *closed.borrow() => {
                    Err(acp::Error::internal_error().data("ACP adapter process exited"))
                }
                Ok(()) => Ok(None),
                Err(_) => Err(acp::Error::internal_error().data("ACP process monitor ended")),
            }
        }
    }
}

/// Run one control command and complete its responder (when it carries one)
/// exactly once, from the single result - a branch that early-returns can
/// never strand a phone/CLI caller in the 30s control timeout.
async fn apply_acp_control(
    cx: &acp::ConnectionTo<acp::Agent>,
    session_id: &acp::schema::v1::SessionId,
    mut command: AcpCommand,
    handle: &AcpHandle,
    inner: &SessionInner,
) -> acp::Result<()> {
    let responder = command.take_responder();
    let result = apply_acp_control_inner(cx, session_id, command, handle, inner).await;
    complete_agent_control(
        responder,
        result.as_ref().map(|_| ()).map_err(|e| e.to_string()),
    );
    result
}

async fn apply_acp_control_inner(
    cx: &acp::ConnectionTo<acp::Agent>,
    session_id: &acp::schema::v1::SessionId,
    command: AcpCommand,
    handle: &AcpHandle,
    inner: &SessionInner,
) -> acp::Result<()> {
    match command {
        AcpCommand::Cancel => {
            // Resolve approvals first so neither end remains blocked waiting
            // for a response that cancellation has made irrelevant.
            cancel_pending_permissions(handle, inner);
            cx.send_notification(CancelNotification::new(session_id.clone()))?;
        }
        AcpCommand::SetMode { mode_id, .. } => {
            cx.send_request(SetSessionModeRequest::new(
                session_id.clone(),
                mode_id.clone(),
            ))
            .block_task()
            .await?;
            let available_modes = current_modes(inner);
            inner.push_agent_event(AgentEvent::ModeState {
                current_mode_id: mode_id,
                available_modes,
            });
        }
        AcpCommand::SetConfig {
            config_id, value, ..
        } => {
            if config_id == LEGACY_MODEL_CONFIG_ID {
                let AgentConfigValue::Select(model_id) = value else {
                    return Err(acp::Error::invalid_params()
                        .data("legacy ACP model values must be select ids"));
                };
                cx.send_request(LegacySetSessionModelRequest {
                    session_id: session_id.clone(),
                    model_id: model_id.clone(),
                })
                .block_task()
                .await?;
                update_config_value(
                    inner,
                    LEGACY_MODEL_CONFIG_ID,
                    AgentConfigValue::Select(model_id),
                );
                return Ok(());
            }
            let value = match value {
                AgentConfigValue::Select(value) => SessionConfigOptionValue::value_id(value),
                AgentConfigValue::Boolean(value) => SessionConfigOptionValue::boolean(value),
            };
            let result = cx
                .send_request(SetSessionConfigOptionRequest::new(
                    session_id.clone(),
                    config_id,
                    value,
                ))
                .block_task()
                .await?;
            // The response is authoritative and may include cascading changes.
            inner.push_agent_event(AgentEvent::ConfigOptions {
                options: map_config_options(result.config_options),
            });
        }
        AcpCommand::Authenticate(method_id) => {
            cx.send_request(AuthenticateRequest::new(method_id))
                .block_task()
                .await?;
            inner.push_agent_event(AgentEvent::AuthRequired {
                methods: Vec::new(),
            });
        }
        AcpCommand::Prompt(_) => unreachable!("prompts are handled by the turn loop"),
    }
    Ok(())
}

fn update_config_value(inner: &SessionInner, config_id: &str, value: AgentConfigValue) {
    let Backend::Acp { handle } = &inner.backend else {
        return;
    };
    let mut options = handle
        .history
        .lock()
        .unwrap()
        .sticky
        .get(&StickyAgentEvent::Config)
        .and_then(|event| match &event.event {
            AgentEvent::ConfigOptions { options } => Some(options.clone()),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(option) = options.iter_mut().find(|option| option.id == config_id) {
        option.current_value = value;
        inner.push_agent_event(AgentEvent::ConfigOptions { options });
    }
}

fn complete_agent_control(
    response: Option<oneshot::Sender<Result<(), String>>>,
    result: Result<(), String>,
) {
    if let Some(response) = response {
        let _ = response.send(result);
    }
}

async fn apply_acp_control_with_feedback(
    cx: &acp::ConnectionTo<acp::Agent>,
    session_id: &acp::schema::v1::SessionId,
    command: AcpCommand,
    handle: &AcpHandle,
    inner: &SessionInner,
) {
    if let Err(error) = apply_acp_control(cx, session_id, command, handle, inner).await {
        // A rejected mode/config value is a command error, not an adapter
        // crash. Keep the conversation alive and let reducer state roll the
        // controlled picker back to the last authoritative value.
        inner.push_agent_event(AgentEvent::Error {
            message: clamp_agent_text(format!("Agent control failed: {error}")),
        });
    }
}

fn cancel_pending_permissions(handle: &AcpHandle, inner: &SessionInner) {
    let pending = std::mem::take(&mut *handle.pending.lock().unwrap());
    for (tool_call_id, request) in pending {
        let _ = request.responder.send(None);
        let _ = inner.events_tx.send(ManagerEvent::AgentPermissionResolved {
            id: inner.id,
            tool_call_id,
            resolution: PermissionResolution::Cancelled,
            by: PermissionResolver::System,
        });
    }
}

fn current_modes(inner: &SessionInner) -> Vec<AgentMode> {
    let Backend::Acp { handle } = &inner.backend else {
        return Vec::new();
    };
    handle
        .history
        .lock()
        .unwrap()
        .sticky
        .get(&StickyAgentEvent::Mode)
        .and_then(|event| match &event.event {
            AgentEvent::ModeState {
                available_modes, ..
            } => Some(available_modes.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn reduce_session_update(inner: &SessionInner, update: SessionUpdate) {
    if matches!(update, SessionUpdate::UserMessageChunk(_)) && !is_replaying(inner) {
        // Live prompts are echoed at enqueue time. User chunks are only needed
        // while session/load is replaying history.
        return;
    }
    if let SessionUpdate::CurrentModeUpdate(mode) = &update {
        inner.push_agent_event(AgentEvent::ModeState {
            current_mode_id: clamp_agent_short_text(mode.current_mode_id.to_string()),
            available_modes: current_modes(inner),
        });
        return;
    }
    if let Some(event) = map_session_update(update) {
        if let AgentEvent::SessionInfo { title: Some(title) } = &event {
            *inner.title.lock().unwrap() = clamp_title(title.clone());
            // SessionAdded is an id-keyed upsert on every Portty client. Reuse
            // it for title refreshes to remain wire-compatible with existing
            // peers while keeping the session list authoritative.
            let _ = inner.events_tx.send(ManagerEvent::Added(SessionInfo {
                id: inner.id,
                title: inner.title.lock().unwrap().clone(),
                kind: inner.kind,
                source: inner.source,
                has_activity: inner.has_unseen_activity.load(Ordering::Relaxed),
            }));
        }
        inner.push_agent_event(event);
    }
}

fn is_replaying(inner: &SessionInner) -> bool {
    let Backend::Acp { handle } = &inner.backend else {
        return false;
    };
    handle
        .history
        .lock()
        .unwrap()
        .sticky
        .get(&StickyAgentEvent::Replaying)
        .is_some_and(|event| matches!(event.event, AgentEvent::Replaying { active: true }))
}

fn map_session_update(update: SessionUpdate) -> Option<AgentEvent> {
    match update {
        SessionUpdate::UserMessageChunk(chunk) => {
            content_text(chunk.content).map(|text| AgentEvent::UserMessage { text })
        }
        SessionUpdate::AgentMessageChunk(chunk) => {
            content_text(chunk.content).map(|text| AgentEvent::MessageChunk { text })
        }
        SessionUpdate::AgentThoughtChunk(chunk) => {
            content_text(chunk.content).map(|text| AgentEvent::ThoughtChunk { text })
        }
        SessionUpdate::ToolCall(tool) => Some(AgentEvent::ToolCall {
            tool_call_id: clamp_agent_short_text(tool.tool_call_id.to_string()),
            title: clamp_agent_short_text(tool.title),
            kind: map_tool_kind(tool.kind),
            status: map_tool_status(tool.status),
            detail: tool.raw_input.and_then(json_detail),
        }),
        SessionUpdate::ToolCallUpdate(update) => Some(AgentEvent::ToolCallUpdate {
            tool_call_id: clamp_agent_short_text(update.tool_call_id.to_string()),
            title: update.fields.title.map(clamp_agent_short_text),
            kind: update.fields.kind.map(map_tool_kind),
            status: update.fields.status.map(map_tool_status),
            detail: update
                .fields
                .raw_output
                .or(update.fields.raw_input)
                .and_then(json_detail),
        }),
        SessionUpdate::Plan(plan) => Some(AgentEvent::Plan {
            entries: plan
                .entries
                .into_iter()
                .take(MAX_AGENT_PLAN_ENTRIES)
                .map(|entry| AgentPlanEntry {
                    content: clamp_agent_short_text(entry.content),
                    status: map_plan_status(entry.status),
                })
                .collect(),
        }),
        SessionUpdate::AvailableCommandsUpdate(update) => Some(AgentEvent::AvailableCommands {
            commands: update
                .available_commands
                .into_iter()
                .take(MAX_AGENT_COMMANDS)
                .map(|command| AgentCommand {
                    name: clamp_agent_short_text(command.name),
                    description: clamp_agent_short_text(command.description),
                    input_hint: command.input.and_then(|input| match input {
                        acp::schema::v1::AvailableCommandInput::Unstructured(input) => {
                            Some(clamp_agent_short_text(input.hint))
                        }
                        _ => None,
                    }),
                })
                .collect(),
        }),
        SessionUpdate::ConfigOptionUpdate(update) => Some(AgentEvent::ConfigOptions {
            options: map_config_options(update.config_options),
        }),
        SessionUpdate::UsageUpdate(update) => Some(AgentEvent::Usage {
            used_tokens: update.used,
            max_tokens: update.size,
            cost: update.cost.map(|cost| {
                clamp_agent_short_text(format!("{:.2} {}", cost.amount, cost.currency))
            }),
        }),
        SessionUpdate::SessionInfoUpdate(update) if !update.title.is_undefined() => {
            Some(AgentEvent::SessionInfo {
                title: update.title.take().map(clamp_agent_short_text),
            })
        }
        // Current mode needs the reducer's existing available-mode list, so it
        // is handled by `reduce_session_update` above.
        _ => None,
    }
}

fn map_mode_state(state: SessionModeState) -> AgentEvent {
    AgentEvent::ModeState {
        current_mode_id: clamp_agent_short_text(state.current_mode_id.to_string()),
        available_modes: state
            .available_modes
            .into_iter()
            .take(MAX_AGENT_MODES)
            .map(|mode| AgentMode {
                id: clamp_agent_short_text(mode.id.to_string()),
                name: clamp_agent_short_text(mode.name),
                description: mode.description.map(clamp_agent_short_text),
            })
            .collect(),
    }
}

fn map_config_options(options: Vec<AcpSessionConfigOption>) -> Vec<AgentConfigOption> {
    options
        .into_iter()
        .take(MAX_AGENT_CONFIG_OPTIONS)
        .filter_map(|option| {
            let (current_value, choices) = match option.kind {
                SessionConfigKind::Select(select) => {
                    // Per-option cap: a long model list must not starve the
                    // mode/thought-level pickers that follow it.
                    let choices: Vec<_> = match select.options {
                        SessionConfigSelectOptions::Ungrouped(options) => options
                            .into_iter()
                            .take(MAX_AGENT_CONFIG_CHOICES)
                            .map(|choice| map_config_choice(choice, None))
                            .collect(),
                        SessionConfigSelectOptions::Grouped(groups) => groups
                            .into_iter()
                            .flat_map(|group| {
                                let group_name = clamp_agent_short_text(group.name);
                                group.options.into_iter().map(move |choice| {
                                    map_config_choice(choice, Some(group_name.clone()))
                                })
                            })
                            .take(MAX_AGENT_CONFIG_CHOICES)
                            .collect(),
                        _ => Vec::new(),
                    };
                    (
                        AgentConfigValue::Select(clamp_agent_short_text(
                            select.current_value.to_string(),
                        )),
                        choices,
                    )
                }
                SessionConfigKind::Boolean(boolean) => {
                    (AgentConfigValue::Boolean(boolean.current_value), Vec::new())
                }
                _ => return None,
            };
            Some(AgentConfigOption {
                id: clamp_agent_short_text(option.id.to_string()),
                name: clamp_agent_short_text(option.name),
                description: option.description.map(clamp_agent_short_text),
                category: option.category.map(config_category),
                current_value,
                choices,
            })
        })
        .collect()
}

fn map_legacy_model_option(models: LegacyModelState) -> AgentConfigOption {
    AgentConfigOption {
        id: LEGACY_MODEL_CONFIG_ID.into(),
        name: "Model".into(),
        description: Some("Legacy ACP model selector".into()),
        category: Some("model".into()),
        current_value: AgentConfigValue::Select(clamp_agent_short_text(models.current_model_id)),
        choices: models
            .available_models
            .into_iter()
            .take(MAX_AGENT_CONFIG_CHOICES)
            .map(|model| AgentConfigChoice {
                value: clamp_agent_short_text(model.model_id),
                name: clamp_agent_short_text(model.name),
                description: model.description.map(clamp_agent_short_text),
                group: None,
            })
            .collect(),
    }
}

fn map_config_choice(
    choice: acp::schema::v1::SessionConfigSelectOption,
    group: Option<String>,
) -> AgentConfigChoice {
    AgentConfigChoice {
        value: clamp_agent_short_text(choice.value.to_string()),
        name: clamp_agent_short_text(choice.name),
        description: choice.description.map(clamp_agent_short_text),
        group,
    }
}

fn config_category(category: SessionConfigOptionCategory) -> String {
    match category {
        SessionConfigOptionCategory::Mode => "mode".into(),
        SessionConfigOptionCategory::Model => "model".into(),
        SessionConfigOptionCategory::ModelConfig => "model_config".into(),
        SessionConfigOptionCategory::ThoughtLevel => "thought_level".into(),
        SessionConfigOptionCategory::Other(value) => value,
        _ => "unknown".into(),
    }
}

fn map_auth_methods(methods: &[acp::schema::v1::AuthMethod]) -> Vec<AgentAuthMethod> {
    methods
        .iter()
        .take(MAX_AGENT_AUTH_METHODS)
        .map(|method| AgentAuthMethod {
            id: clamp_agent_short_text(method.id().to_string()),
            name: clamp_agent_short_text(method.name().to_string()),
            description: method
                .description()
                .map(|value| clamp_agent_short_text(value.into())),
        })
        .collect()
}

fn acp_reconnect_fallback_error(error: &acp::Error) -> bool {
    if matches!(
        error.code,
        acp::ErrorCode::MethodNotFound
            | acp::ErrorCode::InvalidParams
            | acp::ErrorCode::ResourceNotFound
    ) {
        return true;
    }
    let message = error.message.to_ascii_lowercase();
    !message.contains("timeout")
        && !message.contains("timed out")
        && (message.contains("not found") || message.contains("empty session"))
}

fn content_text(content: ContentBlock) -> Option<String> {
    match content {
        ContentBlock::Text(text) => Some(clamp_agent_text(text.text)),
        _ => None,
    }
}

fn json_detail(value: serde_json::Value) -> Option<String> {
    serde_json::to_string_pretty(&value)
        .ok()
        .map(clamp_agent_text)
}

fn map_tool_kind(kind: AcpToolKind) -> AgentToolKind {
    match kind {
        AcpToolKind::Read => AgentToolKind::Read,
        AcpToolKind::Edit => AgentToolKind::Edit,
        AcpToolKind::Delete => AgentToolKind::Delete,
        AcpToolKind::Move => AgentToolKind::Move,
        AcpToolKind::Search => AgentToolKind::Search,
        AcpToolKind::Execute => AgentToolKind::Execute,
        AcpToolKind::Think => AgentToolKind::Think,
        AcpToolKind::Fetch => AgentToolKind::Fetch,
        _ => AgentToolKind::Other,
    }
}

fn permission_category(kind: AgentToolKind) -> PermissionCategory {
    match kind {
        AgentToolKind::Read | AgentToolKind::Search => PermissionCategory::Read,
        AgentToolKind::Edit | AgentToolKind::Move => PermissionCategory::Write,
        AgentToolKind::Execute => PermissionCategory::Execute,
        AgentToolKind::Fetch => PermissionCategory::Network,
        AgentToolKind::Delete => PermissionCategory::Destructive,
        AgentToolKind::Think | AgentToolKind::Other => PermissionCategory::Unknown,
    }
}

fn map_tool_status(status: AcpToolCallStatus) -> AgentToolStatus {
    match status {
        AcpToolCallStatus::Pending => AgentToolStatus::Pending,
        AcpToolCallStatus::InProgress => AgentToolStatus::InProgress,
        AcpToolCallStatus::Completed => AgentToolStatus::Completed,
        AcpToolCallStatus::Failed => AgentToolStatus::Failed,
        _ => AgentToolStatus::Pending,
    }
}

fn map_plan_status(status: AcpPlanEntryStatus) -> AgentPlanStatus {
    match status {
        AcpPlanEntryStatus::Pending => AgentPlanStatus::Pending,
        AcpPlanEntryStatus::InProgress => AgentPlanStatus::InProgress,
        AcpPlanEntryStatus::Completed => AgentPlanStatus::Completed,
        _ => AgentPlanStatus::Pending,
    }
}

/// Map ACP's (non_exhaustive) permission option kind onto Portty's. Unknown
/// kinds default to RejectOnce - never auto-approve something we don't understand.
fn map_perm_kind(k: AcpPermissionOptionKind) -> PermissionOptionKind {
    match k {
        AcpPermissionOptionKind::AllowOnce => PermissionOptionKind::AllowOnce,
        AcpPermissionOptionKind::AllowAlways => PermissionOptionKind::AllowAlways,
        AcpPermissionOptionKind::RejectOnce => PermissionOptionKind::RejectOnce,
        AcpPermissionOptionKind::RejectAlways => PermissionOptionKind::RejectAlways,
        _ => PermissionOptionKind::RejectOnce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn spawned_shell_is_a_login_shell() {
        // A daemon under launchd/systemd has a bare env; the interactive shell
        // must be a login shell so it re-reads the user's profile/PATH (#21).
        let (_shell, args) = login_shell_argv();
        assert!(
            args.iter().any(|a| a == "-l"),
            "interactive shell must be spawned as a login shell"
        );
    }

    #[test]
    fn acp_event_janitor_prunes_across_sessions_and_protects_live_writer() {
        let data = tempfile::tempdir().unwrap();
        let root = data.path().join("acp-events");
        let mut paths = Vec::new();
        for session in 1..=4 {
            let dir = root.join(session.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("events-00.ndjson");
            std::fs::write(&path, [session as u8; 10]).unwrap();
            paths.push(path);
        }
        let unrelated = root.join("1").join("notes.txt");
        std::fs::write(&unrelated, b"keep me").unwrap();
        let active = HashSet::from([paths[2].clone()]);

        let retained = prune_acp_event_log_files_with_active(&root, 20, 10, &active).unwrap();

        assert!(retained <= 20);
        assert!(paths[2].exists(), "the live writer's segment was removed");
        assert!(unrelated.exists(), "the janitor touched a non-event file");
        assert_eq!(paths.iter().filter(|path| path.exists()).count(), 2);
    }

    #[test]
    fn acp_event_janitor_reserves_unwritten_live_segment_space() {
        let data = tempfile::tempdir().unwrap();
        let root = data.path().join("acp-events");
        let live_dir = root.join("1");
        let closed_dir = root.join("2");
        std::fs::create_dir_all(&live_dir).unwrap();
        std::fs::create_dir_all(&closed_dir).unwrap();
        let live = live_dir.join("events-00.ndjson");
        let closed = closed_dir.join("events-00.ndjson");
        std::fs::write(&live, b"x").unwrap();
        std::fs::write(&closed, b"1234567890").unwrap();

        let retained =
            prune_acp_event_log_files_with_active(&root, 10, 10, &HashSet::from([live.clone()]))
                .unwrap();

        assert_eq!(retained, 1);
        assert!(live.exists());
        assert!(!closed.exists());
    }

    #[test]
    fn acp_updates_normalize_for_mobile_feed() {
        use agent_client_protocol::schema::v1::{ContentChunk, ToolCall};

        let message = SessionUpdate::AgentMessageChunk(ContentChunk::new(ContentBlock::from(
            "hello from the agent",
        )));
        assert_eq!(
            map_session_update(message),
            Some(AgentEvent::MessageChunk {
                text: "hello from the agent".into(),
            })
        );

        let tool = SessionUpdate::ToolCall(
            ToolCall::new("tool-7", "Run tests")
                .kind(AcpToolKind::Execute)
                .status(AcpToolCallStatus::InProgress),
        );
        assert!(matches!(
            map_session_update(tool),
            Some(AgentEvent::ToolCall {
                tool_call_id,
                kind: AgentToolKind::Execute,
                status: AgentToolStatus::InProgress,
                ..
            }) if tool_call_id == "tool-7"
        ));
    }

    #[test]
    fn compatible_new_session_captures_legacy_models() {
        let response: CompatibleNewSessionResponse = serde_json::from_value(serde_json::json!({
            "sessionId": "legacy-session",
            "models": {
                "currentModelId": "legacy-fast",
                "availableModels": [
                    {
                        "modelId": "legacy-fast",
                        "name": "Legacy Fast"
                    },
                    {
                        "modelId": "legacy-deep",
                        "name": "Legacy Deep",
                        "description": "More deliberate"
                    }
                ]
            }
        }))
        .unwrap();
        let option = map_legacy_model_option(response.models.unwrap());
        assert_eq!(option.id, LEGACY_MODEL_CONFIG_ID);
        assert_eq!(option.category.as_deref(), Some("model"));
        assert_eq!(
            option.current_value,
            AgentConfigValue::Select("legacy-fast".into())
        );
        assert_eq!(option.choices.len(), 2);
    }

    #[test]
    fn reconnect_fallback_is_strict_and_never_treats_timeout_as_missing() {
        assert!(acp_reconnect_fallback_error(&acp::Error::new(
            -32601,
            "method not found",
        )));
        assert!(acp_reconnect_fallback_error(&acp::Error::new(
            -32603,
            "cached session not found",
        )));
        assert!(!acp_reconnect_fallback_error(&acp::Error::new(
            -32603,
            "session not found because lookup timed out",
        )));
        assert!(!acp_reconnect_fallback_error(&acp::Error::new(
            -32603,
            "transport timeout",
        )));
    }

    #[test]
    fn reducer_state_survives_bounded_history_pruning() {
        let mut history = AgentHistory::default();
        history.push(AgentTimelineEvent {
            seq: 1,
            event: AgentEvent::AvailableCommands {
                commands: vec![AgentCommand {
                    name: "review".into(),
                    description: "Review the current changes".into(),
                    input_hint: Some("focus".into()),
                }],
            },
        });
        for seq in 2..=12 {
            history.push(AgentTimelineEvent {
                seq,
                event: AgentEvent::MessageChunk {
                    text: "x".repeat(MAX_AGENT_EVENT_TEXT_BYTES),
                },
            });
        }

        assert!(history.events.front().is_some_and(|event| event.seq > 1));
        let snapshot = history.snapshot();
        assert!(snapshot.iter().any(|event| {
            matches!(
                &event.event,
                AgentEvent::AvailableCommands { commands }
                    if commands.first().is_some_and(|command| command.name == "review")
            )
        }));
        assert!(snapshot.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    }

    #[test]
    fn acp_file_access_is_confined_to_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let inside_file = workspace.path().join("inside.txt");
        std::fs::write(&inside_file, "one\ntwo\nthree\n").unwrap();
        let session_id = acp::schema::v1::SessionId::new("sandbox-test");

        let response = read_acp_text_file(
            workspace.path(),
            ReadTextFileRequest::new(session_id.clone(), &inside_file)
                .line(2)
                .limit(1),
        )
        .unwrap();
        assert_eq!(response.content, "two\n");

        let new_file = workspace.path().join("created.txt");
        write_acp_text_file(
            workspace.path(),
            WriteTextFileRequest::new(session_id.clone(), &new_file, "safe"),
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(new_file).unwrap(), "safe");

        let outside_file = outside.path().join("outside.txt");
        std::fs::write(&outside_file, "secret").unwrap();
        assert!(read_acp_text_file(
            workspace.path(),
            ReadTextFileRequest::new(session_id.clone(), &outside_file),
        )
        .is_err());
        assert!(write_acp_text_file(
            workspace.path(),
            WriteTextFileRequest::new(session_id, outside.path().join("new.txt"), "escape"),
        )
        .is_err());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside_file, workspace.path().join("link.txt")).unwrap();
            assert!(read_acp_text_file(
                workspace.path(),
                ReadTextFileRequest::new("sandbox-test", workspace.path().join("link.txt")),
            )
            .is_err());

            // A DANGLING symlink must not smuggle a create/write outside the
            // workspace: canonicalize fails NotFound, but following the link
            // on create would land at the outside target.
            let escape_target = outside.path().join("does-not-exist-yet.txt");
            std::os::unix::fs::symlink(&escape_target, workspace.path().join("dangling.txt"))
                .unwrap();
            assert!(write_acp_text_file(
                workspace.path(),
                WriteTextFileRequest::new(
                    "sandbox-test",
                    workspace.path().join("dangling.txt"),
                    "escape"
                ),
            )
            .is_err());
            assert!(!escape_target.exists());
        }
    }

    #[test]
    fn terminal_output_front_truncation_preserves_utf8() {
        let mut state = AcpTerminalState {
            output_limit: 5,
            ..AcpTerminalState::default()
        };
        append_terminal_output(&mut state, "ééé");
        assert_eq!(state.output, "éé");
        assert!(state.truncated);
        assert!(state.output.len() <= state.output_limit);

        append_terminal_output(&mut state, "z");
        assert_eq!(state.output, "ééz");
        assert!(state.output.is_char_boundary(0));

        let mut pending = Vec::new();
        let emoji = "🦆".as_bytes();
        assert_eq!(decode_terminal_utf8(&mut pending, &emoji[..2], false), "");
        assert_eq!(decode_terminal_utf8(&mut pending, &emoji[2..], false), "🦆");
        assert!(pending.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn acp_terminal_lifecycle_distinguishes_release_from_kill() {
        use std::time::Duration;

        let workspace = tempfile::tempdir().unwrap();
        let terminals = AcpTerminals::new(workspace.path().to_path_buf());
        let session_id = acp::schema::v1::SessionId::new("terminal-test");

        let completed = terminals
            .create(
                CreateTerminalRequest::new(session_id.clone(), "/bin/sh")
                    .args(vec!["-c".into(), "printf hello".into()])
                    .cwd(workspace.path()),
            )
            .unwrap();
        terminals
            .wait(WaitForTerminalExitRequest::new(
                session_id.clone(),
                completed.terminal_id.clone(),
            ))
            .await
            .unwrap();
        let output = terminals
            .output(TerminalOutputRequest::new(
                session_id.clone(),
                completed.terminal_id.clone(),
            ))
            .unwrap();
        assert_eq!(output.output, "hello");
        assert!(output.exit_status.is_some());

        let marker = workspace.path().join("released-finished");
        let released = terminals
            .create(
                CreateTerminalRequest::new(session_id.clone(), "/bin/sh")
                    .args(vec![
                        "-c".into(),
                        "sleep 0.1; printf alive > \"$1\"".into(),
                        "portty".into(),
                        marker.display().to_string(),
                    ])
                    .cwd(workspace.path()),
            )
            .unwrap();
        terminals
            .release(ReleaseTerminalRequest::new(
                session_id.clone(),
                released.terminal_id,
            ))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !marker.is_file() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("release incorrectly killed the terminal process");

        let killed = terminals
            .create(
                CreateTerminalRequest::new(session_id.clone(), "/bin/sh")
                    .args(vec!["-c".into(), "sleep 10".into()])
                    .cwd(workspace.path()),
            )
            .unwrap();
        terminals
            .kill(KillTerminalRequest::new(
                session_id.clone(),
                killed.terminal_id.clone(),
            ))
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            terminals.wait(WaitForTerminalExitRequest::new(
                session_id,
                killed.terminal_id,
            )),
        )
        .await
        .expect("killed terminal did not exit")
        .unwrap();
    }

    #[tokio::test]
    async fn adopted_session_lists_and_streams() {
        let mgr = SessionManager::new();
        let (to_relay_tx, mut to_relay_rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);

        // A relay registers a terminal at its laptop's size.
        let (id, session) = mgr
            .register_adopted("build".into(), 190, 52, to_relay_tx)
            .await
            .unwrap();

        // It shows up in the list with the right title, at the relay's size.
        let list = mgr.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].title, "build");
        assert_eq!(session.size(), (190, 52));

        // A viewer subscribes, the relay pushes output, the viewer receives it
        // and it lands in scrollback.
        let (_snap, _seq, mut rx) = session.snapshot_and_subscribe();
        session.push_output(b"compiling...\n");
        let got = rx.recv().await.unwrap();
        assert_eq!(got.bytes.as_slice(), b"compiling...\n");
        assert_eq!(session.scrollback_snapshot(), b"compiling...\n");

        // Viewer input is proxied back out to the relay.
        session.write_input(b"y\n").unwrap();
        match to_relay_rx.recv().await.unwrap() {
            HostToRelay::Input(b) => assert_eq!(b, b"y\n"),
            other => panic!("expected Input, got {other:?}"),
        }

        // Viewers cannot resize an adopted session - its terminal owns the size.
        assert!(session.resize(100, 30).is_err());

        // The relay reporting a laptop resize updates the authoritative size
        // and broadcasts a Resized event; a repeat of the same size is a no-op.
        let mut events = mgr.subscribe_events();
        session.set_size(200, 60);
        assert_eq!(session.size(), (200, 60));
        match events.recv().await.unwrap() {
            ManagerEvent::Resized {
                id: rid,
                cols,
                rows,
            } => {
                assert_eq!(rid, id);
                assert_eq!((cols, rows), (200, 60));
            }
            other => panic!("expected Resized, got {other:?}"),
        }
        session.set_size(200, 60);
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        // Killing the adopted session tells the relay and removes it.
        assert!(mgr.kill(id).await);
        assert!(matches!(
            to_relay_rx.recv().await.unwrap(),
            HostToRelay::Kill
        ));
        assert_eq!(mgr.list().await.len(), 0);
    }

    #[tokio::test]
    async fn snapshot_and_subscription_partition_concurrent_output() {
        use std::sync::Barrier;

        let mgr = SessionManager::new_with_cap(16 * 1024);
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        let (_id, session) = mgr
            .register_adopted("race".into(), 80, 24, tx)
            .await
            .unwrap();

        // For every concurrent push/snapshot race, the new chunk must be in
        // exactly one side of the hand-off: snapshot XOR live receiver.
        for i in 0u64..500 {
            let before = i as usize * std::mem::size_of::<u64>();
            let chunk = i.to_le_bytes();
            let barrier = Arc::new(Barrier::new(2));
            let worker_barrier = barrier.clone();
            let worker_session = session.clone();
            let worker = std::thread::spawn(move || {
                worker_barrier.wait();
                worker_session.push_output(&chunk);
            });

            barrier.wait();
            let (snap, _seq, mut live) = session.snapshot_and_subscribe();
            worker.join().unwrap();
            let received = live.try_recv().ok();

            match (snap.len(), received) {
                (n, None) if n == before + chunk.len() => {}
                (n, Some(bytes)) if n == before && bytes.bytes.as_slice() == chunk => {}
                other => panic!("output crossed snapshot boundary incorrectly: {other:?}"),
            }
        }
    }

    /// Resolving the program must not disturb the arguments or the environment.
    ///
    /// `acp_agent_from_spec` promises that only the PROGRAM is rewritten, and it
    /// used to keep that promise for free by mutating one field in place. Under
    /// agent-client-protocol 2.0 `AcpAgentConfig` has no setters, so it rebuilds
    /// the config instead and has to copy args and env across by hand - which is
    /// something that can be silently forgotten. A dropped `--experimental-acp`
    /// or a lost API-key env var would launch a subtly different adapter and look
    /// like the agent misbehaving, so pin the contract here.
    ///
    /// A command containing a slash resolves without probing PATH or spawning a
    /// login shell, which keeps this deterministic and instant.
    #[test]
    fn resolving_an_agent_program_preserves_arguments_and_environment() {
        let spec = r#"{"command": "/usr/bin/env", "args": ["-i", "adapter", "--experimental-acp"], "env": {"PORTTY_SPEC_TEST": "kept"}}"#;

        let agent = acp_agent_from_spec(spec).expect("spec parses");
        let config = agent.config();

        assert_eq!(
            config.arguments(),
            ["-i", "adapter", "--experimental-acp"],
            "argument list must survive the config rebuild verbatim"
        );
        assert_eq!(
            config
                .environment()
                .get("PORTTY_SPEC_TEST")
                .map(String::as_str),
            Some("kept"),
            "environment must survive the config rebuild"
        );
        assert_eq!(
            config.command(),
            std::path::Path::new("/usr/bin/env"),
            "an already-absolute program should come back unchanged"
        );
    }

    /// Phase 3 proof: an ACP agent session intercepts a permission request and
    /// routes the phone's decision back. Uses the mock ACP agent shipped with
    /// acp-probe (no AI, no auth) so it's deterministic and runs in CI.
    #[tokio::test]
    async fn agent_session_permission_round_trip() {
        use std::time::Duration;
        let mgr = SessionManager::new();
        let mut events = mgr.subscribe_events();

        // Path to the mock ACP agent (acp-probe crate, sibling of host).
        // Forward slashes: AcpAgent::from_str shell-tokenizes and treats `\` as
        // an escape on Windows (see spawn_agent docs). `python3` on Linux CI,
        // `python` on Windows.
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let spec = format!("{py} {mock}");

        let id = mgr
            .spawn_agent(&spec, Some("test-agent".into()), None)
            .await
            .expect("spawn_agent");

        // 1) Added event for the agent session.
        let added = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("Added timed out")
            .expect("recv");
        assert!(matches!(added, ManagerEvent::Added(ref i) if i.kind == SessionKind::Agent));

        // 2) Send a prompt; the mock replies with a session/request_permission.
        let session = mgr.get(id).await.expect("session exists");
        session
            .agent_prompt("do the thing".into())
            .expect("agent_prompt");

        // 3) The interception surfaces as an AgentPermission manager event.
        let perm = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = events.recv().await.expect("recv");
                if matches!(event, ManagerEvent::AgentPermission { .. }) {
                    break event;
                }
            }
        })
        .await
        .expect("AgentPermission timed out");
        let tool_call_id = match perm {
            ManagerEvent::AgentPermission {
                id: pid,
                tool_call,
                options,
                ..
            } => {
                assert_eq!(pid, id);
                assert_eq!(tool_call.title, "Write acp_probe_test.txt");
                assert_eq!(options.len(), 2);
                assert!(options
                    .iter()
                    .any(|o| o.kind == PermissionOptionKind::AllowOnce));
                assert!(options
                    .iter()
                    .any(|o| o.kind == PermissionOptionKind::RejectOnce));
                tool_call.tool_call_id
            }
            other => panic!("expected AgentPermission, got {other:?}"),
        };

        // The doorbell's post-lag reconciliation relies on this: while the card
        // is unanswered, the manager reports a pending permission.
        assert!(
            mgr.any_agent_permission_pending().await,
            "a just-surfaced permission must be reported as pending"
        );

        // 4) Resolve as cancel - the mock then ends its turn and exits. Every
        //    OTHER viewer must hear the card was answered (dual-control sync).
        mgr.resolve_permission(&tool_call_id, None, PermissionResolver::Phone)
            .await;
        let resolved = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = events.recv().await.expect("recv");
                if let ManagerEvent::AgentPermissionResolved {
                    id: rid,
                    tool_call_id: rtid,
                    ..
                } = event
                {
                    break (rid, rtid);
                }
            }
        })
        .await
        .expect("AgentPermissionResolved timed out");
        assert_eq!(resolved, (id, tool_call_id.clone()));

        // Resolving clears it - so a post-lag reconcile won't ring a dead card.
        assert!(
            !mgr.any_agent_permission_pending().await,
            "resolved permission must no longer be pending"
        );

        // 5) Routing by tool_call_id (no SessionId on the frame): a wrong id is a no-op,
        //    and cleanup removes the session.
        mgr.resolve_permission(
            "nonexistent-tool-call",
            Some("allow-once".into()),
            PermissionResolver::Phone,
        )
        .await;
        assert!(mgr.kill(id).await);
        assert_eq!(mgr.list().await.len(), 0);
    }

    #[tokio::test]
    async fn agent_reducer_captures_early_commands_and_authoritative_controls() {
        use std::time::Duration;

        let mgr = SessionManager::new();
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let id = mgr
            .spawn_agent(
                &format!("{py} {mock}"),
                Some("state-test-agent".into()),
                None,
            )
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let snapshot = session.agent_snapshot().unwrap();
                let commands_ready = snapshot.iter().any(|event| {
                    matches!(
                        &event.event,
                        AgentEvent::AvailableCommands { commands }
                            if commands.iter().any(|command| command.name == "review")
                    )
                });
                let config_ready = snapshot
                    .iter()
                    .any(|event| matches!(event.event, AgentEvent::ConfigOptions { .. }));
                if commands_ready && config_ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("initial ACP reducer state timed out");

        assert!(session.agent_prompt("/not-advertised".into()).is_err());
        // Text that merely starts with a path is a prompt, not a command.
        // (Classified without sending: the mock blocks every real prompt on a
        // permission request, which would wedge the controls below.)
        assert!(matches!(
            session
                .agent_command_for_text("/tmp/build.log explain this")
                .unwrap(),
            AcpCommand::Prompt(_)
        ));
        // Bare control commands teach their choices instead of a blank usage.
        let usage = session.agent_prompt("/model".into()).unwrap_err();
        assert!(usage.to_string().contains("available: "), "{usage}");
        assert!(usage.to_string().contains("mock-deep"), "{usage}");
        let usage = session.agent_prompt("/mode".into()).unwrap_err();
        assert!(usage.to_string().contains("plan"), "{usage}");
        session.agent_set_mode("plan".into()).await.unwrap();
        session
            .agent_set_config("model".into(), AgentConfigValue::Select("mock-deep".into()))
            .await
            .unwrap();

        let snapshot = session.agent_snapshot().unwrap();
        assert!(snapshot.iter().rev().any(|event| {
            matches!(
                &event.event,
                AgentEvent::ModeState { current_mode_id, .. } if current_mode_id == "plan"
            )
        }));
        assert!(snapshot.iter().rev().any(|event| {
            matches!(
                &event.event,
                AgentEvent::ConfigOptions { options }
                    if options.iter().any(|option| {
                        option.id == "model"
                            && option.current_value
                                == AgentConfigValue::Select("mock-deep".into())
                    })
            )
        }));

        assert!(mgr.kill(id).await);
    }

    #[tokio::test]
    async fn agent_auth_required_surfaces_method_and_retries_new_session_once() {
        use std::time::Duration;

        let mgr = SessionManager::new();
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let id = mgr
            .spawn_agent(
                &format!("{py} {mock} --auth"),
                Some("auth-test-agent".into()),
                None,
            )
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let has_auth = session.agent_snapshot().unwrap().iter().any(|event| {
                    matches!(
                        &event.event,
                        AgentEvent::AuthRequired { methods }
                            if methods.iter().any(|method| method.id == "mock-login")
                    )
                });
                if has_auth {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("auth requirement timed out");

        session
            .agent_authenticate("mock-login".into())
            .expect("queue authentication");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let snapshot = session.agent_snapshot().unwrap();
                let auth_cleared = snapshot.iter().rev().any(|event| {
                    matches!(&event.event, AgentEvent::AuthRequired { methods } if methods.is_empty())
                });
                let session_ready = snapshot
                    .iter()
                    .any(|event| matches!(event.event, AgentEvent::ConfigOptions { .. }));
                if auth_cleared && session_ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated session setup timed out");

        assert!(mgr.kill(id).await);
    }

    /// #45: an agent that demands (re)login on the FIRST prompt must not drop that
    /// prompt. After the user authenticates, the SAME prompt is retried and
    /// actually runs - proven by the tool-permission request that only the
    /// retried prompt can produce (the pre-auth attempt errors before requesting
    /// anything).
    #[tokio::test]
    async fn agent_retries_prompt_after_mid_turn_auth_required() {
        use std::time::Duration;

        let mgr = SessionManager::new();
        let mut events = mgr.subscribe_events();
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let id = mgr
            .spawn_agent(
                &format!("{py} {mock} --auth-on-prompt"),
                Some("reauth-agent".into()),
                None,
            )
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();

        // Session sets up fine - auth is only demanded once a prompt is sent.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if session
                    .agent_snapshot()
                    .unwrap()
                    .iter()
                    .any(|e| matches!(e.event, AgentEvent::ConfigOptions { .. }))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session setup timed out");

        // Send a prompt; the agent returns AuthRequired mid-turn → the auth card.
        session
            .agent_prompt("run after login".into())
            .expect("agent_prompt");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let has_auth = session.agent_snapshot().unwrap().iter().any(|event| {
                    matches!(
                        &event.event,
                        AgentEvent::AuthRequired { methods }
                            if methods.iter().any(|method| method.id == "mock-login")
                    )
                });
                if has_auth {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("mid-turn auth card timed out");

        // Authenticate → the SAME prompt is retried and reaches the agent's
        // permission request. That AgentPermission cannot come from the pre-auth
        // attempt, so its arrival proves the prompt was retried, not dropped.
        session
            .agent_authenticate("mock-login".into())
            .expect("queue authentication");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if matches!(
                    events.recv().await.expect("recv"),
                    ManagerEvent::AgentPermission { id: pid, .. } if pid == id
                ) {
                    break;
                }
            }
        })
        .await
        .expect("retried prompt never reached the agent");

        assert!(mgr.kill(id).await);
    }

    #[tokio::test]
    async fn agent_cancel_resolves_permission_before_notification() {
        use std::time::Duration;

        let mgr = SessionManager::new();
        let mut events = mgr.subscribe_events();
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let id = mgr
            .spawn_agent(
                &format!("{py} {mock}"),
                Some("cancel-test-agent".into()),
                None,
            )
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();
        session
            .agent_prompt("cancel this turn".into())
            .expect("queue prompt");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if matches!(
                    events.recv().await.unwrap(),
                    ManagerEvent::AgentPermission { .. }
                ) {
                    break;
                }
            }
        })
        .await
        .expect("permission timed out");
        assert_eq!(session.agent_permissions().len(), 1);
        session.agent_cancel().expect("queue cancel");

        let mut saw_resolved = false;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await.unwrap() {
                    ManagerEvent::AgentPermissionResolved { id: resolved, .. } => {
                        assert_eq!(resolved, id);
                        saw_resolved = true;
                        assert!(session.agent_permissions().is_empty());
                    }
                    ManagerEvent::AgentTimeline {
                        event:
                            AgentTimelineEvent {
                                event: AgentEvent::TurnFinished { stop_reason },
                                ..
                            },
                        ..
                    } if stop_reason == "Cancelled" => {
                        assert!(
                            saw_resolved,
                            "turn finished before its approval was resolved"
                        );
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("cancel completion timed out");

        assert!(mgr.kill(id).await);
    }

    #[tokio::test]
    async fn clean_adapter_exit_respawns_and_accepts_another_prompt() {
        use std::time::Duration;

        let mgr = SessionManager::new();
        let mut events = mgr.subscribe_events();
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let id = mgr
            .spawn_agent(
                &format!("{py} {mock}"),
                Some("respawn-test-agent".into()),
                None,
            )
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();
        session.agent_prompt("first turn".into()).unwrap();

        let first_tool_call = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let ManagerEvent::AgentPermission { tool_call, .. } =
                    events.recv().await.unwrap()
                {
                    break tool_call.tool_call_id;
                }
            }
        })
        .await
        .expect("first permission timed out");
        mgr.resolve_permission(&first_tool_call, None, PermissionResolver::Phone)
            .await;

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if matches!(
                    events.recv().await.unwrap(),
                    ManagerEvent::AgentTimeline {
                        event: AgentTimelineEvent {
                            event: AgentEvent::Error { ref message },
                            ..
                        },
                        ..
                    } if message.contains("reconnecting")
                ) {
                    break;
                }
            }
        })
        .await
        .expect("adapter did not enter reconnect state");

        // Queue during backoff; the respawned adapter must consume it after
        // initialize/session-new completes.
        session.agent_prompt("second turn".into()).unwrap();
        let second_tool_call = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let ManagerEvent::AgentPermission { tool_call, .. } =
                    events.recv().await.unwrap()
                {
                    break tool_call.tool_call_id;
                }
            }
        })
        .await
        .expect("second permission timed out");
        mgr.resolve_permission(&second_tool_call, None, PermissionResolver::Phone)
            .await;

        assert!(mgr.kill(id).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn killing_agent_gives_adapter_sigterm_grace_period() {
        use std::time::Duration;

        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("sigterm-marker");
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let spec = format!("python3 {mock} --signal-file={}", marker.display());
        let mgr = SessionManager::new();
        let id = mgr
            .spawn_agent(&spec, Some("signal-test-agent".into()), None)
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !session
                .agent_snapshot()
                .unwrap()
                .iter()
                .any(|event| matches!(&event.event, AgentEvent::ConfigOptions { .. }))
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("mock adapter setup timed out");

        assert!(mgr.kill(id).await);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !marker.is_file() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("adapter did not receive SIGTERM before escalation");
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "sigterm");
    }

    /// End-to-end fixed-size proof: a spawned shell's PTY is genuinely BORN at
    /// the daemon's fixed grid - the shell itself reports it via `stty size`.
    #[cfg(unix)]
    #[tokio::test]
    async fn spawned_shell_is_born_at_fixed_size() {
        use std::time::Duration;
        let mgr = SessionManager::new();
        let id = mgr
            .spawn_shell(None, Some("size-probe".into()))
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();
        let (cols, rows) = fixed_pty_size();
        assert_eq!(session.size(), (cols, rows));

        // Ask the shell for its own size; `stty size` prints "rows cols".
        session.write_input(b"stty size\n").unwrap();
        let want = format!("{rows} {cols}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let text = String::from_utf8_lossy(&session.scrollback_snapshot()).into_owned();
            if text.contains(&want) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "shell never reported {want:?}; scrollback: {text:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        mgr.kill(id).await;
    }

    /// End-to-end proof of the directory fix: a shell spawned with no chosen cwd
    /// opens in the WORKSPACE, and the shell itself says so via `pwd`.
    ///
    /// Nothing cheaper could have caught the bug this pins. `spawn_shell` simply
    /// never set a cwd, so portable_pty planted the PTY in HOME while
    /// `workspace_dir()` sat unused - a state in which every unit test still
    /// passed, the local browser proof still looked right (it passes the workspace
    /// itself), and only a real phone showed the wrong directory. Asking the shell
    /// where it actually is, is the assertion that fails when this regresses.
    ///
    /// Unix-only for determinism: `pwd` is not a `cmd.exe` builtin, and Windows
    /// spawns the default program rather than a login shell.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_shell_with_no_chosen_directory_opens_in_the_workspace() {
        use std::time::Duration;
        // No test sets PORTTY_WORKSPACE, so the workspace is the crate directory
        // cargo runs us from. Deterministic, and with no process-global env
        // mutation that a parallel test could trip over.
        let want = std::fs::canonicalize(crate::iroh_serve::workspace_dir())
            .expect("the crate directory resolves");
        let want = want.to_string_lossy().into_owned();
        // Guard the guard: if HOME were the workspace, this test would pass while
        // proving nothing, because the buggy behaviour and the fixed one agree.
        let home = std::env::var("HOME").unwrap_or_default();
        assert_ne!(
            want, home,
            "the workspace must differ from HOME or this test cannot distinguish \
             the fix from the bug"
        );

        let mgr = SessionManager::new();
        let id = mgr
            .spawn_shell(None, Some("cwd-probe".into()))
            .await
            .unwrap();
        let session = mgr.get(id).await.unwrap();

        // The host never parses these bytes - we read the raw scrollback and look
        // for the path the shell printed, exactly as the size probe does.
        session.write_input(b"pwd\n").unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut reported = false;
        let mut text = String::new();
        while tokio::time::Instant::now() < deadline {
            text = String::from_utf8_lossy(&session.scrollback_snapshot()).into_owned();
            if text.contains(&want) {
                reported = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Kill BEFORE asserting. Panicking with the session still alive leaves its
        // blocking PTY reader running, the runtime then refuses to shut down, and
        // the failure surfaces as a HUNG test binary instead of a red test -
        // verified the hard way while checking this test could actually fail.
        mgr.kill(id).await;
        assert!(
            reported,
            "the shell never reported {want:?} - a shell with no chosen directory \
             must open in the workspace, not the platform default; scrollback: {text:?}"
        );
    }

    /// The default is the workspace, not portable_pty's HOME fallback.
    ///
    /// Complements the PTY probe above: that one proves the wiring end to end but
    /// needs a shell, so it cannot run on Windows. This pins the value itself on
    /// every platform.
    #[test]
    fn the_default_shell_directory_is_the_canonical_workspace() {
        let expected = std::fs::canonicalize(crate::iroh_serve::workspace_dir()).unwrap();
        assert_eq!(default_shell_cwd(), Some(expected));
    }

    #[tokio::test]
    async fn session_cap_rejects_beyond_limit() {
        let mgr = SessionManager::new_with_limits(DEFAULT_SCROLLBACK_BYTES, 2);
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        assert!(mgr
            .register_adopted("a".into(), 80, 24, tx.clone())
            .await
            .is_ok());
        assert!(mgr
            .register_adopted("b".into(), 80, 24, tx.clone())
            .await
            .is_ok());
        // Third exceeds the cap and must be refused.
        let res = mgr.register_adopted("c".into(), 80, 24, tx).await;
        assert!(matches!(res, Err(crate::error::HostError::Limit(_))));
        assert_eq!(mgr.list().await.len(), 2);
    }

    #[tokio::test]
    async fn concurrent_session_creates_cannot_overshoot_cap() {
        let mgr = SessionManager::new_with_limits(DEFAULT_SCROLLBACK_BYTES, 2);
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        let gate = Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = Vec::new();

        for i in 0..16 {
            let mgr = mgr.clone();
            let tx = tx.clone();
            let gate = gate.clone();
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                mgr.register_adopted(format!("race-{i}"), 80, 24, tx).await
            }));
        }

        let mut admitted = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 2);
        assert_eq!(mgr.list().await.len(), 2);
    }

    #[tokio::test]
    async fn removing_session_returns_slot_even_with_external_handle() {
        let mgr = SessionManager::new_with_limits(DEFAULT_SCROLLBACK_BYTES, 1);
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        let (id, held) = mgr
            .register_adopted("first".into(), 80, 24, tx.clone())
            .await
            .unwrap();
        assert!(mgr.kill(id).await);
        assert_eq!(held.id(), id); // an output forwarder may still hold this Arc
        assert!(mgr
            .register_adopted("second".into(), 80, 24, tx)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn oversized_title_is_clamped() {
        let mgr = SessionManager::new();
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        let huge = "x".repeat(10_000);
        let (id, _s) = mgr.register_adopted(huge, 80, 24, tx).await.unwrap();
        let title = mgr.get(id).await.unwrap().info().title;
        assert!(
            title.len() <= MAX_TITLE_BYTES,
            "title not clamped: {}",
            title.len()
        );
    }

    #[test]
    fn clamp_title_respects_char_boundaries() {
        // A multi-byte char straddling the cap must not be split mid-codepoint.
        let s = "é".repeat(MAX_TITLE_BYTES); // 2 bytes each
        let out = clamp_title(s);
        assert!(out.len() <= MAX_TITLE_BYTES);
        assert!(out.chars().all(|c| c == 'é')); // still valid UTF-8, no replacement
    }

    #[tokio::test]
    async fn delta_since_serves_exactly_the_missing_chunks() {
        let mgr = SessionManager::new_with_cap(16 * 1024);
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        let (_id, session) = mgr
            .register_adopted("delta".into(), 80, 24, tx)
            .await
            .unwrap();
        session.push_output(b"one"); // seq 1
        session.push_output(b"two"); // seq 2
        session.push_output(b"three"); // seq 3

        // Fresh client (seen nothing → after_seq 0) gets everything.
        let (chunks, through, _rx) = session.delta_since_and_subscribe(0).unwrap();
        let all: Vec<u8> = chunks
            .iter()
            .flat_map(|c| c.bytes.iter().copied())
            .collect();
        assert_eq!(all, b"onetwothree");
        assert_eq!(through, 3);

        // Client that saw through seq 2 gets only chunk 3.
        let (chunks, through, _rx) = session.delta_since_and_subscribe(2).unwrap();
        let tail: Vec<u8> = chunks
            .iter()
            .flat_map(|c| c.bytes.iter().copied())
            .collect();
        assert_eq!(tail, b"three");
        assert_eq!(through, 3);

        // Fully caught up: empty delta, same checkpoint.
        let (chunks, through, _rx) = session.delta_since_and_subscribe(3).unwrap();
        assert!(chunks.is_empty());
        assert_eq!(through, 3);

        // A seq from the future (stale client / other host lifetime) must NOT
        // be served as an (empty) delta - that would silently lose output.
        assert!(session.delta_since_and_subscribe(4).is_none());
    }

    #[tokio::test]
    async fn delta_since_refuses_aged_out_boundaries() {
        // Cap of 4 KiB (the env-clamp minimum) with 1 KiB chunks: after eight
        // pushes the first chunks are long gone.
        let mgr = SessionManager::new_with_cap(4 * 1024);
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        let (_id, session) = mgr
            .register_adopted("aged".into(), 80, 24, tx)
            .await
            .unwrap();
        for i in 0u8..8 {
            session.push_output(&[i; 1024]); // seqs 1..=8
        }
        // Chunks 1-4 were evicted; a client that saw only chunk 1 must get the
        // conservative full-resync answer, not a silently gappy delta.
        assert!(session.delta_since_and_subscribe(1).is_none());
        // A client that saw everything still resumable from the retained tail.
        let (chunks, through, _rx) = session.delta_since_and_subscribe(7).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(through, 8);
        assert_eq!(chunks[0].seq, 8);
    }

    #[tokio::test]
    async fn ring_truncating_one_oversized_chunk_advances_min_full_seq() {
        // A single push larger than the whole cap forces a front-trim; the ring
        // must then refuse deltas that would start inside the partial chunk.
        let mgr = SessionManager::new_with_cap(4 * 1024);
        let (tx, _rx) = mpsc::channel::<HostToRelay>(ADOPTED_CTRL_QUEUE);
        let (_id, session) = mgr
            .register_adopted("trim".into(), 80, 24, tx)
            .await
            .unwrap();
        session.push_output(&[0xab; 10 * 1024]); // seq 1, trimmed to 4 KiB
        assert_eq!(session.scrollback_snapshot().len(), 4 * 1024);
        // Delta "from the start" would need the trimmed-away front - refuse.
        assert!(session.delta_since_and_subscribe(0).is_none());
        // But a caught-up client resumes fine past the partial chunk.
        let (chunks, through, _rx) = session.delta_since_and_subscribe(1).unwrap();
        assert!(chunks.is_empty());
        assert_eq!(through, 1);
    }

    fn option(id: &str, kind: PermissionOptionKind) -> PermissionOption {
        PermissionOption {
            option_id: id.into(),
            name: id.into(),
            kind,
        }
    }

    /// Tapping "Deny" sends a valid option id, so the old "an id means allowed"
    /// rule broadcast a REJECTION to every other viewer - and into their decision
    /// logs - as "Allowed".
    #[test]
    fn a_rejected_option_is_never_reported_as_allowed() {
        let options = vec![
            option("allow-once", PermissionOptionKind::AllowOnce),
            option("allow-always", PermissionOptionKind::AllowAlways),
            option("reject-once", PermissionOptionKind::RejectOnce),
            option("reject-always", PermissionOptionKind::RejectAlways),
        ];

        for id in ["reject-once", "reject-always"] {
            let (forwarded, resolution) = permission_outcome(Some(id.into()), &options);
            // The adapter still gets the exact option the user chose...
            assert_eq!(forwarded.as_deref(), Some(id));
            // ...and the other viewers are told the truth about it.
            assert_eq!(resolution, PermissionResolution::Rejected, "{id}");
        }
        for id in ["allow-once", "allow-always"] {
            let (forwarded, resolution) = permission_outcome(Some(id.into()), &options);
            assert_eq!(forwarded.as_deref(), Some(id));
            assert_eq!(resolution, PermissionResolution::Allowed, "{id}");
        }
    }

    /// An id the agent never offered must not reach it, and must not read as a
    /// decision the user made.
    #[test]
    fn an_unoffered_option_id_becomes_a_cancel() {
        let options = vec![option("allow-once", PermissionOptionKind::AllowOnce)];
        let (forwarded, resolution) = permission_outcome(Some("smuggled".into()), &options);
        assert_eq!(forwarded, None);
        assert_eq!(resolution, PermissionResolution::Cancelled);
    }

    #[test]
    fn no_option_at_all_is_a_reject() {
        let options = vec![option("allow-once", PermissionOptionKind::AllowOnce)];
        let (forwarded, resolution) = permission_outcome(None, &options);
        assert_eq!(forwarded, None);
        assert_eq!(resolution, PermissionResolution::Rejected);
    }

    /// Raw transcripts hold prompts, file contents, and tool arguments, so
    /// writing them is a deliberate debugging choice - never the default.
    #[test]
    fn acp_transcript_logging_is_opt_in() {
        assert!(!acp_event_log_enabled(None));
        for off in ["", "0", "false", "no", "off", " ", "2", "on"] {
            assert!(!acp_event_log_enabled(Some(off)), "{off:?} must not enable");
        }
        for on in ["1", "true", "TRUE", "yes", " 1 "] {
            assert!(acp_event_log_enabled(Some(on)), "{on:?} must enable");
        }
    }

    const MISSING_ADAPTER: &str = "portty-adapter-that-is-not-installed";

    /// A phone tap must not be able to fetch and execute a package on its own.
    /// Without a local adapter and without an owner opt-in, this fails.
    #[test]
    fn missing_adapter_fails_instead_of_downloading_one() {
        let var = "PORTTY_TEST_ACP_COMMAND_UNSET";
        std::env::remove_var(var);

        let error = AdapterLaunch::resolve(MISSING_ADAPTER, var, "Test Agent")
            .err()
            .expect("a missing adapter is an error, never a silent download");
        let message = error.to_string();
        assert!(
            message.contains(var),
            "the error names the opt-in: {message}"
        );
        assert!(
            !message.contains("npx"),
            "no implicit package runner is offered: {message}"
        );
    }

    /// The escape hatch is explicit, local, and the owner's own command.
    #[test]
    fn owner_supplied_adapter_command_is_used_verbatim() {
        let var = "PORTTY_TEST_ACP_COMMAND_PINNED";
        std::env::set_var(var, "  npx -y @agentclientprotocol/codex-acp@0.4.1  ");

        let launch = AdapterLaunch::resolve(MISSING_ADAPTER, var, "Test Agent").unwrap();

        assert_eq!(launch.spec, "npx -y @agentclientprotocol/codex-acp@0.4.1");
        assert_eq!(launch.required, "npx");
        assert_eq!(launch.default_title, "Test Agent");
        std::env::remove_var(var);
    }

    /// npm drops an extension-less Unix shim next to its `.cmd` launcher, and
    /// Windows cannot execute the extension-less one. Resolution must therefore
    /// prefer the runnable file, or the adapter dies with "program not found"
    /// after the readiness check said it was there.
    #[test]
    fn windows_path_resolution_prefers_the_runnable_launcher() {
        let dir = tempfile::tempdir().unwrap();
        // Same pair `npm i -g opencode` leaves behind.
        std::fs::write(dir.path().join("opencode"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("opencode.cmd"), b"@echo off\n").unwrap();

        let resolved = resolve_in_dirs("opencode", std::iter::once(dir.path().to_path_buf()))
            .expect("the launcher resolves");

        if cfg!(windows) {
            assert_eq!(
                resolved,
                dir.path().join("opencode.cmd"),
                "Windows must get the .cmd, not the shell shim"
            );
        } else {
            assert_eq!(resolved, dir.path().join("opencode"));
        }
    }

    /// A name that already carries its extension still resolves, and an absolute
    /// path the owner spelled out is left untouched.
    #[test]
    fn explicit_program_spelling_is_respected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("codex-acp.cmd"), b"@echo off\n").unwrap();

        assert_eq!(
            resolve_in_dirs("codex-acp.cmd", std::iter::once(dir.path().to_path_buf())),
            Some(dir.path().join("codex-acp.cmd"))
        );
        assert_eq!(
            resolve_in_dirs("nope", std::iter::once(dir.path().to_path_buf())),
            None
        );
    }

    /// A blank opt-in is not an opt-in.
    #[test]
    fn blank_adapter_command_does_not_count_as_opting_in() {
        let var = "PORTTY_TEST_ACP_COMMAND_BLANK";
        std::env::set_var(var, "   ");

        assert!(AdapterLaunch::resolve(MISSING_ADAPTER, var, "Test Agent").is_err());
        std::env::remove_var(var);
    }

    fn cached(id: &str, cwd: &str, when: u64) -> CachedAcpSession {
        CachedAcpSession {
            provider: AgentProvider::OpenCode,
            cwd: PathBuf::from(cwd),
            acp_session_id: id.into(),
            title: format!("session {id}"),
            first_prompt_label: Some(format!("prompt {id}")),
            last_active_at_unix_ms: when,
            desired_mode: None,
            desired_config: HashMap::new(),
        }
    }

    #[test]
    fn session_listing_is_scoped_to_one_directory_and_newest_first() {
        let entries = vec![
            cached("old", "/w/app", 100),
            cached("elsewhere", "/w/other", 999),
            cached("new", "/w/app", 300),
        ];
        let listed = select_sessions_for_cwd(entries, std::path::Path::new("/w/app"));
        let ids: Vec<&str> = listed.iter().map(|e| e.acp_session_id.as_str()).collect();
        // Another directory's conversation must never be offered here, however
        // recently it was used - that is the whole point of scoping by cwd.
        assert_eq!(ids, vec!["new", "old"]);
    }

    #[test]
    fn resuming_by_id_requires_the_directory_to_match() {
        let entries = vec![cached("s1", "/w/app", 1), cached("s2", "/w/other", 2)];
        assert!(
            select_session_by_id(entries.clone(), std::path::Path::new("/w/app"), "s1").is_some()
        );
        // Right id, wrong workspace: a conversation cannot be pulled into a
        // directory it never belonged to even if its id is known.
        assert!(
            select_session_by_id(entries.clone(), std::path::Path::new("/w/app"), "s2").is_none()
        );
        // And an unknown id resolves to nothing rather than to "the newest".
        assert!(select_session_by_id(entries, std::path::Path::new("/w/app"), "nope").is_none());
    }

    fn session_info(id: &str, cwd: &str) -> acp::schema::v1::SessionInfo {
        acp::schema::v1::SessionInfo::new(acp::schema::v1::SessionId::new(id.to_string()), cwd)
    }

    fn discovered(id: &str, cwd: &str, when: Option<u64>) -> DiscoveredAcpSession {
        DiscoveredAcpSession {
            provider: AgentProvider::OpenCode,
            cwd: PathBuf::from(cwd),
            acp_session_id: id.into(),
            title: format!("agent title {id}"),
            last_active_at_unix_ms: when,
        }
    }

    /// Stand-in for `canonicalize` that does nothing, for the cases where the
    /// spelling is not what is under test.
    fn as_written(path: &std::path::Path) -> Option<PathBuf> {
        Some(path.to_path_buf())
    }

    /// The confinement rule for the v11 listing.
    ///
    /// `session/list` is sent WITH a `cwd` filter, but the filter is the agent's.
    /// The directory is a boundary the workspace resolver owns, so an adapter that
    /// answers with a conversation from somewhere else does not get it offered -
    /// otherwise a compromised or merely sloppy adapter could surface (and then
    /// resume) a conversation from any directory on the machine.
    #[test]
    fn listed_conversations_outside_the_asked_directory_are_dropped() {
        let listed = vec![
            session_info("here", "/w/app"),
            session_info("elsewhere", "/w/other"),
            session_info("parent", "/w"),
        ];
        let kept = discovered_from_session_infos(
            AgentProvider::ClaudeCode,
            std::path::Path::new("/w/app"),
            listed,
            &as_written,
        );
        let ids: Vec<&str> = kept.iter().map(|e| e.acp_session_id.as_str()).collect();
        assert_eq!(ids, vec!["here"]);
    }

    /// The directory match is on the RESOLVED path, not the spelling.
    ///
    /// The resolver canonicalizes; an agent reports whatever its process cwd was.
    /// On Windows those differ by a `\\?\` verbatim prefix and on macOS by a
    /// symlinked project root, and comparing the strings is not stricter - it just
    /// drops every row and reports "nothing to resume" for a whole platform.
    #[test]
    fn listed_conversations_match_the_directory_through_symlinks_and_prefixes() {
        // Two spellings of one directory, and a third that is genuinely elsewhere.
        let resolve = |path: &std::path::Path| -> Option<PathBuf> {
            match path.to_string_lossy().as_ref() {
                r"\\?\C:\w\app" | r"C:\w\app" | "/var/w/app" => Some(PathBuf::from("/real/w/app")),
                "/w/nowhere" => None,
                other => Some(PathBuf::from(other)),
            }
        };
        let listed = vec![
            session_info("windows-spelling", r"C:\w\app"),
            session_info("symlinked", "/var/w/app"),
            session_info("elsewhere", "/w/other"),
            // A path that will not resolve is dropped, so the comparison still
            // fails closed rather than falling back to string equality.
            session_info("unresolvable", "/w/nowhere"),
        ];
        let kept = discovered_from_session_infos(
            AgentProvider::ClaudeCode,
            std::path::Path::new(r"\\?\C:\w\app"),
            listed,
            &resolve,
        );
        let ids: Vec<&str> = kept.iter().map(|e| e.acp_session_id.as_str()).collect();
        assert_eq!(ids, vec!["windows-spelling", "symlinked"]);
        // And the row still carries the RESOLVER's path, never the agent's, so a
        // resume can only ever land where the resolver said.
        assert!(kept
            .iter()
            .all(|row| row.cwd == std::path::Path::new(r"\\?\C:\w\app")));
    }

    #[test]
    fn listed_conversations_are_deduped_bounded_and_always_named() {
        let mut listed = vec![
            session_info("dup", "/w/app"),
            session_info("dup", "/w/app"),
            // An agent that reports a blank title still gets a row - it is a
            // resumable conversation, and an unnamed button beats a missing one.
            session_info("blank", "/w/app").title("   ".to_string()),
            // Dropped, not truncated: a shortened id is a different id. Fifty
            // unbounded ones would also push the reply past MAX_FRAME_BYTES,
            // which drops the phone's connection rather than the listing.
            session_info(&"x".repeat(MAX_AGENT_SHORT_TEXT_BYTES + 1), "/w/app"),
        ];
        listed.extend(
            (0..MAX_LISTED_AGENT_SESSIONS + 20).map(|n| session_info(&format!("s{n}"), "/w/app")),
        );
        let kept = discovered_from_session_infos(
            AgentProvider::ClaudeCode,
            std::path::Path::new("/w/app"),
            listed,
            &as_written,
        );
        assert_eq!(kept.len(), MAX_LISTED_AGENT_SESSIONS);
        assert_eq!(kept[0].acp_session_id, "dup");
        assert_eq!(kept[1].acp_session_id, "blank");
        assert_eq!(kept[1].title, "conversation");
        assert!(kept[0].last_active_at_unix_ms.is_none());
        assert!(
            kept.iter()
                .all(|row| row.acp_session_id.len() <= MAX_AGENT_SHORT_TEXT_BYTES),
            "an oversized id must be dropped, never clamped into a different id"
        );
    }

    /// Which store wins, field by field. The split matters: Portty knows the
    /// conversation's first prompt (a far better name than an auto-title), and the
    /// AGENT knows when it was last touched - including from the laptop, which is
    /// the entire reason this listing exists.
    #[test]
    fn merged_listing_keeps_the_cached_label_and_the_agents_newer_time() {
        let rows = merge_agent_sessions(
            AgentProvider::OpenCode,
            vec![cached("shared", "/w/app", 100)],
            vec![discovered("shared", "/w/app", Some(900))],
        );
        assert_eq!(rows.len(), 1, "one conversation, seen twice, is one row");
        assert_eq!(rows[0].label.as_deref(), Some("prompt shared"));
        assert_eq!(rows[0].title, "session shared");
        assert_eq!(rows[0].last_active_at_unix_ms, 900);

        // …and never backwards: a stale probe must not age a conversation Portty
        // just watched happen.
        let rows = merge_agent_sessions(
            AgentProvider::OpenCode,
            vec![cached("shared", "/w/app", 900)],
            vec![discovered("shared", "/w/app", Some(100))],
        );
        assert_eq!(rows[0].last_active_at_unix_ms, 900);
    }

    #[test]
    fn merged_listing_is_provider_scoped_newest_first_and_bounded() {
        let mut cached_rows = vec![
            cached("mine-old", "/w/app", 10),
            cached("mine-new", "/w/app", 500),
        ];
        // A conversation from ANOTHER agent has no business on this screen:
        // tapping it would correctly start that other agent, which is not what
        // choosing this provider promised.
        let mut other = cached("theirs", "/w/app", 999);
        other.provider = AgentProvider::Codex;
        cached_rows.push(other);

        let rows = merge_agent_sessions(
            AgentProvider::OpenCode,
            cached_rows,
            vec![
                discovered("laptop", "/w/app", Some(700)),
                // Unknown time sorts LAST rather than to the top or to 1970's
                // bottom by accident - see `unix_ms_from_rfc3339`.
                discovered("undated", "/w/app", None),
            ],
        );
        let ids: Vec<&str> = rows.iter().map(|r| r.acp_session_id.as_str()).collect();
        assert_eq!(ids, vec!["laptop", "mine-new", "mine-old", "undated"]);
        assert!(rows
            .iter()
            .all(|row| row.provider == AgentProvider::OpenCode));
        assert_eq!(rows[0].label, None, "the agent's rows have no first prompt");

        let flood: Vec<DiscoveredAcpSession> = (0..MAX_LISTED_AGENT_SESSIONS + 40)
            .map(|n| discovered(&format!("s{n}"), "/w/app", Some(n as u64)))
            .collect();
        assert_eq!(
            merge_agent_sessions(AgentProvider::OpenCode, Vec::new(), flood).len(),
            MAX_LISTED_AGENT_SESSIONS
        );
    }

    #[test]
    fn discovered_index_is_bounded_and_matched_on_directory_and_id() {
        let mut index = DiscoveredAcpSessions::default();
        index.remember(&[discovered("s1", "/w/app", Some(1))]);
        index.remember(&[discovered("s2", "/w/other", Some(2))]);

        assert!(index.find(std::path::Path::new("/w/app"), "s1").is_some());
        // Right id, wrong directory: same rule the on-disk cache enforces, so a
        // guessed id cannot pull a conversation into a workspace it never
        // belonged to.
        assert!(index.find(std::path::Path::new("/w/app"), "s2").is_none());
        assert!(index.find(std::path::Path::new("/w/app"), "nope").is_none());

        // Re-listing the same folder must not grow the index once per browse.
        index.remember(&[discovered("s1", "/w/app", Some(5))]);
        assert_eq!(index.0.len(), 2);

        let flood: Vec<DiscoveredAcpSession> = (0..MAX_DISCOVERED_ACP_SESSIONS + 10)
            .map(|n| discovered(&format!("f{n}"), "/w/app", Some(n as u64)))
            .collect();
        index.remember(&flood);
        assert_eq!(index.0.len(), MAX_DISCOVERED_ACP_SESSIONS);
        // Oldest out, newest in.
        assert!(index.find(std::path::Path::new("/w/app"), "f0").is_none());
        assert!(index
            .find(
                std::path::Path::new("/w/app"),
                &format!("f{}", MAX_DISCOVERED_ACP_SESSIONS + 9)
            )
            .is_some());
    }

    /// The one that matters: against a live adapter, reopening a conversation the
    /// phone has never seen must call `session/load` FIRST and the replayed
    /// transcript must reach the timeline.
    ///
    /// This drives the real `spawn_agent_provider` -> `run_acp_session` path,
    /// which is the only place the bug could live: the ordering unit tests below
    /// all passed while the shipped host resumed first and showed an empty chat,
    /// because the input to the decision was wrong rather than the decision.
    ///
    /// Safe to run anywhere on two counts, both worth stating because both look
    /// like the opposite at a glance:
    ///
    /// - The provider resolves through [`AdapterResolver`] to the mock, never to
    ///   whatever real adapter is installed on the machine running the suite.
    /// - It drives the real driver, which reaches `persist_tracked_acp_session` -
    ///   but `build_cached_acp_session` returns `None` under `cfg!(test)` unless
    ///   `PORTTY_ACP_SESSION_CACHE` is set, so the operator's own
    ///   `acp-sessions.json` is never touched. Do not set that variable here: the
    ///   cache path is process-global and this suite runs in parallel.
    #[tokio::test]
    async fn reopening_an_unseen_conversation_replays_it_into_the_timeline() {
        use std::time::Duration;

        let log = tempfile::tempdir().unwrap();
        let reopen_log = log.path().join("reopen.txt");
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let spec = format!(
            "{py} {mock} --reopen-log={}",
            reopen_log.display().to_string().replace('\\', "/")
        );
        let manager = SessionManager::new_with_adapter_resolver(Arc::new(move |_provider| {
            Ok(AdapterLaunch {
                required: py.to_string(),
                hint: "install python".into(),
                spec: spec.clone(),
                default_title: "Mock Agent",
            })
        }));

        // A conversation the agent remembers and Portty has never cached - the
        // laptop-started case, reached exactly as the phone reaches it.
        let cwd = tempfile::tempdir().unwrap();
        let cwd = cwd.path().canonicalize().unwrap();
        manager
            .discovered
            .lock()
            .unwrap()
            .remember(&[DiscoveredAcpSession {
                provider: AgentProvider::ClaudeCode,
                cwd: cwd.clone(),
                acp_session_id: "sess-1".into(),
                title: "started on the laptop".into(),
                last_active_at_unix_ms: Some(1),
            }]);

        let id = manager
            .resume_agent_session(cwd, "sess-1".into())
            .await
            .expect("a probed conversation resumes");
        let session = manager.get(id).await.expect("session exists");

        // The replayed line reaching the timeline is the whole point: with
        // `session/resume` first the conversation is live but INVISIBLE, which is
        // indistinguishable from a broken resume to the person holding the phone.
        let replayed = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let seen = session
                    .agent_snapshot()
                    .unwrap_or_default()
                    .into_iter()
                    .any(|event| {
                        matches!(event.event, AgentEvent::UserMessage { ref text }
                            if text.contains("a conversation this phone never started"))
                    });
                if seen {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            replayed.is_ok(),
            "the reopened conversation never reached the timeline; \
             snapshot was {:?}",
            session.agent_snapshot()
        );

        let first = std::fs::read_to_string(&reopen_log).expect("the mock recorded a reopen call");
        assert_eq!(
            first, "session/load",
            "a conversation the phone has never seen must be reopened with the call \
             that replays it; session/resume restores context and sends no history"
        );
    }

    /// A first connect must REPLAY, and only a driver that already replayed may
    /// prefer the call that does not.
    ///
    /// `session/resume` restores the agent's context and sends no history, so
    /// resume-first on a first connect hands the phone a conversation it cannot
    /// see - which is the entire defect the v11 work set out to fix, and which it
    /// reintroduced once by deciding this from `history.events.is_empty()`. See
    /// [`acp_reopen_order`] for why that input cannot work.
    ///
    /// NOT covered here: that the driver actually calls `session/load` first
    /// against a live adapter. Proving that needs a provider-backed spawn, and a
    /// provider resolves to a REAL adapter whenever one is on PATH - so the test
    /// would launch Claude Code or Codex on whichever machine had it installed.
    /// Verified by hand instead.
    #[test]
    fn a_first_connect_replays_and_a_reconnect_does_not() {
        assert_eq!(
            acp_reopen_order(false),
            [AcpReopen::Load, AcpReopen::Resume],
            "a conversation the phone has never seen must be replayed into it"
        );
        assert_eq!(acp_reopen_order(true), [AcpReopen::Resume, AcpReopen::Load]);

        // And a driver starts having replayed nothing, whatever is already in the
        // timeline - which is the whole point of tracking it separately.
        let replayed = AtomicBool::new(false);
        assert_eq!(
            acp_reopen_order(replayed.load(Ordering::Relaxed))[0],
            AcpReopen::Load
        );
    }

    /// An adapter's error text is arbitrary UTF-8, and it reaches this on a path
    /// a paired phone can trigger at will - so the bound must be a truncation,
    /// not a panic.
    #[test]
    fn an_adapter_error_is_reduced_to_a_bounded_first_line() {
        // A THREE-byte character, because 200 is divisible by 2 and by 4: with
        // `é` or `🔒` the cut lands on a boundary by luck and the naive
        // `&line[..200]` passes. 200 % 3 == 2, so this one actually straddles it.
        let straddling = "中".repeat(300);
        assert!(first_line(&straddling).len() <= 200);
        assert!(!first_line(&straddling).is_empty());
        let wide = "é".repeat(300);
        assert_eq!(first_line(&wide).len(), 200);
        // Only the first line: the rest of an adapter's stderr is where auth
        // failures and tokens live.
        assert_eq!(
            first_line("failed to start\nAUTH_TOKEN=hunter2"),
            "failed to start"
        );
        assert_eq!(first_line(""), "");
        // A single character wider than the whole budget truncates to nothing
        // rather than slicing through it.
        assert_eq!(first_line(&"🔒".repeat(80)).len() % 4, 0);
    }

    /// Neither call is attempted against an agent that does not advertise it.
    #[test]
    fn reopen_calls_respect_the_advertised_capabilities() {
        use acp::schema::v1::{AgentCapabilities, SessionCapabilities, SessionResumeCapabilities};

        let neither = AgentCapabilities::default();
        assert!(!AcpReopen::Load.supported(&neither));
        assert!(!AcpReopen::Resume.supported(&neither));

        let mut load_only = AgentCapabilities::default();
        load_only.load_session = true;
        assert!(AcpReopen::Load.supported(&load_only));
        assert!(!AcpReopen::Resume.supported(&load_only));

        let mut resume_only = AgentCapabilities::default();
        resume_only.session_capabilities = SessionCapabilities::default();
        resume_only.session_capabilities.resume = Some(SessionResumeCapabilities::default());
        assert!(!AcpReopen::Load.supported(&resume_only));
        assert!(AcpReopen::Resume.supported(&resume_only));
    }

    /// Two agents reporting the same id in one folder must not let one of them
    /// answer for the other.
    ///
    /// The index's whole job is to say WHICH agent owns a conversation, so it is
    /// keyed by provider too - and where it genuinely cannot tell, it says nothing
    /// rather than guessing. Starting Claude Code against an OpenCode conversation
    /// is exactly the mix-up the "provider never comes from the phone" rule exists
    /// to prevent, and a collision here would smuggle it in through the back.
    #[test]
    fn a_shared_id_across_two_agents_resolves_to_neither() {
        let mut index = DiscoveredAcpSessions::default();
        let mut claude = discovered("shared", "/w/app", Some(1));
        claude.provider = AgentProvider::ClaudeCode;
        index.remember(&[claude]);
        // Browsing the same folder in the other agent's picker must ADD, not
        // overwrite - the two rows are two different conversations.
        index.remember(&[discovered("shared", "/w/app", Some(2))]);
        assert_eq!(index.0.len(), 2);
        assert!(index
            .find(std::path::Path::new("/w/app"), "shared")
            .is_none());

        // An unambiguous id in the same index still resolves.
        index.remember(&[discovered("mine", "/w/app", Some(3))]);
        assert_eq!(
            index
                .find(std::path::Path::new("/w/app"), "mine")
                .map(|entry| entry.provider),
            Some(AgentProvider::OpenCode)
        );
    }

    /// Resuming a conversation the agent's CLI started: nothing is in the disk
    /// cache, so the record has to come from the last probe - and the provider has
    /// to come with it.
    #[tokio::test]
    async fn a_probed_conversation_is_resumable_without_a_cache_entry() {
        let manager = SessionManager::new();
        let app = std::path::Path::new("/w/app");
        manager.discovered.lock().unwrap().remember(&[discovered(
            "laptop-started",
            "/w/app",
            Some(42),
        )]);

        let entry = manager
            .resumable_conversation(app, "laptop-started")
            .await
            .expect("a probed conversation is resumable");
        assert_eq!(entry.provider, AgentProvider::OpenCode);
        assert_eq!(entry.title, "agent title laptop-started");
        assert_eq!(entry.last_active_at_unix_ms, 42);
        // Portty never drove this conversation, so it has no opinion about how to
        // drive it - the agent's own mode and settings stand.
        assert!(entry.desired_mode.is_none());
        assert!(entry.desired_config.is_empty());
        // No first prompt either: Portty never watched it happen.
        assert!(entry.first_prompt_label.is_none());

        // Right id, wrong directory, and an id nobody has ever seen, both resolve
        // to nothing rather than to "the newest".
        assert!(manager
            .resumable_conversation(std::path::Path::new("/w/other"), "laptop-started")
            .await
            .is_none());
        assert!(manager
            .resumable_conversation(app, "invented")
            .await
            .is_none());
    }

    /// Backtracking through the picker must not relaunch the adapter, and a memo
    /// must not outlive its usefulness.
    #[test]
    fn probe_answers_are_reused_briefly_then_expire() {
        let mut memos = ProbeMemos::default();
        let start = std::time::Instant::now();
        let app = std::path::Path::new("/w/app");
        memos.store(ProbeMemo {
            provider: AgentProvider::OpenCode,
            cwd: app.to_path_buf(),
            taken_at: start,
            sessions: vec![discovered("s1", "/w/app", Some(1))],
        });

        assert_eq!(
            memos
                .get(AgentProvider::OpenCode, app, start)
                .map(|s| s.len()),
            Some(1)
        );
        // Another agent's answer is not this agent's answer, and neither is
        // another directory's.
        assert!(memos.get(AgentProvider::Codex, app, start).is_none());
        assert!(memos
            .get(
                AgentProvider::OpenCode,
                std::path::Path::new("/w/other"),
                start
            )
            .is_none());
        // Past the TTL the host asks the agent again rather than showing a list
        // that no longer includes what you just started.
        assert!(memos
            .get(
                AgentProvider::OpenCode,
                app,
                start + ACP_SESSION_LIST_TTL + std::time::Duration::from_millis(1)
            )
            .is_none());

        for n in 0..MAX_MEMOIZED_PROBES + 4 {
            memos.store(ProbeMemo {
                provider: AgentProvider::OpenCode,
                cwd: PathBuf::from(format!("/w/{n}")),
                taken_at: start,
                sessions: Vec::new(),
            });
        }
        assert_eq!(memos.0.len(), MAX_MEMOIZED_PROBES);
    }

    /// The timestamps adapters actually emit, and the ones Portty refuses to
    /// guess at.
    #[test]
    fn agent_timestamps_parse_or_stay_unknown() {
        // `new Date().toISOString()` - what both shipped adapters send.
        assert_eq!(
            unix_ms_from_rfc3339("2026-08-06T06:53:09.852Z"),
            Some(1_785_999_189_852)
        );
        // Whole seconds, lowercase zone, and a numeric offset all round-trip to
        // the same instant.
        assert_eq!(
            unix_ms_from_rfc3339("1970-01-01T00:00:00Z"),
            Some(0),
            "the epoch itself is a real timestamp"
        );
        assert_eq!(
            unix_ms_from_rfc3339("2026-08-06t06:53:09z"),
            Some(1_785_999_189_000)
        );
        assert_eq!(
            unix_ms_from_rfc3339("2026-08-06T12:23:09+05:30"),
            Some(1_785_999_189_000)
        );
        assert_eq!(
            unix_ms_from_rfc3339("2026-08-06T01:53:09-05:00"),
            Some(1_785_999_189_000)
        );
        // Sub-millisecond precision is dropped, not rounded - a picker sorts by
        // the second.
        assert_eq!(
            unix_ms_from_rfc3339("2026-08-06T06:53:09.8529999Z"),
            Some(1_785_999_189_852)
        );
        // Leap-year day, and a leap SECOND, are both real instants.
        assert!(unix_ms_from_rfc3339("2024-02-29T00:00:00Z").is_some());
        assert!(unix_ms_from_rfc3339("2016-12-31T23:59:60Z").is_some());

        // Everything below stays unknown rather than becoming a plausible-looking
        // lie in the picker. A no-zone timestamp is the important one: assuming
        // UTC would silently shift a conversation by up to half a day.
        for rejected in [
            "",
            "2026-08-06",
            "2026-08-06T06:53:09",
            "2026-08-06T06:53:09.Z",
            "2026-08-06T06:53:09+0530",
            "2026-13-06T06:53:09Z",
            "2026-08-06T24:53:09Z",
            "2026-08-06T06:73:09Z",
            "yesterday afternoon",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(
                unix_ms_from_rfc3339(rejected),
                None,
                "{rejected:?} must not parse"
            );
        }
    }

    /// The `.cmd` fix must reach the ACP TERMINAL path, not just the adapter
    /// spawn: an agent asking to run `npm test` hits exactly the same trap. This
    /// drives the real `AcpTerminals::create` with a launcher that exists ONLY as
    /// a `.cmd`, which is what every npm-installed tool looks like.
    ///
    /// Windows-only on purpose - on unix `execvp` already walks PATH, so there is
    /// no behaviour here to pin down.
    #[cfg(windows)]
    #[tokio::test]
    async fn acp_terminal_spawns_a_cmd_launcher_given_a_bare_name() {
        let workspace = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        // Uniquely named so prepending this dir to PATH cannot shadow anything a
        // concurrent test might spawn.
        std::fs::write(
            bin.path().join("portty-cmd-probe.cmd"),
            b"@echo off\r\necho probe-ran\r\n",
        )
        .unwrap();

        let original = std::env::var_os("PATH").unwrap_or_default();
        let mut prepended = std::ffi::OsString::from(bin.path());
        prepended.push(";");
        prepended.push(&original);
        std::env::set_var("PATH", &prepended);

        // Built by decoding the wire form, exactly as an adapter's
        // `terminal/create` arrives - no hand-assembled struct that could drift
        // from what the schema actually accepts.
        let request: CreateTerminalRequest = serde_json::from_value(serde_json::json!({
            "sessionId": "probe",
            "command": "portty-cmd-probe",
        }))
        .expect("a minimal terminal/create request decodes");

        let terminals = AcpTerminals::new(workspace.path().to_path_buf());
        let result = terminals.create(request);

        std::env::set_var("PATH", &original);

        assert!(
            result.is_ok(),
            "a bare npm-style launcher must spawn, not fail with \"program not found\": {:?}",
            result.err()
        );
    }
}
