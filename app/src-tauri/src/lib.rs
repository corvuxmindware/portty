//! Portty phone app - Tauri 2 core.
//!
//! Pairs with a host over iroh (ticket + PIN), then exchanges sealed `Frame`s.
//! The SolidJS UI invokes the commands below and listens for the `portty://*`
//! events this core emits (list / added / removed / output / disconnected).
//!
//! Concurrency model (mirrors the host, `crates/host/src/iroh_serve.rs`): a
//! dedicated reader task feeds raw sealed-envelope bytes into a session loop,
//! which owns the single non-`Clone` `EnvelopeCipher` and does all seal/open.
//! Reading in its own task means the session loop's `select!` only ever
//! cancels mpsc recvs (cancel-safe), never a mid-frame transport read.

#[cfg(target_os = "android")]
mod android_context;
#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile_credentials;
mod push_wake;

use blake3::Hasher;
use portty_protocol::{
    AgentAuthMethod, AgentCommand, AgentConfigOption, AgentConfigValue, AgentEvent, AgentMode,
    AgentPlanEntry, AgentProvider, AgentTimelineEvent, AgentToolKind, AgentToolStatus,
    CommandOutcome, Frame, PermissionCategory, PermissionOption, PermissionResolution,
    PermissionResolver, RequestKind, SessionId, SessionInfo, SessionKind, SessionSource,
    TerminalRoot, ToolCallCard, TransferId, WorkspaceScope, FILE_CHUNK_BYTES,
};
use portty_transport::{
    build_endpoint, decode_ticket, decode_ticket_secret, open_msg, run_client_handshake,
    run_client_handshake_with, seal_msg, ClientHandshake, DeviceId, EnvelopeCipher,
    HandshakeCommit, Identity, IrohReader, IrohTransport, IrohWriter, PairingFailure,
    PairingSecret, PeerStore, ProtocolError, SealedEnvelope, SyncError, TransportError,
    PROTOCOL_VERSION,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, State};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

const CONNECTION_OUTBOUND_FRAMES: usize = 16;
const CONNECTION_INBOUND_RAW_FRAMES: usize = 16;
const MAX_ACTIVE_FILE_TRANSFERS: usize = 4;
/// Hard ceiling on ONE download, mirroring the host's own
/// `PORTTY_MAX_TRANSFER_BYTES` default. A download has no declared size on the
/// wire - `FileDone` states it only at the end - so without this a paired host
/// could answer `FileGetReq` with an endless chunk stream and fill the phone's
/// storage while the progress line counted up. At the limit the transfer is
/// abandoned and the partial file deleted.
const MAX_DOWNLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Ceiling across ALL active downloads together. The per-transfer limit alone
/// still let four concurrent downloads write 16 GiB, which is more than a phone
/// has; this is what actually bounds the disk a host can consume.
const MAX_TOTAL_DOWNLOAD_BYTES: u64 = 6 * 1024 * 1024 * 1024;
/// How many times a download may restart from zero after failing verification.
/// A checksum mismatch cannot say which chunk was bad, so the whole file is
/// re-fetched - which a malicious or broken host could otherwise make it do
/// forever, re-reading and re-writing the same bytes with nothing converging.
const MAX_DOWNLOAD_RESTARTS: u32 = 3;

/// Registry of in-flight correlated commands: `req_id -> resolver`. The session
/// loop resolves each entry when the matching `CommandResult` arrives.
type Pending = Arc<AsyncMutex<HashMap<u64, oneshot::Sender<CommandOutcome>>>>;
type UnpairPending = Arc<AsyncMutex<HashMap<u64, oneshot::Sender<Result<(), String>>>>>;
/// Workspace listings, correlated by the same `req_id` as `Pending`. The listing
/// rides its own frame (it cannot fit in a `CommandOutcome`), so a directory
/// browse resolves two channels for one request.
type DirsPending = Arc<AsyncMutex<HashMap<u64, oneshot::Sender<WorkspaceListing>>>>;
/// Cached-conversation listings, correlated the same way as `DirsPending`.
type SessionsPending = Arc<AsyncMutex<HashMap<u64, oneshot::Sender<AgentSessionListing>>>>;
/// Adapter-availability answers, correlated the same way.
type ProvidersPending = Arc<AsyncMutex<HashMap<u64, oneshot::Sender<Vec<AgentProviderRow>>>>>;
/// Which terminal roots the host serves, correlated the same way.
type RootsPending = Arc<AsyncMutex<HashMap<u64, oneshot::Sender<Vec<String>>>>>;

/// Whether one agent can actually be launched on the host.
#[derive(Serialize, Clone)]
struct AgentProviderRow {
    provider: &'static str,
    available: bool,
    detail: Option<String>,
}

/// The resumable conversations for one workspace directory, newest first.
#[derive(Serialize, Clone)]
struct AgentSessionListing {
    rel: String,
    sessions: Vec<AgentSessionRow>,
}

/// One row of that list. `provider` is stringified to the same names the
/// frontend already uses for starting an agent.
#[derive(Serialize, Clone)]
struct AgentSessionRow {
    acp_session_id: String,
    provider: &'static str,
    title: String,
    label: Option<String>,
    last_active_at_unix_ms: u64,
}

/// One level of the workspace tree, as the picker sees it.
#[derive(Serialize, Clone)]
struct WorkspaceListing {
    /// The RESOLVED path relative to the workspace root; `""` is the root, where
    /// the picker hides "up" because there is nothing above it to reach.
    rel: String,
    names: Vec<String>,
}

/// Event carrying the six-digit pairing comparison code to the UI.
///
/// Emitted mid-handshake, because the host deliberately withholds its
/// acknowledgement until a human there confirms the code. The phone has to show
/// it during that wait, not after. The value is NOT secret - it is derived from
/// the completed exchange purely so two screens can be compared, and it is
/// useless to anyone who did not run that exchange.
const PAIR_CODE_EVENT: &str = "portty://pair-code";

/// Everything owned by one authenticated link. Keeping command resolvers with
/// the link prevents a stale session task from clearing a newer connection's
/// requests after a fast disconnect/reconnect.
struct Connection {
    id: u64,
    peer_device_id: DeviceId,
    pair_id: portty_transport::PairId,
    outbound: mpsc::Sender<Frame>,
    pending: Pending,
    unpair_pending: UnpairPending,
    dirs_pending: DirsPending,
    sessions_pending: SessionsPending,
    providers_pending: ProvidersPending,
    roots_pending: RootsPending,
    /// Kill switch for this link's session task. Dropping the `Connection` - on
    /// `disconnect`, a host switch, or `remove_host` - resolves the paired
    /// receiver and the session loop breaks, closing the iroh endpoint.
    ///
    /// This must NOT be inferred from `outbound` closing: the session loop holds
    /// its own clone of that sender (it needs it to answer `FileRetry`), so the
    /// outbound receiver never sees a close. Before this existed, a
    /// "disconnected" link kept an authenticated QUIC connection running and its
    /// host could still inject session, terminal, permission, and transfer
    /// events into the UI after the phone had moved on.
    _shutdown: oneshot::Sender<()>,
}

type CurrentConnection = Arc<AsyncMutex<Option<Connection>>>;

struct PorttyState {
    identity: Identity,
    /// The currently authenticated link. Session cleanup is generation-checked:
    /// an old task may only remove the exact connection it belongs to.
    connection: CurrentConnection,
    /// SEC-2: persisted per-peer reconnect tokens (+ the host's ticket, so the
    /// phone can redial). Lets a reconnect skip the out-of-band secret entirely.
    peers: Arc<AsyncMutex<PeerStore>>,
    /// Held for the whole duration of a `pair`/`reconnect`. `try_lock` here means
    /// only ONE connection attempt runs at a time - concurrent attempts (double
    /// taps, a visibility-change reconnect racing a manual pair) are rejected
    /// rather than both proceeding and creating orphaned sessions / rotating the
    /// token twice.
    connecting: AsyncMutex<()>,
    /// Monotonic connection/request generations (process-local only).
    next_connection_id: AtomicU64,
    next_req_id: AtomicU64,
    /// App data dir (identity, peer store, host-name labels live here).
    data_dir: std::path::PathBuf,
    transfers: Arc<ClientTransfers>,
    /// session id → last rendered output seq. Fed by `SequencedOutput`; read
    /// by `resume_output` so a warm reconnect asks the host for exactly the
    /// missed delta instead of a full reset + snapshot.
    last_seen_seq: Arc<AsyncMutex<HashMap<u64, u64>>>,
    /// session id → host generation of the `ScreenReset` that established the
    /// screen we're rendering. Echoed in `OutputResume` so the host can detect a
    /// restart (its generation changed) and force a fresh attach instead of a
    /// delta that would corrupt the screen (#14).
    last_seen_generation: Arc<AsyncMutex<HashMap<u64, u64>>>,
    /// Phone-local key sealing the push wake blobs (never leaves the device).
    wake_key: [u8; 32],
}

struct ClientTransfers {
    next_id: AtomicU64,
    slots: Arc<Semaphore>,
    downloads: AsyncMutex<HashMap<TransferId, DownloadTransfer>>,
    uploads: AsyncMutex<HashMap<TransferId, UploadTransfer>>,
}

/// Which pairing a transfer belongs to. `TransferId`s are process-local and
/// sequential, so without this a second host could name another host's transfer
/// and be handed its bytes, its remote path, or its local source file.
#[derive(Clone, Copy, PartialEq, Eq)]
struct TransferOwner {
    peer_device_id: DeviceId,
    pair_id: portty_transport::PairId,
}

#[derive(Clone)]
struct UploadTransfer {
    owner: TransferOwner,
    /// The OPEN handle this transfer streams from, held for the whole transfer
    /// including every retry.
    ///
    /// This used to be a path, reopened by name in `spawn_upload_range` on the
    /// first pass and again on each `FileRetry`, after a separate `metadata()`
    /// call had already told the host the size. Anything able to replace the
    /// path in between - another local process, or a cloud-file provider
    /// re-materializing it - substituted a different file, and since the digest
    /// is computed over what is actually read, the host committed the swap
    /// happily under the name the user approved.
    ///
    /// One handle, opened once, makes the path irrelevant after the open: every
    /// pass reads the same inode no matter what the name points at later.
    /// Behind a mutex because a superseded streaming task can still be inside
    /// its final chunk when its replacement starts.
    ///
    /// Deliberately NOT `O_NOFOLLOW`: with the handle held, following a symlink
    /// once at open time is no longer a race, so refusing symlinked uploads
    /// would break legitimate use for no additional guarantee.
    ///
    /// The local path is deliberately NOT kept beside it. Reintroducing this bug
    /// now requires adding a path field back, which is visible in review; a
    /// struct that cannot name the file cannot reopen it.
    file: Arc<tokio::sync::Mutex<tokio::fs::File>>,
    remote_path: String,
    size: u64,
    /// Set when the host rejects the upload (`FileErr`): the streaming task
    /// checks it per chunk and stops, instead of pushing the rest of a large
    /// file into the void chunk by bounced chunk.
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    /// Which streaming task is the live one. Every `FileRetry` bumps it, and a
    /// task whose epoch no longer matches stops at its next chunk.
    ///
    /// Without this, each retry spawned ANOTHER reader for the same file while
    /// the previous ones kept going: a host that answered every chunk with a
    /// retry could make the phone run unbounded concurrent file reads, all
    /// pushing into the same connection. One retry now replaces the stream it
    /// retries rather than joining it.
    epoch: Arc<AtomicU64>,
    /// Shared with the streaming task; the slot is released only when both the
    /// registry entry and any in-flight task have gone away.
    _slot: Arc<OwnedSemaphorePermit>,
}

struct DownloadTransfer {
    owner: TransferOwner,
    /// Verification failures that restarted this download (see
    /// `MAX_DOWNLOAD_RESTARTS`).
    restarts: u32,
    remote_path: String,
    target: std::path::PathBuf,
    temporary: std::path::PathBuf,
    file: tokio::fs::File,
    next_seq: u64,
    written: u64,
    hasher: Hasher,
    allow_outside_home: bool,
    _slot: OwnedSemaphorePermit,
}

/// Commit a verified sibling temporary file without deleting the user's
/// existing destination first. POSIX rename replaces atomically. Windows does
/// not overwrite with `rename`, so retain the old destination as a backup and
/// roll it back if installing the verified file fails.
async fn replace_download_file(
    temporary: &std::path::Path,
    target: &std::path::Path,
) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        tokio::fs::rename(temporary, target).await
    }
    #[cfg(windows)]
    {
        if !tokio::fs::try_exists(target).await? {
            return tokio::fs::rename(temporary, target).await;
        }

        let backup = temporary.with_extension("previous");
        if tokio::fs::try_exists(&backup).await? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "download backup already exists; refusing to overwrite it",
            ));
        }
        tokio::fs::rename(target, &backup).await?;
        if let Err(install_error) = tokio::fs::rename(temporary, target).await {
            return match tokio::fs::rename(&backup, target).await {
                Ok(()) => Err(install_error),
                Err(rollback_error) => Err(std::io::Error::new(
                    install_error.kind(),
                    format!(
                        "could not install verified download ({install_error}); \
                         original remains at {} because rollback failed ({rollback_error})",
                        backup.display()
                    ),
                )),
            };
        }
        tokio::fs::remove_file(backup).await
    }
}

#[derive(Serialize, Clone)]
struct TransferProgressPayload {
    id: u64,
    direction: &'static str,
    transferred: u64,
    total: Option<u64>,
    path: String,
}

#[derive(Serialize, Clone)]
struct TransferCompletePayload {
    id: u64,
    direction: &'static str,
    path: String,
}

#[derive(Serialize, Clone)]
struct TransferErrorPayload {
    id: u64,
    message: String,
}

#[derive(Serialize, Clone)]
struct PushRegisteredPayload {
    ok: bool,
    detail: Option<String>,
}

#[derive(Serialize, Clone)]
struct PairRevokedPayload {
    host: String,
}

#[derive(Serialize)]
struct RemoveHostResult {
    disconnected: bool,
    remote_revoked: bool,
}

/// Non-secret display names for saved hosts (the host picker's labels), keyed
/// by device id in their OWN file - extending the credential store's postcard
/// format would break decoding of existing stores and silently drop pairings.
fn host_names_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("portty-host-names.dat")
}

/// The nicknames the USER typed, in a second file for the same reason the
/// announced names are not in the credential store: the file above already
/// ships as a bare `HashMap<DeviceId, String>`, so widening it to a struct
/// would fail to decode every existing store and silently drop every label.
/// A nickname could not share that map anyway - every pair and reconnect
/// rewrites the announced name, which would clobber the user's choice.
fn host_nicknames_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("portty-host-nicknames.dat")
}

/// Longest nickname the picker will store. Rows are single-line and ellipsized,
/// so a longer label is invisible anyway - and a pasted essay would bloat a
/// file that is read on every `list_hosts`.
const MAX_HOST_NICKNAME_CHARS: usize = 40;

fn load_host_labels(path: &std::path::Path) -> HashMap<DeviceId, String> {
    std::fs::read(path)
        .ok()
        .and_then(|b| postcard::from_bytes(&b).ok())
        .unwrap_or_default()
}

/// Write a label map back, removing the file entirely once the map empties so a
/// phone with no saved hosts leaves no stray label file behind.
fn store_host_labels(
    path: &std::path::Path,
    labels: &HashMap<DeviceId, String>,
) -> std::io::Result<()> {
    if labels.is_empty() {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
    }
    let bytes = postcard::to_allocvec(labels)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, bytes)
}

fn load_host_names(dir: &std::path::Path) -> HashMap<DeviceId, String> {
    load_host_labels(&host_names_path(dir))
}

fn load_host_nicknames(dir: &std::path::Path) -> HashMap<DeviceId, String> {
    load_host_labels(&host_nicknames_path(dir))
}

/// Each host's chosen default folder for new terminals, workspace-relative.
///
/// Its own file for the same reason the nickname has one: these maps ship as a
/// bare `HashMap<DeviceId, String>`, so widening an existing one to a struct
/// would fail to decode every store already on a phone and silently drop its
/// contents.
///
/// Phone-local and per host, exactly like the nickname - nothing is sent to the
/// host, so it works offline and another phone paired to the same laptop keeps its
/// own choice. That also means it is a PREFERENCE, never a permission: the host
/// re-resolves and re-confines whatever `rel` it is handed
/// (`workspace::resolve_within`), so a stale or hand-edited value can only be
/// refused, never escape the workspace.
fn host_default_dirs_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("portty-host-default-dirs.dat")
}

fn load_host_default_dirs(dir: &std::path::Path) -> HashMap<DeviceId, String> {
    load_host_labels(&host_default_dirs_path(dir))
}

/// Longest stored default folder. Deep trees are legitimate, so this is
/// generous: it exists to stop a pathological value bloating a file that is read
/// on every `list_hosts`, not to police depth.
const MAX_DEFAULT_DIR_CHARS: usize = 512;

/// Encode/decode a stored default folder as `root:rel`.
///
/// The label store is a bare `HashMap<DeviceId, String>` on disk, so the root
/// rides IN the string rather than in a widened struct that no existing store
/// could decode.
///
/// **Values written before v10 have no prefix** and meant the workspace, so an
/// unprefixed value decodes as `Workspace` - that is the migration, and it costs
/// nothing. An unknown prefix also decodes as workspace-relative rather than being
/// dropped: the host re-resolves every rel anyway, so the worst case is a refusal
/// the user can see, not a silently forgotten setting.
fn encode_default_dir(root: &str, rel: &str) -> String {
    format!("{root}:{rel}")
}

fn decode_default_dir(stored: &str) -> (String, String) {
    match stored.split_once(':') {
        Some((root, rel)) if root == "home" || root == "workspace" => {
            (root.to_string(), rel.to_string())
        }
        _ => ("workspace".to_string(), stored.to_string()),
    }
}

/// Map a phone-supplied root name onto the wire enum. Unknown names are refused
/// rather than defaulted - a root nobody recognizes is not the workspace.
fn terminal_root_from_str(raw: &str) -> Result<TerminalRoot, String> {
    match raw {
        "workspace" => Ok(TerminalRoot::Workspace),
        "home" => Ok(TerminalRoot::Home),
        other => Err(format!("unknown folder root: {other}")),
    }
}

fn terminal_root_name(root: TerminalRoot) -> &'static str {
    match root {
        TerminalRoot::Workspace => "workspace",
        TerminalRoot::Home => "home",
    }
}

/// Normalize a phone-chosen default folder, or reject it.
///
/// `Ok(String)` is storable (empty = the workspace root = clear the setting).
/// The host is the authority on whether the path resolves, and re-checks
/// containment regardless; this only refuses values that could never be valid, so
/// they are caught when set rather than surfacing as a confusing refusal later:
/// absolute paths, `..`, Windows prefixes, control characters.
///
/// Mirrors `portty_host::workspace::normalize_rel` deliberately. Duplicated
/// rather than shared because that crate is not a dependency of the app shell -
/// if the two ever disagree the host still wins, which is the safe direction.
fn sanitize_default_dir(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.chars().count() > MAX_DEFAULT_DIR_CHARS {
        return Err("that folder path is too long to save".into());
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("that folder path is not valid".into());
    }
    let path = std::path::Path::new(trimmed);
    if path.is_absolute() {
        return Err("the default folder must be inside the workspace".into());
    }
    let mut parts: Vec<&str> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => {
                parts.push(part.to_str().ok_or("that folder path is not valid")?);
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err("the default folder must be inside the workspace".into());
            }
        }
    }
    Ok(parts.join("/"))
}

// ── Agent approval log storage ────────────────────────────────────────
//
// The log used to live in WebView `localStorage`. That is plaintext inside the
// app container, and on iOS the container goes into device backups - so a record
// of up to 200 commands, arguments and paths left the device with every backup,
// protected only by the phone-side redaction, which is pattern matching and
// therefore cannot recognize every secret.
//
// It now lives here instead: one owner-only file per host in the app data dir,
// marked excluded from backup. The phone-side redaction is KEPT on top - this
// store writes whatever it is handed, so removing the redaction would put
// secrets in the file rather than in localStorage, which is not the point.
//
// This is confinement, not encryption. Anything that can already read the app
// container as this user can read this file. What it removes is the copy that
// used to travel off the device in a backup.

/// The most a stored log may occupy on disk. The phone caps the log at 200
/// entries, but that is the phone's promise, not this side's - a bug or a
/// tampered frontend must not be able to fill the data dir.
const MAX_DECISION_LOG_BYTES: usize = 1024 * 1024;

/// Per-host file name for the approval log.
///
/// `host` comes from the frontend, so it is validated rather than trusted: only
/// lowercase hex (a device id) or the literal `unpaired` placeholder. That is
/// deliberately stricter than "reject `..`" - an allowlist has no clever
/// encodings to miss, and the caller only ever produces those two shapes.
fn decision_log_path(dir: &std::path::Path, host: &str) -> Result<std::path::PathBuf, String> {
    let valid = host == "unpaired"
        || (!host.is_empty()
            && host.len() <= 64
            && host
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    if !valid {
        return Err("invalid host id for the approval log".into());
    }
    Ok(dir.join("decision-logs").join(format!("{host}.json")))
}

/// Read one host's stored approval log. Returns `"[]"` for anything unreadable:
/// a missing, truncated or oversized file must degrade to an empty log, never
/// to an error the UI has to handle mid-connect.
#[tauri::command]
fn decision_log_load(state: State<'_, PorttyState>, host: String) -> Result<String, String> {
    let path = decision_log_path(&state.data_dir, &host)?;
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() <= MAX_DECISION_LOG_BYTES => {
            Ok(String::from_utf8(bytes).unwrap_or_else(|_| "[]".into()))
        }
        Ok(_) => {
            tracing::warn!("stored approval log is oversized; ignoring it");
            Ok("[]".into())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("[]".into()),
        Err(error) => {
            tracing::warn!(%error, "could not read the stored approval log");
            Ok("[]".into())
        }
    }
}

/// Replace one host's stored approval log. `entries` is the already-redacted
/// JSON the phone decided to keep.
#[tauri::command]
fn decision_log_save(
    state: State<'_, PorttyState>,
    host: String,
    entries: String,
) -> Result<(), String> {
    let path = decision_log_path(&state.data_dir, &host)?;
    if entries.len() > MAX_DECISION_LOG_BYTES {
        return Err("approval log is too large to store".into());
    }
    let dir = path
        .parent()
        .ok_or("approval log has no parent directory")?;
    portty_transport::secure::prepare_secret_dir(dir).map_err(|e| e.to_string())?;
    portty_transport::secure::write_owner_only(&path, entries.as_bytes())
        .map_err(|e| e.to_string())?;
    // Best-effort by design: on platforms where exclusion is declarative
    // (Android) or unnecessary (Windows/Linux per-user storage) this is a no-op,
    // and a failure here must not lose the write that already succeeded.
    if let Err(error) = portty_transport::secure::exclude_from_backup(&path) {
        tracing::warn!(%error, "could not exclude the approval log from backup");
    }
    Ok(())
}

/// Delete one host's stored approval log. Called when the host is forgotten, so
/// the record of what an agent ran there does not outlive the pairing.
#[tauri::command]
fn decision_log_forget(state: State<'_, PorttyState>, host: String) -> Result<(), String> {
    let path = decision_log_path(&state.data_dir, &host)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

/// Remember what a host calls itself (its hostname, sent in the handshake
/// Hello). Best-effort: labels are cosmetic, so failures only log.
fn save_host_name(dir: &std::path::Path, dev: DeviceId, name: &str) {
    let name = name.trim();
    // "host" is the legacy placeholder older daemons send - not a real label.
    if name.is_empty() || name == "host" {
        return;
    }
    let mut names = load_host_names(dir);
    if names.get(&dev).map(String::as_str) == Some(name) {
        return;
    }
    names.insert(dev, name.to_string());
    if let Err(e) = store_host_labels(&host_names_path(dir), &names) {
        tracing::warn!(error = %e, "could not save host name label");
    }
}

/// A nickname is pure UI text on a single-line row, so fold every control
/// character and run of whitespace into one space (a pasted newline would
/// otherwise break the row) and cap the length. An empty result means "no
/// nickname" - the picker falls back to the announced hostname.
fn sanitize_host_nickname(raw: &str) -> String {
    let mut nickname = String::new();
    for word in raw
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
    {
        if !nickname.is_empty() {
            nickname.push(' ');
        }
        nickname.push_str(word);
    }
    // Truncate by chars, not bytes - a byte cut would panic mid-codepoint on
    // any non-ASCII label. Re-trim: the cap can land on the joining space.
    if nickname.chars().count() > MAX_HOST_NICKNAME_CHARS {
        nickname = nickname
            .chars()
            .take(MAX_HOST_NICKNAME_CHARS)
            .collect::<String>()
            .trim_end()
            .to_string();
    }
    nickname
}

/// Send a correlated command and await its outcome (with a timeout). Returns the
/// affected session id on success, or the host's error message.
async fn request(
    state: &State<'_, PorttyState>,
    kind: RequestKind,
) -> Result<Option<SessionId>, String> {
    let req_id = state.next_req_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    let (outbound, pending) = {
        let connection = state.connection.lock().await;
        let current = connection.as_ref().ok_or("not paired")?;
        // Insert while the connection lock proves this generation is current.
        // Inserting after release raced disconnect/reconnect: the resolver
        // could land in a just-retired generation's map, never resolve, and
        // turn an instant "connection closed" into a 10s timeout.
        current.pending.lock().await.insert(req_id, tx);
        (current.outbound.clone(), current.pending.clone())
    };
    if let Err(e) = try_enqueue(&outbound, Frame::Request { req_id, kind }) {
        pending.lock().await.remove(&req_id);
        return Err(e);
    }
    // 5s: a spawn/attach/kill answers in well under a second even via the
    // relay; the ceiling only matters when the link is silently dead, where
    // every extra second is the user staring at a spinner.
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(CommandOutcome::Ok { session })) => Ok(session),
        Ok(Ok(CommandOutcome::Error { message })) => Err(message),
        // Sender dropped - the connection ended before a reply arrived.
        Ok(Err(_)) => Err("connection closed before the command completed".into()),
        Err(_) => {
            pending.lock().await.remove(&req_id);
            Err("command timed out".into())
        }
    }
}

#[derive(Serialize, Clone)]
struct InfoPayload {
    id: u64,
    title: String,
    kind: &'static str,
    source: &'static str,
    has_activity: bool,
}

fn info_payload(info: SessionInfo) -> InfoPayload {
    let kind = match info.kind {
        SessionKind::Shell => "shell",
        SessionKind::Agent => "agent",
    };
    let source = match info.source {
        SessionSource::Spawned => "spawned",
        SessionSource::Adopted => "adopted",
    };
    InfoPayload {
        id: info.id.0,
        title: info.title,
        kind,
        source,
        has_activity: info.has_activity,
    }
}

#[derive(Serialize, Clone)]
struct AgentSnapshotPayload {
    id: u64,
    events: Vec<AgentTimelinePayload>,
}

#[derive(Serialize, Clone)]
struct AgentTimelinePayload {
    seq: u64,
    event: AgentEventPayload,
}

#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AgentEventPayload {
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
    AvailableCommands {
        commands: Vec<AgentCommand>,
    },
    ModeState {
        current_mode_id: String,
        available_modes: Vec<AgentMode>,
    },
    ConfigOptions {
        options: Vec<AgentConfigOption>,
    },
    SessionInfo {
        title: Option<String>,
    },
    Replaying {
        active: bool,
    },
    AuthRequired {
        methods: Vec<AgentAuthMethod>,
    },
    Usage {
        used_tokens: u64,
        max_tokens: u64,
        cost: Option<String>,
    },
}

impl From<AgentTimelineEvent> for AgentTimelinePayload {
    fn from(value: AgentTimelineEvent) -> Self {
        let event = match value.event {
            AgentEvent::SessionStarted { provider } => {
                AgentEventPayload::SessionStarted { provider }
            }
            AgentEvent::UserMessage { text } => AgentEventPayload::UserMessage { text },
            AgentEvent::TurnStarted => AgentEventPayload::TurnStarted,
            AgentEvent::MessageChunk { text } => AgentEventPayload::MessageChunk { text },
            AgentEvent::ThoughtChunk { text } => AgentEventPayload::ThoughtChunk { text },
            AgentEvent::ToolCall {
                tool_call_id,
                title,
                kind,
                status,
                detail,
            } => AgentEventPayload::ToolCall {
                tool_call_id,
                title,
                kind,
                status,
                detail,
            },
            AgentEvent::ToolCallUpdate {
                tool_call_id,
                title,
                kind,
                status,
                detail,
            } => AgentEventPayload::ToolCallUpdate {
                tool_call_id,
                title,
                kind,
                status,
                detail,
            },
            AgentEvent::Plan { entries } => AgentEventPayload::Plan { entries },
            AgentEvent::TurnFinished { stop_reason } => {
                AgentEventPayload::TurnFinished { stop_reason }
            }
            AgentEvent::Error { message } => AgentEventPayload::Error { message },
            AgentEvent::AvailableCommands { commands } => {
                AgentEventPayload::AvailableCommands { commands }
            }
            AgentEvent::ModeState {
                current_mode_id,
                available_modes,
            } => AgentEventPayload::ModeState {
                current_mode_id,
                available_modes,
            },
            AgentEvent::ConfigOptions { options } => AgentEventPayload::ConfigOptions { options },
            AgentEvent::SessionInfo { title } => AgentEventPayload::SessionInfo { title },
            AgentEvent::Replaying { active } => AgentEventPayload::Replaying { active },
            AgentEvent::AuthRequired { methods } => AgentEventPayload::AuthRequired { methods },
            AgentEvent::Usage {
                used_tokens,
                max_tokens,
                cost,
            } => AgentEventPayload::Usage {
                used_tokens,
                max_tokens,
                cost,
            },
        };
        Self {
            seq: value.seq,
            event,
        }
    }
}

#[derive(Serialize, Clone)]
struct PermissionPayload {
    id: u64,
    tool_call: ToolCallCard,
    options: Vec<PermissionOption>,
    category: PermissionCategory,
    /// Which link raised this card. ACP session ids and tool-call ids are both
    /// host-local, so a card from one host can collide with a pending request on
    /// another; the UI echoes this back and `permission_decision` refuses to
    /// answer a card that a different generation minted.
    connection: u64,
    /// How broad the agent's sandbox root is for this card's session. Passed
    /// straight through to the policy engine, which refuses blanket read
    /// approval when it is `Broad`.
    workspace_scope: WorkspaceScope,
}

#[derive(Serialize, Clone)]
struct PermissionResolvedPayload {
    id: u64,
    tool_call_id: String,
    /// v5: "allowed" | "rejected" | "cancelled". `None` for a pre-v5 frame.
    resolution: Option<String>,
    /// v5: "phone" | "laptop" | "system". `None` for a pre-v5 frame.
    by: Option<String>,
}

/// Bind the host identity announced by the application handshake to the
/// identity already authenticated by iroh from the pairing ticket. The
/// handshake field is useful metadata, but it must never be allowed to choose
/// which peer record, approval policy, or live connection receives trust.
fn validate_handshake_host(
    authenticated_host: DeviceId,
    announced_host: DeviceId,
) -> Result<DeviceId, String> {
    if announced_host != authenticated_host {
        return Err(
            "host identity mismatch - discard this ticket and pair with the host again".into(),
        );
    }
    Ok(authenticated_host)
}

/// A reconnect ticket is persisted under one saved host. Refuse to dial it if
/// its QUIC-authenticated identity no longer matches that record; otherwise a
/// corrupt or substituted local record could redirect one host's trust to
/// another endpoint.
fn validate_reconnect_ticket_host(
    saved_host: DeviceId,
    ticket_host: DeviceId,
) -> Result<DeviceId, String> {
    if ticket_host != saved_host {
        return Err(
            "saved reconnect ticket does not match this host - remove it and pair again".into(),
        );
    }
    Ok(saved_host)
}

/// Pair with a host: decode the ticket, build an endpoint, connect, run the PIN
/// handshake, then start the reader + session loop. `on_output` is a binary
/// The one pairing failure whose fix isn't "re-pair": a protocol-version
/// mismatch. Peers do NOT negotiate (append-only wire, see frame.rs), so the
/// only remedy is updating the older side. Surface that plainly instead of the
/// Debug-formatted `PairingFailed(UnsupportedVersion)` blob.
///
/// When the frame layer rejects an incompatible peer it hands us the peer's
/// wire version (`found`); compare it to ours to name the older side. `None`
/// falls back to the generic message (the handshake `PairingFailure` variant
/// carries no version number).
fn version_mismatch_message(peer_version: Option<u16>) -> String {
    match peer_version {
        Some(peer) if peer < PROTOCOL_VERSION => "The laptop is running an older Portty version \
             than this phone. Update Portty on the laptop, then reconnect."
            .to_string(),
        Some(peer) if peer > PROTOCOL_VERSION => "This phone is running an older Portty version \
             than the laptop. Update Portty from the App Store, then reconnect."
            .to_string(),
        _ => "This phone and the laptop are running different Portty versions. Update \
             whichever is older, then reconnect."
            .to_string(),
    }
}

/// Tauri Channel the loop pushes ordered `[kind][8-byte LE id][PTY bytes]`
/// messages onto - avoiding JSON byte arrays while keeping reset + snapshot on
/// one ordered path (`kind=0` output, `kind=1` reset).
#[tauri::command]
async fn pair(
    state: State<'_, PorttyState>,
    app: tauri::AppHandle,
    ticket: String,
    secret_phrase: Option<String>,
    on_output: tauri::ipc::Channel<Vec<u8>>,
) -> Result<(), String> {
    // Single in-flight connection op (see PorttyState::connecting).
    let _conn = state
        .connecting
        .try_lock()
        .map_err(|_| "a connection attempt is already in progress".to_string())?;
    // Self-heal: a lingering (possibly dead) link must not block a deliberate
    // pair. Take it down exactly like `disconnect` - dropping the `Connection`
    // fires its shutdown kill switch, which stops the session loop and closes
    // that endpoint, and the generation check keeps the old loop from clobbering
    // the connection created below. Erroring out here ("already paired") used to
    // strand the user behind their own dead link until the QUIC idle timeout.
    if let Some(old) = state.connection.lock().await.take() {
        old.pending.lock().await.clear();
    }
    let peer = decode_ticket(ticket.trim()).map_err(|e| e.to_string())?;
    let expected_host = portty_transport::device_id_from_node_id(peer.id)
        .map_err(|e| format!("invalid host identity in pairing ticket: {e}"))?;
    let observed_revocation = state.peers.lock().await.revocation_marker(&expected_host);
    // The out-of-band secret IS the first-pair credential - there is no PIN
    // beside it any more, so without one there is nothing to pair with and we
    // stop here rather than dialing. Either the scanned/pasted ticket carries it,
    // or the user typed the host's six-word phrase alongside a bare NodeId.
    let ticket_secret = decode_ticket_secret(ticket.trim())
        .or_else(|| {
            secret_phrase
                .as_deref()
                .filter(|p| !p.trim().is_empty())
                .and_then(PairingSecret::from_phrase)
        })
        .ok_or(
            "this pairing code carries no secret. Scan the QR, paste the full \
             portty1:… ticket, or type the six-word phrase shown on your computer",
        )?;
    let endpoint = build_endpoint(&state.identity, iroh::RelayMode::Default)
        .await
        .map_err(|e| e.to_string())?;
    let mut tport = match IrohTransport::connect(&endpoint, peer).await {
        Ok(tport) => tport,
        Err(e) => {
            endpoint.close().await;
            return Err(e.to_string());
        }
    };
    let mut hs =
        ClientHandshake::first_pair(state.identity.device_id(), "phone".into(), ticket_secret);
    tracing::info!("pair: running client handshake");
    // The host will not acknowledge until a human there confirms the comparison
    // code, so surface it the moment it exists. Without this the phone would sit
    // on a blank spinner while its own screen holds the thing the user is being
    // asked to check.
    let code_app = app.clone();
    let outcome = match run_client_handshake_with(&mut tport, &mut hs, move |code| {
        if let Err(e) = code_app.emit(PAIR_CODE_EVENT, code.to_string()) {
            tracing::warn!(error = %e, "could not show the pairing code on screen");
        }
    })
    .await
    {
        Ok(outcome) => outcome,
        // Frame-layer rejection of an incompatible peer: we know the peer's wire
        // version, so name the older side.
        Err(SyncError::Transport(TransportError::UnsupportedProtocolVersion { found, .. })) => {
            endpoint.close().await;
            return Err(version_mismatch_message(Some(found)));
        }
        Err(SyncError::Protocol(ProtocolError::PairingFailed(
            PairingFailure::UnsupportedVersion,
        ))) => {
            endpoint.close().await;
            return Err(version_mismatch_message(None));
        }
        Err(e) => {
            endpoint.close().await;
            return Err(e.to_string());
        }
    };
    let validated_host = match validate_handshake_host(expected_host, outcome.peer_device_id) {
        Ok(host) => host,
        Err(error) => {
            tracing::warn!("rejecting host: handshake identity does not match pairing ticket");
            endpoint.close().await;
            return Err(error);
        }
    };
    tracing::info!("pair: handshake done, starting session loop");
    // SEC-2: persist the reconnect token + this host's ticket so the phone can
    // resume by token next time, without re-entering the PIN.
    let committed_pair_id = {
        let mut peers = state.peers.lock().await;
        let pair_id = match peers.commit_handshake(
            validated_host,
            HandshakeCommit {
                ticket: Some(ticket.trim().to_string()),
                token: outcome.reconnect_token,
                resumed: outcome.resumed,
                candidate_pair_id: outcome.pair_id,
                candidate_event_key: outcome.pair_event_key,
                observed_revocation,
                // A PIN pair authenticates against no token, so there is none to
                // hold unchanged. `commit_handshake` ignores this on a fresh pair
                // and refuses a resume that arrives without one - which is the
                // right outcome here, since this path resuming would be a bug.
                observed_token: None,
            },
        ) {
            Ok(pair_id) => pair_id,
            Err(e) => {
                drop(peers);
                endpoint.close().await;
                return Err(format!(
                    "paired, but could not save reconnect credentials: {e}"
                ));
            }
        };
        // Remember this as the host to redial by default (deterministic last_host).
        if let Err(e) = peers.set_last_host(validated_host) {
            tracing::warn!(error = %e, "paired, but could not save last-host preference");
        }
        pair_id
    };
    // Label the host with the name it announced (its hostname) for the picker.
    save_host_name(&state.data_dir, validated_host, &outcome.peer_display_name);
    start_session(
        &state,
        app,
        endpoint,
        tport,
        validated_host,
        committed_pair_id,
        outcome.cipher,
        on_output,
    )
    .await;
    Ok(())
}

/// Wire the post-handshake reader task + session loop, and store the outbound
/// channel in state. Shared by `pair` (first pair by PIN) and `reconnect`
/// (resume by token).
// Keep the authenticated peer, pair generation, transport owners, and UI
// channel explicit at this connection-establishment trust boundary.
#[allow(clippy::too_many_arguments)]
async fn start_session(
    state: &State<'_, PorttyState>,
    app: tauri::AppHandle,
    endpoint: iroh::Endpoint,
    tport: IrohTransport,
    peer_device_id: DeviceId,
    pair_id: portty_transport::PairId,
    cipher: EnvelopeCipher,
    on_output: tauri::ipc::Channel<Vec<u8>>,
) {
    let (writer, reader) = tport.split();
    // Bounded so a slow webview render can't let inbound host output grow RAM
    // without limit. At the 1 MiB wire ceiling these queues contribute at most
    // ~32 MiB per connection; backpressure then reaches the network and host.
    let (outbound_tx, outbound_rx) = mpsc::channel::<Frame>(CONNECTION_OUTBOUND_FRAMES);
    let (raw_tx, raw_rx) = mpsc::channel::<Vec<u8>>(CONNECTION_INBOUND_RAW_FRAMES);
    let pending: Pending = Arc::new(AsyncMutex::new(HashMap::new()));
    let unpair_pending: UnpairPending = Arc::new(AsyncMutex::new(HashMap::new()));
    let dirs_pending: DirsPending = Arc::new(AsyncMutex::new(HashMap::new()));
    let sessions_pending: SessionsPending = Arc::new(AsyncMutex::new(HashMap::new()));
    let providers_pending: ProvidersPending = Arc::new(AsyncMutex::new(HashMap::new()));
    let roots_pending: RootsPending = Arc::new(AsyncMutex::new(HashMap::new()));
    let connection_id = state.next_connection_id.fetch_add(1, Ordering::Relaxed);
    // Kill switch: held by the `Connection`, awaited by the session loop.
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let owner = TransferOwner {
        peer_device_id,
        pair_id,
    };

    // Dedicated reader task - owns the read half, never cancelled mid-frame.
    tokio::spawn(async move {
        let mut reader: IrohReader = reader;
        loop {
            match reader.recv_raw().await {
                Ok(bytes) => {
                    if raw_tx.send(bytes).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    tracing::warn!("reader: recv_raw closed (connection ended)");
                    break;
                }
            }
        }
    });

    // Publish the new generation before its task starts. If the link ends
    // immediately, cleanup can still remove this exact entry instead of leaving
    // a closed sender installed in state.
    *state.connection.lock().await = Some(Connection {
        id: connection_id,
        peer_device_id,
        pair_id,
        outbound: outbound_tx.clone(),
        pending: pending.clone(),
        unpair_pending: unpair_pending.clone(),
        dirs_pending: dirs_pending.clone(),
        sessions_pending: sessions_pending.clone(),
        providers_pending: providers_pending.clone(),
        roots_pending: roots_pending.clone(),
        _shutdown: shutdown_tx,
    });

    // A transfer belongs to one pairing, so a host switch ends it: nothing here
    // can serve it any more, and leaving it parked would hold one of the four
    // transfer slots forever. Cancel it and say so, rather than stall in silence.
    for (id, temporary) in take_transfers_not_owned_by(&state.transfers, owner).await {
        if let Some(temporary) = temporary {
            let _ = tokio::fs::remove_file(temporary).await;
        }
        let _ = app.emit(
            "portty://transfer-error",
            TransferErrorPayload {
                id: id.0,
                message: "transfer canceled - it belonged to a different host".into(),
            },
        );
    }

    // Resume interrupted downloads at the first missing 16 KiB chunk. Partial
    // files and hash state live in app state across connection generations -
    // but only for the SAME pairing. Resuming a transfer against a different
    // host would disclose the first host's remote path to the second and let it
    // supply the bytes (and matching checksum) for a destination the user chose
    // for someone else.
    {
        let downloads = state.transfers.downloads.lock().await;
        for (id, transfer) in downloads.iter().filter(|(_, t)| t.owner == owner) {
            let _ = outbound_tx
                .send(Frame::FileGetReq {
                    id: *id,
                    path: transfer.remote_path.clone(),
                    start_seq: transfer.next_seq,
                    allow_outside_home: transfer.allow_outside_home,
                })
                .await;
        }
    }

    // Push doorbell registration: if the native layer has delivered an
    // APNs/FCM token, register it with THIS host (sealed blob = this host's
    // device id under the phone-local wake key). Runs per connect so token
    // rotations and new pairings converge without any UI step.
    {
        let app3 = app.clone();
        let outbound = outbound_tx.clone();
        let wake_key = state.wake_key;
        tokio::spawn(async move {
            let Some(native) = push_wake::read_native_token(&app3) else {
                return;
            };
            let provider = match native.provider.as_str() {
                "apns" => portty_protocol::PushProvider::Apns,
                "fcm" => portty_protocol::PushProvider::Fcm,
                other => {
                    tracing::warn!(provider = %other, "unknown native push provider");
                    return;
                }
            };
            let Some(blob) = push_wake::seal_wake_blob(&wake_key, &peer_device_id) else {
                return;
            };
            let _ = outbound
                .send(Frame::PushRegister {
                    provider,
                    token: native.token,
                    sealed_wake_blob: blob,
                })
                .await;
        });
    }

    // Session loop - owns the cipher (single owner), does all seal/open.
    // Move the endpoint in so it outlives the call (see `session_loop`).
    let app2 = app.clone();
    tokio::spawn(session_loop(
        writer,
        cipher,
        outbound_rx,
        raw_rx,
        app2,
        endpoint,
        on_output,
        pending,
        unpair_pending,
        dirs_pending,
        sessions_pending,
        providers_pending,
        roots_pending,
        state.peers.clone(),
        peer_device_id,
        pair_id,
        state.connection.clone(),
        connection_id,
        outbound_tx,
        state.transfers.clone(),
        state.last_seen_seq.clone(),
        state.last_seen_generation.clone(),
        shutdown_rx,
    ));
}

/// Reconnect to the last-paired host by the stored resumption token - no PIN, no
/// pasted ticket. Fails (→ caller shows the pair screen) if no host is saved or
/// the token was rejected (host re-paired / rotated): then re-pair by PIN.
#[tauri::command]
async fn reconnect(
    state: State<'_, PorttyState>,
    app: tauri::AppHandle,
    on_output: tauri::ipc::Channel<Vec<u8>>,
    // Host picker: resume a SPECIFIC saved laptop by its device-id hex.
    // `None` keeps the classic behavior (most recent host).
    host: Option<String>,
) -> Result<(), String> {
    // Single in-flight connection op (see PorttyState::connecting).
    let _conn = state
        .connecting
        .try_lock()
        .map_err(|_| "a connection attempt is already in progress".to_string())?;
    // Self-heal a lingering dead link (see `pair` for the full rationale).
    if let Some(old) = state.connection.lock().await.take() {
        old.pending.lock().await.clear();
    }
    let (host_dev, ticket, token, observed_revocation) = {
        let peers = state.peers.lock().await;
        let selected = match host.as_deref() {
            // Host picker: a specific saved laptop.
            Some(hex) => {
                let dev = DeviceId::from_hex(hex).ok_or("bad host id")?;
                peers
                    .known_hosts()
                    .into_iter()
                    .find(|(d, _, _)| *d == dev)
                    .ok_or_else(|| "that host is no longer saved - pair it again".to_string())?
            }
            None => peers
                .last_host()
                .ok_or_else(|| "no saved host - pair first".to_string())?,
        };
        let marker = peers.revocation_marker(&selected.0);
        (selected.0, selected.1, selected.2, marker)
    };
    let peer = decode_ticket(&ticket).map_err(|e| e.to_string())?;
    let ticket_host = portty_transport::device_id_from_node_id(peer.id)
        .map_err(|e| format!("invalid host identity in saved reconnect ticket: {e}"))?;
    validate_reconnect_ticket_host(host_dev, ticket_host)?;
    let endpoint = build_endpoint(&state.identity, iroh::RelayMode::Default)
        .await
        .map_err(|e| e.to_string())?;
    let mut tport = match IrohTransport::connect(&endpoint, peer).await {
        Ok(tport) => tport,
        Err(e) => {
            endpoint.close().await;
            return Err(e.to_string());
        }
    };
    // SEC-2: resume by the stored token. The PIN is unused on a resume, so a
    // placeholder is fine (the token branch never reads it).

    // Kept for the commit's compare-and-swap: the rotated token replaces THIS
    // one or the commit is refused. Two reconnects racing (the app can start one
    // while another is in flight) would otherwise each overwrite the other's
    // rotation, leaving a stored token the host no longer knows.
    let observed_token = Some(token.clone());
    let mut hs = ClientHandshake::resume(state.identity.device_id(), "phone".into(), token);
    tracing::info!("reconnect: resuming by stored token");
    let outcome = match run_client_handshake(&mut tport, &mut hs).await {
        Ok(outcome) => outcome,
        Err(SyncError::Protocol(ProtocolError::PairingFailed(PairingFailure::Revoked))) => {
            endpoint.close().await;
            state
                .peers
                .lock()
                .await
                .forget(&host_dev)
                .map_err(|e| format!("host revoked this pair; local cleanup failed: {e}"))?;
            let _ = app.emit(
                "portty://pair-revoked",
                PairRevokedPayload {
                    host: host_dev.as_hex(),
                },
            );
            return Err("pair revoked by laptop".into());
        }
        Err(SyncError::Transport(TransportError::UnsupportedProtocolVersion { found, .. })) => {
            endpoint.close().await;
            return Err(version_mismatch_message(Some(found)));
        }
        Err(SyncError::Protocol(ProtocolError::PairingFailed(
            PairingFailure::UnsupportedVersion,
        ))) => {
            endpoint.close().await;
            return Err(version_mismatch_message(None));
        }
        Err(e) => {
            endpoint.close().await;
            return Err(format!("reconnect failed - re-pair: {e}"));
        }
    };
    let validated_host = match validate_handshake_host(host_dev, outcome.peer_device_id) {
        Ok(host) => host,
        Err(error) => {
            tracing::warn!("rejecting host: handshake identity does not match saved host");
            endpoint.close().await;
            return Err(error);
        }
    };
    // Rotate the token for next time; keep the same ticket to redial.
    let committed_pair_id = {
        let mut peers = state.peers.lock().await;
        let pair_id = match peers.commit_handshake(
            validated_host,
            HandshakeCommit {
                ticket: Some(ticket),
                token: outcome.reconnect_token,
                resumed: outcome.resumed,
                candidate_pair_id: outcome.pair_id,
                candidate_event_key: outcome.pair_event_key,
                observed_revocation,
                observed_token,
            },
        ) {
            Ok(pair_id) => pair_id,
            Err(e) => {
                drop(peers);
                endpoint.close().await;
                return Err(format!(
                    "reconnected, but could not save rotated token: {e}"
                ));
            }
        };
        if let Err(e) = peers.set_last_host(validated_host) {
            tracing::warn!(error = %e, "reconnected, but could not save last-host preference");
        }
        pair_id
    };
    // Refresh the label too - the host's hostname can change between runs.
    save_host_name(&state.data_dir, validated_host, &outcome.peer_display_name);
    start_session(
        &state,
        app,
        endpoint,
        tport,
        validated_host,
        committed_pair_id,
        outcome.cipher,
        on_output,
    )
    .await;
    Ok(())
}

/// Remove every transfer that belongs to a different pairing, releasing its slot
/// and returning any partial file to delete. Called when a link is established:
/// whatever the new host is, it may not serve another host's transfer, so those
/// transfers can never make progress again.
///
/// Uploads are flagged cancelled here so their streaming task stops at its next
/// chunk - no byte of a file chosen for the old host reaches the new one.
async fn take_transfers_not_owned_by(
    transfers: &ClientTransfers,
    owner: TransferOwner,
) -> Vec<(TransferId, Option<std::path::PathBuf>)> {
    let mut cancelled = Vec::new();
    {
        let mut downloads = transfers.downloads.lock().await;
        let stale: Vec<TransferId> = downloads
            .iter()
            .filter(|(_, transfer)| transfer.owner != owner)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(transfer) = downloads.remove(&id) {
                cancelled.push((id, Some(transfer.temporary)));
            }
        }
    }
    {
        let mut uploads = transfers.uploads.lock().await;
        let stale: Vec<TransferId> = uploads
            .iter()
            .filter(|(_, transfer)| transfer.owner != owner)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(transfer) = uploads.remove(&id) {
                transfer.cancelled.store(true, Ordering::Relaxed);
                cancelled.push((id, None));
            }
        }
    }
    cancelled
}

/// Remove a download only if `owner` started it. A host may finish, fail, or
/// resume its OWN transfers and nobody else's.
async fn take_owned_download(
    transfers: &ClientTransfers,
    id: TransferId,
    owner: TransferOwner,
) -> Option<DownloadTransfer> {
    let mut downloads = transfers.downloads.lock().await;
    if downloads.get(&id).is_some_and(|t| t.owner == owner) {
        downloads.remove(&id)
    } else {
        None
    }
}

/// Upload counterpart of [`take_owned_download`].
async fn take_owned_upload(
    transfers: &ClientTransfers,
    id: TransferId,
    owner: TransferOwner,
) -> Option<UploadTransfer> {
    let mut uploads = transfers.uploads.lock().await;
    if uploads.get(&id).is_some_and(|t| t.owner == owner) {
        uploads.remove(&id)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)] // internal wiring fn; grouping would obscure it
async fn session_loop(
    mut writer: IrohWriter,
    cipher: EnvelopeCipher,
    mut outbound_rx: mpsc::Receiver<Frame>,
    mut raw_rx: mpsc::Receiver<Vec<u8>>,
    app: tauri::AppHandle,
    // Held for the connection lifetime. The iroh `Endpoint` owns the QUIC socket
    // + every connection riding on it; dropping it aborts them all. It used to be
    // a local in `pair` and was dropped at `pair`'s return - which killed the link
    // the instant pairing finished (iroh logged "Endpoint dropped … Aborting
    // ungracefully"). Keep it alive here until the session disconnects.
    endpoint: iroh::Endpoint,
    on_output: tauri::ipc::Channel<Vec<u8>>,
    pending: Pending,
    unpair_pending: UnpairPending,
    dirs_pending: DirsPending,
    sessions_pending: SessionsPending,
    providers_pending: ProvidersPending,
    roots_pending: RootsPending,
    peers: Arc<AsyncMutex<PeerStore>>,
    peer_device_id: DeviceId,
    pair_id: portty_transport::PairId,
    current: CurrentConnection,
    connection_id: u64,
    control_tx: mpsc::Sender<Frame>,
    transfers: Arc<ClientTransfers>,
    last_seen_seq: Arc<AsyncMutex<HashMap<u64, u64>>>,
    last_seen_generation: Arc<AsyncMutex<HashMap<u64, u64>>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    // This link's transfer owner. Frames naming a transfer that belongs to a
    // different pairing are dropped, not applied.
    let owner = TransferOwner {
        peer_device_id,
        pair_id,
    };
    loop {
        tokio::select! {
            biased;
            // The UI took this connection out of state (disconnect, host switch,
            // remove_host). Stop BEFORE processing another inbound frame, so a
            // dropped link cannot keep driving the app. Both a signalled and a
            // dropped sender mean the same thing: this generation is over.
            _ = &mut shutdown => {
                tracing::info!(connection_id, "session: shutdown requested - closing link");
                break;
            }
            // Outbound Frame → seal → wire.
            out = outbound_rx.recv() => {
                let Some(frame) = out else { break; };
                let sealed: SealedEnvelope = match seal_msg(&cipher, &frame, b"") {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("session: sealing failed; closing connection: {e}");
                        break;
                    }
                };
                let bytes = match postcard::to_allocvec(&sealed) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if writer.send_raw(&bytes).await.is_err() {
                    break;
                }
            }
            // Inbound raw bytes → open → emit event.
            raw = raw_rx.recv() => {
                let Some(bytes) = raw else { break; };
                let env: SealedEnvelope = match postcard::from_bytes(&bytes) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!("session: postcard decode of sealed envelope failed: {e}");
                        break;
                    }
                };
                let frame: Frame = match open_msg(&cipher, &env, b"") {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!("session: open_msg (decrypt) failed: {e}");
                        break;
                    }
                };
                if !frame.direction().allows_host_to_phone() {
                    tracing::warn!(
                        direction = ?frame.direction(),
                        "closing connection after phone-only frame arrived from host"
                    );
                    break;
                }
                match frame {
                    Frame::SessionList { sessions } => {
                        tracing::info!("session: SessionList received, {} sessions", sessions.len());
                        let payload: Vec<InfoPayload> = sessions.into_iter().map(info_payload).collect();
                        let _ = app.emit("portty://list", payload);
                    }
                    Frame::SessionAdded { info } => {
                        let _ = app.emit("portty://added", info_payload(info));
                    }
                    Frame::SessionRemoved { id } => {
                        let _ = app.emit("portty://removed", id.0);
                    }
                    Frame::Output { id, bytes } => {
                        // Binary channel: [0][8-byte LE session id][raw PTY bytes].
                        // No JSON byte-array - keeps a `cargo build`-sized burst fast.
                        let mut msg = Vec::with_capacity(9 + bytes.len());
                        msg.push(0);
                        msg.extend_from_slice(&id.0.to_le_bytes());
                        msg.extend_from_slice(&bytes);
                        let _ = on_output.send(msg);
                    }
                    Frame::SequencedOutput { id, seq, bytes } => {
                        // Record the boundary FIRST (checkpoints and data alike):
                        // it is what `resume_output` hands back as `after_seq`
                        // so a warm reconnect fetches only the missed delta.
                        last_seen_seq.lock().await.insert(id.0, seq);
                        // Empty payloads are snapshot sequence checkpoints.
                        // They intentionally update no pixels.
                        if !bytes.is_empty() {
                            let mut msg = Vec::with_capacity(9 + bytes.len());
                            msg.push(0);
                            msg.extend_from_slice(&id.0.to_le_bytes());
                            msg.extend_from_slice(&bytes);
                            let _ = on_output.send(msg);
                        }
                    }
                    Frame::ActivityBlip { id } => {
                        let _ = app.emit("portty://activity", id.0);
                    }
                    Frame::CommandError { message } => {
                        // A phone command the host couldn't carry out (e.g. the
                        // session limit was hit). Surface it in the UI.
                        let _ = app.emit("portty://error", message);
                    }
                    Frame::ScreenReset { id, generation } => {
                        // Remember which host lifetime produced this screen; a
                        // warm resume echoes it so the host can spot a restart
                        // and repaint instead of replaying a corrupting delta (#14).
                        last_seen_generation.lock().await.insert(id.0, generation);
                        // Use the SAME ordered channel as Output. A separate Tauri
                        // event can race the binary channel and clear a snapshot
                        // that already rendered.
                        let mut msg = Vec::with_capacity(9);
                        msg.push(1);
                        msg.extend_from_slice(&id.0.to_le_bytes());
                        let _ = on_output.send(msg);
                    }
                    Frame::SessionSize { id, cols, rows } => {
                        // Authoritative PTY size. Rides the SAME ordered channel
                        // as Output/ScreenReset: on attach the host sends
                        // reset → size → snapshot, and match-width mode must
                        // apply the size BEFORE parsing the snapshot bytes.
                        // [2][8-byte LE id][2-byte LE cols][2-byte LE rows]
                        let mut msg = Vec::with_capacity(13);
                        msg.push(2);
                        msg.extend_from_slice(&id.0.to_le_bytes());
                        msg.extend_from_slice(&cols.to_le_bytes());
                        msg.extend_from_slice(&rows.to_le_bytes());
                        let _ = on_output.send(msg);
                    }
                    Frame::CommandResult { req_id, outcome } => {
                        // Resolve exactly the command that carried this req_id.
                        if let Some(tx) = pending.lock().await.remove(&req_id) {
                            let _ = tx.send(outcome);
                        }
                    }
                    // Arrives immediately BEFORE the CommandResult for the same
                    // req_id, so a waiter that resolves on the outcome already
                    // has this in hand.
                    Frame::WorkspaceDirs {
                        req_id,
                        rel,
                        names,
                    } => {
                        if let Some(tx) = dirs_pending.lock().await.remove(&req_id) {
                            let _ = tx.send(WorkspaceListing { rel, names });
                        }
                    }
                    Frame::TerminalRoots { req_id, roots } => {
                        if let Some(tx) = roots_pending.lock().await.remove(&req_id) {
                            // Names, not the enum: the UI labels and stores roots by
                            // name, and a root this build does not know about is
                            // dropped rather than guessed at.
                            let _ = tx.send(roots.iter().copied().map(terminal_root_name).map(str::to_string).collect());
                        }
                    }
                    Frame::AgentProviders { req_id, providers } => {
                        if let Some(tx) = providers_pending.lock().await.remove(&req_id) {
                            let _ = tx.send(
                                providers
                                    .into_iter()
                                    .map(|entry| AgentProviderRow {
                                        provider: agent_provider_name(entry.provider),
                                        available: entry.available,
                                        detail: entry.detail,
                                    })
                                    .collect(),
                            );
                        }
                    }
                    Frame::AgentSessions {
                        req_id,
                        rel,
                        sessions,
                    } => {
                        if let Some(tx) = sessions_pending.lock().await.remove(&req_id) {
                            let _ = tx.send(AgentSessionListing {
                                rel,
                                sessions: sessions
                                    .into_iter()
                                    .map(|entry| AgentSessionRow {
                                        acp_session_id: entry.acp_session_id,
                                        provider: agent_provider_name(entry.provider),
                                        title: entry.title,
                                        label: entry.label,
                                        last_active_at_unix_ms: entry.last_active_at_unix_ms,
                                    })
                                    .collect(),
                            });
                        }
                    }
                    Frame::AgentSnapshot { id, events } => {
                        let _ = app.emit(
                            "portty://agent-snapshot",
                            AgentSnapshotPayload {
                                id: id.0,
                                events: events.into_iter().map(Into::into).collect(),
                            },
                        );
                    }
                    Frame::AgentTimeline { id, event } => {
                        let _ = app.emit(
                            "portty://agent-event",
                            AgentSnapshotPayload {
                                id: id.0,
                                events: vec![event.into()],
                            },
                        );
                    }
                    Frame::RequestPermission {
                        id,
                        tool_call,
                        options,
                    } => {
                        let _ = app.emit(
                            "portty://permission",
                            PermissionPayload {
                                id: id.0,
                                tool_call,
                                options,
                                category: PermissionCategory::Unknown,
                                connection: connection_id,
                                // Legacy frame, no scope on the wire. `Unknown`
                                // already forces a prompt, and `Broad` keeps
                                // this fail-closed if that ever changes.
                                workspace_scope: WorkspaceScope::Broad,
                            },
                        );
                    }
                    Frame::PolicyPermissionRequest {
                        id,
                        tool_call,
                        options,
                        category,
                        workspace_scope,
                    } => {
                        let _ = app.emit(
                            "portty://permission",
                            PermissionPayload {
                                id: id.0,
                                tool_call,
                                options,
                                category,
                                connection: connection_id,
                                workspace_scope,
                            },
                        );
                    }
                    Frame::FileChunk { id, seq, bytes } => {
                        let mut downloads = transfers.downloads.lock().await;
                        // Summed BEFORE taking the mutable borrow below. Includes
                        // this transfer's own bytes, which is what we want: the
                        // budget is over everything in flight.
                        let live_total: u64 = downloads.values().map(|t| t.written).sum();
                        let Some(transfer) = downloads.get_mut(&id).filter(|t| t.owner == owner)
                        else {
                            tracing::warn!(
                                transfer = id.0,
                                "ignoring file chunk for a transfer this host does not own"
                            );
                            continue;
                        };
                        if seq != transfer.next_seq {
                            // Spawned, not try_send: this loop is the outbound
                            // consumer, so awaiting here would deadlock on a
                            // full queue - while a dropped try_send would stall
                            // the transfer forever with nothing re-triggering it.
                            let tx = control_tx.clone();
                            let from_seq = transfer.next_seq;
                            tokio::spawn(async move {
                                let _ = tx.send(Frame::FileRetry { id, from_seq }).await;
                            });
                            continue;
                        }
                        // Nothing on the wire declares a download's size until
                        // `FileDone`, so the only defence against an endless
                        // stream is to stop counting up and abandon it. Checked
                        // per transfer AND across all of them, since four
                        // concurrent downloads at the per-file limit would still
                        // outgrow the device.
                        let over_budget = transfer.written.saturating_add(bytes.len() as u64)
                            > MAX_DOWNLOAD_BYTES
                            || live_total.saturating_add(bytes.len() as u64)
                                > MAX_TOTAL_DOWNLOAD_BYTES;
                        if over_budget {
                            let temp = transfer.temporary.clone();
                            downloads.remove(&id);
                            drop(downloads);
                            let _ = tokio::fs::remove_file(temp).await;
                            let tx = control_tx.clone();
                            tokio::spawn(async move {
                                let _ = tx
                                    .send(Frame::FileErr {
                                        id,
                                        reason: "download exceeded the phone's size limit".into(),
                                    })
                                    .await;
                            });
                            let _ = app.emit(
                                "portty://transfer-error",
                                TransferErrorPayload {
                                    id: id.0,
                                    message: format!(
                                        "download stopped: transfers may not exceed {} GiB each \
                                         or {} GiB in total",
                                        MAX_DOWNLOAD_BYTES / (1024 * 1024 * 1024),
                                        MAX_TOTAL_DOWNLOAD_BYTES / (1024 * 1024 * 1024)
                                    ),
                                },
                            );
                            continue;
                        }
                        if bytes.len() > FILE_CHUNK_BYTES {
                            let _ = app.emit(
                                "portty://transfer-error",
                                TransferErrorPayload {
                                    id: id.0,
                                    message: "host sent an oversized file chunk".into(),
                                },
                            );
                            continue;
                        }
                        if let Err(error) = transfer.file.write_all(&bytes).await {
                            // A failing disk won't heal mid-transfer: abort the
                            // download (remove entry + temp) and tell the host
                            // to stop streaming, instead of erroring per chunk
                            // into a broken file handle forever.
                            let temp = transfer.temporary.clone();
                            downloads.remove(&id);
                            drop(downloads);
                            let _ = tokio::fs::remove_file(temp).await;
                            let tx = control_tx.clone();
                            tokio::spawn(async move {
                                let _ = tx
                                    .send(Frame::FileErr {
                                        id,
                                        reason: "phone could not save the download".into(),
                                    })
                                    .await;
                            });
                            let _ = app.emit(
                                "portty://transfer-error",
                                TransferErrorPayload {
                                    id: id.0,
                                    message: format!("could not save download: {error}"),
                                },
                            );
                            continue;
                        }
                        transfer.hasher.update(&bytes);
                        transfer.written += bytes.len() as u64;
                        transfer.next_seq += 1;
                        let _ = app.emit(
                            "portty://transfer-progress",
                            TransferProgressPayload {
                                id: id.0,
                                direction: "download",
                                transferred: transfer.written,
                                total: None,
                                path: transfer.target.to_string_lossy().into_owned(),
                            },
                        );
                    }
                    Frame::FileDone { id, size, checksum } => {
                        let transfer = take_owned_download(&transfers, id, owner).await;
                        let Some(mut transfer) = transfer else {
                            if let Some(upload) = take_owned_upload(&transfers, id, owner).await {
                                let _ = app.emit(
                                    "portty://transfer-complete",
                                    TransferCompletePayload {
                                        id: id.0,
                                        direction: "upload",
                                        path: upload.remote_path,
                                    },
                                );
                            }
                            continue;
                        };
                        let actual = *transfer.hasher.clone().finalize().as_bytes();
                        if transfer.written != size || actual != checksum {
                            // Retry only this transfer range. A checksum failure
                            // cannot identify a single corrupt chunk, so the
                            // precise failed range is the file's chunk interval.
                            // Bounded: a host that never produces a matching file
                            // would otherwise have the phone re-fetch it forever.
                            transfer.restarts = transfer.restarts.saturating_add(1);
                            if transfer.restarts > MAX_DOWNLOAD_RESTARTS {
                                let temporary = transfer.temporary.clone();
                                drop(transfer);
                                let _ = tokio::fs::remove_file(&temporary).await;
                                let tx = control_tx.clone();
                                tokio::spawn(async move {
                                    let _ = tx
                                        .send(Frame::FileErr {
                                            id,
                                            reason: "phone gave up after repeated verification \
                                                     failures"
                                                .into(),
                                        })
                                        .await;
                                });
                                let _ = app.emit(
                                    "portty://transfer-error",
                                    TransferErrorPayload {
                                        id: id.0,
                                        message: format!(
                                            "download failed verification {} times - giving up",
                                            MAX_DOWNLOAD_RESTARTS
                                        ),
                                    },
                                );
                                continue;
                            }
                            let _ = transfer.file.set_len(0).await;
                            let _ = transfer.file.seek(std::io::SeekFrom::Start(0)).await;
                            transfer.next_seq = 0;
                            transfer.written = 0;
                            transfer.hasher = Hasher::new();
                            transfers.downloads.lock().await.insert(id, transfer);
                            // Spawned for the same reason as the gap retry: a
                            // dropped try_send here stalled the download forever.
                            let tx = control_tx.clone();
                            tokio::spawn(async move {
                                let _ = tx.send(Frame::FileRetry { id, from_seq: 0 }).await;
                            });
                            continue;
                        }
                        if let Err(error) = transfer.file.flush().await {
                            drop(transfer.file);
                            let _ = tokio::fs::remove_file(&transfer.temporary).await;
                            let _ = app.emit(
                                "portty://transfer-error",
                                TransferErrorPayload {
                                    id: id.0,
                                    message: format!("could not flush verified download: {error}"),
                                },
                            );
                            continue;
                        }
                        if let Err(error) = transfer.file.sync_all().await {
                            drop(transfer.file);
                            let _ = tokio::fs::remove_file(&transfer.temporary).await;
                            let _ = app.emit(
                                "portty://transfer-error",
                                TransferErrorPayload {
                                    id: id.0,
                                    message: format!("could not sync verified download: {error}"),
                                },
                            );
                            continue;
                        }
                        drop(transfer.file);
                        match replace_download_file(&transfer.temporary, &transfer.target).await {
                            Ok(()) => {
                                let _ = app.emit(
                                    "portty://transfer-complete",
                                    TransferCompletePayload {
                                        id: id.0,
                                        direction: "download",
                                        path: transfer.target.to_string_lossy().into_owned(),
                                    },
                                );
                            }
                            Err(error) => {
                                let _ = tokio::fs::remove_file(&transfer.temporary).await;
                                let _ = app.emit(
                                    "portty://transfer-error",
                                    TransferErrorPayload { id: id.0, message: error.to_string() },
                                );
                            }
                        }
                    }
                    // A retry request makes this host the recipient of a local
                    // file the user picked. Only the host the upload was started
                    // against may ask for (more of) it.
                    Frame::FileRetry { id, from_seq } => {
                        let upload = transfers
                            .uploads
                            .lock()
                            .await
                            .get(&id)
                            .filter(|upload| upload.owner == owner)
                            .cloned();
                        if let Some(upload) = upload {
                            spawn_upload_range(
                                id,
                                upload,
                                from_seq,
                                control_tx.clone(),
                                app.clone(),
                                transfers.clone(),
                            );
                        }
                    }
                    Frame::FileErr { id, reason } => {
                        let mut owned = false;
                        if let Some(transfer) = take_owned_download(&transfers, id, owner).await {
                            owned = true;
                            let _ = tokio::fs::remove_file(transfer.temporary).await;
                        }
                        // Stop the streaming task too - a rejected upload used
                        // to keep pushing the whole file into the void.
                        if let Some(upload) = take_owned_upload(&transfers, id, owner).await {
                            owned = true;
                            upload.cancelled.store(true, Ordering::Relaxed);
                        }
                        // Another host's failure is not this transfer's failure:
                        // reporting it would cancel a healthy transfer in the UI.
                        if owned {
                            let _ = app.emit(
                                "portty://transfer-error",
                                TransferErrorPayload { id: id.0, message: reason },
                            );
                        }
                    }
                    Frame::PushRegisterAck { ok, detail } => {
                        let _ = app.emit(
                            "portty://push-registered",
                            PushRegisteredPayload { ok, detail },
                        );
                    }
                    Frame::UnpairResult {
                        request_id,
                        pair_id: response_pair_id,
                        committed,
                        detail,
                    } => {
                        if let Some(tx) = unpair_pending.lock().await.remove(&request_id) {
                            let result = if response_pair_id != pair_id.0 {
                                Err("host replied for a different pair generation".into())
                            } else if committed {
                                Ok(())
                            } else {
                                Err(detail.unwrap_or_else(|| "host did not commit revocation".into()))
                            };
                            let _ = tx.send(result);
                        }
                    }
                    Frame::PairRevoked {
                        pair_id: revoked_pair_id,
                        event_id: _,
                    } => {
                        // Generation check is mandatory: a delayed/replayed
                        // revocation from an older relationship must not delete
                        // a newly paired credential for this same host identity.
                        if revoked_pair_id == pair_id.0
                            && peers.lock().await.pair_id(&peer_device_id) == Some(pair_id)
                        {
                            if let Err(error) = peers.lock().await.forget(&peer_device_id) {
                                tracing::error!(%error, "could not delete locally revoked pair credential");
                            } else {
                                let _ = app.emit(
                                    "portty://pair-revoked",
                                    PairRevokedPayload {
                                        host: peer_device_id.as_hex(),
                                    },
                                );
                            }
                            break;
                        }
                    }
                    // Some viewer (this phone, another phone, or the laptop's
                    // `portty agent` chat) answered - dismiss the card here too.
                    Frame::AgentPermissionResolved { id, tool_call_id } => {
                        let _ = app.emit(
                            "portty://permission-resolved",
                            PermissionResolvedPayload {
                                id: id.0,
                                tool_call_id,
                                resolution: None,
                                by: None,
                            },
                        );
                    }
                    // v5: same dismissal, but carries the outcome + which viewer
                    // answered so the card can say what happened.
                    Frame::AgentPermissionResolvedInfo {
                        id,
                        tool_call_id,
                        resolution,
                        by,
                    } => {
                        let resolution = match resolution {
                            PermissionResolution::Allowed => "allowed",
                            PermissionResolution::Rejected => "rejected",
                            PermissionResolution::Cancelled => "cancelled",
                        };
                        let by = match by {
                            PermissionResolver::Phone => "phone",
                            PermissionResolver::Laptop => "laptop",
                            PermissionResolver::System => "system",
                        };
                        let _ = app.emit(
                            "portty://permission-resolved",
                            PermissionResolvedPayload {
                                id: id.0,
                                tool_call_id,
                                resolution: Some(resolution.to_string()),
                                by: Some(by.to_string()),
                            },
                        );
                    }
                    // Direction was checked above; these arms cannot arrive
                    // from a conforming or malicious host.
                    _ => unreachable!("host frame direction checked before dispatch"),
                }
            }
        }
    }
    // Fail any commands still awaiting a reply - dropping the senders wakes their
    // awaiters with a "connection closed" error instead of hanging to the timeout.
    pending.lock().await.clear();
    unpair_pending.lock().await.clear();
    dirs_pending.lock().await.clear();
    sessions_pending.lock().await.clear();
    providers_pending.lock().await.clear();
    roots_pending.lock().await.clear();

    // Tell iroh to close its socket actors cleanly. Bound the drain wait so a
    // broken relay cannot delay UI recovery indefinitely; calling `close` marks
    // the endpoint closed before it waits for its actors to finish.
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.close()).await;

    // A replaced generation must never clear or emit a disconnect for the new
    // healthy link. Only the task that still owns the current id may do so.
    if remove_connection_if_current(&current, connection_id).await {
        tracing::info!(
            connection_id,
            "session loop ended - emitting portty://disconnected"
        );
        let _ = app.emit("portty://disconnected", ());
    }
}

/// Send a Frame to the session loop (best-effort). Errors if not paired.
async fn enqueue(state: &State<'_, PorttyState>, frame: Frame) -> Result<(), String> {
    let outbound = {
        let connection = state.connection.lock().await;
        connection
            .as_ref()
            .map(|current| current.outbound.clone())
            .ok_or_else(|| "not paired".to_string())?
    };
    try_enqueue(&outbound, frame)
}

/// Random hex for a staging filename, so its path cannot be guessed and
/// pre-planted. Not a secret - just unpredictable.
fn random_hex_suffix() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 8];
    // Unguessable filename, not key material - no need to fail closed here.
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// A `current_transfer_owner` helper used to live here, taking the connection lock
// on its own. Both transfer commands now read the owner AND that link's sender in
// ONE lock instead: two separate lookups let a host switch land in between, so a
// transfer could be tagged for one host and its request sent to another.

fn try_enqueue(outbound: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), String> {
    use tokio::sync::mpsc::error::TrySendError;
    // Human-paced control queue: Full means the link is genuinely stalled.
    outbound.try_send(frame).map_err(|e| match e {
        TrySendError::Full(_) => "connection busy - try again".into(),
        TrySendError::Closed(_) => "connection closed".into(),
    })
}

async fn remove_connection_if_current(current: &CurrentConnection, id: u64) -> bool {
    let mut slot = current.lock().await;
    if slot.as_ref().is_some_and(|connection| connection.id == id) {
        *slot = None;
        true
    } else {
        false
    }
}

#[tauri::command]
async fn attach(state: State<'_, PorttyState>, id: u64) -> Result<(), String> {
    // Correlated: resolves on the host's ack, or errors if the session is gone.
    request(&state, RequestKind::Attach { id: SessionId(id) })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn detach(state: State<'_, PorttyState>) -> Result<(), String> {
    enqueue(&state, Frame::Detach).await
}

/// Resume the viewed session's output after a reconnect WITHOUT a repaint:
/// asks the host for everything strictly after the last seq this phone saw.
/// The host falls back to reset + full snapshot by itself when the boundary
/// aged out, so the caller needs no fallback logic. Use `attach` instead when
/// the local terminal buffer is empty (cold start).
#[tauri::command]
async fn resume_output(state: State<'_, PorttyState>, id: u64) -> Result<(), String> {
    let after_seq = state
        .last_seen_seq
        .lock()
        .await
        .get(&id)
        .copied()
        .unwrap_or(0);
    // The host lifetime that produced the screen we last rendered. If the host
    // restarted since, its generation differs and it will repaint instead of
    // serving a delta that no longer lines up (#14).
    let generation = state
        .last_seen_generation
        .lock()
        .await
        .get(&id)
        .copied()
        .unwrap_or(0);
    enqueue(
        &state,
        Frame::OutputResume {
            id: SessionId(id),
            after_seq,
            generation,
        },
    )
    .await
}

/// Read + consume the wake blob the native push layer stored on the last
/// notification, returning the paired host's device-id hex when the blob was
/// sealed by THIS phone. `None` → launch normally.
#[tauri::command]
async fn consume_push_wake(
    state: State<'_, PorttyState>,
    app: tauri::AppHandle,
) -> Result<Option<String>, String> {
    // First candidate that OPENS wins. Anything that does not open was not sealed
    // by this phone - a spoofed Intent extra on Android, or a blob left by a
    // previous install - and is simply not ours. See `consume_wake_blobs`.
    Ok(push_wake::consume_wake_blobs(&app)
        .into_iter()
        .find_map(|blob| push_wake::open_wake_blob(&state.wake_key, &blob))
        .map(|host| host.as_hex()))
}

/// Manual push registration (dev/testing seam; the automatic path reads the
/// native token file on every connect). Registers with the CURRENTLY
/// connected host.
#[tauri::command]
async fn register_push(
    state: State<'_, PorttyState>,
    provider: String,
    token: String,
) -> Result<(), String> {
    let provider = match provider.as_str() {
        "apns" => portty_protocol::PushProvider::Apns,
        "fcm" => portty_protocol::PushProvider::Fcm,
        _ => return Err("provider must be apns or fcm".into()),
    };
    let peer = {
        let connection = state.connection.lock().await;
        connection
            .as_ref()
            .map(|c| c.peer_device_id)
            .ok_or_else(|| "not paired".to_string())?
    };
    let blob =
        push_wake::seal_wake_blob(&state.wake_key, &peer).ok_or("could not seal wake blob")?;
    enqueue(
        &state,
        Frame::PushRegister {
            provider,
            token,
            sealed_wake_blob: blob,
        },
    )
    .await
}

/// Freeze live output for the viewed session so the user can scroll/read without
/// the cursor jumping (and save cellular data). The host keeps buffering into
/// its ring; `resume_stream` replays scrollback + restarts the live stream.
#[tauri::command]
async fn pause_stream(state: State<'_, PorttyState>) -> Result<(), String> {
    enqueue(&state, Frame::PauseStream).await
}

#[tauri::command]
async fn resume_stream(state: State<'_, PorttyState>) -> Result<(), String> {
    enqueue(&state, Frame::ResumeStream).await
}

#[tauri::command]
async fn input(state: State<'_, PorttyState>, id: u64, data: String) -> Result<(), String> {
    enqueue(
        &state,
        Frame::Input {
            id: SessionId(id),
            bytes: data.into_bytes(),
        },
    )
    .await
}

/// Create a shell on the host and return ITS id, so the phone opens exactly that
/// session (no "the next SessionAdded must be mine" guessing). The shell is born
/// at the host's FIXED size (fixed-size model) - the phone renders around it and
/// never drives the PTY size.
#[tauri::command]
async fn new_session(state: State<'_, PorttyState>, title: Option<String>) -> Result<u64, String> {
    let session = request(&state, RequestKind::NewSession { cwd: None, title }).await?;
    session
        .map(|id| id.0)
        .ok_or_else(|| "host did not return a session id".to_string())
}

/// Start a structured coding-agent session using an allow-listed host preset.
#[tauri::command]
async fn new_agent(
    state: State<'_, PorttyState>,
    provider: String,
    title: Option<String>,
) -> Result<u64, String> {
    let provider = match provider.as_str() {
        "claude_code" => AgentProvider::ClaudeCode,
        "open_code" => AgentProvider::OpenCode,
        "codex" => AgentProvider::Codex,
        "goose" => AgentProvider::Goose,
        _ => return Err("unknown agent provider".into()),
    };
    let session = request(&state, RequestKind::NewAgentSession { provider, title }).await?;
    session
        .map(|id| id.0)
        .ok_or_else(|| "host did not return an agent session id".to_string())
}

/// Inverse of [`agent_provider_from_str`], so a resumed conversation reports the
/// same provider names the frontend already uses to start one.
fn agent_provider_name(provider: AgentProvider) -> &'static str {
    match provider {
        AgentProvider::ClaudeCode => "claude_code",
        AgentProvider::OpenCode => "open_code",
        AgentProvider::Codex => "codex",
        AgentProvider::Goose => "goose",
    }
}

fn agent_provider_from_str(provider: &str) -> Result<AgentProvider, String> {
    match provider {
        "claude_code" => Ok(AgentProvider::ClaudeCode),
        "open_code" => Ok(AgentProvider::OpenCode),
        "codex" => Ok(AgentProvider::Codex),
        "goose" => Ok(AgentProvider::Goose),
        _ => Err("unknown agent provider".into()),
    }
}

/// Start an agent in a directory the user picked, instead of the workspace root.
///
/// `rel` is relative to the host's workspace root. The host re-resolves and
/// re-checks containment - nothing here is trusted to have done that - and the
/// chosen directory becomes the agent's ACP sandbox root, so a deeper pick means
/// strictly less reachable filesystem.
#[tauri::command]
async fn new_agent_in(
    state: State<'_, PorttyState>,
    provider: String,
    title: Option<String>,
    rel: String,
) -> Result<u64, String> {
    let provider = agent_provider_from_str(&provider)?;
    let session = request(
        &state,
        RequestKind::NewAgentSessionIn {
            provider,
            title,
            rel,
        },
    )
    .await?;
    session
        .map(|id| id.0)
        .ok_or_else(|| "host did not return an agent session id".to_string())
}

/// Open a shell in a chosen workspace directory.
///
/// `rel` is workspace-relative and the host re-resolves it - the phone's job is
/// to pass through what the picker listed, never to compose a path itself. Note
/// the deliberate absence of a `cwd` parameter: `RequestKind::NewSession` still
/// carries one on the wire, but sending an absolute path from the phone is the
/// thing `rel` exists to prevent.
#[tauri::command]
async fn new_session_in(
    state: State<'_, PorttyState>,
    rel: String,
    title: Option<String>,
) -> Result<u64, String> {
    let session = request(&state, RequestKind::NewSessionIn { title, rel }).await?;
    session
        .map(|id| id.0)
        .ok_or_else(|| "host did not return a session id".to_string())
}

/// Which folder roots this host serves for terminals.
///
/// Asked rather than assumed: the operator can turn the non-workspace roots off
/// (`PORTTY_TERMINAL_ROOTS`), and offering a root the host will refuse is worse
/// than not offering it. An older host does not know this request and answers with
/// an error, which the caller treats as "workspace only" - the pre-v10 behaviour.
#[tauri::command]
async fn list_terminal_roots(state: State<'_, PorttyState>) -> Result<Vec<String>, String> {
    let req_id = state.next_req_id.fetch_add(1, Ordering::Relaxed);
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (roots_tx, roots_rx) = oneshot::channel();
    let (outbound, pending, roots_pending) = {
        let connection = state.connection.lock().await;
        let current = connection.as_ref().ok_or("not paired")?;
        current.pending.lock().await.insert(req_id, outcome_tx);
        current.roots_pending.lock().await.insert(req_id, roots_tx);
        (
            current.outbound.clone(),
            current.pending.clone(),
            current.roots_pending.clone(),
        )
    };
    if let Err(e) = try_enqueue(
        &outbound,
        Frame::Request {
            req_id,
            kind: RequestKind::ListTerminalRoots,
        },
    ) {
        pending.lock().await.remove(&req_id);
        roots_pending.lock().await.remove(&req_id);
        return Err(e);
    }
    match tokio::time::timeout(Duration::from_secs(5), outcome_rx).await {
        Ok(Ok(CommandOutcome::Ok { .. })) => {}
        Ok(Ok(CommandOutcome::Error { message })) => {
            roots_pending.lock().await.remove(&req_id);
            return Err(message);
        }
        Ok(Err(_)) => {
            roots_pending.lock().await.remove(&req_id);
            return Err("connection closed before the folder roots arrived".into());
        }
        Err(_) => {
            pending.lock().await.remove(&req_id);
            roots_pending.lock().await.remove(&req_id);
            return Err("listing timed out".into());
        }
    }
    match tokio::time::timeout(Duration::from_secs(2), roots_rx).await {
        Ok(Ok(roots)) => Ok(roots),
        _ => {
            roots_pending.lock().await.remove(&req_id);
            Err("host confirmed the roots but did not send them".into())
        }
    }
}

/// Open a shell in `rel` inside a named root.
#[tauri::command]
async fn new_session_in_root(
    state: State<'_, PorttyState>,
    root: String,
    rel: String,
    title: Option<String>,
) -> Result<u64, String> {
    let root = terminal_root_from_str(&root)?;
    let session = request(&state, RequestKind::NewSessionInRoot { root, rel, title }).await?;
    session
        .map(|id| id.0)
        .ok_or_else(|| "host did not return a session id".to_string())
}

/// Which agents this host can actually launch.
///
/// Asked once when the picker opens, so an agent whose adapter is missing is
/// shown as unavailable up front instead of failing after three taps.
#[tauri::command]
async fn list_agent_providers(
    state: State<'_, PorttyState>,
) -> Result<Vec<AgentProviderRow>, String> {
    let req_id = state.next_req_id.fetch_add(1, Ordering::Relaxed);
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (rows_tx, rows_rx) = oneshot::channel();
    let (outbound, pending, providers_pending) = {
        let connection = state.connection.lock().await;
        let current = connection.as_ref().ok_or("not paired")?;
        current.pending.lock().await.insert(req_id, outcome_tx);
        current
            .providers_pending
            .lock()
            .await
            .insert(req_id, rows_tx);
        (
            current.outbound.clone(),
            current.pending.clone(),
            current.providers_pending.clone(),
        )
    };
    if let Err(e) = try_enqueue(
        &outbound,
        Frame::Request {
            req_id,
            kind: RequestKind::ListAgentProviders,
        },
    ) {
        pending.lock().await.remove(&req_id);
        providers_pending.lock().await.remove(&req_id);
        return Err(e);
    }
    match tokio::time::timeout(Duration::from_secs(8), outcome_rx).await {
        Ok(Ok(CommandOutcome::Ok { .. })) => {}
        Ok(Ok(CommandOutcome::Error { message })) => {
            providers_pending.lock().await.remove(&req_id);
            return Err(message);
        }
        Ok(Err(_)) => {
            providers_pending.lock().await.remove(&req_id);
            return Err("connection closed before the agent list arrived".into());
        }
        Err(_) => {
            pending.lock().await.remove(&req_id);
            providers_pending.lock().await.remove(&req_id);
            return Err("listing timed out".into());
        }
    }
    match tokio::time::timeout(Duration::from_secs(2), rows_rx).await {
        Ok(Ok(rows)) => Ok(rows),
        _ => {
            providers_pending.lock().await.remove(&req_id);
            Err("host confirmed the list but did not send it".into())
        }
    }
}

/// Reopen a specific saved conversation. The host recovers the provider from its
/// own cache, so this only names the directory and the id.
#[tauri::command]
async fn resume_agent_session(
    state: State<'_, PorttyState>,
    rel: String,
    acp_session_id: String,
) -> Result<u64, String> {
    let session = request(
        &state,
        RequestKind::ResumeAgentSession {
            rel,
            acp_session_id,
        },
    )
    .await?;
    session
        .map(|id| id.0)
        .ok_or_else(|| "host did not return an agent session id".to_string())
}

/// The saved conversations for one workspace directory, from Portty's cache
/// alone.
///
/// Kept for hosts older than PROTOCOL_VERSION 11 and for callers with no
/// provider in hand. `list_agent_sessions_for` is the one the agent picker uses.
#[tauri::command]
async fn list_agent_sessions(
    state: State<'_, PorttyState>,
    rel: String,
) -> Result<AgentSessionListing, String> {
    request_agent_sessions(
        &state,
        RequestKind::ListAgentSessions { rel },
        Duration::from_secs(5),
    )
    .await
}

/// Every conversation one agent can continue in a directory - Portty's cache
/// PLUS what the agent itself remembers, which is how a chat started in the
/// laptop terminal shows up here at all.
///
/// The longer budget is the point of the separate command: answering this
/// launches the provider's ACP adapter on the host and asks it, and an `npx`
/// adapter can take several seconds just to resolve. The host bounds its own
/// probe below this, so a slow agent yields a short list, not a timeout.
#[tauri::command]
async fn list_agent_sessions_for(
    state: State<'_, PorttyState>,
    rel: String,
    provider: String,
) -> Result<AgentSessionListing, String> {
    let provider = agent_provider_from_str(&provider)?;
    request_agent_sessions(
        &state,
        RequestKind::ListAgentSessionsFor { rel, provider },
        Duration::from_secs(20),
    )
    .await
}

/// Shared plumbing for both conversation listings.
///
/// Same two-map correlation as `list_workspace_dirs`: the payload rides its own
/// frame, the outcome reports success or the host's refusal.
async fn request_agent_sessions(
    state: &State<'_, PorttyState>,
    kind: RequestKind,
    outcome_timeout: Duration,
) -> Result<AgentSessionListing, String> {
    let req_id = state.next_req_id.fetch_add(1, Ordering::Relaxed);
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (rows_tx, rows_rx) = oneshot::channel();
    let (outbound, pending, sessions_pending) = {
        let connection = state.connection.lock().await;
        let current = connection.as_ref().ok_or("not paired")?;
        current.pending.lock().await.insert(req_id, outcome_tx);
        current
            .sessions_pending
            .lock()
            .await
            .insert(req_id, rows_tx);
        (
            current.outbound.clone(),
            current.pending.clone(),
            current.sessions_pending.clone(),
        )
    };
    if let Err(e) = try_enqueue(&outbound, Frame::Request { req_id, kind }) {
        pending.lock().await.remove(&req_id);
        sessions_pending.lock().await.remove(&req_id);
        return Err(e);
    }
    match tokio::time::timeout(outcome_timeout, outcome_rx).await {
        Ok(Ok(CommandOutcome::Ok { .. })) => {}
        Ok(Ok(CommandOutcome::Error { message })) => {
            sessions_pending.lock().await.remove(&req_id);
            return Err(message);
        }
        Ok(Err(_)) => {
            sessions_pending.lock().await.remove(&req_id);
            return Err("connection closed before the conversation list arrived".into());
        }
        Err(_) => {
            pending.lock().await.remove(&req_id);
            sessions_pending.lock().await.remove(&req_id);
            return Err("listing timed out".into());
        }
    }
    match tokio::time::timeout(Duration::from_secs(2), rows_rx).await {
        Ok(Ok(listing)) => Ok(listing),
        _ => {
            sessions_pending.lock().await.remove(&req_id);
            Err("host confirmed the list but did not send it".into())
        }
    }
}

/// One level of the workspace tree for the directory picker.
///
/// Unlike every other command here the answer does not fit in a
/// `CommandOutcome`, so this registers in TWO maps under one `req_id`: the
/// listing rides its own frame, the outcome reports success or the host's
/// refusal. The host sends the listing first, so by the time the outcome
/// resolves the payload is already delivered.
#[tauri::command]
async fn list_workspace_dirs(
    state: State<'_, PorttyState>,
    rel: String,
) -> Result<WorkspaceListing, String> {
    list_dirs_request(state, RequestKind::ListWorkspaceDirs { rel }).await
}

/// The same listing, inside a named root.
///
/// Shares every line of the correlation dance with `list_workspace_dirs` because
/// the host answers both with `Frame::WorkspaceDirs` - two copies of that
/// two-channel timeout logic would be two places for it to drift.
#[tauri::command]
async fn list_dirs_in(
    state: State<'_, PorttyState>,
    root: String,
    rel: String,
) -> Result<WorkspaceListing, String> {
    let root = terminal_root_from_str(&root)?;
    list_dirs_request(state, RequestKind::ListDirsIn { root, rel }).await
}

async fn list_dirs_request(
    state: State<'_, PorttyState>,
    kind: RequestKind,
) -> Result<WorkspaceListing, String> {
    let req_id = state.next_req_id.fetch_add(1, Ordering::Relaxed);
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (dirs_tx, dirs_rx) = oneshot::channel();
    let (outbound, pending, dirs_pending) = {
        let connection = state.connection.lock().await;
        let current = connection.as_ref().ok_or("not paired")?;
        current.pending.lock().await.insert(req_id, outcome_tx);
        current.dirs_pending.lock().await.insert(req_id, dirs_tx);
        (
            current.outbound.clone(),
            current.pending.clone(),
            current.dirs_pending.clone(),
        )
    };
    let forget = |pending: Pending, dirs: DirsPending| async move {
        pending.lock().await.remove(&req_id);
        dirs.lock().await.remove(&req_id);
    };
    if let Err(e) = try_enqueue(&outbound, Frame::Request { req_id, kind }) {
        forget(pending, dirs_pending).await;
        return Err(e);
    }
    match tokio::time::timeout(Duration::from_secs(5), outcome_rx).await {
        Ok(Ok(CommandOutcome::Ok { .. })) => {}
        Ok(Ok(CommandOutcome::Error { message })) => {
            dirs_pending.lock().await.remove(&req_id);
            return Err(message);
        }
        Ok(Err(_)) => {
            dirs_pending.lock().await.remove(&req_id);
            return Err("connection closed before the listing arrived".into());
        }
        Err(_) => {
            forget(pending, dirs_pending).await;
            return Err("listing timed out".into());
        }
    }
    // The outcome said Ok, so the frame was sent before it. Anything but an
    // immediate resolve here means the two got separated - report it rather than
    // showing an empty directory, which reads as "this folder has nothing in it".
    match tokio::time::timeout(Duration::from_secs(2), dirs_rx).await {
        Ok(Ok(listing)) => Ok(listing),
        _ => {
            dirs_pending.lock().await.remove(&req_id);
            Err("host confirmed the listing but did not send it".into())
        }
    }
}

#[tauri::command]
async fn agent_prompt(state: State<'_, PorttyState>, id: u64, text: String) -> Result<(), String> {
    request(
        &state,
        RequestKind::AgentPrompt {
            id: SessionId(id),
            text,
        },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
async fn agent_cancel(state: State<'_, PorttyState>, id: u64) -> Result<(), String> {
    request(&state, RequestKind::AgentCancel { id: SessionId(id) })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn agent_set_mode(
    state: State<'_, PorttyState>,
    id: u64,
    mode_id: String,
) -> Result<(), String> {
    request(
        &state,
        RequestKind::AgentSetMode {
            id: SessionId(id),
            mode_id,
        },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
async fn agent_set_config(
    state: State<'_, PorttyState>,
    id: u64,
    config_id: String,
    value: AgentConfigValue,
) -> Result<(), String> {
    request(
        &state,
        RequestKind::AgentSetConfigOption {
            id: SessionId(id),
            config_id,
            value,
        },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
async fn agent_authenticate(
    state: State<'_, PorttyState>,
    id: u64,
    method_id: String,
) -> Result<(), String> {
    request(
        &state,
        RequestKind::AgentAuthenticate {
            id: SessionId(id),
            method_id,
        },
    )
    .await
    .map(|_| ())
}

/// Answer one approval card. `connection` is the generation that raised it (see
/// `PermissionPayload::connection`): a decision may only reach the exact link
/// that asked, never whichever host happens to be installed now. Without this,
/// a card left over from host A could resolve a same-id pending request on B.
#[tauri::command]
async fn permission_decision(
    state: State<'_, PorttyState>,
    id: u64,
    tool_call_id: String,
    option_id: Option<String>,
    connection: u64,
) -> Result<(), String> {
    let outbound = {
        let current = state.connection.lock().await;
        let current = current.as_ref().ok_or_else(|| "not paired".to_string())?;
        if current.id != connection {
            return Err(
                "this approval belongs to an earlier connection - it can no longer be answered"
                    .into(),
            );
        }
        current.outbound.clone()
    };
    try_enqueue(
        &outbound,
        Frame::AgentPermissionDecision {
            id: SessionId(id),
            tool_call_id,
            option_id,
        },
    )
}

/// Pull a host file into a user-selected local destination. The `.part` file is
/// retained across link generations and the next connection resumes at its
/// first missing chunk.
#[tauri::command]
async fn download_file(
    state: State<'_, PorttyState>,
    remote_path: String,
    local_path: String,
    allow_outside_home: Option<bool>,
) -> Result<u64, String> {
    let slot = state
        .transfers
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            format!("at most {MAX_ACTIVE_FILE_TRANSFERS} file transfers may run at once")
        })?;
    // Bind the transfer to the pairing that will serve it AND take that link's
    // sender in the same lock. Looking the connection up twice - once for the
    // owner, once to send - left a window where a host switch in between tagged
    // the transfer for A and sent A's remote path to B. B could not overwrite the
    // destination (the response checks ownership), but it learned the path and
    // the transfer stalled. Same one-look rule `upload_file` already follows.
    let (owner, outbound) = {
        let connection = state.connection.lock().await;
        let connection = connection
            .as_ref()
            .ok_or_else(|| "not paired".to_string())?;
        (
            TransferOwner {
                peer_device_id: connection.peer_device_id,
                pair_id: connection.pair_id,
            },
            connection.outbound.clone(),
        )
    };
    let id = TransferId(state.transfers.next_id.fetch_add(1, Ordering::Relaxed));
    let target = std::path::PathBuf::from(local_path);
    let parent = target
        .parent()
        .ok_or_else(|| "download destination has no parent directory".to_string())?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| format!("cannot create download directory: {e}"))?;
    // Unpredictable name, and CREATE_NEW rather than create+truncate.
    //
    // The old `.portty-download-<n>.part` was guessable (ids start at 1 and
    // count up) and opened with `create(true).truncate(true)`, which follows a
    // symlink: anything that could write the download directory - another app in
    // a shared folder, or any local user on a desktop build - could pre-plant a
    // link and have the download written through it, to a path the user never
    // chose. A random name nobody can guess plus O_EXCL closes both: a link
    // sitting at our path is now an error, not a redirect.
    let temporary = parent.join(format!(
        ".portty-download-{}-{}.part",
        id.0,
        random_hex_suffix()
    ));
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        // Downloads can be anything the user pulled off a host; keep the staging
        // file owner-only rather than at the process umask. (`mode` is inherent on
        // tokio's OpenOptions - no std extension trait needed.)
        options.mode(0o600);
    }
    let file = options
        .open(&temporary)
        .await
        .map_err(|e| format!("cannot create download file: {e}"))?;
    let allow_outside_home = allow_outside_home.unwrap_or(false);
    state.transfers.downloads.lock().await.insert(
        id,
        DownloadTransfer {
            owner,
            restarts: 0,
            remote_path: remote_path.clone(),
            target,
            temporary,
            file,
            next_seq: 0,
            written: 0,
            hasher: Hasher::new(),
            allow_outside_home,
            _slot: slot,
        },
    );
    if let Err(error) = try_enqueue(
        &outbound,
        Frame::FileGetReq {
            id,
            path: remote_path,
            start_seq: 0,
            allow_outside_home,
        },
    ) {
        if let Some(transfer) = state.transfers.downloads.lock().await.remove(&id) {
            let _ = tokio::fs::remove_file(transfer.temporary).await;
        }
        return Err(error);
    }
    Ok(id.0)
}

/// Push a local file to a host path. The host commits atomically only after it
/// verifies this task's final size and BLAKE3 digest.
#[tauri::command]
async fn upload_file(
    state: State<'_, PorttyState>,
    app: tauri::AppHandle,
    local_path: String,
    remote_path: String,
    allow_outside_home: Option<bool>,
) -> Result<u64, String> {
    let slot = Arc::new(
        state
            .transfers
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                format!("at most {MAX_ACTIVE_FILE_TRANSFERS} file transfers may run at once")
            })?,
    );
    let local_path = std::path::PathBuf::from(local_path);
    // Open FIRST, then ask the handle about itself. Statting the path and
    // opening it separately are two different files whenever anything can write
    // the directory in between; the size announced to the host must describe the
    // bytes actually about to be sent.
    let file = tokio::fs::File::open(&local_path)
        .await
        .map_err(|e| format!("cannot open upload: {e}"))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|e| format!("cannot read upload: {e}"))?;
    if !metadata.is_file() {
        return Err("upload source is not a regular file".into());
    }
    let id = TransferId(state.transfers.next_id.fetch_add(1, Ordering::Relaxed));
    // Owner and outbound sender come from ONE look at the current connection, so
    // the upload can never be tagged for one host and streamed to another.
    let (owner, outbound) = {
        let connection = state.connection.lock().await;
        let connection = connection
            .as_ref()
            .ok_or_else(|| "not paired".to_string())?;
        (
            TransferOwner {
                peer_device_id: connection.peer_device_id,
                pair_id: connection.pair_id,
            },
            connection.outbound.clone(),
        )
    };
    let upload = UploadTransfer {
        owner,
        file: Arc::new(tokio::sync::Mutex::new(file)),
        remote_path: remote_path.clone(),
        size: metadata.len(),
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        epoch: Arc::new(AtomicU64::new(0)),
        _slot: slot,
    };
    state
        .transfers
        .uploads
        .lock()
        .await
        .insert(id, upload.clone());
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode() & 0o777)
    };
    #[cfg(not(unix))]
    let mode = None;
    if outbound
        .send(Frame::FilePutReq {
            id,
            path: remote_path,
            size: metadata.len(),
            mode,
            allow_outside_home: allow_outside_home.unwrap_or(false),
        })
        .await
        .is_err()
    {
        state.transfers.uploads.lock().await.remove(&id);
        return Err("connection closed".into());
    }
    spawn_upload_range(id, upload, 0, outbound, app, state.transfers.clone());
    Ok(id.0)
}

/// Stream `upload` from `from_seq`, claiming the transfer's streaming slot.
///
/// Bumping the epoch here is what retires any earlier task for the same
/// transfer: the loop below checks it every chunk, so at most one reader per
/// upload is ever live no matter how many retries a host asks for.
fn spawn_upload_range(
    id: TransferId,
    upload: UploadTransfer,
    from_seq: u64,
    outbound: mpsc::Sender<Frame>,
    app: tauri::AppHandle,
    transfers: Arc<ClientTransfers>,
) {
    let epoch = upload.epoch.fetch_add(1, Ordering::Relaxed) + 1;
    tokio::spawn(async move {
        let result: Result<(), String> = async {
            // The handle opened when the transfer was created - NOT a fresh open
            // of `local_path`, which is what let the file be swapped between the
            // size check and the read, and again on every retry.
            let mut file = upload.file.lock().await;
            file.rewind()
                .await
                .map_err(|e| format!("cannot rewind upload: {e}"))?;
            let mut hasher = Hasher::new();
            let mut seq = 0u64;
            let mut sent = from_seq.saturating_mul(FILE_CHUNK_BYTES as u64);
            let mut buf = vec![0u8; FILE_CHUNK_BYTES];
            loop {
                if upload.cancelled.load(Ordering::Relaxed) {
                    // Host rejected the upload (`FileErr`) - stop streaming.
                    // The error event was already emitted by the FileErr arm.
                    return Ok(());
                }
                if upload.epoch.load(Ordering::Relaxed) != epoch {
                    // A newer retry took over this transfer. Exit quietly: the
                    // replacement owns the progress events and the outcome.
                    return Ok(());
                }
                let read = file
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("cannot read upload: {e}"))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buf[..read]);
                if seq >= from_seq {
                    outbound
                        .send(Frame::FileChunk {
                            id,
                            seq,
                            bytes: buf[..read].to_vec(),
                        })
                        .await
                        .map_err(|_| "connection closed during upload".to_string())?;
                    sent = (sent + read as u64).min(upload.size);
                    let _ = app.emit(
                        "portty://transfer-progress",
                        TransferProgressPayload {
                            id: id.0,
                            direction: "upload",
                            transferred: sent,
                            total: Some(upload.size),
                            path: upload.remote_path.clone(),
                        },
                    );
                }
                seq += 1;
            }
            outbound
                .send(Frame::FileDone {
                    id,
                    size: upload.size,
                    checksum: *hasher.finalize().as_bytes(),
                })
                .await
                .map_err(|_| "connection closed before upload verification".to_string())?;
            Ok(())
        }
        .await;
        if let Err(message) = result {
            // Superseded tasks return Ok, so reaching here means THIS task was
            // still the live one when it failed.
            if upload.epoch.load(Ordering::Relaxed) != epoch {
                return;
            }
            upload.cancelled.store(true, Ordering::Relaxed);
            let mut uploads = transfers.uploads.lock().await;
            if uploads
                .get(&id)
                .is_some_and(|active| Arc::ptr_eq(&active.cancelled, &upload.cancelled))
            {
                uploads.remove(&id);
            }
            drop(uploads);
            let _ = app.emit(
                "portty://transfer-error",
                TransferErrorPayload { id: id.0, message },
            );
        }
    });
}

#[tauri::command]
async fn kill(state: State<'_, PorttyState>, id: u64) -> Result<(), String> {
    request(&state, RequestKind::KillSession { id: SessionId(id) })
        .await
        .map(|_| ())
}

/// Give a session a custom name. The host updates the title and re-sends the
/// session list, which arrives as a `portty://list` event.
#[tauri::command]
async fn rename(state: State<'_, PorttyState>, id: u64, title: String) -> Result<(), String> {
    request(
        &state,
        RequestKind::RenameSession {
            id: SessionId(id),
            title,
        },
    )
    .await
    .map(|_| ())
}

/// One saved laptop for the host picker.
#[derive(Serialize, Clone)]
struct HostPayload {
    /// Device-id hex - pass back to `reconnect` as `host` to switch to it.
    id: String,
    /// What to display: the user's nickname if they set one, else the name the
    /// host announced (its hostname). None when neither exists.
    name: Option<String>,
    /// The announced hostname on its own, kept separate so the rename field can
    /// offer it as the placeholder - it is what clearing the nickname restores.
    announced_name: Option<String>,
    /// True when `name` is a user-chosen nickname rather than the announced one.
    is_renamed: bool,
    /// True for the most recently connected host (the default Reconnect target).
    is_last: bool,
    /// The folder new terminals open in by default, relative to `default_root`.
    /// `None` means none chosen - the root itself.
    default_dir: Option<String>,
    /// Which root `default_dir` is relative to (`"workspace"` or `"home"`).
    /// `None` whenever `default_dir` is.
    default_root: Option<String>,
}

/// The laptops this phone can resume by stored token - the host picker's data.
#[tauri::command]
async fn list_hosts(state: State<'_, PorttyState>) -> Result<Vec<HostPayload>, String> {
    let peers = state.peers.lock().await;
    let last = peers.last_host().map(|(d, _, _)| d);
    let names = load_host_names(&state.data_dir);
    let nicknames = load_host_nicknames(&state.data_dir);
    let default_dirs = load_host_default_dirs(&state.data_dir);
    Ok(peers
        .known_hosts()
        .into_iter()
        .map(|(d, _, _)| {
            let announced = names.get(&d).cloned();
            let nickname = nicknames.get(&d).cloned();
            HostPayload {
                // Full hex, NOT Display - Display truncates ("97ff954c…") and
                // could never round-trip through `DeviceId::from_hex`.
                id: d.as_hex(),
                is_renamed: nickname.is_some(),
                name: nickname.or_else(|| announced.clone()),
                announced_name: announced,
                is_last: Some(d) == last,
                // Stored as `root:rel`; pre-v10 values have no prefix and meant
                // the workspace, which `decode_default_dir` handles.
                default_root: default_dirs
                    .get(&d)
                    .map(|stored| decode_default_dir(stored).0),
                default_dir: default_dirs
                    .get(&d)
                    .map(|stored| decode_default_dir(stored).1),
            }
        })
        .collect())
}

/// Rename a saved laptop in the picker. Purely cosmetic and purely local: the
/// nickname is never sent to the host (no frame, no handshake field), so this
/// needs neither the host to be reachable nor a live connection. An empty or
/// whitespace-only name clears the nickname, restoring the announced hostname.
/// Returns the nickname as stored (after trimming), or None if it was cleared.
#[tauri::command]
async fn rename_host(
    state: State<'_, PorttyState>,
    host: String,
    name: String,
) -> Result<Option<String>, String> {
    let device = DeviceId::from_hex(&host).ok_or("bad host id")?;
    // Only label a host this phone actually holds a credential for: a nickname
    // for an unknown device would never appear in the picker and nothing would
    // ever clean it up, since `remove_host` is the only thing that erases one.
    let known = {
        let peers = state.peers.lock().await;
        peers.known_hosts().into_iter().any(|(d, _, _)| d == device)
    };
    if !known {
        return Err("no such saved host".to_string());
    }

    let nickname = sanitize_host_nickname(&name);
    let mut nicknames = load_host_nicknames(&state.data_dir);
    let changed = if nickname.is_empty() {
        nicknames.remove(&device).is_some()
    } else if nicknames.get(&device) == Some(&nickname) {
        false
    } else {
        nicknames.insert(device, nickname.clone());
        true
    };
    // Unlike the announced label this was an explicit user action, so a write
    // failure is surfaced instead of only logged - otherwise the rename would
    // appear to work and silently revert on the next `list_hosts`.
    if changed {
        store_host_labels(&host_nicknames_path(&state.data_dir), &nicknames)
            .map_err(|e| format!("could not save host name: {e}"))?;
    }
    Ok((!nickname.is_empty()).then_some(nickname))
}

/// Set (or clear) the folder new terminals open in for one saved host.
///
/// Phone-local and per host, like `rename_host` - nothing is sent to the laptop,
/// so it works offline. An empty `rel` clears the choice, which means "the
/// workspace root". Resolves with the value as stored, or `None` once cleared.
///
/// This is a preference, not a permission: the host re-resolves and re-confines
/// every `rel` it is handed, so the worst a bad value can do is be refused.
#[tauri::command]
async fn set_host_default_dir(
    state: State<'_, PorttyState>,
    host: String,
    root: String,
    rel: String,
) -> Result<Option<String>, String> {
    let device = DeviceId::from_hex(&host).ok_or("bad host id")?;
    // Refuse an unknown root here rather than storing it: the value would sit in
    // the file until someone noticed the default silently never applied.
    let root = terminal_root_name(terminal_root_from_str(&root)?);
    // Only for a host this phone holds a credential for - same reasoning as the
    // nickname: an entry for an unknown device would never be shown and nothing
    // would ever clean it up, since `remove_host` is what erases these.
    let known = {
        let peers = state.peers.lock().await;
        peers.known_hosts().into_iter().any(|(d, _, _)| d == device)
    };
    if !known {
        return Err("no such saved host".to_string());
    }

    let rel = sanitize_default_dir(&rel)?;
    let mut defaults = load_host_default_dirs(&state.data_dir);
    // An empty rel in the WORKSPACE is "no default" - the workspace root is the
    // fallback, so storing it would be storing nothing. An empty rel in another
    // root is a real choice ("open in home"), so it is kept.
    let clears = rel.is_empty() && root == "workspace";
    let stored = encode_default_dir(root, &rel);
    let changed = if clears {
        defaults.remove(&device).is_some()
    } else if defaults.get(&device) == Some(&stored) {
        false
    } else {
        defaults.insert(device, stored.clone());
        true
    };
    // An explicit user action, so a write failure is surfaced rather than logged -
    // otherwise it would appear to save and revert on the next `list_hosts`.
    if changed {
        store_host_labels(&host_default_dirs_path(&state.data_dir), &defaults)
            .map_err(|e| format!("could not save the default folder: {e}"))?;
    }
    // The rel as stored, so the caller can patch its row without re-listing. The
    // root is whatever it just passed, so it is not echoed back.
    Ok((!clears).then_some(rel))
}

/// Forget one saved laptop on the phone. This removes its reconnect credential
/// from the OS-backed store and its cosmetic label. If it is the live host, end
/// that link without emitting the generic disconnect event (which would make
/// the UI's silent-drop handler immediately reconnect to the host just removed).
/// Returns whether the removed host was connected.
#[tauri::command]
async fn remove_host(
    state: State<'_, PorttyState>,
    host: String,
) -> Result<RemoveHostResult, String> {
    // Serialize with pair/reconnect so a successful reconnect cannot rotate and
    // re-save the credential while the user is deleting it.
    let _conn = state
        .connecting
        .try_lock()
        .map_err(|_| "a connection attempt is already in progress".to_string())?;
    let device = DeviceId::from_hex(&host).ok_or("bad host id")?;

    // Ask the authenticated host to revoke THIS connection identity before the
    // phone destroys its local credential. The wait is bounded and local erase
    // still wins if the laptop is unreachable.
    let live_unpair = {
        let current = state.connection.lock().await;
        current.as_ref().and_then(|connection| {
            (connection.peer_device_id == device).then(|| {
                (
                    connection.outbound.clone(),
                    connection.pair_id,
                    connection.unpair_pending.clone(),
                )
            })
        })
    };
    let remote_revoked = if let Some((outbound, pair_id, unpair_pending)) = &live_unpair {
        let request_id = state.next_req_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        unpair_pending.lock().await.insert(request_id, tx);
        let sent = try_enqueue(
            outbound,
            Frame::UnpairSelf {
                request_id,
                pair_id: pair_id.0,
            },
        );
        let result = if sent.is_ok() {
            match tokio::time::timeout(Duration::from_secs(3), rx).await {
                Ok(Ok(Ok(()))) => true,
                Ok(Ok(Err(error))) => {
                    tracing::warn!(%error, "host refused phone-initiated unpair");
                    false
                }
                Ok(Err(_)) | Err(_) => false,
            }
        } else {
            false
        };
        unpair_pending.lock().await.remove(&request_id);
        result
    } else {
        false
    };

    state
        .peers
        .lock()
        .await
        .forget(&device)
        .map_err(|e| format!("could not remove saved host: {e}"))?;

    // Host labels are non-secret and best-effort, but do not leave a stale label
    // behind after the credential itself has been deleted - the nickname least
    // of all, or re-pairing the same laptop would silently inherit the old one.
    for path in [
        host_names_path(&state.data_dir),
        host_nicknames_path(&state.data_dir),
        // The default folder goes too: re-pairing the same laptop must not
        // silently inherit a folder choice made for the credential just deleted,
        // for the same reason the nickname must not.
        host_default_dirs_path(&state.data_dir),
    ] {
        let mut labels = load_host_labels(&path);
        if labels.remove(&device).is_some() {
            if let Err(e) = store_host_labels(&path, &labels) {
                tracing::warn!(error = %e, "could not remove saved host name label");
            }
        }
    }

    let removed_connection = take_connection_for_peer(&state.connection, device).await;
    if let Some(connection) = removed_connection {
        connection.pending.lock().await.clear();
        // Fires the kill switch: the session loop stops and closes the endpoint,
        // so a removed host keeps no authenticated link. Generation cleanup
        // suppresses its (now redundant) disconnect event.
        drop(connection);
        Ok(RemoveHostResult {
            disconnected: true,
            remote_revoked,
        })
    } else {
        Ok(RemoveHostResult {
            disconnected: false,
            remote_revoked,
        })
    }
}

async fn take_connection_for_peer(
    current: &CurrentConnection,
    peer_device_id: DeviceId,
) -> Option<Connection> {
    let mut slot = current.lock().await;
    if slot
        .as_ref()
        .is_some_and(|connection| connection.peer_device_id == peer_device_id)
    {
        slot.take()
    } else {
        None
    }
}

#[tauri::command]
async fn disconnect(state: State<'_, PorttyState>, app: tauri::AppHandle) -> Result<(), String> {
    // Remove the current generation first. Its session task will see that it was
    // deliberately replaced and suppress its later stale disconnect event.
    let old = state.connection.lock().await.take();
    if let Some(connection) = old {
        connection.pending.lock().await.clear();
        // Dropping the `Connection` fires its shutdown kill switch: the session
        // loop breaks and closes the iroh endpoint. Do NOT rely on `outbound`
        // closing here - the session loop holds its own clone of that sender.
        drop(connection);
        let _ = app.emit("portty://disconnected", ());
    }
    Ok(())
}

/// Install the process-wide Rustls crypto provider before any crate builds a
/// TLS client. Tauri/Wry builds a `reqwest` client while serving the initial
/// webview protocol response, so installing it only inside `setup` is too late
/// on mobile - iroh's relay client (reqwest → rustls) would panic with
/// "No rustls crypto provider is configured" on the first HTTPS call.
fn install_rustls_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Install a tracing subscriber so transport/handshake/session events reach the
/// console + logcat (Tauri redirects stderr to the `RustStdoutStderr` sink on
/// Android). Without this, every `tracing::` event is dropped and the phone is a
/// black box during pairing. Default filter: our crates at `debug`, everything
/// else at `info`; override with `RUST_LOG` where that's settable.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,portty_transport=debug,portty_app_lib=debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

/// Open an agent-supplied link in the system browser. Agent markdown links used
/// to render with `target="_blank"`, which in the app's own webview navigated the
/// SPA away instead of opening a browser (#53); the renderer now routes link
/// clicks here. Restricted to http(s) so a crafted link can't launch another URL
/// scheme's handler.
#[tauri::command]
fn open_external_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("refusing to open a non-http(s) link".into());
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|error| error.to_string())
}

/// True on the platforms where the biometric plugin is compiled in and
/// registered (`#[cfg(mobile)]` below). The JS gate uses this to tell "no plugin
/// here, pass through" (desktop dev) apart from "the plugin is present but its
/// status call failed" - the second case must fail CLOSED rather than silently
/// unlock the app.
#[tauri::command]
fn biometric_platform_enforced() -> bool {
    cfg!(mobile)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_rustls_crypto_provider();
    init_tracing();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            use tauri::Manager;
            // Biometric app-lock (D2 hardening). Mobile-only - the plugin has no
            // desktop backend, so it's both dep-gated (Cargo.toml target cfg) and
            // registered behind `#[cfg(mobile)]`. On desktop the JS gate detects
            // the missing plugin and degrades to unlocked (dev stays usable).
            #[cfg(mobile)]
            app.handle().plugin(tauri_plugin_biometric::init())?;
            // Local notifications for pending approvals. Authorization is
            // already requested at launch by push_glue.mm's
            // `requestAuthorizationWithOptions`, so this shares that grant
            // rather than prompting a second time.
            #[cfg(mobile)]
            app.handle().plugin(tauri_plugin_notification::init())?;
            // Per-app writable data dir for the device identity. `app_data_dir()`
            // resolves correctly on Android (the app's private files dir); the
            // `directories` crate returned None on Android, which left the
            // identity write landing on a read-only fs and crashed every launch
            // (EROFS / errno 30). Works on desktop too.
            let dir = app.path().app_data_dir()?;
            // On iOS the credentials live in the Keychain, so nothing else
            // guarantees this dir exists - and host-name labels, the wake key,
            // and the push bridge all live under it. Best-effort: a failure
            // here surfaces as those features' own (non-fatal) errors.
            let _ = std::fs::create_dir_all(&dir);
            #[cfg(any(target_os = "android", target_os = "ios"))]
            let (identity, peers) = mobile_credentials::load_or_migrate(&dir)?;
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            let (identity, peers) = (Identity::load_or_create(&dir)?, PeerStore::load(&dir)?);
            // The wake key is a push-doorbell nicety - it must NEVER take the
            // app down. On any storage failure fall back to a fresh in-memory
            // key: everything works, except that a push tapped after the next
            // relaunch can't name which host rang (the app just opens normally
            // and the reconnect replay still surfaces the pending card).
            // Ahead of the wake key, and ahead of any push callback firing: the
            // native layer writes the bridge files itself and cannot mark them, so
            // the no-backup flag has to be on the directory before they exist.
            push_wake::prepare_bridge_dirs(app.handle());
            let wake_key = push_wake::load_or_create_wake_key(&dir).unwrap_or_else(|error| {
                tracing::warn!(%error, "wake key unavailable; using an ephemeral one");
                let mut key = [0u8; 32];
                use rand::TryRng;
                rand::rngs::SysRng
                    .try_fill_bytes(&mut key)
                    .expect("OS entropy source unavailable");
                key
            });
            app.manage(PorttyState {
                identity,
                connection: Arc::new(AsyncMutex::new(None)),
                peers: Arc::new(AsyncMutex::new(peers)),
                connecting: AsyncMutex::new(()),
                next_connection_id: AtomicU64::new(1),
                next_req_id: AtomicU64::new(1),
                data_dir: dir,
                transfers: Arc::new(ClientTransfers {
                    next_id: AtomicU64::new(1),
                    slots: Arc::new(Semaphore::new(MAX_ACTIVE_FILE_TRANSFERS)),
                    downloads: AsyncMutex::new(HashMap::new()),
                    uploads: AsyncMutex::new(HashMap::new()),
                }),
                last_seen_seq: Arc::new(AsyncMutex::new(HashMap::new())),
                last_seen_generation: Arc::new(AsyncMutex::new(HashMap::new())),
                wake_key,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            decision_log_load,
            decision_log_save,
            decision_log_forget,
            pair,
            reconnect,
            attach,
            detach,
            resume_output,
            pause_stream,
            resume_stream,
            input,
            new_session,
            new_agent,
            new_agent_in,
            new_session_in,
            new_session_in_root,
            list_terminal_roots,
            list_dirs_in,
            set_host_default_dir,
            list_workspace_dirs,
            list_agent_sessions,
            list_agent_sessions_for,
            list_agent_providers,
            resume_agent_session,
            agent_prompt,
            agent_cancel,
            agent_set_mode,
            agent_set_config,
            agent_authenticate,
            permission_decision,
            download_file,
            upload_file,
            kill,
            rename,
            disconnect,
            list_hosts,
            rename_host,
            remove_host,
            consume_push_wake,
            register_push,
            open_external_url,
            biometric_platform_enforced
        ])
        .run(tauri::generate_context!())
        .expect("error while running Portty app");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_rejects_handshake_host_that_does_not_match_ticket() {
        let ticket_host = DeviceId([1; 16]);
        let announced_host = DeviceId([2; 16]);

        assert!(validate_handshake_host(ticket_host, announced_host).is_err());
        assert_eq!(
            validate_handshake_host(ticket_host, ticket_host).unwrap(),
            ticket_host
        );
    }

    #[test]
    fn reconnect_rejects_ticket_that_does_not_match_saved_host() {
        let saved_host = DeviceId([3; 16]);
        let ticket_host = DeviceId([4; 16]);

        assert!(validate_reconnect_ticket_host(saved_host, ticket_host).is_err());
        assert_eq!(
            validate_reconnect_ticket_host(saved_host, saved_host).unwrap(),
            saved_host
        );
    }

    #[test]
    fn reconnect_rejects_handshake_host_that_does_not_match_saved_host() {
        let saved_host = DeviceId([5; 16]);
        let announced_host = DeviceId([6; 16]);

        assert!(validate_handshake_host(saved_host, announced_host).is_err());
    }

    #[tokio::test]
    async fn verified_download_replaces_existing_target_without_delete_window() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("result.txt");
        let temporary = dir.path().join(".result.part");
        tokio::fs::write(&target, b"old").await.unwrap();
        tokio::fs::write(&temporary, b"verified new").await.unwrap();

        replace_download_file(&temporary, &target).await.unwrap();

        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"verified new");
        assert!(!temporary.exists());
    }

    #[tokio::test]
    async fn failed_download_replacement_preserves_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("result.txt");
        let missing_temporary = dir.path().join("missing.part");
        tokio::fs::write(&target, b"keep me").await.unwrap();

        assert!(replace_download_file(&missing_temporary, &target)
            .await
            .is_err());
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"keep me");
    }

    #[test]
    fn agent_payload_has_typescript_discriminant() {
        let payload = AgentTimelinePayload::from(AgentTimelineEvent {
            seq: 9,
            event: AgentEvent::MessageChunk {
                text: "hello".into(),
            },
        });
        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["seq"], 9);
        assert_eq!(json["event"]["type"], "message_chunk");
        assert_eq!(json["event"]["text"], "hello");
    }

    struct TestLink {
        outbound: mpsc::Receiver<Frame>,
        /// Stands in for the session loop's shutdown branch: resolves (with
        /// `Err`) as soon as the `Connection` is dropped.
        shutdown: oneshot::Receiver<()>,
    }

    fn test_connection(id: u64) -> (Connection, TestLink) {
        let (outbound, outbound_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = oneshot::channel();
        (
            Connection {
                id,
                peer_device_id: DeviceId([id as u8; 16]),
                pair_id: portty_transport::PairId([id as u8; 16]),
                outbound,
                pending: Arc::new(AsyncMutex::new(HashMap::new())),
                unpair_pending: Arc::new(AsyncMutex::new(HashMap::new())),
                dirs_pending: Arc::new(AsyncMutex::new(HashMap::new())),
                sessions_pending: Arc::new(AsyncMutex::new(HashMap::new())),
                providers_pending: Arc::new(AsyncMutex::new(HashMap::new())),
                roots_pending: Arc::new(AsyncMutex::new(HashMap::new())),
                _shutdown: shutdown_tx,
            },
            TestLink {
                outbound: outbound_rx,
                shutdown,
            },
        )
    }

    fn owner(byte: u8) -> TransferOwner {
        TransferOwner {
            peer_device_id: DeviceId([byte; 16]),
            pair_id: portty_transport::PairId([byte; 16]),
        }
    }

    /// An open handle for an `UploadTransfer` fixture. The struct now owns a real
    /// fd rather than a path it reopens, so the fixtures have to as well.
    fn test_upload_handle() -> Arc<tokio::sync::Mutex<tokio::fs::File>> {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let handle = tokio::fs::File::from_std(file.reopen().expect("reopen temp file"));
        Arc::new(tokio::sync::Mutex::new(handle))
    }

    fn test_download(owner: TransferOwner, slot: OwnedSemaphorePermit) -> DownloadTransfer {
        DownloadTransfer {
            owner,
            restarts: 0,
            remote_path: "/home/user/secret.txt".into(),
            target: "/phone/secret.txt".into(),
            temporary: "/phone/.secret.part".into(),
            file: tokio::fs::File::from_std(tempfile::tempfile().unwrap()),
            next_seq: 0,
            written: 0,
            hasher: Hasher::new(),
            allow_outside_home: false,
            _slot: slot,
        }
    }

    fn test_transfers() -> Arc<ClientTransfers> {
        Arc::new(ClientTransfers {
            next_id: AtomicU64::new(1),
            slots: Arc::new(Semaphore::new(MAX_ACTIVE_FILE_TRANSFERS)),
            downloads: AsyncMutex::new(HashMap::new()),
            uploads: AsyncMutex::new(HashMap::new()),
        })
    }

    /// The regression that made "Disconnect" cosmetic: the session loop holds its
    /// own clone of `outbound`, so a closed outbound receiver never stopped it.
    /// The kill switch must fire from dropping the `Connection` alone.
    #[tokio::test]
    async fn dropping_the_connection_signals_its_session_loop_to_stop() {
        let (connection, mut link) = test_connection(1);
        let session_outbound = connection.outbound.clone(); // what session_loop keeps
        assert!(link
            .shutdown
            .try_recv()
            .is_err_and(|e| matches!(e, oneshot::error::TryRecvError::Empty)));

        drop(connection);

        // Outbound is still open (the loop's own clone keeps it alive) - proof
        // that only the explicit kill switch can end the link.
        assert!(!session_outbound.is_closed());
        assert!(link.shutdown.await.is_err());
        drop(link.outbound);
    }

    #[tokio::test]
    async fn disconnect_stops_the_session_loop_of_the_connection_it_took() {
        let (connection, link) = test_connection(4);
        let current = Arc::new(AsyncMutex::new(Some(connection)));

        let taken = current.lock().await.take().expect("connection installed");
        drop(taken);

        assert!(link.shutdown.await.is_err(), "session loop was not stopped");
    }

    #[tokio::test]
    async fn a_second_host_cannot_claim_another_hosts_transfers() {
        let transfers = test_transfers();
        let first = owner(1);
        let second = owner(2);
        let id = TransferId(1);
        let slot = transfers.slots.clone().try_acquire_owned().unwrap();
        transfers
            .downloads
            .lock()
            .await
            .insert(id, test_download(first, slot));

        // Host B naming host A's transfer id gets nothing - not the remote path,
        // not the destination, not the chance to supply its own bytes.
        assert!(take_owned_download(&transfers, id, second).await.is_none());
        assert!(transfers.downloads.lock().await.contains_key(&id));

        let claimed = take_owned_download(&transfers, id, first)
            .await
            .expect("the owning host still completes its own transfer");
        assert_eq!(claimed.remote_path, "/home/user/secret.txt");
    }

    /// A cross-host transfer can never progress again, so connecting elsewhere
    /// must release its slot and its `.part` file instead of parking it.
    #[tokio::test]
    async fn connecting_to_another_host_cancels_the_previous_hosts_transfers() {
        let transfers = test_transfers();
        let first = owner(5);
        let second = owner(6);
        let mine = TransferId(1);
        let theirs = TransferId(2);
        transfers.downloads.lock().await.insert(
            theirs,
            test_download(first, transfers.slots.clone().try_acquire_owned().unwrap()),
        );
        transfers.downloads.lock().await.insert(
            mine,
            test_download(second, transfers.slots.clone().try_acquire_owned().unwrap()),
        );
        let upload_cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        transfers.uploads.lock().await.insert(
            TransferId(3),
            UploadTransfer {
                owner: first,
                file: test_upload_handle(),
                remote_path: "/home/user/private.key".into(),
                size: 1,
                cancelled: upload_cancelled.clone(),
                epoch: Arc::new(AtomicU64::new(0)),
                _slot: Arc::new(transfers.slots.clone().try_acquire_owned().unwrap()),
            },
        );
        assert_eq!(transfers.slots.available_permits(), 1);

        let cancelled = take_transfers_not_owned_by(&transfers, second).await;

        assert_eq!(cancelled.len(), 2, "both of the old host's transfers end");
        assert!(cancelled
            .iter()
            .any(|(id, temp)| *id == theirs && temp.is_some()));
        // The upload's streaming task must stop pushing a locally chosen file.
        assert!(upload_cancelled.load(Ordering::Relaxed));
        // This host's own transfer survives untouched, and the slots came back.
        assert!(transfers.downloads.lock().await.contains_key(&mine));
        assert!(transfers.uploads.lock().await.is_empty());
        assert_eq!(transfers.slots.available_permits(), 3);
    }

    /// A host that answers every chunk with `FileRetry` must not accumulate
    /// concurrent readers of the same local file. Each retry claims the streaming
    /// slot; every earlier task sees a changed epoch and stops.
    #[tokio::test]
    async fn each_upload_retry_retires_the_stream_it_replaces() {
        let transfers = test_transfers();
        let upload = UploadTransfer {
            owner: owner(8),
            file: test_upload_handle(),
            remote_path: "/home/user/big.bin".into(),
            size: 1,
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            epoch: Arc::new(AtomicU64::new(0)),
            _slot: Arc::new(transfers.slots.clone().try_acquire_owned().unwrap()),
        };

        // What spawn_upload_range does when it claims the slot.
        let first = upload.epoch.fetch_add(1, Ordering::Relaxed) + 1;
        let second = upload.epoch.fetch_add(1, Ordering::Relaxed) + 1;
        let third = upload.epoch.fetch_add(1, Ordering::Relaxed) + 1;

        let live = upload.epoch.load(Ordering::Relaxed);
        assert_ne!(first, live, "the first stream must stand down");
        assert_ne!(second, live, "the second stream must stand down");
        assert_eq!(third, live, "only the newest retry keeps streaming");
    }

    #[tokio::test]
    async fn a_second_host_cannot_request_a_retry_of_another_hosts_upload() {
        let transfers = test_transfers();
        let first = owner(3);
        let id = TransferId(7);
        let slot = Arc::new(transfers.slots.clone().try_acquire_owned().unwrap());
        transfers.uploads.lock().await.insert(
            id,
            UploadTransfer {
                owner: first,
                file: test_upload_handle(),
                remote_path: "/home/user/private.key".into(),
                size: 1,
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                epoch: Arc::new(AtomicU64::new(0)),
                _slot: slot,
            },
        );

        assert!(take_owned_upload(&transfers, id, owner(4)).await.is_none());
        assert!(take_owned_upload(&transfers, id, first).await.is_some());
    }

    #[tokio::test]
    async fn stale_session_cannot_remove_new_connection() {
        let (new, mut link) = test_connection(2);
        let current = Arc::new(AsyncMutex::new(Some(new)));

        assert!(!remove_connection_if_current(&current, 1).await);
        assert!(current.lock().await.is_some());
        assert!(matches!(
            link.outbound.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        // The live generation's session loop must NOT have been told to stop.
        assert!(matches!(
            link.shutdown.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        assert!(remove_connection_if_current(&current, 2).await);
        assert!(current.lock().await.is_none());
        assert!(link.outbound.recv().await.is_none());
        assert!(link.shutdown.await.is_err());
    }

    #[test]
    fn host_nickname_is_folded_to_one_display_line() {
        assert_eq!(sanitize_host_nickname("  Work  Mac \n"), "Work Mac");
        assert_eq!(sanitize_host_nickname("desk\ttop\r\nrig"), "desk top rig");
        // Whitespace-only means "clear the nickname", not a blank label.
        assert_eq!(sanitize_host_nickname("   \n\t "), "");
    }

    #[test]
    fn overlong_host_nickname_is_capped_without_splitting_a_codepoint() {
        let capped = sanitize_host_nickname(&"é".repeat(MAX_HOST_NICKNAME_CHARS + 10));
        assert_eq!(capped.chars().count(), MAX_HOST_NICKNAME_CHARS);

        // A cap landing on the joining space must not leave a trailing one.
        let words = sanitize_host_nickname(&"ab ".repeat(MAX_HOST_NICKNAME_CHARS));
        assert!(words.chars().count() <= MAX_HOST_NICKNAME_CHARS);
        assert_eq!(words.trim_end(), words);
    }

    /// The default folder is a preference, and the host re-confines every `rel`
    /// regardless - but a value that could never resolve should be refused when
    /// it is SET, not stored and then surfaced as a puzzling refusal later.
    #[test]
    fn default_dir_refuses_what_the_host_could_never_accept() {
        // Normal relative paths, normalized to the wire's `a/b` form.
        assert_eq!(
            sanitize_default_dir("crates/host"),
            Ok("crates/host".into())
        );
        assert_eq!(
            sanitize_default_dir("  crates/host  "),
            Ok("crates/host".into())
        );
        assert_eq!(
            sanitize_default_dir("./crates/./host"),
            Ok("crates/host".into())
        );
        // Empty means "the workspace root", i.e. clear the setting.
        assert_eq!(sanitize_default_dir(""), Ok(String::new()));
        assert_eq!(sanitize_default_dir("   "), Ok(String::new()));

        // Traversal and absolute paths: refused, never resolved or clamped.
        assert!(sanitize_default_dir("../etc").is_err());
        assert!(sanitize_default_dir("crates/../../etc").is_err());
        assert!(sanitize_default_dir("/etc").is_err());
        // Control characters would corrupt the row and cannot name a real folder.
        assert!(sanitize_default_dir("crates\nhost").is_err());
        // Bounded before it reaches a file read on every `list_hosts`.
        assert!(sanitize_default_dir(&"a".repeat(MAX_DEFAULT_DIR_CHARS + 1)).is_err());
        assert!(sanitize_default_dir(&"a".repeat(MAX_DEFAULT_DIR_CHARS)).is_ok());
    }

    /// The root rides in the stored string, so a value written before v10 - which
    /// had no prefix and meant the workspace - must still decode. That IS the
    /// migration, and getting it wrong would silently move every existing default
    /// to a folder of the same name under home.
    #[test]
    fn a_pre_v10_default_folder_still_means_the_workspace() {
        assert_eq!(
            decode_default_dir("crates/host"),
            ("workspace".to_string(), "crates/host".to_string())
        );
        // Round-trips for both roots.
        for (root, rel) in [
            ("workspace", "crates/host"),
            ("home", "code/app"),
            ("home", ""),
        ] {
            assert_eq!(
                decode_default_dir(&encode_default_dir(root, rel)),
                (root.to_string(), rel.to_string())
            );
        }
        // A rel that itself contains a colon is not mistaken for a root prefix.
        assert_eq!(
            decode_default_dir("weird:folder"),
            ("workspace".to_string(), "weird:folder".to_string())
        );
        // An unknown prefix is treated as workspace-relative rather than dropped:
        // the host re-resolves anyway, so the worst case is a visible refusal.
        assert_eq!(
            decode_default_dir("mars:base"),
            ("workspace".to_string(), "mars:base".to_string())
        );
    }

    /// Root names are refused, never defaulted - a root nobody recognizes is not
    /// the workspace.
    #[test]
    fn unknown_terminal_roots_are_refused() {
        assert_eq!(
            terminal_root_from_str("workspace"),
            Ok(TerminalRoot::Workspace)
        );
        assert_eq!(terminal_root_from_str("home"), Ok(TerminalRoot::Home));
        assert!(terminal_root_from_str("/").is_err());
        assert!(terminal_root_from_str("Home").is_err(), "names are exact");
        assert!(terminal_root_from_str("").is_err());
        // And the names survive a round trip through the wire enum.
        for name in ["workspace", "home"] {
            assert_eq!(
                terminal_root_name(terminal_root_from_str(name).unwrap()),
                name
            );
        }
    }

    /// Its own file, for the reason the nickname has one: these maps are bare
    /// `HashMap<DeviceId, String>` on disk, so they cannot share without one
    /// concern's writes dropping the other's.
    #[test]
    fn default_dir_file_is_separate_from_the_label_files() {
        let dir = tempfile::tempdir().unwrap();
        let host = DeviceId([12; 16]);
        save_host_name(dir.path(), host, "laptop-hostname");

        let mut defaults = load_host_default_dirs(dir.path());
        defaults.insert(host, "crates/host".into());
        store_host_labels(&host_default_dirs_path(dir.path()), &defaults).unwrap();

        assert_eq!(
            load_host_default_dirs(dir.path())
                .get(&host)
                .map(String::as_str),
            Some("crates/host")
        );
        // The announced name survived the default-folder write, and vice versa.
        assert_eq!(
            load_host_names(dir.path()).get(&host).map(String::as_str),
            Some("laptop-hostname")
        );
        assert!(load_host_nicknames(dir.path()).is_empty());
    }

    #[test]
    fn host_nickname_file_is_separate_from_the_announced_name_file() {
        let dir = tempfile::tempdir().unwrap();
        let host = DeviceId([11; 16]);
        save_host_name(dir.path(), host, "laptop-hostname");

        let mut nicknames = HashMap::new();
        nicknames.insert(host, "Work Mac".to_string());
        store_host_labels(&host_nicknames_path(dir.path()), &nicknames).unwrap();

        // A later reconnect refreshes the announced name; the nickname survives
        // because it lives in its own map - the whole point of two files.
        save_host_name(dir.path(), host, "renamed-hostname");

        assert_eq!(
            load_host_names(dir.path()).get(&host).map(String::as_str),
            Some("renamed-hostname")
        );
        assert_eq!(
            load_host_nicknames(dir.path())
                .get(&host)
                .map(String::as_str),
            Some("Work Mac")
        );
    }

    #[test]
    fn emptying_a_label_map_deletes_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = host_nicknames_path(dir.path());
        let mut labels = HashMap::new();
        labels.insert(DeviceId([12; 16]), "Studio".to_string());
        store_host_labels(&path, &labels).unwrap();
        assert!(path.exists());

        labels.clear();
        store_host_labels(&path, &labels).unwrap();
        assert!(!path.exists());
        // Deleting an already-absent file is not an error (double removal).
        store_host_labels(&path, &labels).unwrap();
        assert!(load_host_labels(&path).is_empty());
    }

    #[tokio::test]
    async fn removing_saved_host_only_closes_that_hosts_connection() {
        let (connection, mut link) = test_connection(7);
        let peer = connection.peer_device_id;
        let current = Arc::new(AsyncMutex::new(Some(connection)));

        assert!(take_connection_for_peer(&current, DeviceId([9; 16]))
            .await
            .is_none());
        assert!(current.lock().await.is_some());
        assert!(matches!(
            link.shutdown.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(take_connection_for_peer(&current, peer).await.is_some());
        assert!(current.lock().await.is_none());
        assert!(link.outbound.recv().await.is_none());
        // Removing a saved host tears its link down, not just its state entry.
        assert!(link.shutdown.await.is_err());
    }
}
