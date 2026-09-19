//! iroh serve mode - the real host.
//!
//! Builds the endpoint, prints a `portty1:` pairing ticket + a 6-digit PIN, then
//! accepts phone connections, runs the pairing handshake, and drives the
//! SessionManager over the authenticated sealed channel.
//!
//! Concurrency model: each connection is `split()` into a reader task and a
//! writer. The reader feeds raw sealed-envelope bytes into the main loop; the
//! main loop owns the single `EnvelopeCipher` (it is intentionally not `Clone`)
//! and does all seal/open. Reading in its own task means `select!` in the main
//! loop can never cancel a frame read mid-way (which would corrupt framing).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use iroh::RelayMode;
use portty_protocol::{CommandOutcome, Frame, PermissionResolver, RequestKind, SessionId};
use portty_transport::{
    build_endpoint, confirm_server_handshake, encode_compact_ticket, encode_ticket, open_msg,
    run_server_handshake, seal_msg, DeviceId, EnvelopeCipher, HandshakeCommit, Identity,
    IrohTransport, IrohWriter, KeyedPairingRateLimiter, PairingSecret, PairingState, PeerStore,
    SealedEnvelope, ServerHandshake, SharedPairingState, SharedRateLimiter, ENROLLMENT_WINDOW,
};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::file_transfer::{Transfers, UploadCleanup};
use crate::pair_confirm::PairConfirm;
use crate::session::{AgentResume, ManagerEvent, SessionManager};

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Set when the host is detached (the default for bare `portty-host`, or explicit
/// `--detach`). After the first phone pairs we print a "connected" banner and
/// silence stdout so the backgrounded daemon stops writing to the terminal.
pub static DETACHED: AtomicBool = AtomicBool::new(false);
/// Guards the one-time stdout silencing (only the first pair triggers it).
static SILENCED: AtomicBool = AtomicBool::new(false);
/// Set by the authenticated local relay control path (`portty-host stop`). A
/// sticky bit plus `Notify` avoids losing a request that arrives just before a
/// serve loop begins polling [`shutdown_signal`].
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_NOTIFY: OnceLock<tokio::sync::Notify> = OnceLock::new();

pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    SHUTDOWN_NOTIFY
        .get_or_init(tokio::sync::Notify::new)
        .notify_waiters();
}

async fn local_shutdown_request() {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return;
        }
        let notified = SHUTDOWN_NOTIFY
            .get_or_init(tokio::sync::Notify::new)
            .notified();
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

/// Bounded depth of the outbound frame queue to a phone (see `handle_client`).
/// At the 1 MiB wire-frame ceiling this contributes at most ~16 MiB per
/// connection. Typical frames are a single PTY read (KiB); when the queue fills
/// the producer backpressures and lag recovery sends a fresh snapshot.
const OUT_QUEUE_FRAMES: usize = 16;
/// Bounded depth of the inbound (phone → host) raw-frame queue. Inbound is
/// human-paced input or 16 KiB file chunks, so eight slots are plenty and bound
/// worst-case raw payload storage to ~8 MiB per connection. Together the two
/// queues have a conservative ~24 MiB wire-sized ceiling per connection.
const IN_QUEUE_FRAMES: usize = 8;

/// A random token minted once per host process - it identifies this host
/// lifetime. It rides every `ScreenReset` and is echoed back in `OutputResume`;
/// a mismatch on resume means the host restarted since the phone last attached,
/// so the retained-delta path would replay onto an unrelated screen (session ids
/// restart from 1). On mismatch we force a full re-attach instead (gap #14).
static HOST_GENERATION: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
fn host_generation() -> u64 {
    *HOST_GENERATION.get_or_init(rand::random::<u64>)
}

/// Scrollback snapshots are split into Output frames of this size on attach /
/// lag-resync. Keeps every frame comfortably under MAX_FRAME_BYTES (1 MiB)
/// regardless of the configured scrollback cap (which may be up to 4 MiB).
const SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;

/// Max connections BEING SERVED at once. Every accepted connection spawns a
/// task; without a cap, a peer (or a flood of half-open dials) could spawn tasks
/// without limit. Excess connections are dropped.
const MAX_ACTIVE_CONNECTIONS: usize = 8;

/// Max connections in the HANDSHAKE phase at once, counted separately from the
/// serving budget above.
///
/// One pool for both phases meant eight half-open dials - none of them
/// authenticated, none of them costing the dialer anything - held every slot the
/// host had, and a real phone could not get in until they timed out. Staging is
/// now its own, larger pool, so exhausting it does not touch the capacity that
/// established phones occupy, and a staged connection graduates to a serving
/// permit only once it has actually authenticated.
const MAX_STAGING_CONNECTIONS: usize = 24;

/// Staging slots ONE source may hold at once. Relayed dials are keyed by the
/// dialer's endpoint id and direct ones by IP, so a single peer cannot fill the
/// staging pool on its own; it has to keep minting fresh identities to try.
const MAX_STAGING_PER_SOURCE: usize = 2;

/// A connection that doesn't complete its handshake within this deadline is
/// dropped, so a stalled or malicious dialer can't hold a slot open forever.
/// Ten seconds is generous for a QUIC handshake plus the first stream; the old
/// thirty meant one stalled dial squatted a slot for half a minute.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How many staged handshakes each source currently holds.
///
/// Deliberately a plain counter rather than a rate limiter: this bounds
/// CONCURRENCY, which is the resource being exhausted. A source that dials
/// repeatedly but sequentially is not a problem and is not throttled here (the
/// pairing rate limiter covers guessing).
#[derive(Clone, Default)]
struct StagingGate {
    in_flight: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
}

/// Releases its source's staging slot on drop, however the task ends.
struct StagingSlot {
    gate: StagingGate,
    key: String,
}

impl StagingGate {
    /// Claim a staging slot for `key`, or `None` if that source already holds
    /// `max`. A poisoned lock denies (fail closed).
    fn try_enter(&self, key: String, max: usize) -> Option<StagingSlot> {
        let mut in_flight = self.in_flight.lock().ok()?;
        let count = in_flight.entry(key.clone()).or_insert(0);
        if *count >= max {
            // Do not leave a zero entry behind for a source that never got in.
            if *count == 0 {
                in_flight.remove(&key);
            }
            return None;
        }
        *count += 1;
        drop(in_flight);
        Some(StagingSlot {
            gate: self.clone(),
            key,
        })
    }

    #[cfg(test)]
    fn tracked_sources(&self) -> usize {
        self.in_flight.lock().map(|map| map.len()).unwrap_or(0)
    }
}

impl Drop for StagingSlot {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.gate.in_flight.lock() {
            if let Some(count) = in_flight.get_mut(&self.key) {
                *count = count.saturating_sub(1);
                // Remove empties, or the map would grow once per distinct dialer.
                if *count == 0 {
                    in_flight.remove(&self.key);
                }
            }
        }
    }
}

/// Staging slots held back for dialers that LOOK like an already-paired device.
///
/// Filling the general staging pool is cheap - endpoint ids are free to mint - so
/// without a reserve a flood could still keep real phones from ever reaching the
/// handshake. Four is enough for a household's phones to get in while a flood is
/// running.
const STAGING_RESERVE_FOR_KNOWN_PEERS: usize = 4;

/// Does this dial come from an endpoint id we already hold a pairing for?
///
/// A RELAY-AUTHENTICATED capacity hint, never Portty authorization.
///
/// For a relayed dial the id is not merely self-asserted: iroh-relay's handshake
/// makes the client sign a server challenge (or exported TLS keying material) with
/// the secret key matching the `EndpointId` it connects under, so reaching this
/// point under a paired phone's id means possessing that phone's key. It is still
/// not PORTTY authentication - no PIN or resumption token has been proved yet - so
/// it decides nothing but which capacity pool the dial may draw from. Direct dials
/// carry no id at this stage and never look known.
fn dial_claims_known_peer(addr: &iroh::endpoint::IncomingAddr, known: &[DeviceId]) -> bool {
    let iroh::endpoint::IncomingAddr::Relay { endpoint_id, .. } = addr else {
        return false;
    };
    portty_transport::device_id_from_node_id(*endpoint_id)
        .is_ok_and(|device| known.contains(&device))
}

/// Bucket an inbound dial by who it came from, before any authentication.
///
/// A relayed dial already names the dialer's endpoint id, which is the strongest
/// pre-handshake signal available (minting a new one is cheap, but each costs a
/// fresh relay connection). Direct dials fall back to source IP. Neither is
/// trusted for authorization - only for spreading the staging budget.
fn staging_source_key(addr: &iroh::endpoint::IncomingAddr) -> String {
    match addr {
        iroh::endpoint::IncomingAddr::Ip(socket) => format!("ip:{}", socket.ip()),
        iroh::endpoint::IncomingAddr::Relay { endpoint_id, .. } => format!("node:{endpoint_id}"),
        other => format!("other:{other:?}"),
    }
}

/// Resolves when the process is asked to stop, by EITHER an OS signal
/// (SIGTERM/SIGINT on Unix; Ctrl-C where a console exists) OR an authenticated
/// local `portty-host stop`, delivered over the control pipe ([`request_shutdown`]).
/// The control-pipe arm is what makes a graceful stop possible on Windows: a
/// detached background daemon runs with no console (DETACHED_PROCESS |
/// CREATE_NO_WINDOW), so its Ctrl-C arm can never fire (#63) - `portty-host stop`
/// (a named-pipe control message, no console or signal needed) is its graceful
/// path. The serve loops race this so shutdown is GRACEFUL: the future returns,
/// `run_mode` returns, and RAII guards run - the PID file is removed and the
/// keep-awake child (`caffeinate`) is killed. A hard kill would skip all of that.
pub async fn shutdown_signal() {
    tokio::select! {
        _ = os_shutdown_signal() => {}
        _ = local_shutdown_request() => info!("authenticated local shutdown requested"),
    }
}

async fn os_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "could not install SIGTERM handler");
                return std::future::pending().await;
            }
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "could not install SIGINT handler");
                return std::future::pending().await;
            }
        };
        tokio::select! {
            _ = term.recv() => info!("SIGTERM received; shutting down"),
            _ = int.recv() => info!("SIGINT received; shutting down"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("Ctrl-C received; shutting down");
    }
}

/// Double-fork + setsid so the daemon keeps running after the launching shell
/// returns. Called from `main` BEFORE the tokio runtime starts (fork after the
/// runtime's threads exist is unsound). The parent exits inside here - only the
/// backgrounded grandchild returns. stdin is redirected to /dev/null; stdout and
/// stderr are DELIBERATELY kept on the inherited terminal so the QR + PIN are
/// still visible for first-pair. They're silenced later (see [`silence_stdout`]).
#[cfg(unix)]
pub fn daemonize() -> crate::error::HostResult<()> {
    // SAFETY: standard daemonization dance; we only call async-signal-safe libc
    // fns between fork and the point where the child resumes normal execution.
    unsafe {
        match libc::fork() {
            -1 => return Err(crate::error::HostError::Io(std::io::Error::last_os_error())),
            0 => {}                     // child: continue
            _ => std::process::exit(0), // parent: free the shell prompt
        }
        if libc::setsid() == -1 {
            return Err(crate::error::HostError::Io(std::io::Error::last_os_error()));
        }
        // Second fork so the daemon can never reacquire a controlling terminal.
        match libc::fork() {
            -1 => return Err(crate::error::HostError::Io(std::io::Error::last_os_error())),
            0 => {}
            _ => std::process::exit(0),
        }
        // Background process: detach stdin. Keep stdout/stderr on the terminal.
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            if devnull > libc::STDERR_FILENO {
                libc::close(devnull);
            }
        }
    }
    Ok(())
}

/// Redirect stdout+stderr to /dev/null so a detached daemon stops logging to the
/// terminal it handed back. Called once, right after the "connected" banner.
#[cfg(unix)]
fn silence_stdout() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // SAFETY: dup2/open/close on well-known fds; the banner is already flushed.
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            if devnull > libc::STDERR_FILENO {
                libc::close(devnull);
            }
        }
    }
}

/// Print the "✓ phone connected" banner when a phone finishes pairing. In
/// detached mode this is also where we let go of the terminal: after the
/// banner, stdout/stderr are silenced so the backgrounded daemon goes quiet.
pub fn notify_phone_connected(name: impl std::fmt::Display) {
    use std::io::Write;
    println!();
    println!("  ✓ phone connected - {name}");
    if DETACHED.load(Ordering::Relaxed) {
        println!("  Portty is running in the background - you can close or reuse this terminal.");
        println!("  Run `portty share` in any terminal to share it; `portty-host peers` to manage devices.");
        let _ = std::io::stdout().flush();
        if !SILENCED.swap(true, Ordering::SeqCst) {
            #[cfg(unix)]
            silence_stdout();
        }
    } else {
        let _ = std::io::stdout().flush();
    }
}

/// A shared, persisted map of per-peer reconnect tokens. Loaded once at startup;
/// mutated (rotated) after each successful handshake.
type SharedPeers = Arc<AsyncMutex<PeerStore>>;

/// Host-wide pairing gating state shared across every accepted connection (the
/// brute-force hardening lifted from Corvux). Cloned cheaply - all `Arc`/`Clone`
/// handles - into each per-connection task.
///
/// - `creds`: a 128-bit QR/full-ticket secret plus a separate 32-bit manual
///   phrase, both minted per serve session and folded into first-pair proofs.
/// - `window`: time-boxed first-pair enrollment window + source-independent
///   global failure cap. First-pair is refused entirely outside the window, and
///   fresh-NodeId spraying trips the cap inside it. Reconnects are never gated.
/// - `limiter`: the per-source exponential-backoff limiter, shared so backoff
///   spans every connection (not a fresh counter per handshake).
#[derive(Clone)]
pub struct PairingGuard {
    /// Live pairing credentials AND the enrollment window, behind ONE lock -
    /// swappable at runtime by `portty pair`, snapshotted per-connection by the
    /// accept path (so a reopen takes effect instantly).
    ///
    /// They used to be two independent mutexes, which is exactly what let a
    /// connection hold one generation's secret and the next generation's
    /// enrollment epoch. See `PairingState`.
    state: SharedPairingState,
    limiter: SharedRateLimiter,
    /// Where a FIRST pair goes to be confirmed by a human before it is
    /// committed. Shared so every console - the foreground stdin reader and any
    /// connected `portty pair` - can answer for the whole host.
    confirm: PairConfirm,
}

/// Everything `portty pair` needs to re-arm pairing at runtime. Each reopen
/// MINTS fresh ticket/manual secrets + PIN (the startup banner's pair becomes
/// invalid), re-encodes the ticket/QR, and reopens the enrollment window.
pub struct PairingReopen {
    /// Address snapshot for re-encoding tickets (same lifetime as the banner's).
    addr: iroh::EndpointAddr,
    state: SharedPairingState,
    /// So a connected `portty pair` can attach itself as the console that
    /// confirms the comparison code - the only approval channel a daemonised
    /// host has, since it owns no terminal.
    confirm: PairConfirm,
}

impl PairingReopen {
    /// The host-wide confirmation broker, for a CLI session that wants to act as
    /// the approval console while it is connected.
    pub fn confirm(&self) -> &PairConfirm {
        &self.confirm
    }
}

/// What a reopen hands back for the CLI to print.
///
/// There is no PIN here any more. The ticket/QR/phrase each carry the whole
/// first-pair credential, and the human step is the comparison code confirmed
/// after the exchange (see `crate::pair_confirm`).
pub struct FreshPairing {
    pub ticket: String,
    pub qr: String,
    pub phrase: String,
    pub window_secs: u64,
}

impl PairingReopen {
    /// Mint fresh credentials, arm them for the accept path, reopen the
    /// first-pair window, and return everything the CLI needs to print.
    pub fn reopen(&self) -> crate::error::HostResult<FreshPairing> {
        let ticket_secret = PairingSecret::generate_ticket();
        let manual_secret = PairingSecret::generate_manual();
        let ticket = encode_ticket(&self.addr, Some(&ticket_secret))?;
        let qr = encode_compact_ticket(&self.addr, &ticket_secret)?;
        let phrase = manual_secret
            .to_phrase()
            .expect("a manual pairing secret always has a phrase");
        // One step, one lock: a connection can never observe the new window with
        // the old secret, or the reverse.
        self.state
            .lock()
            .unwrap()
            .rotate(vec![ticket_secret, manual_secret], ENROLLMENT_WINDOW);
        Ok(FreshPairing {
            ticket,
            qr,
            phrase,
            window_secs: ENROLLMENT_WINDOW.as_secs(),
        })
    }
}

/// The folder new shells open in - the Portty "workspace". `PORTTY_WORKSPACE`
/// (if set and a real directory) wins; otherwise the directory the host was
/// launched from. This must be explicit: portable_pty spawns a PTY with no cwd
/// in the user's HOME dir (%USERPROFILE% on Windows), so without this the phone
/// terminal opens at "root" instead of the project you're working in.
pub fn workspace_dir() -> PathBuf {
    if let Ok(p) = std::env::var("PORTTY_WORKSPACE") {
        if Path::new(&p).is_dir() {
            return PathBuf::from(p);
        }
        warn!("PORTTY_WORKSPACE={p:?} is not a directory - falling back to the launch dir");
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// A host that starts with pairing CLOSED and no credential in existence.
///
/// Startup used to mint a ticket + phrase, open the five-minute enrollment
/// window, and print all of it to stdout. Every restart therefore wrote a fresh,
/// complete key to this machine into whatever captures stdout - journald under
/// systemd, `~/Library/Logs` under launchd, a per-user file on Windows - and
/// opened a window for it, whether or not any device was already paired. A log
/// reader, or a compromised log shipper, only had to watch for a restart.
///
/// So: no secret exists until someone runs `portty pair`. That is a deliberate,
/// same-user, authenticated act over the local relay socket, it prints to that
/// operator's terminal instead of to a log, and it is also the session that
/// confirms the resulting comparison code. Nothing about an unattended restart
/// can enrol a device.
///
/// [`PairingState::new`] with no secrets is fail-closed twice over: the window
/// is shut, AND the handshake refuses a first pair against a host with no armed
/// secret even if something reopened the window.
fn closed_pairing_guard() -> (SharedPairingState, PairingGuard) {
    let state: SharedPairingState = Arc::new(std::sync::Mutex::new(PairingState::new(Vec::new())));
    let guard = PairingGuard {
        state: state.clone(),
        limiter: Arc::new(Mutex::new(KeyedPairingRateLimiter::new())),
        confirm: PairConfirm::new(),
    };
    (state, guard)
}

/// Run the host over iroh. `seed_sessions` shells are spawned on startup so a
/// freshly-paired phone sees something immediately.
pub async fn serve(identity_dir: &Path, seed_sessions: usize) -> crate::error::HostResult<()> {
    // Hold a keep-awake inhibitor for the whole serve lifetime so a laptop host
    // doesn't idle-sleep while waiting for the phone to reach it (D1 fix).
    let _keep = crate::keepalive::KeepAwake::activate();
    let (mgr, endpoint, did, peers, guard, pairing) = setup(identity_dir, seed_sessions).await?;
    // Accept `portty share` relays so adopted terminals reach the phone too,
    // and `portty pair` requests to re-arm the enrollment window.
    let active = crate::active::ActiveDevices::new(identity_dir);
    let push_ctx = crate::push::configured(identity_dir);
    let (upload_cleanup, stale_uploads_removed) = UploadCleanup::open(identity_dir)?;
    if stale_uploads_removed > 0 {
        info!(
            stale_uploads_removed,
            "removed stale upload temporary files"
        );
    }
    crate::relay_pipe::spawn(
        mgr.clone(),
        Some(pairing),
        Some(peers.clone()),
        Some(active.clone()),
        push_ctx.clone(),
    );
    // Race the accept loop against a shutdown signal so `serve` RETURNS on
    // SIGTERM/SIGINT - letting the caller's RAII guards (PID file, keep-awake)
    // clean up instead of the process being killed mid-flight.
    tokio::select! {
        _ = accept_loop(endpoint.clone(), mgr, did, peers, guard, identity_dir.to_path_buf(), active, push_ctx, upload_cleanup) => {}
        _ = shutdown_signal() => {}
    }
    endpoint.close().await;
    Ok(())
}

/// Build the identity + iroh endpoint, print the pairing ticket + PIN, and seed
/// `seed_sessions` shells. Returns the shared session manager, the endpoint
/// (the caller must keep it alive for the connection lifetime), the handshake
/// inputs, the persisted peer/token store, and the host-wide [`PairingGuard`]
/// (brute-force hardening). Split out so a host can serve the same shells to a
/// local browser AND a phone concurrently ("both" mode).
pub async fn setup(
    identity_dir: &Path,
    seed_sessions: usize,
) -> crate::error::HostResult<(
    SessionManager,
    iroh::Endpoint,
    DeviceId,
    SharedPeers,
    PairingGuard,
    Arc<PairingReopen>,
)> {
    if let Err(error) = crate::session::prune_acp_event_logs(identity_dir) {
        warn!(%error, "could not prune stale ACP event logs");
    }
    let identity = Identity::load_or_create(identity_dir)?;
    let endpoint = build_endpoint(&identity, RelayMode::Default).await?;
    let mgr = SessionManager::new_with_cap(crate::session::scrollback_cap_from_env());
    let peers = Arc::new(AsyncMutex::new(PeerStore::load(identity_dir)?));

    // Open seed shells IN the workspace folder. Without an explicit cwd,
    // portable_pty falls back to the user's home dir (%USERPROFILE% on Windows)
    // - which is why terminals used to open at "root" instead of the project.
    let workspace = workspace_dir();
    for i in 1..=seed_sessions {
        mgr.spawn_shell(Some(workspace.clone()), Some(format!("session {i}")))
            .await?;
    }

    // Give iroh a moment to register its relay URL before snapshotting the addr.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Startup arms NOTHING and prints NO pairing material. See
    // `closed_pairing_guard` for why; `portty pair` is the only thing that mints
    // a credential, opens the window, and can confirm the result.
    let (pairing_state, guard) = closed_pairing_guard();

    let paired_devices = peers.lock().await.len();
    println!();
    println!("==========================================================");
    println!("  Portty host ready  (device {})", identity.device_id());
    println!("  Workspace (terminals open here): {}", workspace.display());
    // The workspace is also the ACP file sandbox root. Confining to the home
    // directory confines to nothing that matters, and the phone then refuses to
    // auto-approve reads at all - so say why here rather than letting it look
    // like the approval policy is broken.
    if crate::workspace::workspace_scope(&workspace) == portty_protocol::WorkspaceScope::Broad {
        println!();
        println!("  ! This workspace is your home directory (or wider), so it is");
        println!("    also the folder an agent may read ANY file inside. Reads");
        println!("    will need a tap every time until you narrow it:");
        println!("      PORTTY_WORKSPACE=/path/to/your/project portty-host");
        warn!(
            workspace = %workspace.display(),
            "workspace root is the home directory or wider; agent reads will always prompt"
        );
    }
    println!("----------------------------------------------------------");
    if paired_devices == 0 {
        println!("  No devices are paired yet.");
    } else {
        println!("  Paired devices: {paired_devices} (they reconnect on their own).");
    }
    println!();
    println!("  Pairing is CLOSED. To add a phone, run this on this machine:");
    println!();
    println!("      portty pair");
    println!();
    println!("  That prints a QR, waits for the phone, and asks you to confirm");
    println!("  the 6-digit code it shows. Nothing here is a credential, so");
    println!("  this output is safe to leave in a service log.");
    println!("==========================================================");
    println!();

    info!(
        sessions = seed_sessions,
        paired_devices, "portty host serving; pairing closed until `portty pair`"
    );

    let pairing = Arc::new(PairingReopen {
        addr: endpoint.addr(),
        state: pairing_state,
        confirm: guard.confirm.clone(),
    });
    Ok((mgr, endpoint, identity.device_id(), peers, guard, pairing))
}
/// This machine's human name, sent in the handshake Hello so the phone's host
/// picker can show "Example-MacBook-Air" instead of a hex id. Falls back
/// to "host" when the OS won't say.
fn host_display_name() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes a NUL-terminated name into the buffer.
        if unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } == 0 {
            if let Some(end) = buf.iter().position(|&b| b == 0) {
                if let Ok(s) = std::str::from_utf8(&buf[..end]) {
                    let s = s.trim().trim_end_matches(".local");
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(n) = std::env::var("COMPUTERNAME") {
            if !n.trim().is_empty() {
                return n;
            }
        }
    }
    "host".into()
}

/// Accept phone connections forever: handshake each, then drive its session
/// over the sealed channel. Runs until the process is killed.
///
/// `identity_dir` is the on-disk PeerStore location. Each connection reloads the
/// store from disk before checking tokens, so an external `portty-host revoke`
/// (which edits that file) takes effect on the phone's NEXT reconnect - **instant
/// revoke without a restart**. The in-memory `peers` cache is just a write
/// buffer; the file is the source of truth.
///
/// `guard` carries the host-wide brute-force hardening (one-time ticket secret +
/// enrollment window + shared rate limiter); it's cloned cheaply into each
/// per-connection task so a fresh-NodeId sprayer can't brute-force the PIN.
// Explicit runtime handles make ownership and security boundaries visible at
// this orchestration seam; bundling them would only hide which state is shared.
#[allow(clippy::too_many_arguments)]
pub async fn accept_loop(
    endpoint: iroh::Endpoint,
    mgr: SessionManager,
    did: DeviceId,
    peers: SharedPeers,
    guard: PairingGuard,
    identity_dir: PathBuf,
    active: crate::active::ActiveDevices,
    push_ctx: Option<crate::push::PushCtx>,
    upload_cleanup: UploadCleanup,
) {
    // Two admission pools. A staged connection holds only a staging permit while
    // it handshakes, and takes a serving permit once it has authenticated - so a
    // flood of unauthenticated dials can exhaust staging without touching the
    // capacity real phones hold. Both permits release on drop; excess dials are
    // refused, not queued.
    let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    let staging_sem = Arc::new(tokio::sync::Semaphore::new(MAX_STAGING_CONNECTIONS));
    let known_staging_sem = Arc::new(tokio::sync::Semaphore::new(STAGING_RESERVE_FOR_KNOWN_PEERS));
    let staging_gate = StagingGate::default();
    let connected_phones = Arc::new(AtomicUsize::new(0));

    // Optional blind doorbell. The watcher deliberately ignores every field of
    // the approval event; the wake body carries only a random host pseudonym.
    // The relay/network still observes transport metadata documented in
    // PUSH-SETUP.md. The ACP request itself remains queued in SessionManager.
    // `PushCtx` also owns the persisted device registrations, which the
    // per-connection `Frame::PushRegister` handler feeds.
    if let Some(ctx) = push_ctx.clone() {
        crate::push::spawn_doorbell(mgr.clone(), ctx, connected_phones.clone());
    }

    // Watcher: reload the peer store periodically and abort any live connection
    // whose token was revoked on disk, so `portty-host revoke` takes effect NOW
    // instead of only on the phone's next reconnect.
    {
        let active = active.clone();
        let peers = peers.clone();
        let identity_dir = identity_dir.clone();
        tokio::spawn(async move {
            let period = std::time::Duration::from_secs(crate::active::REVOKE_POLL_SECS);
            loop {
                tokio::time::sleep(period).await;
                let tokens = {
                    let mut store = peers.lock().await;
                    let fresh = match PeerStore::load(&identity_dir) {
                        Ok(fresh) => fresh,
                        Err(e) => {
                            warn!(error = %e, "revoke watcher could not securely reload peer store");
                            continue;
                        }
                    };
                    *store = fresh;
                    store.tokens()
                };
                let dropped = active.drop_revoked(&tokens).await;
                if dropped > 0 {
                    info!(dropped, "revoke watcher closed revoked live connection(s)");
                }
            }
        });
    }

    loop {
        let incoming = match endpoint.accept().await {
            Some(i) => i,
            None => break,
        };
        // Spread the staging budget across sources FIRST: this is the only check
        // that can look at who is dialing before spending anything on them.
        let source = staging_source_key(&incoming.remote_addr());
        let Some(staging_slot) = staging_gate.try_enter(source.clone(), MAX_STAGING_PER_SOURCE)
        else {
            warn!(
                %source,
                max = MAX_STAGING_PER_SOURCE,
                "source already has the most half-open dials it may hold; refusing"
            );
            incoming.refuse();
            continue;
        };
        // Reserve before awaiting the QUIC handshake. Awaiting `incoming` in the
        // accept loop lets one half-open dial block every later peer and bypasses
        // the cap entirely.
        let staging_permit = match staging_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            // General pool full. A dialer claiming an id we are already paired
            // with may draw from the small reserve instead, so a flood of fresh
            // identities cannot keep this household's phones out.
            Err(_) => {
                let known = { peers.lock().await.known_devices() };
                let looks_known = dial_claims_known_peer(&incoming.remote_addr(), &known);
                match known_staging_sem
                    .clone()
                    .try_acquire_owned()
                    .ok()
                    .filter(|_| looks_known)
                {
                    Some(p) => p,
                    None => {
                        warn!(
                            max = MAX_STAGING_CONNECTIONS,
                            %source,
                            looks_known,
                            "handshake capacity reached; refusing incoming connection"
                        );
                        incoming.refuse();
                        continue;
                    }
                }
            }
        };
        let conn_sem = conn_sem.clone();
        let mgr = mgr.clone();
        let peers = peers.clone();
        let guard = guard.clone();
        let identity_dir = identity_dir.clone();
        let active = active.clone();
        let connected_phones = connected_phones.clone();
        let push_ctx = push_ctx.clone();
        let upload_cleanup = upload_cleanup.clone();
        tokio::spawn(async move {
            // Staging capacity is held only until this connection has proved who
            // it is. Both are dropped when the task ends, whichever way it ends.
            let mut staging_permit = Some(staging_permit);
            let mut staging_slot = Some(staging_slot);
            let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    warn!("incoming connection failed: {e:?}");
                    return;
                }
                Err(_) => {
                    warn!("incoming QUIC handshake timed out");
                    return;
                }
            };
            // Bound the accept_bi wait too (not just the handshake): a peer that
            // opens a QUIC connection but never opens a stream would otherwise
            // hold a permit forever and, with enough such peers, exhaust them.
            let mut tport =
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, IrohTransport::accept(conn)).await {
                    Ok(Ok(t)) => t,
                    Ok(Err(e)) => {
                        error!("accept_bi: {e}");
                        return;
                    }
                    Err(_) => {
                        warn!("accept_bi timed out; dropping connection");
                        return;
                    }
                };
            // The QUIC handshake authenticates the peer's NodeId; derive the
            // DeviceId it MUST match. Used as the per-peer rate-limit key (so one
            // attacker can't back off everyone via the shared empty key) and, after
            // the handshake, to reject a Hello that claims a different identity.
            let authed_node_id = tport.peer_node_id();
            let authed_device_id = match portty_transport::device_id_from_node_id(authed_node_id) {
                Ok(d) => d,
                Err(e) => {
                    warn!("could not derive DeviceId from NodeId: {e}");
                    return;
                }
            };
            // NOTE: the serving permit is deliberately NOT taken here. A completed
            // QUIC handshake only proves the dialer owns some NodeId, which anyone
            // can mint for free - it says nothing about being PAIRED. Taking a
            // serving slot at this point let eight unpaired peers hold the whole
            // serving budget through the pairing handshake and lock real phones
            // out. The permit is acquired below, once Portty's own handshake has
            // authenticated the peer by PIN or resumption token; until then this
            // connection is still charged to the staging pool, which is per-source
            // bounded and shorter-lived.
            //
            // Reload the peer store from disk so a `portty-host revoke` that ran
            // since startup is honored NOW (the revoked token is gone from the
            // file). Cheap: a tiny postcard read, once per connection.
            let (tokens, observed_revocation) = {
                let mut store = peers.lock().await;
                let fresh = match PeerStore::load(&identity_dir) {
                    Ok(fresh) => fresh,
                    Err(e) => {
                        warn!(error = %e, "rejecting connection: could not securely reload peer store");
                        return;
                    }
                };
                *store = fresh;
                (store.tokens(), store.revocation_marker(&authed_device_id))
            };
            // The exact credential this handshake may authenticate against, kept
            // aside before `tokens` is handed to the handshake. A resume commits
            // only while this is still the token on record, so two concurrent
            // resumes cannot each rotate away the other's result.
            let observed_token = tokens.get(&authed_device_id).cloned();
            // SEC-2: inject the reconnect tokens we hold so a known phone resumes
            // by token instead of re-proving the human PIN. The guard wires in
            // the brute-force hardening: shared limiter (backoff spans all
            // connections), enrollment window (first-pair only while open), and
            // the ticket secret (PIN proof can't be guessed without the ticket).
            // Read the LIVE credentials - `portty pair` may have rotated them since
            // startup - together with the enrollment generation they belong to, in
            // ONE lock. The generation travels with them into the handshake, so a
            // rotation that lands mid-connection retires this attempt instead of
            // letting its old QR/PIN enrol against the new opportunity.
            let snapshot = guard.state.lock().unwrap().snapshot();
            let mut hs = ServerHandshake::new(did, host_display_name())
                .with_resumption_tokens(tokens)
                .with_shared_rate_limiter(guard.limiter.clone())
                .with_rate_limit_key(authed_node_id.to_string())
                .with_first_pair(guard.state.clone(), snapshot)
                .with_authenticated_device(authed_device_id, observed_revocation.is_some());
            let outcome = match tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                run_server_handshake(&mut tport, &mut hs),
            )
            .await
            {
                Ok(Ok(o)) => o,
                Ok(Err(e)) => {
                    error!("handshake failed: {e}");
                    return;
                }
                Err(_) => {
                    warn!("handshake timed out; dropping connection");
                    return;
                }
            };
            // Bind the claimed identity to the authenticated transport identity:
            // the Hello's DeviceId MUST equal the one derived from the QUIC-
            // authenticated NodeId. Otherwise a peer could claim another device's
            // id (weakening revocation, rate-limit tracking, and active-device
            // attribution). iroh authenticates the NodeId, so this can't be forged.
            if outcome.peer_device_id != authed_device_id {
                warn!(
                    claimed = %outcome.peer_device_id,
                    authenticated = %authed_device_id,
                    "rejecting connection: Hello device_id does not match authenticated NodeId"
                );
                return;
            }
            // ── Finalization order matters, and this is the order ──────────────
            //
            // The phone has NOT been told anything succeeded yet (see
            // `confirm_server_handshake`). Everything from here to that call is
            // abandonable: if we bail, the phone stores no token and treats the
            // attempt as failed, which is recoverable. So all the ways this can
            // fail come first, and the acknowledgement comes last.
            //
            //   1. take a serving slot        - can fail, nothing consumed yet
            //   2. get a human to confirm     - first pair only; can fail
            //   3. claim the enrollment slot  - atomic, exactly one winner
            //   4. persist the rotated token  - can fail
            //   5. tell the phone             - only now, and it cannot fail us
            //
            // The human confirmation sits BEFORE the enrollment claim on purpose.
            // A rejected or unanswered pair must leave the window intact, so the
            // legitimate phone can still pair inside it; burning the window on a
            // refusal would let anyone who reaches the endpoint deny the pairing
            // the user actually wants.
            //
            // Graduating here (not at the QUIC handshake) is deliberate: a
            // completed QUIC handshake only proves the dialer owns some NodeId,
            // which is free to mint. This is the first point where the peer is
            // known to be PAIRED and to be the device it claims.
            let _serving_permit = match conn_sem.try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!(
                        max = MAX_ACTIVE_CONNECTIONS,
                        peer = %outcome.peer_device_id,
                        "connection limit reached; dropping authenticated connection \
                         before acknowledging it"
                    );
                    return;
                }
            };
            // Staging capacity goes back now - this connection is past the phase
            // that pool exists to bound.
            staging_permit.take();
            staging_slot.take();
            // FIRST PAIR ONLY: a human at the host must confirm that the phone is
            // showing the same comparison code.
            //
            // The out-of-band secret already authenticated this exchange, so this
            // is the second line, not the first: it is what stops a credential
            // that LEAKED - a photographed QR, an overheard phrase - from turning
            // into a paired device without anyone noticing. The code comes from
            // the finished session, so a peer in the middle cannot make the two
            // screens agree.
            //
            // Gated on `!resumed`, NOT on `enrollment_epoch.is_some()`.
            //
            // They look interchangeable and are not: the B4 enrollment exemption
            // produces a FIRST pair with no epoch, so keying on the epoch would
            // let an exempt device skip confirmation entirely. Nothing sets that
            // exemption in production today, which is exactly why the wrong
            // condition would have gone unnoticed until it did. `resumed` is the
            // real question - did an existing rotating token authenticate this,
            // or is a new device being enrolled?
            if !outcome.resumed
                && !guard
                    .confirm
                    .confirm(
                        outcome.peer_device_id,
                        &outcome.peer_display_name,
                        &outcome.verification_code,
                    )
                    .await
            {
                warn!(
                    peer = %outcome.peer_device_id,
                    "refusing first pair: not confirmed at the host"
                );
                return;
            }
            // Claim the one-time enrollment opportunity, if this was a first pair.
            // Atomic: concurrent proofs against the same ticket all reach here, and
            // exactly one claim succeeds. The losers stop before persisting or
            // acknowledging anything, so only one device is ever enrolled.
            if let Some(epoch) = outcome.enrollment_epoch {
                let claimed = guard
                    .state
                    .lock()
                    .map(|mut state| state.consume_first_pair(epoch))
                    .unwrap_or(false);
                if !claimed {
                    warn!(
                        peer = %outcome.peer_device_id,
                        "refusing first pair: the enrollment window was already used \
                         or reopened while this handshake ran"
                    );
                    return;
                }
            }
            // Persist token rotation + pair-generation state under the exact
            // revocation marker observed before the handshake. A concurrent
            // revoke changes that marker and MUST win; never start an authorized
            // session after a failed commit.
            let pair_id = match peers.lock().await.commit_handshake(
                outcome.peer_device_id,
                HandshakeCommit {
                    ticket: None,
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
                    warn!(peer = %outcome.peer_device_id, error = %e, "rejecting completed handshake: pair state changed or could not be persisted");
                    return;
                }
            };
            // Step 4: the pairing is durable, so it is finally safe to tell the
            // phone. Before this point the phone has stored nothing; after it, both
            // sides agree on the same rotated token.
            if let Err(e) = confirm_server_handshake(&mut tport, &hs).await {
                // One message cannot make two machines agree, so this picks WHICH
                // way to be wrong. The commit already landed, so the host now holds
                // the rotated token while the phone kept its old one; the phone's
                // next reconnect is refused and the user has to run `portty pair`.
                //
                // That is deliberate, and it is the better direction. The reverse -
                // acknowledging first - left the PHONE holding a credential the host
                // had never stored, with the enrollment window already spent, which
                // is the same dead end plus no signal about why.
                //
                // Not rolled back on purpose: a send error can arrive after the
                // bytes actually reached the phone, and restoring the old token then
                // would put us in the worse direction. Accepting one honest failure
                // beats guessing. (A one-reconnect grace period on the previous
                // token would remove this cliff; it needs peer-store support.)
                warn!(peer = %outcome.peer_device_id, error = %e, "paired but could not acknowledge the phone; it must re-pair with `portty pair`");
                return;
            }
            info!(peer = %outcome.peer_device_id, name = %outcome.peer_display_name, "phone paired");
            notify_phone_connected(&outcome.peer_display_name);
            // Run the session as a child task so we hold an AbortHandle for it:
            // the revocation watcher aborts it to drop a revoked phone instantly.
            let device_id = outcome.peer_device_id;
            let peer_display_name = outcome.peer_display_name.clone();
            let cipher = outcome.cipher;
            connected_phones.fetch_add(1, Ordering::Relaxed);
            let (security_tx, security_rx) = mpsc::channel(1);
            // Do not let the connection task emit session data until it is in
            // the live revocation registry. A revoke in the handshake→register
            // gap is caught by handle_client's durable tombstone check; every
            // later revoke has a registered security-control sender.
            let (start_tx, start_rx) = tokio::sync::oneshot::channel();
            let client_peers = peers.clone();
            let client = tokio::spawn(async move {
                start_rx.await.map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "connection start cancelled",
                    )
                })?;
                handle_client(
                    tport,
                    cipher,
                    mgr,
                    device_id,
                    pair_id,
                    client_peers,
                    push_ctx,
                    upload_cleanup,
                    security_rx,
                )
                .await
            });
            let connection_id = active
                .register(
                    device_id,
                    peer_display_name,
                    client.abort_handle(),
                    security_tx,
                )
                .await;
            let _ = start_tx.send(());
            match client.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("client session ended: {e}"),
                Err(e) if e.is_cancelled() => {
                    // Aborted via the registry: either a revoke, or the SAME
                    // device reconnected and took over (register aborts the
                    // superseded task). Don't log a takeover as a revoke.
                    info!(peer = %device_id, "connection closed (superseded by reconnect, or revoked)")
                }
                Err(e) => warn!("client task failed: {e}"),
            }
            active.deregister(&device_id, connection_id).await;
            connected_phones.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Drive one paired phone: stream sessions over the sealed channel.
// Keep authenticated identity, pair generation, authority store, and security
// control receiver explicit at this trust boundary.
#[allow(clippy::too_many_arguments)]
async fn handle_client(
    tport: IrohTransport,
    cipher: EnvelopeCipher,
    mgr: SessionManager,
    phone_device_id: DeviceId,
    pair_id: portty_transport::PairId,
    peers: SharedPeers,
    push_ctx: Option<crate::push::PushCtx>,
    upload_cleanup: UploadCleanup,
    mut security_rx: mpsc::Receiver<crate::active::ConnectionControl>,
) -> crate::error::HostResult<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let (mut writer, mut reader) = tport.split();

    // A revoke may have committed after the handshake but before this task was
    // registered for live control. Consult the durable authority before any
    // session metadata is emitted. A legacy/corrupt record without generation
    // metadata still closes fail-closed; the next reconnect returns Revoked.
    if let Some(record) = peers.lock().await.revocation(&phone_device_id) {
        if record.pair_id == Some(pair_id) {
            let _ = send_frame(
                &mut writer,
                &cipher,
                &Frame::PairRevoked {
                    pair_id: pair_id.0,
                    event_id: record.event_id,
                },
            )
            .await;
        }
        return Ok(());
    }

    // All outbound Frames funnel through ONE bounded channel. Bounded so a slow
    // phone (or stalled network) can't make a fast producer grow RAM without
    // limit: when the queue fills, the background forwarders block on `send`,
    // which makes the per-session output broadcast Lag instead - and a Lag is
    // handled by resyncing scrollback (see `attach`), so memory stays bounded
    // and the terminal stays coherent. Frames originated by THIS loop (snapshot
    // on attach, rename's list) are written straight to the socket instead of
    // enqueued, so the sole consumer can never deadlock waiting on itself.
    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(OUT_QUEUE_FRAMES);
    let active_id = Arc::new(AtomicU64::new(0));

    // Manager events (session added/removed/activity) → outbound Frames.
    {
        let tx = out_tx.clone();
        let mut events = mgr.subscribe_events();
        let active_id = active_id.clone();
        let mgr_ev = mgr.clone();
        tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            loop {
                let evt = match events.recv().await {
                    Ok(evt) => evt,
                    // Dropped some events: don't silently stop forwarding. Send a
                    // fresh full session list so the phone re-syncs its list, then
                    // keep going.
                    Err(RecvError::Lagged(_)) => {
                        let sessions = mgr_ev.list().await;
                        if tx.send(Frame::SessionList { sessions }).await.is_err() {
                            break;
                        }
                        let viewed = SessionId(active_id.load(Ordering::Relaxed));
                        if viewed.0 != 0 {
                            if let Some(session) = mgr_ev.get(viewed).await {
                                if let Some(events) = session.agent_snapshot() {
                                    if tx
                                        .send(Frame::AgentSnapshot { id: viewed, events })
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    // The phone clears its approval cards on
                                    // every snapshot and relies on the host to
                                    // replay the still-pending ones - the same
                                    // contract as `attach`. Without this, a lag
                                    // during a pending approval (or a dropped
                                    // AgentPermission event - it rides this
                                    // very channel) strands the agent until the
                                    // next re-attach.
                                    let mut send_failed = false;
                                    let workspace_scope = session.agent_workspace_scope();
                                    for (tool_call, options, category) in
                                        session.agent_permissions()
                                    {
                                        if tx
                                            .send(Frame::PolicyPermissionRequest {
                                                id: viewed,
                                                tool_call,
                                                options,
                                                category,
                                                workspace_scope,
                                            })
                                            .await
                                            .is_err()
                                        {
                                            send_failed = true;
                                            break;
                                        }
                                    }
                                    if send_failed {
                                        break;
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                };
                let frame = match evt {
                    ManagerEvent::Added(info) => Some(Frame::SessionAdded { info }),
                    ManagerEvent::Removed(id) => Some(Frame::SessionRemoved { id }),
                    ManagerEvent::Activity(id) => {
                        if active_id.load(Ordering::Relaxed) != id.0 {
                            Some(Frame::ActivityBlip { id })
                        } else {
                            None
                        }
                    }
                    // Agent (ACP) permission request → the phone's approval card.
                    ManagerEvent::AgentPermission {
                        id,
                        tool_call,
                        options,
                        category,
                        workspace_scope,
                    } => Some(Frame::PolicyPermissionRequest {
                        id,
                        tool_call,
                        options,
                        category,
                        workspace_scope,
                    }),
                    ManagerEvent::AgentTimeline { id, event } => {
                        if active_id.load(Ordering::Relaxed) == id.0 {
                            Some(Frame::AgentTimeline { id, event })
                        } else {
                            None
                        }
                    }
                    // NOT gated on the viewed session: the phone holds cards
                    // for background sessions too, and a stale card there
                    // would re-strand the approval it represents.
                    ManagerEvent::AgentPermissionResolved {
                        id,
                        tool_call_id,
                        resolution,
                        by,
                    } => Some(Frame::AgentPermissionResolvedInfo {
                        id,
                        tool_call_id,
                        resolution,
                        by,
                    }),
                    // Authoritative size changed (adopted session's laptop was
                    // resized) - the phone's match-width mode follows it.
                    ManagerEvent::Resized { id, cols, rows } => {
                        Some(Frame::SessionSize { id, cols, rows })
                    }
                };
                if let Some(frame) = frame {
                    if tx.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        });
    }

    // Initial state is staged, not written directly. The biased select below
    // always polls a queued revocation before these frames, so revocation can
    // preempt disclosure even during connection startup.
    let initial_sessions = mgr.list().await;
    let mut initial_frames = std::collections::VecDeque::from([Frame::SessionList {
        sessions: initial_sessions.clone(),
    }]);
    // Pending approvals are host-owned and survive a phone disconnect. Replay
    // every card immediately on reconnect so a notification tap can land on
    // the approval without first guessing which agent session to attach.
    for info in initial_sessions {
        if let Some(session) = mgr.get(info.id).await {
            let workspace_scope = session.agent_workspace_scope();
            for (tool_call, options, category) in session.agent_permissions() {
                initial_frames.push_back(Frame::PolicyPermissionRequest {
                    id: info.id,
                    tool_call,
                    options,
                    category,
                    workspace_scope,
                });
            }
        }
    }

    // Dedicated reader task: raw framed bytes → main loop. (Owns the read half,
    // so the main loop's select! can't cancel a read mid-frame.)
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(IN_QUEUE_FRAMES);
    tokio::spawn(async move {
        while let Ok(bytes) = reader.recv_raw().await {
            if in_tx.send(bytes).await.is_err() {
                break;
            }
        }
    });

    let mut active: Option<JoinHandle<()>> = None;
    let mut transfers = Transfers::new(upload_cleanup);
    loop {
        tokio::select! {
            biased;
            security = security_rx.recv() => {
                match security {
                    Some(crate::active::ConnectionControl::Revoked { pair_id, event_id }) => {
                        // The tombstone was committed before this control was
                        // queued. Best-effort notify over the authenticated
                        // envelope, then close regardless of flush success.
                        let _ = send_frame(
                            &mut writer,
                            &cipher,
                            &Frame::PairRevoked { pair_id, event_id },
                        )
                        .await;
                        break;
                    }
                    None => break,
                }
            }
            // Inbound FIRST: phone commands are human-paced and must stay
            // responsive even while output floods outbound. With outbound
            // polled first, a flooding child (e.g. `yes`) kept the full
            // out-queue Ready on every iteration - the forwarder refilled it
            // during each send_frame await - so KillSession/Input were never
            // polled and a runaway process could not be killed or Ctrl-C'd
            // from the phone until its output paused. Inbound-first cannot
            // starve outbound: inbound is bounded human input.
            bytes = in_rx.recv() => {
                let Some(bytes) = bytes else { break; };
                let env: SealedEnvelope = match postcard::from_bytes(&bytes) {
                    Ok(e) => e,
                    Err(error) => {
                        warn!(%error, "closing connection after malformed sealed envelope");
                        break;
                    }
                };
                let frame: Frame = match open_msg(&cipher, &env, b"") {
                    Ok(f) => f,
                    Err(error) => {
                        warn!(%error, "closing connection after envelope authentication failure");
                        break;
                    }
                };
                if !frame.direction().allows_phone_to_host() {
                    warn!(
                        direction = ?frame.direction(),
                        "closing connection after host-only frame arrived from phone"
                    );
                    break;
                }
                // The daemon control path commits under this same mutex. Once a
                // tombstone exists, no later phone command is authorized even if
                // the connection has not yet observed its close notification.
                if peers.lock().await.is_revoked(&phone_device_id) {
                    break;
                }
                match frame {
                    Frame::NewSession { cwd, title } => {
                        let cwd = cwd.map(std::path::PathBuf::from);
                        match mgr.spawn_shell(cwd, title).await {
                            Ok(id) => {
                                active_id.store(id.0, Ordering::Relaxed);
                                attach(&mgr, id, &mut writer, &cipher, &out_tx, &mut active).await?;
                            }
                            // Report the failure (e.g. session limit) instead of
                            // dropping it silently.
                            Err(e) => {
                                send_frame(
                                    &mut writer,
                                    &cipher,
                                    &Frame::CommandError {
                                        message: format!("could not create session: {e}"),
                                    },
                                )
                                .await?;
                            }
                        }
                    }
                    Frame::Attach { id } => {
                        // Report attaching to a session that's gone, instead of
                        // silently doing nothing (the phone would just hang on a
                        // blank terminal).
                        if mgr.get(id).await.is_none() {
                            send_frame(
                                &mut writer,
                                &cipher,
                                &Frame::CommandError {
                                    message: "that session is no longer available".into(),
                                },
                            )
                            .await?;
                        } else {
                            active_id.store(id.0, Ordering::Relaxed);
                            attach(&mgr, id, &mut writer, &cipher, &out_tx, &mut active).await?;
                        }
                    }
                    Frame::Detach => {
                        active_id.store(0, Ordering::Relaxed);
                        if let Some(h) = active.take() { h.abort(); }
                    }
                    Frame::Input { id, bytes } => {
                        if let Some(s) = mgr.get(id).await {
                            let _ = s.write_input(&bytes);
                        }
                    }
                    // Fixed-size model: viewers never drive the PTY size - the
                    // phone renders around the authoritative size it learns from
                    // `Frame::SessionSize`. Old phones may still send this; drop it.
                    Frame::Resize { .. } => {}
                    Frame::KillSession { id } => {
                        if active_id.load(Ordering::Relaxed) == id.0 {
                            active_id.store(0, Ordering::Relaxed);
                            // Abort the live forwarder like every other teardown
                            // path (Detach/Pause/attach). It holds an Arc to the
                            // session - and thus the broadcast sender - so it
                            // would otherwise park on recv() forever, pinning
                            // the dead session's scrollback until the next attach.
                            if let Some(h) = active.take() {
                                h.abort();
                            }
                        }
                        mgr.kill(id).await;
                    }
                    // Phone renamed a session. Update the title, then push a fresh
                    // full list so the phone re-renders the new name.
                    Frame::RenameSession { id, title } => {
                        if mgr.rename(id, title).await {
                            let sessions = mgr.list().await;
                            // Written directly (not enqueued): this loop is the
                            // sole queue consumer, so it must not send into a
                            // possibly-full queue and wait on itself.
                            send_frame(&mut writer, &cipher, &Frame::SessionList { sessions }).await?;
                        } else {
                            // Rename of a session that's gone - no longer silent.
                            send_frame(
                                &mut writer,
                                &cipher,
                                &Frame::CommandError {
                                    message: "rename failed: that session no longer exists".into(),
                                },
                            )
                            .await?;
                        }
                    }
                    // Phone's approve/deny on an agent (ACP) session. Routes by
                    // tool_call_id to the session holding the pending permission.
                    Frame::PermissionDecision { tool_call_id, option_id } => {
                        mgr.resolve_permission(&tool_call_id, option_id, PermissionResolver::Phone)
                            .await;
                    }
                    Frame::AgentPermissionDecision {
                        id,
                        tool_call_id,
                        option_id,
                    } => {
                        if let Some(session) = mgr.get(id).await {
                            session.resolve_permission(
                                &tool_call_id,
                                option_id,
                                PermissionResolver::Phone,
                            );
                        }
                    }
                    // Freeze live output so the user can scroll/read without the
                    // cursor jumping (and save cellular data). Keep the session
                    // "viewed" - no ActivityBlip; the ring keeps filling.
                    Frame::PauseStream => {
                        if let Some(h) = active.take() {
                            h.abort();
                        }
                    }
                    // Resume: re-send scrollback (recent history) + restart the
                    // live forwarder, without changing which session is viewed.
                    Frame::ResumeStream => {
                        let id = SessionId(active_id.load(Ordering::Relaxed));
                        if id.0 != 0 {
                            attach(&mgr, id, &mut writer, &cipher, &out_tx, &mut active).await?;
                        }
                    }
                    Frame::OutputResume { id, after_seq, generation } => {
                        // Serve the retained chunks strictly after the client's
                        // last-seen seq (no repaint); fall back to reset + full
                        // snapshot when that boundary aged out of the ring OR the
                        // generation is from a previous host lifetime (#14).
                        if mgr.get(id).await.is_some() {
                            active_id.store(id.0, Ordering::Relaxed);
                            attach_resume(
                                &mgr,
                                id,
                                after_seq,
                                generation,
                                &mut writer,
                                &cipher,
                                &out_tx,
                                &mut active,
                            )
                            .await?;
                        }
                    }
                    Frame::FileGetReq {
                        id,
                        path,
                        start_seq,
                        allow_outside_home,
                    } => {
                        transfers
                            .start_download(
                                id,
                                path,
                                start_seq,
                                allow_outside_home,
                                out_tx.clone(),
                            )
                            .await;
                    }
                    Frame::FilePutReq {
                        id,
                        path,
                        size,
                        mode,
                        allow_outside_home,
                    } => {
                        if let Err(reason) = transfers
                            .start_upload(id, path, size, mode, allow_outside_home)
                            .await
                        {
                            send_frame(&mut writer, &cipher, &Frame::FileErr { id, reason }).await?;
                        }
                    }
                    Frame::FileChunk { id, seq, bytes } => {
                        match transfers.upload_chunk(id, seq, bytes).await {
                            Ok(Some(reply)) => send_frame(&mut writer, &cipher, &reply).await?,
                            Ok(None) => {}
                            Err(reason) => {
                                transfers.cancel_upload(id);
                                send_frame(&mut writer, &cipher, &Frame::FileErr { id, reason }).await?;
                            }
                        }
                    }
                    Frame::FileDone { id, size, checksum } => {
                        let reply = match transfers.finish_upload(id, size, checksum).await {
                            Ok(done) => done,
                            Err(reason) => Frame::FileErr { id, reason },
                        };
                        send_frame(&mut writer, &cipher, &reply).await?;
                    }
                    Frame::FileRetry { id, from_seq } => {
                        transfers.retry_download(id, from_seq, out_tx.clone());
                    }
                    // Phone aborted a download (e.g. its disk failed): stop the
                    // streaming task instead of pushing the rest of the file.
                    // The same frame also cancels a phone-originated upload.
                    Frame::FileErr { id, .. } => {
                        transfers.cancel_download(id);
                        transfers.cancel_upload(id);
                    }
                    // Store the phone's push registration, forward it to the
                    // relay, and ack. The relay POST runs OFF the main loop
                    // (bounded out_tx carries the ack) so a slow relay can't
                    // stall this phone's keystrokes.
                    Frame::PushRegister {
                        provider,
                        token,
                        sealed_wake_blob,
                    } => match &push_ctx {
                        Some(ctx) => {
                            let reg = crate::push::PushRegistration::new(
                                crate::push::provider_name(provider).to_string(),
                                token,
                                sealed_wake_blob,
                            );
                            let ctx = ctx.clone();
                            let ack_tx = out_tx.clone();
                            tokio::spawn(async move {
                                let stored =
                                    { ctx.registry.lock().await.upsert(&phone_device_id, reg.clone()) };
                                let ack = match stored {
                                    Ok(stored_reg) => match ctx.register_with_relay(&stored_reg).await {
                                        Ok(()) => Frame::PushRegisterAck {
                                            ok: true,
                                            detail: None,
                                        },
                                        Err(e) => Frame::PushRegisterAck {
                                            ok: false,
                                            detail: Some(format!("relay: {e}")),
                                        },
                                    },
                                    Err(e) => Frame::PushRegisterAck {
                                        ok: false,
                                        detail: Some(format!("store: {e}")),
                                    },
                                };
                                let _ = ack_tx.send(ack).await;
                            });
                        }
                        None => {
                            send_frame(
                                &mut writer,
                                &cipher,
                                &Frame::PushRegisterAck {
                                    ok: false,
                                    detail: Some(
                                        "host has no push relay configured (set PORTTY_PUSH_RELAY_URL)"
                                            .into(),
                                    ),
                                },
                            )
                            .await?;
                        }
                    },
                    Frame::UnpairSelf {
                        request_id,
                        pair_id: claimed_pair_id,
                    } => {
                        if claimed_pair_id != pair_id.0 {
                            send_frame(
                                &mut writer,
                                &cipher,
                                &Frame::UnpairResult {
                                    request_id,
                                    pair_id: pair_id.0,
                                    committed: false,
                                    detail: Some("pair generation mismatch".into()),
                                },
                            )
                            .await?;
                            continue;
                        }
                        let result = peers.lock().await.revoke(&phone_device_id);
                        match result {
                            Ok(record) => {
                                if let Some(ctx) = &push_ctx {
                                    let ctx = ctx.clone();
                                    tokio::spawn(async move {
                                        ctx.notify_revoked(phone_device_id).await;
                                    });
                                }
                                send_frame(
                                    &mut writer,
                                    &cipher,
                                    &Frame::UnpairResult {
                                        request_id,
                                        pair_id: pair_id.0,
                                        committed: true,
                                        detail: None,
                                    },
                                )
                                .await?;
                                info!(peer = %phone_device_id, event = %hex::encode(record.event_id), "phone revoked its own pair");
                                break;
                            }
                            Err(error) => {
                                send_frame(
                                    &mut writer,
                                    &cipher,
                                    &Frame::UnpairResult {
                                        request_id,
                                        pair_id: pair_id.0,
                                        committed: false,
                                        detail: Some(error.to_string()),
                                    },
                                )
                                .await?;
                            }
                        }
                    }
                    // Correlated command: run it, then reply with the outcome tagged
                    // by the same req_id so the phone knows THIS command's result.
                    // NewSession does NOT auto-attach here - it returns the new id
                    // and the phone attaches explicitly (no "next SessionAdded is
                    // mine" guessing). Attach/Kill/Rename mirror the legacy handlers.
                    Frame::Request { req_id, kind } => {
                        let outcome = match kind {
                            RequestKind::NewSession { cwd, title } => {
                                let cwd = cwd.map(std::path::PathBuf::from);
                                match mgr.spawn_shell(cwd, title).await {
                                    Ok(id) => CommandOutcome::Ok { session: Some(id) },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not create session: {e}"),
                                    },
                                }
                            }
                            // Legacy sized create (old phones): the size is
                            // ignored - every spawned shell is born at the
                            // daemon's fixed size (fixed-size model).
                            RequestKind::NewSessionSized { cwd, title, .. } => {
                                let cwd = cwd.map(std::path::PathBuf::from);
                                match mgr.spawn_shell(cwd, title).await {
                                    Ok(id) => CommandOutcome::Ok { session: Some(id) },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not create session: {e}"),
                                    },
                                }
                            }
                            // Open a shell in a chosen directory. `rel` arrives
                            // workspace-relative and nothing here trusts that:
                            // `resolve_within` re-checks the shape, canonicalizes,
                            // and re-checks containment, so a symlink pointing out
                            // of the tree is refused even though its text looked
                            // fine. Same resolver the agent picker uses - one
                            // authority for both, rather than a second path to keep
                            // in step.
                            //
                            // Off-loop because resolution walks the filesystem and
                            // can block on a network mount; this loop also pumps
                            // this phone's output.
                            // Which roots this host serves. Asked rather than
                            // assumed, so a phone never offers the operator a root
                            // that would then be refused.
                            RequestKind::ListTerminalRoots => {
                                send_frame(
                                    &mut writer,
                                    &cipher,
                                    &Frame::TerminalRoots {
                                        req_id,
                                        roots: crate::workspace::terminal_roots(),
                                    },
                                )
                                .await?;
                                CommandOutcome::Ok { session: None }
                            }
                            // The rooted listing. Identical to `ListWorkspaceDirs`
                            // once the root resolves to a path - same resolver,
                            // same containment re-check, same entry cap.
                            RequestKind::ListDirsIn { root, rel } => {
                                match crate::workspace::terminal_root_path(root) {
                                    Some(base) => {
                                        let listed = tokio::task::spawn_blocking(move || {
                                            crate::workspace::list_dirs(&base, &rel)
                                        })
                                        .await;
                                        match listed {
                                            Ok(Ok((rel, names))) => {
                                                send_frame(
                                                    &mut writer,
                                                    &cipher,
                                                    &Frame::WorkspaceDirs { req_id, rel, names },
                                                )
                                                .await?;
                                                CommandOutcome::Ok { session: None }
                                            }
                                            Ok(Err(e)) => CommandOutcome::Error {
                                                message: format!("could not list directories: {e}"),
                                            },
                                            Err(e) => CommandOutcome::Error {
                                                message: format!("could not list directories: {e}"),
                                            },
                                        }
                                    }
                                    // Fail closed: a root this host does not serve
                                    // is refused, not silently substituted with one
                                    // it does.
                                    None => CommandOutcome::Error {
                                        message: "this host does not offer that folder".into(),
                                    },
                                }
                            }
                            RequestKind::NewSessionInRoot { root, rel, title } => {
                                match crate::workspace::terminal_root_path(root) {
                                    Some(base) => {
                                        let resolved = tokio::task::spawn_blocking(move || {
                                            crate::workspace::resolve_within(&base, &rel)
                                        })
                                        .await;
                                        match resolved {
                                            Ok(Ok(cwd)) => {
                                                match mgr.spawn_shell(Some(cwd), title).await {
                                                    Ok(id) => {
                                                        CommandOutcome::Ok { session: Some(id) }
                                                    }
                                                    Err(e) => CommandOutcome::Error {
                                                        message: format!(
                                                            "could not create session: {e}"
                                                        ),
                                                    },
                                                }
                                            }
                                            Ok(Err(e)) => CommandOutcome::Error {
                                                message: format!("could not open that folder: {e}"),
                                            },
                                            Err(e) => CommandOutcome::Error {
                                                message: format!("could not open that folder: {e}"),
                                            },
                                        }
                                    }
                                    None => CommandOutcome::Error {
                                        message: "this host does not offer that folder".into(),
                                    },
                                }
                            }
                            RequestKind::NewSessionIn { title, rel } => {
                                let root = workspace_dir();
                                let resolved = tokio::task::spawn_blocking(move || {
                                    crate::workspace::resolve_within(&root, &rel)
                                })
                                .await;
                                match resolved {
                                    Ok(Ok(cwd)) => match mgr.spawn_shell(Some(cwd), title).await {
                                        Ok(id) => CommandOutcome::Ok { session: Some(id) },
                                        Err(e) => CommandOutcome::Error {
                                            message: format!("could not create session: {e}"),
                                        },
                                    },
                                    // The refusal text stays vague about the host's
                                    // layout (see `WorkspaceError`) - the phone is
                                    // authenticated, but an error string is not the
                                    // place to disclose filesystem structure.
                                    Ok(Err(e)) => CommandOutcome::Error {
                                        message: format!("could not open that folder: {e}"),
                                    },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not open that folder: {e}"),
                                    },
                                }
                            }
                            RequestKind::Attach { id } => {
                                if mgr.get(id).await.is_none() {
                                    CommandOutcome::Error {
                                        message: "that session is no longer available".into(),
                                    }
                                } else {
                                    active_id.store(id.0, Ordering::Relaxed);
                                    attach(&mgr, id, &mut writer, &cipher, &out_tx, &mut active)
                                        .await?;
                                    CommandOutcome::Ok { session: Some(id) }
                                }
                            }
                            RequestKind::KillSession { id } => {
                                if active_id.load(Ordering::Relaxed) == id.0 {
                                    active_id.store(0, Ordering::Relaxed);
                                    // See Frame::KillSession: abort the forwarder
                                    // or it parks forever holding the scrollback.
                                    if let Some(h) = active.take() {
                                        h.abort();
                                    }
                                }
                                if mgr.kill(id).await {
                                    CommandOutcome::Ok { session: Some(id) }
                                } else {
                                    CommandOutcome::Error {
                                        message: "could not close that session - it is gone or its terminal is not responding".into(),
                                    }
                                }
                            }
                            RequestKind::RenameSession { id, title } => {
                                if mgr.rename(id, title).await {
                                    let sessions = mgr.list().await;
                                    send_frame(&mut writer, &cipher, &Frame::SessionList { sessions })
                                        .await?;
                                    CommandOutcome::Ok { session: Some(id) }
                                } else {
                                    CommandOutcome::Error {
                                        message: "rename failed: that session no longer exists".into(),
                                    }
                                }
                            }
                            RequestKind::NewAgentSession { provider, title } => {
                                // Continuity by default: after a host restart the
                                // phone's next open resumes the cached conversation.
                                // The spawn-side guard keeps a conversation already
                                // live in another session from being attached twice.
                                match mgr.spawn_agent_provider(provider, title, AgentResume::Latest, None).await {
                                    Ok(id) => CommandOutcome::Ok { session: Some(id) },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not start agent: {e}"),
                                    },
                                }
                            }
                            // v6: the phone picked a directory. Resolution and
                            // containment live in `crate::workspace` - the ONE
                            // place that decides what is reachable - and the
                            // resolved path becomes both the agent's cwd and its
                            // ACP sandbox root, so this can only narrow.
                            RequestKind::ListWorkspaceDirs { rel } => {
                                let root = workspace_dir();
                                // read_dir on a network mount can block; the loop
                                // it would block also pumps this phone's output.
                                let listed = tokio::task::spawn_blocking(move || {
                                    crate::workspace::list_dirs(&root, &rel)
                                })
                                .await;
                                match listed {
                                    Ok(Ok((rel, names))) => {
                                        send_frame(
                                            &mut writer,
                                            &cipher,
                                            &Frame::WorkspaceDirs {
                                                req_id,
                                                rel,
                                                names,
                                            },
                                        )
                                        .await?;
                                        CommandOutcome::Ok { session: None }
                                    }
                                    Ok(Err(e)) => CommandOutcome::Error {
                                        message: format!("could not list directories: {e}"),
                                    },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not list directories: {e}"),
                                    },
                                }
                            }
                            // v7: which CONVERSATION, after v6 settled which
                            // directory. Both resolve `rel` through the same
                            // workspace guard, so a conversation can only ever
                            // be listed or resumed inside the directory it
                            // belongs to.
                            // Told BEFORE the user invests three taps in a
                            // provider this host cannot launch.
                            RequestKind::ListAgentProviders => {
                                let providers = mgr.agent_provider_availability().await;
                                send_frame(
                                    &mut writer,
                                    &cipher,
                                    &Frame::AgentProviders { req_id, providers },
                                )
                                .await?;
                                CommandOutcome::Ok { session: None }
                            }
                            RequestKind::ListAgentSessions { rel } => {
                                let root = workspace_dir();
                                let listed = tokio::task::spawn_blocking(move || {
                                    crate::workspace::resolve_within(&root, &rel)
                                        .map(|cwd| (rel, cwd))
                                })
                                .await;
                                match listed {
                                    Ok(Ok((rel, cwd))) => {
                                        let sessions =
                                            mgr.list_agent_sessions(cwd.clone()).await;
                                        send_frame(
                                            &mut writer,
                                            &cipher,
                                            &Frame::AgentSessions {
                                                req_id,
                                                rel,
                                                sessions,
                                            },
                                        )
                                        .await?;
                                        CommandOutcome::Ok { session: None }
                                    }
                                    Ok(Err(e)) => CommandOutcome::Error {
                                        message: format!("could not list conversations: {e}"),
                                    },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not list conversations: {e}"),
                                    },
                                }
                            }
                            // v11's widening of `ListAgentSessions`: same reply,
                            // same resolver, but the answer also includes what
                            // the agent itself remembers - which is how a chat
                            // started in the laptop terminal becomes resumable
                            // from the phone. Provider-scoped because answering
                            // launches that provider's adapter.
                            //
                            // Answered from its OWN TASK, like the agent
                            // mode/config commands below and for the same reason:
                            // this one waits on an adapter process starting, and
                            // awaiting that here would stop the select! polling
                            // input and output - up to twelve seconds where the
                            // viewed terminal neither draws nor accepts a Ctrl-C.
                            // Both frames go out over `out_tx`, whose single mpsc
                            // preserves their order.
                            RequestKind::ListAgentSessionsFor { rel, provider } => {
                                let mgr = mgr.clone();
                                let out = out_tx.clone();
                                tokio::spawn(async move {
                                    let root = workspace_dir();
                                    let listed = tokio::task::spawn_blocking(move || {
                                        crate::workspace::resolve_within(&root, &rel)
                                            .map(|cwd| (rel, cwd))
                                    })
                                    .await;
                                    let outcome = match listed {
                                        Ok(Ok((rel, cwd))) => {
                                            let sessions =
                                                mgr.list_agent_sessions_for(provider, cwd).await;
                                            let _ = out
                                                .send(Frame::AgentSessions {
                                                    req_id,
                                                    rel,
                                                    sessions,
                                                })
                                                .await;
                                            CommandOutcome::Ok { session: None }
                                        }
                                        Ok(Err(e)) => CommandOutcome::Error {
                                            message: format!("could not list conversations: {e}"),
                                        },
                                        Err(e) => CommandOutcome::Error {
                                            message: format!("could not list conversations: {e}"),
                                        },
                                    };
                                    let _ =
                                        out.send(Frame::CommandResult { req_id, outcome }).await;
                                });
                                continue;
                            }
                            RequestKind::ResumeAgentSession {
                                rel,
                                acp_session_id,
                            } => {
                                let root = workspace_dir();
                                let resolved = tokio::task::spawn_blocking(move || {
                                    crate::workspace::resolve_within(&root, &rel)
                                })
                                .await;
                                match resolved {
                                    Ok(Ok(cwd)) => {
                                        match mgr
                                            .resume_agent_session(cwd, acp_session_id)
                                            .await
                                        {
                                            Ok(id) => CommandOutcome::Ok { session: Some(id) },
                                            Err(e) => CommandOutcome::Error {
                                                message: format!("could not resume: {e}"),
                                            },
                                        }
                                    }
                                    Ok(Err(e)) => CommandOutcome::Error {
                                        message: format!("could not resume: {e}"),
                                    },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not resume: {e}"),
                                    },
                                }
                            }
                            RequestKind::NewAgentSessionIn {
                                provider,
                                title,
                                rel,
                            } => {
                                let root = workspace_dir();
                                let resolved = tokio::task::spawn_blocking(move || {
                                    crate::workspace::resolve_within(&root, &rel)
                                })
                                .await;
                                match resolved {
                                    Ok(Ok(cwd)) => {
                                        match mgr
                                            .spawn_agent_provider(provider, title, AgentResume::Latest, Some(cwd))
                                            .await
                                        {
                                            Ok(id) => CommandOutcome::Ok { session: Some(id) },
                                            Err(e) => {
                                                // Log it. This failure was only
                                                // ever reported to the PHONE, so
                                                // a missing adapter left no
                                                // trace on the host at all and
                                                // there was nothing to diagnose
                                                // from.
                                                warn!(
                                                    provider = ?provider,
                                                    error = %e,
                                                    "agent start failed"
                                                );
                                                CommandOutcome::Error {
                                                    message: format!("could not start agent: {e}"),
                                                }
                                            }
                                        }
                                    }
                                    Ok(Err(e)) => CommandOutcome::Error {
                                        message: format!("could not start agent: {e}"),
                                    },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not start agent: {e}"),
                                    },
                                }
                            }
                            RequestKind::AgentPrompt { id, text } => {
                                match mgr.get(id).await {
                                    Some(session) => match session.agent_prompt(text) {
                                        Ok(()) => CommandOutcome::Ok { session: Some(id) },
                                        Err(e) => CommandOutcome::Error {
                                            message: format!("could not send prompt: {e}"),
                                        },
                                    },
                                    None => CommandOutcome::Error {
                                        message: "that agent session is no longer available".into(),
                                    },
                                }
                            }
                            RequestKind::AgentCancel { id } => match mgr.get(id).await {
                                Some(session) => match session.agent_cancel() {
                                    Ok(()) => CommandOutcome::Ok { session: Some(id) },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not cancel turn: {e}"),
                                    },
                                },
                                None => CommandOutcome::Error {
                                    message: "that agent session is no longer available".into(),
                                },
                            },
                            // Mode/config changes wait for the agent's answer
                            // (up to 30s). Awaiting that INSIDE this loop would
                            // freeze every following frame - including the
                            // permission decision a mid-turn agent needs before
                            // it will answer the control - so the wait happens
                            // in a task and the result rides the outbound queue.
                            RequestKind::AgentSetMode { id, mode_id } => {
                                let mgr = mgr.clone();
                                let out = out_tx.clone();
                                tokio::spawn(async move {
                                    let outcome = match mgr.get(id).await {
                                        Some(session) => match session.agent_set_mode(mode_id).await {
                                            Ok(()) => CommandOutcome::Ok { session: Some(id) },
                                            Err(e) => CommandOutcome::Error {
                                                message: format!("could not change mode: {e}"),
                                            },
                                        },
                                        None => CommandOutcome::Error {
                                            message: "that agent session is no longer available".into(),
                                        },
                                    };
                                    let _ = out.send(Frame::CommandResult { req_id, outcome }).await;
                                });
                                continue;
                            }
                            RequestKind::AgentSetConfigOption { id, config_id, value } => {
                                let mgr = mgr.clone();
                                let out = out_tx.clone();
                                tokio::spawn(async move {
                                    let outcome = match mgr.get(id).await {
                                        Some(session) => match session
                                            .agent_set_config(config_id, value)
                                            .await
                                        {
                                            Ok(()) => CommandOutcome::Ok { session: Some(id) },
                                            Err(e) => CommandOutcome::Error {
                                                message: format!("could not change agent setting: {e}"),
                                            },
                                        },
                                        None => CommandOutcome::Error {
                                            message: "that agent session is no longer available".into(),
                                        },
                                    };
                                    let _ = out.send(Frame::CommandResult { req_id, outcome }).await;
                                });
                                continue;
                            }
                            RequestKind::AgentAuthenticate { id, method_id } => match mgr.get(id).await {
                                Some(session) => match session.agent_authenticate(method_id) {
                                    Ok(()) => CommandOutcome::Ok { session: Some(id) },
                                    Err(e) => CommandOutcome::Error {
                                        message: format!("could not authenticate agent: {e}"),
                                    },
                                },
                                None => CommandOutcome::Error {
                                    message: "that agent session is no longer available".into(),
                                },
                            },
                        };
                        send_frame(&mut writer, &cipher, &Frame::CommandResult { req_id, outcome })
                            .await?;
                    }
                    // Direction was checked above; these arms are unreachable
                    // for a conforming or malicious phone alike.
                    _ => unreachable!("phone frame direction checked before dispatch"),
                }
            }
            // Outbound: session output, list updates, lifecycle events.
            out = async {
                match initial_frames.pop_front() {
                    Some(frame) => Some(frame),
                    None => out_rx.recv().await,
                }
            } => {
                let Some(frame) = out else { break; };
                if send_frame(&mut writer, &cipher, &frame).await.is_err() {
                    break;
                }
            }
        }
    }

    if let Some(h) = active {
        h.abort();
    }
    let _ = writer.shutdown().await;
    info!("phone disconnected");
    Ok(())
}

/// Attach the phone to a session: cancel the previous forwarder, reset the
/// client screen, send the scrollback snapshot, then stream live output.
///
/// Snapshot + subscription are taken ATOMICALLY (`snapshot_and_subscribe`) so no
/// output produced during attach is lost or duplicated. A `ScreenReset` precedes
/// the snapshot so the client renders it on a clean screen (not on top of old
/// content). Both are written straight to the socket (this runs in the sole
/// queue consumer, which must not enqueue-and-wait on itself). Live output goes
/// over the bounded `out_tx`, so a slow phone backpressures the forwarder - which
/// makes the session broadcast Lag rather than growing RAM. A Lag is recovered
/// the same way (reset + fresh snapshot), so the terminal stays coherent instead
/// of the forwarder silently dying (the old `while let Ok` did).
async fn attach(
    mgr: &SessionManager,
    id: SessionId,
    writer: &mut IrohWriter,
    cipher: &EnvelopeCipher,
    out_tx: &mpsc::Sender<Frame>,
    active: &mut Option<JoinHandle<()>>,
) -> crate::error::HostResult<()> {
    if let Some(h) = active.take() {
        h.abort();
    }
    let Some(session) = mgr.get(id).await else {
        return Ok(());
    };

    // Agent sessions never enter xterm. Re-send their bounded structured
    // history; live updates arrive through ManagerEvent and are de-duplicated
    // by sequence number on the phone.
    if let Some(events) = session.agent_snapshot() {
        send_frame(writer, cipher, &Frame::AgentSnapshot { id, events }).await?;
        let workspace_scope = session.agent_workspace_scope();
        for (tool_call, options, category) in session.agent_permissions() {
            send_frame(
                writer,
                cipher,
                &Frame::PolicyPermissionRequest {
                    id,
                    tool_call,
                    options,
                    category,
                    workspace_scope,
                },
            )
            .await?;
        }
        return Ok(());
    }

    // Atomic snapshot + subscription (no gap), then reset-then-snapshot direct.
    // The snapshot is CHUNKED into multiple Output frames: scrollback caps can
    // exceed the 1 MiB wire-frame limit, and the phone renders consecutive
    // Output frames for one session identically to one big frame.
    let (snap, through_seq, rx) = session.snapshot_and_subscribe();
    send_frame(
        writer,
        cipher,
        &Frame::ScreenReset {
            id,
            generation: host_generation(),
        },
    )
    .await?;
    // Authoritative size BEFORE the snapshot: the phone's match-width mode must
    // set its grid before it parses the snapshot bytes (the wire order is
    // preserved end-to-end, so this is race-free on the client).
    let (cols, rows) = session.size();
    send_frame(writer, cipher, &Frame::SessionSize { id, cols, rows }).await?;
    for chunk in snap.chunks(SNAPSHOT_CHUNK_BYTES) {
        send_frame(
            writer,
            cipher,
            &Frame::Output {
                id,
                bytes: chunk.to_vec(),
            },
        )
        .await?;
    }
    // Empty sequence marker: the snapshot already contains every byte through
    // this boundary. The phone records it without rendering anything, so live
    // sequenced output can be resumed/de-duplicated after reconnect.
    send_frame(
        writer,
        cipher,
        &Frame::SequencedOutput {
            id,
            seq: through_seq,
            bytes: Vec::new(),
        },
    )
    .await?;

    // Live output forwarder (owns the pre-obtained receiver - no re-subscribe gap).
    *active = Some(spawn_live_forwarder(session, rx, out_tx.clone()));
    Ok(())
}

/// Resume a viewer after reconnect without a full repaint when possible: serve
/// the retained output strictly after the client's `after_seq` as sequenced
/// frames (no `ScreenReset` - the client keeps its rendered screen), then hand
/// off to the live forwarder with an atomically obtained receiver. Falls back
/// to the classic reset + full snapshot `attach` when the boundary has aged
/// out of the ring (or is from another host lifetime).
// One over clippy's 7-arg default: all are the per-connection I/O handles the
// sibling `attach` also takes, plus the client's resume boundary + generation.
#[allow(clippy::too_many_arguments)]
async fn attach_resume(
    mgr: &SessionManager,
    id: SessionId,
    after_seq: u64,
    client_generation: u64,
    writer: &mut IrohWriter,
    cipher: &EnvelopeCipher,
    out_tx: &mpsc::Sender<Frame>,
    active: &mut Option<JoinHandle<()>>,
) -> crate::error::HostResult<()> {
    let Some(session) = mgr.get(id).await else {
        return Ok(());
    };
    // A resume boundary minted by a PREVIOUS host lifetime cannot be trusted:
    // session ids restart from 1, so a stale (id, after_seq) can match a fresh
    // session's ring and replay a delta onto an unrelated screen. Force a full
    // reset+snapshot attach when the generation doesn't match (gap #14).
    if client_generation != host_generation() {
        return attach(mgr, id, writer, cipher, out_tx, active).await;
    }
    // Agent sessions have no byte stream to resume; their structured history
    // replay is already idempotent (phone de-duplicates by event seq).
    if session.agent_snapshot().is_some() {
        return attach(mgr, id, writer, cipher, out_tx, active).await;
    }
    let Some((chunks, through_seq, rx)) = session.delta_since_and_subscribe(after_seq) else {
        return attach(mgr, id, writer, cipher, out_tx, active).await;
    };
    if let Some(h) = active.take() {
        h.abort();
    }
    // Size first: an adopted session may have been resized while the phone was
    // away, and the client must set its grid before parsing the delta bytes.
    let (cols, rows) = session.size();
    send_frame(writer, cipher, &Frame::SessionSize { id, cols, rows }).await?;
    // Replay the delta coalesced into few frames; each carries the seq of the
    // last chunk it contains so the client's last-seen cursor stays exact.
    let mut merged: Vec<u8> = Vec::new();
    let mut merged_seq = after_seq;
    for chunk in &chunks {
        merged.extend_from_slice(&chunk.bytes);
        merged_seq = chunk.seq;
        if merged.len() >= SNAPSHOT_CHUNK_BYTES {
            send_frame(
                writer,
                cipher,
                &Frame::SequencedOutput {
                    id,
                    seq: merged_seq,
                    bytes: std::mem::take(&mut merged),
                },
            )
            .await?;
        }
    }
    if !merged.is_empty() {
        send_frame(
            writer,
            cipher,
            &Frame::SequencedOutput {
                id,
                seq: merged_seq,
                bytes: merged,
            },
        )
        .await?;
    }
    // Checkpoint marker: resume is complete through this boundary (also the
    // client's ack that the delta path - not a reset - was taken).
    send_frame(
        writer,
        cipher,
        &Frame::SequencedOutput {
            id,
            seq: through_seq,
            bytes: Vec::new(),
        },
    )
    .await?;
    *active = Some(spawn_live_forwarder(session, rx, out_tx.clone()));
    Ok(())
}

/// Forward live broadcast output to the phone until the connection or session
/// ends. On broadcast lag (slow phone link) the viewer is resynced with a
/// reset + CHUNKED snapshot - chunked on both lag paths, because scrollback
/// caps may exceed the 1 MiB wire-frame limit.
fn spawn_live_forwarder(
    session: Arc<crate::session::Session>,
    rx: tokio::sync::broadcast::Receiver<Arc<crate::session::OutputChunk>>,
    tx: mpsc::Sender<Frame>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        let id = session.id();
        let mut rx = rx;
        // Coalescing cap: enough to collapse a flood's tiny chunks into one
        // seal+write, small enough to keep keystroke echo latency invisible
        // and stay far under MAX_FRAME_BYTES.
        const COALESCE_BYTES: usize = 32 * 1024;
        loop {
            match rx.recv().await {
                Ok(chunk) => {
                    // Merge everything already queued into ONE frame: per-frame
                    // cost (seal + socket write) dominated under heavy output,
                    // where hundreds of PTY-sized chunks each paid it alone.
                    let seq = chunk.seq;
                    let mut merged = chunk.bytes.to_vec();
                    let mut last_seq = seq;
                    let mut lagged = false;
                    while merged.len() < COALESCE_BYTES {
                        use tokio::sync::broadcast::error::TryRecvError;
                        match rx.try_recv() {
                            Ok(more) => {
                                last_seq = more.seq;
                                merged.extend_from_slice(&more.bytes);
                            }
                            Err(TryRecvError::Empty | TryRecvError::Closed) => break,
                            // Chunks were dropped mid-merge: what we have is
                            // still contiguous - send it, then resync below
                            // exactly like the outer Lagged arm.
                            Err(TryRecvError::Lagged(_)) => {
                                lagged = true;
                                break;
                            }
                        }
                    }
                    if tx
                        .send(Frame::SequencedOutput {
                            id,
                            seq: last_seq,
                            bytes: merged,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                    session.mark_seen();
                    if lagged {
                        match resync_after_lag(&session, &tx).await {
                            Some(fresh_rx) => rx = fresh_rx,
                            None => break,
                        }
                    }
                }
                // Slow consumer: live chunks were dropped from the broadcast ring.
                // Reset + resync with the current scrollback so the client stays
                // coherent (no duplication), then keep streaming.
                Err(RecvError::Lagged(_)) => match resync_after_lag(&session, &tx).await {
                    Some(fresh_rx) => rx = fresh_rx,
                    None => break,
                },
                Err(RecvError::Closed) => break,
            }
        }
    })
}

/// Shared lag recovery: atomically snapshot + re-subscribe (keeping the lagged
/// receiver would duplicate chunks already inside the snapshot), then send
/// reset + chunked snapshot + checkpoint. `None` means the connection is gone.
async fn resync_after_lag(
    session: &crate::session::Session,
    tx: &mpsc::Sender<Frame>,
) -> Option<tokio::sync::broadcast::Receiver<Arc<crate::session::OutputChunk>>> {
    let id = session.id();
    let (snap, through_seq, fresh_rx) = session.snapshot_and_subscribe();
    if tx
        .send(Frame::ScreenReset {
            id,
            generation: host_generation(),
        })
        .await
        .is_err()
    {
        return None;
    }
    for chunk in snap.chunks(SNAPSHOT_CHUNK_BYTES) {
        if tx
            .send(Frame::Output {
                id,
                bytes: chunk.to_vec(),
            })
            .await
            .is_err()
        {
            return None;
        }
    }
    if tx
        .send(Frame::SequencedOutput {
            id,
            seq: through_seq,
            bytes: Vec::new(),
        })
        .await
        .is_err()
    {
        return None;
    }
    Some(fresh_rx)
}

/// Seal a Frame with the cipher and write it as one framed postcard payload.
async fn send_frame(
    writer: &mut IrohWriter,
    cipher: &EnvelopeCipher,
    frame: &Frame,
) -> crate::error::HostResult<()> {
    let sealed: SealedEnvelope = seal_msg(cipher, frame, b"")?;
    let bytes = postcard::to_allocvec(&sealed)
        .map_err(|e| crate::error::HostError::Serialization(e.to_string()))?;
    writer.send_raw(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use portty_protocol::{CommandOutcome, RequestKind};
    use portty_transport::{run_client_handshake, ClientHandshake, Transport};
    use std::time::Duration;

    /// Startup must arm NOTHING. This is the whole fix for "every daemon restart
    /// writes fresh shell-access credentials to service logs": if no secret is
    /// ever minted at startup, there is nothing for a log to capture and nothing
    /// a log reader could replay.
    #[test]
    fn startup_pairing_state_is_closed_and_unarmed() {
        let (state, guard) = closed_pairing_guard();
        let snapshot = state.lock().unwrap().snapshot();

        assert!(
            snapshot.secrets.is_empty(),
            "startup must mint no pairing secret"
        );
        assert_eq!(
            snapshot.epoch, None,
            "startup must not open an enrollment opportunity"
        );
        assert!(!state.lock().unwrap().is_open());
        // Belt and braces: even a snapshot taken here cannot gate a first pair.
        assert_eq!(
            guard.state.lock().unwrap().gate_first_pair(snapshot.epoch),
            portty_transport::FirstPairGate::Closed
        );
    }

    /// `portty pair` is what arms it - and it must arm BOTH credentials and the
    /// window, otherwise the closed default would simply mean "cannot pair".
    #[test]
    fn portty_pair_arms_credentials_and_opens_the_window() {
        let (state, _guard) = closed_pairing_guard();
        state.lock().unwrap().rotate(
            vec![
                PairingSecret::generate_ticket(),
                PairingSecret::generate_manual(),
            ],
            ENROLLMENT_WINDOW,
        );

        let snapshot = state.lock().unwrap().snapshot();
        assert_eq!(snapshot.secrets.len(), 2, "ticket + manual phrase");
        assert!(snapshot.epoch.is_some());
        assert!(state.lock().unwrap().is_open());
    }

    #[test]
    fn host_generation_is_stable_within_process() {
        // The generation identifies ONE host lifetime, so it must be constant
        // across calls: a fresh value each call would make every warm resume
        // look like a restart and force a needless full repaint (#14). Distinct
        // processes get distinct values because it is RNG-seeded once.
        assert_eq!(host_generation(), host_generation());
    }

    /// End-to-end over real iroh: pair, then send a correlated `Request` and
    /// prove the host answers with a `CommandResult` echoing the SAME req_id and
    /// carrying the new session's id - and that the session actually exists.
    #[tokio::test(flavor = "multi_thread")]
    async fn request_new_session_round_trips_command_result() {
        let res = tokio::time::timeout(Duration::from_secs(60), async {
            let host_dir = tempfile::tempdir()?;
            let client_dir = tempfile::tempdir()?;
            let host_id = Identity::load_or_create(host_dir.path())?;
            let client_id = Identity::load_or_create(client_dir.path())?;
            // Since v8 the out-of-band secret IS the first-pair credential.
            let ticket_secret = PairingSecret::from_ticket_bytes([0x42; 16]);

            let host_ep = build_endpoint(&host_id, RelayMode::Disabled).await?;
            let client_ep = build_endpoint(&client_id, RelayMode::Disabled).await?;
            let port = host_ep
                .bound_sockets()
                .into_iter()
                .find_map(|s| s.is_ipv4().then_some(s.port()))
                .expect("ipv4 socket");
            let host_addr = iroh::EndpointAddr::new(host_ep.id())
                .with_ip_addr(std::net::SocketAddr::from(([127, 0, 0, 1], port)));

            // Server: accept + handshake, then drive the real client loop.
            let host_ep2 = host_ep.clone();
            let host_did = host_id.device_id();
            let host_secret = ticket_secret.clone();
            let mgr = SessionManager::new();
            let mgr2 = mgr.clone();
            let server = tokio::spawn(async move {
                let conn = host_ep2
                    .accept()
                    .await
                    .expect("accept")
                    .await
                    .expect("conn");
                let mut tport = IrohTransport::accept(conn).await?;
                let mut hs = ServerHandshake::new(host_did, "host".into())
                    .with_unwindowed_pairing_secrets([host_secret]);
                let outcome = run_server_handshake(&mut tport, &mut hs).await?;
                // Production claims the enrollment slot and persists between these
                // two calls; this test has nothing to persist.
                confirm_server_handshake(&mut tport, &hs).await?;
                let phone_did = outcome.peer_device_id;
                let (security_tx, security_rx) = mpsc::channel(1);
                let (upload_cleanup, _) = UploadCleanup::open(host_dir.path())?;
                handle_client(
                    tport,
                    outcome.cipher,
                    mgr2,
                    phone_did,
                    outcome.pair_id,
                    Arc::new(AsyncMutex::new(PeerStore::load(host_dir.path())?)),
                    None,
                    upload_cleanup,
                    security_rx,
                )
                .await?;
                drop(security_tx);
                Ok::<(), crate::error::HostError>(())
            });

            // Client: connect + handshake.
            let mut ctport = IrohTransport::connect(&client_ep, host_addr).await?;
            let mut chs =
                ClientHandshake::first_pair(client_id.device_id(), "phone".into(), ticket_secret);
            let outcome = run_client_handshake(&mut ctport, &mut chs).await?;
            let cipher = outcome.cipher;

            // Send a correlated NewSession request…
            let req = seal_msg(
                &cipher,
                &Frame::Request {
                    req_id: 99,
                    kind: RequestKind::NewSession {
                        cwd: None,
                        title: Some("test".into()),
                    },
                },
                b"",
            )?;
            ctport.send(&req).await?;

            // …and read frames until the matching CommandResult arrives.
            let mut created: Option<SessionId> = None;
            for _ in 0..10 {
                let env: SealedEnvelope = ctport.recv().await?;
                if let Ok(Frame::CommandResult { req_id, outcome }) = open_msg(&cipher, &env, b"") {
                    assert_eq!(req_id, 99, "reply must echo the request id");
                    match outcome {
                        CommandOutcome::Ok { session } => {
                            created = Some(session.expect("NewSession returns the new id"));
                        }
                        CommandOutcome::Error { message } => panic!("unexpected error: {message}"),
                    }
                    break;
                }
            }
            let id = created.expect("a CommandResult for req 99");
            assert!(
                mgr.get(id).await.is_some(),
                "the created session must exist"
            );

            // v9's chosen-directory create, driven through this same real loop
            // rather than by calling the resolver directly - the resolver already
            // has its own tests in `workspace`; what needs proving is that the
            // request arm is wired to it. `src` sits beside this file, so the
            // workspace-relative path must be accepted.
            let chosen = seal_msg(
                &cipher,
                &Frame::Request {
                    req_id: 100,
                    kind: RequestKind::NewSessionIn {
                        title: Some("in-src".into()),
                        rel: "src".into(),
                    },
                },
                b"",
            )?;
            ctport.send(&chosen).await?;
            let mut in_src: Option<SessionId> = None;
            for _ in 0..10 {
                let env: SealedEnvelope = ctport.recv().await?;
                if let Ok(Frame::CommandResult {
                    req_id: 100,
                    outcome,
                }) = open_msg(&cipher, &env, b"")
                {
                    match outcome {
                        CommandOutcome::Ok { session } => {
                            in_src = Some(session.expect("NewSessionIn returns the new id"));
                        }
                        CommandOutcome::Error { message } => {
                            panic!("a workspace-relative folder must be accepted: {message}")
                        }
                    }
                    break;
                }
            }
            let in_src = in_src.expect("a CommandResult for req 100");
            assert!(
                mgr.get(in_src).await.is_some(),
                "the chosen-directory session must exist"
            );

            // …and an escaping path must be REFUSED, not silently clamped to the
            // root. `..` never appears in honest picker traffic (it sends a
            // shorter rel to go up), so this is the fail-closed half.
            let escape = seal_msg(
                &cipher,
                &Frame::Request {
                    req_id: 101,
                    kind: RequestKind::NewSessionIn {
                        title: None,
                        rel: "../../etc".into(),
                    },
                },
                b"",
            )?;
            ctport.send(&escape).await?;
            let mut refused: Option<String> = None;
            for _ in 0..10 {
                let env: SealedEnvelope = ctport.recv().await?;
                if let Ok(Frame::CommandResult {
                    req_id: 101,
                    outcome,
                }) = open_msg(&cipher, &env, b"")
                {
                    match outcome {
                        CommandOutcome::Ok { session } => {
                            // Clean up before failing, or the runtime hangs on the
                            // PTY reader of a session we did not expect to exist.
                            if let Some(session) = session {
                                mgr.kill(session).await;
                            }
                            panic!("an escaping rel must not open a session");
                        }
                        CommandOutcome::Error { message } => refused = Some(message),
                    }
                    break;
                }
            }
            let refused = refused.expect("a CommandResult for req 101");
            assert!(
                !refused.contains("/etc"),
                "the refusal must not echo host filesystem layout back: {refused:?}"
            );

            // Kill the spawned shells so their blocking PTY readers (spawn_blocking)
            // return - otherwise the tokio runtime can't shut down at test end
            // (it waits for blocking tasks) and the test hangs after asserting.
            mgr.kill(id).await;
            mgr.kill(in_src).await;
            drop(ctport); // ends handle_client
            let _ = server.await;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("request round-trip failed: {e}"),
            Err(_) => panic!("timed out"),
        }
    }

    /// One dialer must not be able to hold every half-open slot. Before the
    /// staging gate, eight unauthenticated dials took the whole admission budget
    /// and a real phone could not get in until they timed out.
    #[test]
    fn one_source_cannot_hold_more_than_its_share_of_staging_slots() {
        let gate = StagingGate::default();
        let held: Vec<StagingSlot> = (0..MAX_STAGING_PER_SOURCE)
            .map(|_| {
                gate.try_enter("node:attacker".into(), MAX_STAGING_PER_SOURCE)
                    .expect("within the per-source allowance")
            })
            .collect();

        assert!(
            gate.try_enter("node:attacker".into(), MAX_STAGING_PER_SOURCE)
                .is_none(),
            "a source past its allowance must be refused"
        );
        // ...while a DIFFERENT source is unaffected.
        assert!(gate
            .try_enter("node:real-phone".into(), MAX_STAGING_PER_SOURCE)
            .is_some());

        // Slots come back as the dials end, however they end.
        drop(held);
        assert!(gate
            .try_enter("node:attacker".into(), MAX_STAGING_PER_SOURCE)
            .is_some());
    }

    /// The counter map must not grow by one entry per distinct dialer forever -
    /// that would be the memory leak this gate is supposed to prevent.
    #[test]
    fn staging_gate_forgets_sources_once_they_have_no_dials_left() {
        let gate = StagingGate::default();
        for i in 0..64 {
            let slot = gate.try_enter(format!("node:{i}"), MAX_STAGING_PER_SOURCE);
            assert!(slot.is_some());
            drop(slot);
        }
        assert_eq!(gate.tracked_sources(), 0);

        let held = gate.try_enter("node:live".into(), MAX_STAGING_PER_SOURCE);
        assert_eq!(gate.tracked_sources(), 1);
        drop(held);
        assert_eq!(gate.tracked_sources(), 0);
    }

    /// The reserve exists so a flood of freshly minted endpoint ids cannot keep an
    /// already-paired phone out. It is keyed on an UNAUTHENTICATED id, so it is a
    /// hint: claiming a paired id reaches the reserve but still cannot pair.
    #[test]
    fn only_dials_claiming_a_paired_device_look_known() {
        let paired = DeviceId([3; 16]);
        let known = vec![paired];

        // A direct dial carries no identity at this stage.
        let direct = iroh::endpoint::IncomingAddr::Ip(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            1234,
        )));
        assert!(!dial_claims_known_peer(&direct, &known));
        // ...and neither does an empty peer store.
        assert!(!dial_claims_known_peer(&direct, &[]));
    }

    /// Relayed dials key on the dialer's endpoint id (the strongest signal
    /// available before authentication); direct dials fall back to source IP.
    #[test]
    fn staging_keys_separate_relayed_and_direct_sources() {
        use std::net::{Ipv4Addr, SocketAddr};
        let ip =
            iroh::endpoint::IncomingAddr::Ip(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 7), 41)));
        let key = staging_source_key(&ip);
        assert!(key.starts_with("ip:"), "{key}");
        // The port must NOT be part of the key, or one host could take every slot
        // just by dialing from new source ports.
        assert_eq!(key, "ip:10.0.0.7");
    }
}
