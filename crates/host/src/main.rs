//! Portty host daemon.
//!
//! Two modes:
//!   `portty-host`          → background host: prints a pairing ticket + PIN,
//!                           then releases the terminal after the phone connects.
//!   `portty-host serve`    → foreground host for service managers/debugging.
//!   `portty-host proof`    → the local WebSocket + xterm.js proof (browser only,
//!                           no iroh). Useful for offline UI/PTY development.
//!   `portty-host peers`    → list paired devices (so you know what to revoke).
//!   `portty-host revoke`   → forget a paired device's reconnect token (D2 fix).
//!
//! The SessionManager (`session.rs`) is the shared core all modes front.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use std::collections::HashMap;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

mod active;
mod error;
mod file_transfer;
mod iroh_serve;
mod keepalive;
mod pair_confirm;
mod push;
mod relay_pipe;
mod session;
mod workspace;
use error::HostResult;
use portty_protocol::relay::{HostToRelay, RelayToHost};
use portty_protocol::SessionId;
use portty_transport::{DeviceId, PeerStore};
use session::{scrollback_cap_from_env, ManagerEvent, OutputChunk, Session, SessionManager};

// Vendored locally (no CDN) so the page runs under a strict CSP with no remote
// script/style. Bumping xterm means replacing these files under `web/`.
const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const XTERM_JS: &str = include_str!("../web/xterm.js");
const XTERM_FIT_JS: &str = include_str!("../web/xterm-addon-fit.js");
const XTERM_CSS: &str = include_str!("../web/xterm.css");

/// Strict CSP for the local terminal page: no remote origins, no inline script,
/// and connections restricted to this same loopback server. `style-src` allows
/// inline styles because xterm.js injects `<style>` at runtime.
const CSP: &str = "default-src 'none'; \
    script-src 'self'; \
    style-src 'self' 'unsafe-inline'; \
    img-src 'self' data:; \
    font-src 'self'; \
    connect-src 'self'; \
    base-uri 'none'; \
    form-action 'none'; \
    frame-ancestors 'none'";

/// The loopback terminal server binds here by default; `PORTTY_LOCAL_ADDR`
/// overrides it (e.g. on a port conflict). It must stay a loopback address.
const DEFAULT_LOCAL_ADDR: &str = "127.0.0.1:9876";

fn local_addr() -> String {
    let Ok(v) = std::env::var("PORTTY_LOCAL_ADDR") else {
        return DEFAULT_LOCAL_ADDR.into();
    };
    // The local terminal is authenticated only by a capability token and an
    // Origin check - NOT a network boundary. It must never bind off-loopback
    // (e.g. 0.0.0.0), which would expose the token-bearing page to the LAN.
    match v.parse::<std::net::SocketAddr>() {
        Ok(sa) if sa.ip().is_loopback() => v,
        Ok(sa) => {
            eprintln!(
                "PORTTY_LOCAL_ADDR={v} is not a loopback address ({}); refusing to expose the \
                 local terminal off-host. Falling back to {DEFAULT_LOCAL_ADDR}.",
                sa.ip()
            );
            DEFAULT_LOCAL_ADDR.into()
        }
        Err(_) => {
            eprintln!(
                "PORTTY_LOCAL_ADDR={v} is not a valid host:port; using {DEFAULT_LOCAL_ADDR}."
            );
            DEFAULT_LOCAL_ADDR.into()
        }
    }
}

/// Browser origins allowed to open the control WS: the exact bound address plus
/// the two common loopback spellings a user might type.
fn allowed_origins(addr: &str) -> Vec<String> {
    let port = addr.rsplit(':').next().unwrap_or("9876");
    let mut origins = vec![
        format!("http://{addr}"),
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ];
    origins.sort();
    origins.dedup();
    origins
}

/// Shared router state: the session core, the per-startup capability token that
/// authenticates the local browser, and the origins allowed to connect.
#[derive(Clone)]
struct AppState {
    mgr: SessionManager,
    token: Arc<str>,
    origins: Arc<[String]>,
}

/// A fresh 256-bit hex token minted once per process start. It's handed to the
/// user in the printed page URL (not embedded in the served HTML) and required
/// as `?token=` on the WS upgrade, so neither a hostile webpage nor a local
/// process that merely fetches `/` can open the control channel.
fn mint_token() -> Arc<str> {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    Arc::from(hex::encode(bytes))
}

/// Sync entry: parse args, optionally daemonize (BEFORE the tokio runtime - fork
/// is unsound once the runtime's threads exist), then run the chosen mode on a
/// manually-built multi-thread runtime.
fn main() -> HostResult<()> {
    // FIRST thing, before any mode runs and before anything can fork: take the
    // relay bearer secrets out of this process's environment.
    //
    // Doing it lazily inside `push::configured` was not enough. `proof` mode never
    // calls it at all yet still launches ACP adapters, and the keep-awake child is
    // spawned before it in the normal modes - so those children inherited the
    // credentials. Scrubbing at entry means there is no ordering left to get
    // wrong: every child of this process, in every mode, starts without them.
    push::take_secret_env();

    // Bare `portty-host` is the end-user path and backgrounds by default. An
    // explicit mode stays foreground so launchd/systemd can supervise
    // `portty-host serve`; `--detach` and `--foreground` override that choice.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help" | "help"))
    {
        print_host_usage();
        return Ok(());
    }
    if raw
        .iter()
        .any(|arg| matches!(arg.as_str(), "-V" | "--version" | "version"))
    {
        println!("portty-host {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if let Some(flag) = raw.iter().find(|arg| {
        arg.starts_with('-') && !matches!(arg.as_str(), "--detach" | "-d" | "--foreground" | "-f")
    }) {
        eprintln!("portty-host: unknown option `{flag}`\n");
        print_host_usage();
        std::process::exit(2);
    }
    let explicit_detach = raw.iter().any(|a| a == "--detach" || a == "-d");
    let foreground = raw.iter().any(|a| a == "--foreground" || a == "-f");
    if explicit_detach && foreground {
        eprintln!("portty-host: --detach and --foreground cannot be used together");
        std::process::exit(2);
    }
    let positionals: Vec<&String> = raw.iter().filter(|a| !a.starts_with('-')).collect();
    let explicit_mode = !positionals.is_empty();
    let mode = positionals
        .first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "both".into());
    if (positionals.len() > 1 && mode != "revoke") || positionals.len() > 2 {
        eprintln!("portty-host: too many arguments\n");
        print_host_usage();
        std::process::exit(2);
    }
    let revoke_target = positionals.get(1).map(|s| s.to_string());
    let detach = should_detach(explicit_mode, explicit_detach, foreground);

    #[cfg(windows)]
    if detach && matches!(mode.as_str(), "both" | "serve") {
        return launch_windows_daemon(&mode);
    }

    // Daemonize before starting the runtime. Only the connection modes make sense
    // to background; the short-lived subcommands run in the foreground regardless.
    if detach && matches!(mode.as_str(), "both" | "serve") {
        #[cfg(unix)]
        {
            iroh_serve::daemonize()?;
            iroh_serve::DETACHED.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    if std::env::var_os("PORTTY_HOST_DETACHED_CHILD").is_some() {
        // This marker is only for the daemon bootstrap. Do not let shells and
        // agent subprocesses inherit an internal lifecycle flag.
        std::env::remove_var("PORTTY_HOST_DETACHED_CHILD");
        iroh_serve::DETACHED.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_mode(mode, revoke_target))
}

async fn run_mode(mode: String, revoke_target: Option<String>) -> HostResult<()> {
    match mode.as_str() {
        // Default: local browser terminal + phone pairing, same shells. Starts
        // with NO sessions - terminals appear when you run `portty share` or tap
        // "New session" on the phone.
        "both" => {
            let _pid = PidFile::create(&app_data_dir());
            run_both().await
        }
        // Phone only (iroh), no local browser.
        "serve" => {
            let _pid = PidFile::create(&app_data_dir());
            iroh_serve::serve(&app_data_dir(), 0).await
        }
        // Local browser only (no iroh) - offline UI/PTY development.
        "proof" => run_proof().await,
        // List paired devices (so you know what to revoke).
        "peers" => list_peers(&app_data_dir()),
        // Revoke a paired device by DeviceId hex (or `all`). Locks the phone out
        // of reconnect-by-token; restart the host to also rotate the PIN.
        "revoke" => revoke_cmd(&app_data_dir(), revoke_target).await,
        // Is a host daemon running? (reads the PID file + active-state mirror.)
        "status" => status_cmd(&app_data_dir()),
        // Ask a running daemon to shut down over its authenticated local pipe.
        "stop" => stop_cmd(&app_data_dir()).await,
        other => {
            eprintln!("portty-host: unknown command `{other}`\n");
            print_host_usage();
            std::process::exit(2);
        }
    }
}

fn print_host_usage() {
    eprintln!("Portty host daemon");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  portty-host [both]           connect a phone; background after pairing");
    eprintln!("  portty-host --foreground     connect a phone and keep logs in this terminal");
    eprintln!("  portty-host serve            foreground phone host (for launchd/systemd)");
    eprintln!("  portty-host proof            local browser-only proof mode");
    eprintln!("  portty-host peers            list paired devices (+ who's connected)");
    eprintln!("  portty-host revoke <id|all>  revoke paired devices and drop them live");
    eprintln!("  portty-host status           report whether the daemon is running");
    eprintln!("  portty-host stop             stop the running daemon");
    eprintln!("  portty-host --version        print the installed version");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -d, --detach                 background an explicit connection mode");
    eprintln!("  -f, --foreground             keep a bare invocation in this terminal");
    eprintln!("  -h, --help                   print this help without starting the daemon");
}

/// Bare invocation is the friendly background daemon. Explicit modes remain
/// foreground unless `--detach` is supplied, so service managers retain the
/// child process they supervise.
fn should_detach(explicit_mode: bool, explicit_detach: bool, foreground: bool) -> bool {
    explicit_detach || (!explicit_mode && !foreground)
}

/// Windows has no `fork`, so launch a fresh foreground child in a detached,
/// no-console process group. The parent waits until the authenticated relay pipe
/// answers - proving the daemon came up - and exits.
///
/// It deliberately does NOT ask the child for pairing credentials. It used to,
/// which made every `portty-host` launch mint and print a complete key to this
/// machine and open a five-minute window for it, exactly like the Unix startup
/// banner did. Pairing is now only ever armed by an explicit `portty pair`.
#[cfg(windows)]
fn launch_windows_daemon(mode: &str) -> HostResult<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS,
    };

    let dir = app_data_dir();
    if let Some(pid) = read_pid(&dir).filter(|pid| pid_alive(*pid)) {
        return Err(error::HostError::Relay(format!(
            "another host is already running (pid {pid}); use `portty pair` to enroll a phone"
        )));
    }

    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    // Hand the push credentials to the child EXPLICITLY. `main` scrubbed them
    // from this process's environment before anything could fork, which is right
    // on Unix - the daemon is this process, and it keeps the in-memory snapshot.
    // Windows has no fork, so the daemon is this fresh child, and without this it
    // came up with no fixed host secret and no operator token: push registration
    // just failed. The child scrubs them again as its own first statement, before
    // it can spawn a shell or an adapter. See `push::restore_secret_env_for_relaunch`.
    let restored = push::restore_secret_env_for_relaunch(&mut command);
    if !restored.is_empty() {
        // Names only, never values. Worth saying out loud: when this silently did
        // not happen, the symptom was a daemon whose push registration failed for
        // no visible reason. stderr, so it stays out of the pairing output.
        eprintln!(
            "portty-host: passing {} to the background host",
            restored.join(", ")
        );
    }
    let child = command
        .arg(mode)
        .arg("--foreground")
        .env("PORTTY_HOST_DETACHED_CHILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .spawn()?;
    println!(
        "Portty host started in the background (pid {}).",
        child.id()
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(wait_for_windows_daemon(child.id()))
}

/// Wait until the freshly-spawned background daemon answers its relay pipe.
///
/// `Shutdown` would stop it and `ReopenPairing` would arm a credential, so
/// readiness is probed with neither: any answer at all - including a refusal -
/// proves the pipe is up, which is the only thing being asked.
#[cfg(windows)]
async fn wait_for_windows_daemon(pid: u32) -> HostResult<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match send_daemon_control(RelayToHost::Ping).await {
            Ok(HostToRelay::Pong) => {
                println!();
                println!("==========================================================");
                println!("  Portty host is running.");
                println!();
                println!("  Pairing is CLOSED. To add a phone, run:");
                println!();
                println!("      portty pair");
                println!();
                println!("  That prints a QR, waits for the phone, and asks you to");
                println!("  confirm the 6-digit code it shows.");
                println!("==========================================================");
                println!();
                return Ok(());
            }
            // A reply of the wrong shape means a daemon we cannot talk to.
            Ok(other) => {
                return Err(error::HostError::Relay(format!(
                    "background host answered a readiness probe with {other:?}; \
                     rebuild the portty CLI and daemon from the same version"
                )));
            }
            Err(error) if tokio::time::Instant::now() < deadline && pid_alive(pid) => {
                tracing::debug!(%error, "waiting for background host relay pipe");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => {
                return Err(error::HostError::Relay(format!(
                    "background host did not become ready: {error}; check `portty-host status`"
                )));
            }
        }
    }
}

/// Per-user app-data dir for the device identity, PID file, and peer store.
/// `PORTTY_DATA_DIR` overrides it (isolated instances / testing); otherwise the
/// platform per-user data dir, falling back to a local dir.
///
/// **Windows uses the LOCAL data dir, not the roaming one.** The identity key and
/// reconnect tokens are device-bound credentials: a copied identity is a copied
/// credential. `ProjectDirs::data_dir()` on Windows is `%APPDATA%` (Roaming),
/// which a domain profile service can replicate to every machine the user logs
/// into, so the daemon's credentials could quietly appear on other hosts.
/// `data_local_dir()` is `%LOCALAPPDATA%`, which stays on this machine - the same
/// intent as the Android `dataExtractionRules` exclusion and the Apple
/// `NSURLIsExcludedFromBackupKey` flag. Unix is unaffected (both resolve to the
/// same XDG data dir on Linux, and the same Application Support dir on macOS).
fn app_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("PORTTY_DATA_DIR") {
        return PathBuf::from(p);
    }
    if let Some(dirs) =
        directories::ProjectDirs::from("org.example", "Corvux Mindware", "Portty")
    {
        let local = dirs.data_local_dir().to_path_buf();
        // No cfg needed: on Linux and macOS both dirs resolve to the same path,
        // so this returns immediately there. Keeping it unconditional means the
        // Windows-only path still type-checks and is unit-tested everywhere.
        migrate_credentials_off_roaming(dirs.data_dir(), &local);
        return local;
    }
    PathBuf::from("./portty-data")
}

/// One-time move of an existing install's credentials out of the roaming profile.
///
/// Copy, verify, then delete the source, so an interrupted migration leaves the
/// old location intact and the next run retries. Anything that fails is only
/// logged: a host that cannot migrate must still start, and the worst case is
/// that the user re-pairs.
///
/// A no-op wherever the two directories are the same path (Linux, macOS).
fn migrate_credentials_off_roaming(roaming: &std::path::Path, local: &std::path::Path) {
    use portty_transport::credential_store::{
        IDENTITY_RECORD, LAST_HOST_RECORD, PAIR_STATE_RECORD, PEERS_RECORD, REVOCATIONS_RECORD,
    };
    if roaming == local || !roaming.join(IDENTITY_RECORD).exists() {
        return;
    }
    // A local identity already exists: this machine has its own credentials, so
    // the roaming copy is stale. Leave it alone rather than clobber a live one.
    if local.join(IDENTITY_RECORD).exists() {
        return;
    }
    if let Err(error) = portty_transport::secure::prepare_secret_dir(local) {
        tracing::warn!(%error, "cannot prepare local credential directory; staying on the roaming profile");
        return;
    }
    // IDENTITY GOES LAST, and everything else must succeed first.
    //
    // The gate above is "roaming has an identity and local does not", so the
    // identity file is what makes the migration look done. Moving it first meant a
    // failure partway through left an identity in the new location with its peer
    // tokens and revocation tombstones still in the old one - and the next run saw
    // a local identity, decided there was nothing to migrate, and permanently
    // stranded them. Leaving the identity behind until the rest has landed makes an
    // interrupted migration retry on the next start instead.
    let mut moved_all = true;
    for record in [
        PEERS_RECORD,
        LAST_HOST_RECORD,
        PAIR_STATE_RECORD,
        REVOCATIONS_RECORD,
        IDENTITY_RECORD,
    ] {
        if record == IDENTITY_RECORD && !moved_all {
            tracing::warn!(
                "leaving the identity in the roaming profile so this migration retries; \
                 pairings would otherwise be stranded there"
            );
            break;
        }
        let from = roaming.join(record);
        if !from.exists() {
            continue;
        }
        let to = local.join(record);
        let moved = std::fs::read(&from).and_then(|bytes| {
            portty_transport::secure::write_owner_only(&to, &bytes)?;
            // Verify before removing the only other copy.
            if std::fs::read(&to)? == bytes {
                Ok(())
            } else {
                Err(std::io::Error::other("migrated credential does not match"))
            }
        });
        match moved {
            Ok(()) => {
                if let Err(error) = std::fs::remove_file(&from) {
                    tracing::warn!(record, %error, "migrated credential but could not remove the roaming copy");
                } else {
                    tracing::info!(record, "moved credential out of the roaming profile");
                }
            }
            Err(error) => {
                moved_all = false;
                tracing::warn!(record, %error, "could not migrate credential off the roaming profile");
            }
        }
    }
}

// ── daemon lifecycle: PID file + status/stop ────────────────────────────

fn pid_path(dir: &std::path::Path) -> PathBuf {
    dir.join("portty-host.pid")
}

/// Best-effort check that process `pid` is alive.
#[cfg(unix)]
pub(crate) fn pid_alive(pid: u32) -> bool {
    // kill(pid, 0) probes existence without delivering a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}
#[cfg(windows)]
pub(crate) fn pid_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // OpenProcess returns null for a pid that isn't a running process - so a
    // stale PID file no longer looks "live" forever (which would block restart).
    //
    // OpenProcess succeeding is NOT enough, though: Windows keeps a terminated
    // process's object (and therefore its pid) resolvable for as long as anyone
    // still holds a handle to it. A force-killed daemon whose parent shell still
    // holds that handle stayed "alive" forever here - `status` claimed RUNNING,
    // `stop` failed on the missing control pipe, and a fresh `portty-host`
    // refused to start until the pid file was deleted by hand. Ask for the exit
    // code too and only treat STILL_ACTIVE as running.
    // SAFETY: OpenProcess/GetExitCodeProcess/CloseHandle with a valid pid and a
    // handle we own; `code` is only read after a successful call.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let queried = GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        // If the probe itself fails we cannot prove the process is gone, so keep
        // the conservative answer: PidFile::create must never clobber a live
        // daemon's pid file on an inconclusive check.
        !queried || code == STILL_ACTIVE as u32
    }
}
#[cfg(not(any(unix, windows)))]
pub(crate) fn pid_alive(_pid: u32) -> bool {
    true // no cheap liveness probe on this platform; assume alive if file exists
}

/// Drop the on-disk traces of a daemon that is no longer there: its PID file
/// (which otherwise blocks the next `portty-host` start) and the connected-device
/// mirror (which otherwise keeps reporting phones as connected).
fn clear_daemon_state(dir: &std::path::Path) {
    let _ = std::fs::remove_file(pid_path(dir));
    active::ActiveState::clear_connected(dir);
}

fn read_pid(dir: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(pid_path(dir))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Writes the daemon's PID on creation and removes it on clean shutdown (Drop).
/// A `kill -9` leaves a stale file; readers verify liveness with [`pid_alive`].
struct PidFile {
    path: PathBuf,
}

impl PidFile {
    fn create(dir: &std::path::Path) -> Option<Self> {
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::warn!(error = %e, "pidfile: could not create data dir");
            return None;
        }
        let path = pid_path(dir);
        // Refuse to clobber a live daemon's PID file (two hosts would fight over
        // the same identity/ports).
        if let Some(existing) = read_pid(dir) {
            if pid_alive(existing) && existing != std::process::id() {
                eprintln!("portty-host: another host is already running (pid {existing}).");
                eprintln!("  Stop it with `portty-host stop`, or check `portty-host status`.");
                // Exit SUCCESS, not failure: the daemon's job is already being
                // done by pid {existing}, so this instance stepping aside is not
                // an error. Exiting non-zero here made launchd (KeepAlive
                // SuccessfulExit=false) and systemd (Restart=on-failure) treat it
                // as a crash and relaunch immediately - a tight restart-loop that
                // hammered the machine (#62). A clean exit(0) stops the loop.
                std::process::exit(0);
            }
        }
        if let Err(e) = std::fs::write(&path, std::process::id().to_string()) {
            tracing::warn!(error = %e, "pidfile: could not write");
            return None;
        }
        Some(Self { path })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `portty-host status` - is a daemon running, and who's connected?
fn status_cmd(dir: &std::path::Path) -> HostResult<()> {
    match read_pid(dir) {
        Some(pid) if pid_alive(pid) => {
            println!("Portty host is RUNNING (pid {pid}).");
            let active = active::ActiveState::load(dir);
            let n = active.connected.len();
            if active.daemon_alive() && n > 0 {
                println!("  {n} device(s) connected. See `portty-host peers` for detail.");
            } else {
                println!("  No devices connected.");
            }
        }
        Some(_) => println!("Portty host is NOT running (stale pid file)."),
        None => println!("Portty host is NOT running."),
    }
    Ok(())
}

/// `portty-host stop` - ask a running daemon to shut down over the same-user
/// local management pipe. This works on Windows and Unix and lets the daemon
/// drop its PID/keep-awake guards cleanly.
async fn stop_cmd(dir: &std::path::Path) -> HostResult<()> {
    let Some(pid) = read_pid(dir) else {
        println!("Portty host is not running (no pid file).");
        return Ok(());
    };
    if !pid_alive(pid) {
        println!("Portty host is not running (stale pid file); cleaning up.");
        clear_daemon_state(dir);
        return Ok(());
    }
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        send_daemon_control(RelayToHost::Shutdown),
    )
    .await
    .map_err(|_| error::HostError::Relay("daemon stop request timed out".into()))?;
    let response = match response {
        Ok(response) => response,
        // No control endpoint (Windows: the named pipe doesn't exist; Unix: no
        // socket) means nothing is listening, however live pid {pid} looked. The
        // raw `Io(Os { code: 2, .. })` this used to surface told the user nothing,
        // so name the situation and clear the state that caused it.
        Err(error::HostError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("Portty host is not reachable (pid {pid} has no control channel).");
            println!("  The daemon was most likely force-killed. Cleaning up its leftover state;");
            println!("  start a new host with `portty-host`.");
            clear_daemon_state(dir);
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if !matches!(response, HostToRelay::ShutdownAccepted) {
        return Err(error::HostError::Relay(
            "daemon returned an unexpected stop response".into(),
        ));
    }

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while pid_alive(pid) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    if pid_alive(pid) {
        return Err(error::HostError::Relay(format!(
            "daemon pid {pid} acknowledged shutdown but did not exit within 5 seconds"
        )));
    }
    println!("Portty host stopped (pid {pid}).");
    Ok(())
}

// ── proof mode (local WebSocket + xterm.js, no iroh) ─────────────────

async fn run_proof() -> HostResult<()> {
    let mgr = SessionManager::new_with_cap(scrollback_cap_from_env());
    // Same workspace folder as the phone path (see iroh_serve::workspace_dir).
    let ws = iroh_serve::workspace_dir();
    mgr.spawn_shell(Some(ws.clone()), Some("session 1".into()))
        .await?;
    mgr.spawn_shell(Some(ws), Some("session 2".into())).await?;
    // Also accept `portty share` relays so adopted terminals show up locally.
    // No pairing here - proof mode has no iroh side to pair with.
    relay_pipe::spawn(mgr.clone(), None, None, None, None);
    local_terminal_server(mgr).await
}

/// Serve a SessionManager to a local browser xterm.js client at
/// http://127.0.0.1:9876. Shared by `run_proof` and `run_both` so the SAME
/// shells are reachable from a local browser and (in "both" mode) a phone.
async fn local_terminal_server(mgr: SessionManager) -> HostResult<()> {
    let addr = local_addr();
    let token = mint_token();
    let state = AppState {
        mgr,
        token: token.clone(),
        origins: allowed_origins(&addr).into(),
    };
    let app = Router::new()
        .route("/", get(index))
        .route(
            "/app.js",
            get(|| asset(APP_JS, "text/javascript; charset=utf-8")),
        )
        .route(
            "/xterm.js",
            get(|| asset(XTERM_JS, "text/javascript; charset=utf-8")),
        )
        .route(
            "/xterm-addon-fit.js",
            get(|| asset(XTERM_FIT_JS, "text/javascript; charset=utf-8")),
        )
        .route(
            "/xterm.css",
            get(|| asset(XTERM_CSS, "text/css; charset=utf-8")),
        )
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                tracing::error!(
                    "local terminal address {addr} is already in use - another Portty host \
                     or process holds it. The phone/iroh path is unaffected; set \
                     PORTTY_LOCAL_ADDR to a free loopback port to re-enable the browser \
                     terminal."
                );
            }
            return Err(e.into());
        }
    };
    println!();
    // The token lives in the URL, NOT in the served page - so another local
    // process can't just GET / and read it.
    //
    // And it is printed to a TERMINAL only. Under systemd/launchd this stdout IS
    // the service log, and the audit finding about credentials in service logs
    // applies to this line exactly as much as it did to the pairing banner: this
    // token is full terminal control, so a log reader or a compromised log
    // shipper would get shell access from it on every restart.
    //
    // Withholding it costs nothing. The token is minted fresh per process start
    // and delivered ONLY here, so in a supervised service - where nobody is
    // sitting at a console to copy a URL - the browser terminal is already
    // unusable. Printing it there hands a credential to log readers and to
    // nobody else.
    if std::io::stdout().is_terminal() {
        println!("  Local terminal  → http://{addr}/?token={token}");
        println!(
            "  (Anyone who opens this exact URL controls your terminals - treat it like a password.)"
        );
    } else {
        println!("  Local terminal  → http://{addr}/  (capability URL withheld)");
        println!(
            "  This output is not a terminal, so the token is not printed - it would be a \
             shell-access credential in your service log. Run the host from a terminal to get it."
        );
    }
    println!();
    tracing::info!("Portty local terminal serving on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// "both" mode (default): ONE set of shells, reachable from BOTH a local
/// browser (http://127.0.0.1:9876) AND a paired phone over iroh. The local
/// terminal server and the iroh accept loop run concurrently on the same
/// SessionManager; the host exits when either one stops.
async fn run_both() -> HostResult<()> {
    // Hold a keep-awake inhibitor for the whole serve lifetime so a laptop host
    // doesn't idle-sleep while waiting for the phone to reach it (D1 fix).
    let _keep = keepalive::KeepAwake::activate();
    // The accept path reads LIVE credentials from the guard, so a `portty pair`
    // rotation takes effect without a restart.
    let (mgr, endpoint, did, peers, guard, pairing) = iroh_serve::setup(&app_data_dir(), 0).await?;
    // Accept `portty share` relays alongside the local browser + phone, and
    // `portty pair` requests to re-arm the enrollment window.
    let active = active::ActiveDevices::new(&app_data_dir());
    let push_ctx = push::configured(&app_data_dir());
    let (upload_cleanup, stale_uploads_removed) =
        file_transfer::UploadCleanup::open(&app_data_dir())?;
    if stale_uploads_removed > 0 {
        tracing::info!(
            stale_uploads_removed,
            "removed stale upload temporary files"
        );
    }
    relay_pipe::spawn(
        mgr.clone(),
        Some(pairing),
        Some(peers.clone()),
        Some(active.clone()),
        push_ctx.clone(),
    );
    // The loopback browser server is a CONVENIENCE, not the daemon's reason to
    // live. Run it as its OWN task so a busy port (a leftover process or a second
    // daemon holding 9876) can never take down the iroh accept loop - and with it
    // phone connectivity. It used to be a `select!` arm, so any bind/serve error
    // ended run_both and the whole daemon exited within ~1s, silently dropping the
    // phone even though the failure had nothing to do with iroh.
    let local_mgr = mgr.clone();
    let local_task = tokio::spawn(async move {
        if let Err(e) = local_terminal_server(local_mgr).await {
            tracing::error!("local terminal server unavailable (phone/iroh unaffected): {e}");
        }
    });
    let remote = iroh_serve::accept_loop(
        endpoint.clone(),
        mgr,
        did,
        peers,
        guard,
        app_data_dir(),
        active,
        push_ctx,
        upload_cleanup,
    );
    tokio::select! {
        _ = remote => {
            tracing::info!("iroh accept loop stopped");
        }
        // Graceful stop: return so `_keep` and the caller's PID-file guard drop.
        _ = iroh_serve::shutdown_signal() => {
            tracing::info!("shutdown signal; stopping host");
        }
    }
    local_task.abort();
    endpoint.close().await;
    Ok(())
}

async fn index() -> Response {
    // The page carries NO token - the browser reads it from the URL query string
    // (see app.js). Serving `/` therefore reveals nothing a local snooper can use.
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        INDEX_HTML,
    )
        .into_response()
}

/// Serve a vendored static asset with the strict CSP and a long cache lifetime
/// (contents are pinned at compile time, so caching is safe).
async fn asset(body: &'static str, content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    // Origin gate: a browser ALWAYS sends `Origin` on a WS upgrade, so we
    // require one and require it to match a bound-page origin - a page served
    // from any other site (a hostile webpage driving the terminal) is rejected
    // before the token is even considered. A MISSING Origin is treated as
    // untrusted too: it can't be the legitimate local browser, and skipping the
    // check for it used to let Origin-less clients past this gate entirely. The
    // 256-bit token is still the real authenticator; this is defense in depth.
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(origin) if state.origins.iter().any(|o| o == origin) => {}
        Some(origin) => {
            tracing::warn!(%origin, "rejected WS upgrade from foreign origin");
            return (StatusCode::FORBIDDEN, "bad origin").into_response();
        }
        None => {
            tracing::warn!("rejected WS upgrade with no Origin header");
            return (StatusCode::FORBIDDEN, "missing origin").into_response();
        }
    }
    // Capability token: constant-time compare against the per-startup secret.
    let supplied = params.get("token").map(String::as_str).unwrap_or("");
    let ok: bool = supplied.as_bytes().ct_eq(state.token.as_bytes()).into();
    if !ok {
        tracing::warn!("rejected WS upgrade with missing/invalid token");
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state.mgr))
}

/// Bounded outbound queue to the local browser. Same rationale as the phone
/// path: a fast producer + a slow (or paused) browser must not grow RAM without
/// limit; when it fills, forwarders backpressure and the broadcast Lags, which
/// is recovered by resending scrollback.
const WS_QUEUE_FRAMES: usize = 64;

/// The write half of the browser WebSocket (frames the select loop owns).
type WsSender = futures_util::stream::SplitSink<WebSocket, Message>;

/// One browser client. All output to the browser funnels through a single mpsc
/// so the select loop only has two branches (client cmd in, msgs out). The WS
/// harness speaks JSON; the iroh path (`iroh_serve.rs`) speaks postcard Frames.
async fn handle_socket(socket: WebSocket, mgr: SessionManager) {
    use std::sync::atomic::{AtomicU64, Ordering};

    let (mut sender, mut receiver) = socket.split();

    let list = mgr.list().await;
    let _ = sender
        .send(Message::Text(
            json!({ "type": "list", "sessions": list.iter().map(info_json).collect::<Vec<_>>() })
                .to_string()
                .into(),
        ))
        .await;

    let (to_client_tx, mut to_client_rx) = mpsc::channel::<Message>(WS_QUEUE_FRAMES);
    let active_id = Arc::new(AtomicU64::new(0));

    {
        let tx = to_client_tx.clone();
        let mut events = mgr.subscribe_events();
        let active_id = active_id.clone();
        let mgr_ev = mgr.clone();
        tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            loop {
                let evt = match events.recv().await {
                    Ok(evt) => evt,
                    // Don't die on lag: resend the full list, then keep going.
                    Err(RecvError::Lagged(_)) => {
                        let list = mgr_ev.list().await;
                        let msg = json!({ "type": "list", "sessions": list.iter().map(info_json).collect::<Vec<_>>() }).to_string();
                        if tx.send(Message::Text(msg.into())).await.is_err() {
                            break;
                        }
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                };
                let msg = match evt {
                    ManagerEvent::Added(info) => {
                        Some(json!({ "type": "added", "info": info_json(&info) }).to_string())
                    }
                    ManagerEvent::Removed(id) => {
                        Some(json!({ "type": "removed", "id": id.0 }).to_string())
                    }
                    ManagerEvent::Activity(id) => {
                        if active_id.load(Ordering::Relaxed) != id.0 {
                            Some(json!({ "type": "activity", "id": id.0 }).to_string())
                        } else {
                            None
                        }
                    }
                    // The local proof is shell-only; surface agent permissions as a
                    // minimal JSON note (full agent UI is the phone/Tauri path).
                    ManagerEvent::AgentPermission {
                        id,
                        tool_call,
                        options,
                        ..
                    } => Some(
                        json!({
                            "type": "permission",
                            "id": id.0,
                            "title": tool_call.title,
                            "options": options.len()
                        })
                        .to_string(),
                    ),
                    // The local browser proof remains shell-only; structured
                    // agent rendering lives in the phone app.
                    ManagerEvent::AgentTimeline { .. } => None,
                    ManagerEvent::AgentPermissionResolved { .. } => None,
                    // The local proof drives its own resizes (dev tool, single
                    // viewer) - it has no match-width mode to feed.
                    ManagerEvent::Resized { .. } => None,
                };
                if let Some(msg) = msg {
                    if tx.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
            }
        });
    }

    let mut active_handle: Option<JoinHandle<()>> = None;

    loop {
        tokio::select! {
            biased;
            msg = to_client_rx.recv() => {
                let Some(msg) = msg else { break };
                if sender.send(msg).await.is_err() {
                    break;
                }
            }
            msg = receiver.next() => {
                let Some(res) = msg else { break; };
                let Ok(m) = res else { break; };
                match m {
                    Message::Text(text) => {
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
                        let cmd = v.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
                        match cmd {
                            "new" => {
                                let cwd = v.get("cwd").and_then(|c| c.as_str()).map(std::path::PathBuf::from);
                                let title = v.get("title").and_then(|c| c.as_str()).map(String::from);
                                if let Ok(id) = mgr.spawn_shell(cwd, title).await {
                                    active_id.store(id.0, Ordering::Relaxed);
                                    if attach_to(&mgr, id, &mut sender, &to_client_tx, &mut active_handle).await.is_err() { break; }
                                }
                            }
                            "attach" => {
                                let id = sid(&v);
                                active_id.store(id.0, Ordering::Relaxed);
                                if attach_to(&mgr, id, &mut sender, &to_client_tx, &mut active_handle).await.is_err() { break; }
                            }
                            "detach" => {
                                active_id.store(0, Ordering::Relaxed);
                                if let Some(h) = active_handle.take() { h.abort(); }
                            }
                            "input" => {
                                let id = sid(&v);
                                let data = v.get("data").and_then(|d| d.as_str()).unwrap_or("");
                                if let Some(s) = mgr.get(id).await {
                                    let _ = s.write_input(data.as_bytes());
                                }
                            }
                            "resize" => {
                                let id = sid(&v);
                                let cols = v.get("cols").and_then(|c| c.as_u64()).unwrap_or(80) as u16;
                                let rows = v.get("rows").and_then(|r| r.as_u64()).unwrap_or(24) as u16;
                                if let Some(s) = mgr.get(id).await {
                                    let _ = s.resize(cols, rows);
                                }
                            }
                            "kill" => {
                                let id = sid(&v);
                                if active_id.load(Ordering::Relaxed) == id.0 {
                                    active_id.store(0, Ordering::Relaxed);
                                }
                                mgr.kill(id).await;
                            }
                            _ => {}
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(bytes) => {
                        if sender.send(Message::Pong(bytes)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(h) = active_handle {
        h.abort();
    }
}

/// Terminal output travels as a binary WS frame: `[8-byte LE session id][raw
/// PTY bytes]`. Keeping it binary means the host stays a literal byte pipe -
/// no `String::from_utf8_lossy` round-trip that would corrupt non-UTF-8 output.
fn output_frame(id: SessionId, bytes: &[u8]) -> Message {
    let mut buf = Vec::with_capacity(8 + bytes.len());
    buf.extend_from_slice(&id.0.to_le_bytes());
    buf.extend_from_slice(bytes);
    Message::Binary(buf.into())
}

async fn attach_to(
    mgr: &SessionManager,
    id: SessionId,
    sender: &mut WsSender,
    to_client_tx: &mpsc::Sender<Message>,
    active_handle: &mut Option<JoinHandle<()>>,
) -> Result<(), axum::Error> {
    if let Some(h) = active_handle.take() {
        h.abort();
    }
    let Some(session) = mgr.get(id).await else {
        return Ok(());
    };

    // Atomic snapshot + subscription (no gap where live output could be lost),
    // written straight to the socket. app.js already reset xterm on attach, so
    // the snapshot renders clean; the forwarder owns the pre-obtained receiver.
    let (snap, _seq, rx) = session.snapshot_and_subscribe();
    sender.send(output_frame(id, &snap)).await?;

    let tx = to_client_tx.clone();
    *active_handle = Some(spawn_output_forwarder(session, rx, tx));
    Ok(())
}

/// JSON control message telling the browser to clear the terminal before the
/// snapshot that follows (so a lag-resync doesn't duplicate old output).
fn reset_msg(id: SessionId) -> Message {
    Message::Text(json!({ "type": "reset", "id": id.0 }).to_string().into())
}

fn spawn_output_forwarder(
    session: Arc<Session>,
    mut rx: tokio::sync::broadcast::Receiver<Arc<OutputChunk>>,
    tx: mpsc::Sender<Message>,
) -> JoinHandle<()> {
    let id = session.id();
    tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match rx.recv().await {
                Ok(chunk) => {
                    if tx.send(output_frame(id, &chunk.bytes)).await.is_err() {
                        break;
                    }
                    session.mark_seen();
                }
                // Slow browser: dropped live chunks. Reset then resend scrollback
                // so the client stays coherent (no duplication), then continue.
                Err(RecvError::Lagged(_)) => {
                    // Drop the lagged receiver's queued history and atomically
                    // pair a fresh receiver with this snapshot. Otherwise queued
                    // chunks already present in the snapshot would replay twice.
                    let (snap, _seq, fresh_rx) = session.snapshot_and_subscribe();
                    rx = fresh_rx;
                    if tx.send(reset_msg(id)).await.is_err() {
                        break;
                    }
                    if tx.send(output_frame(id, &snap)).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Closed) => break,
            }
        }
    })
}

fn sid(v: &serde_json::Value) -> SessionId {
    SessionId(v.get("id").and_then(|i| i.as_u64()).unwrap_or(0))
}

fn info_json(info: &portty_protocol::SessionInfo) -> serde_json::Value {
    let kind = match info.kind {
        portty_protocol::SessionKind::Shell => "shell",
        portty_protocol::SessionKind::Agent => "agent",
    };
    let source = match info.source {
        portty_protocol::SessionSource::Spawned => "spawned",
        portty_protocol::SessionSource::Adopted => "adopted",
    };
    json!({
        "id": info.id.0,
        "title": info.title,
        "kind": kind,
        "source": source,
        "has_activity": info.has_activity,
    })
}

// ── paired-device management (D2: instant-revoke) ───────────────────────
//
// `portty-host peers`  → list paired devices (their DeviceId hex).
// `portty-host revoke <id|all>` → forget a device's reconnect token so its
//   SEC-2 resume stops working. Restart the host afterwards to ALSO rotate the
//   pairing PIN - together that's a complete lockout of a lost/stolen phone.
// These are offline file edits on the peers store (the running host holds its
// own in-memory copy until restart); the restart is what makes it "instant."

/// `portty-host peers` - list every paired device's DeviceId (hex) and whether
/// the host holds a reconnect ticket for it.
fn list_peers(dir: &std::path::Path) -> HostResult<()> {
    let store = PeerStore::load(dir)?;
    if store.is_empty() {
        println!("No paired devices.");
        println!();
        println!("Pair a phone with `portty-host serve` (or `both`) first.");
        return Ok(());
    }
    let active = active::ActiveState::load(dir);
    let records = store.records();
    println!("Paired devices ({}):", records.len());
    for (did, rec) in &records {
        let ticket = if rec.ticket.is_some() {
            " (ticket)"
        } else {
            ""
        };
        // Live state comes from the running daemon's mirror file; a device shows
        // as connected only if that daemon is still alive.
        let state = if let Some(since) = active.connected_since(did) {
            format!("  ● connected ({} ago)", fmt_ago(since))
        } else if let Some(seen) = active.last_seen(did) {
            format!("  ○ last seen {} ago", fmt_ago(seen))
        } else {
            String::new()
        };
        println!("  {}{ticket}{state}", did.as_hex());
    }
    println!();
    if !active.daemon_alive() {
        println!("(no running host - connection state is unknown)");
        println!();
    }
    println!("Revoke one with:  portty-host revoke <hex-prefix>");
    println!("Revoke all with:  portty-host revoke all");
    println!("A running host drops a revoked phone within a couple of seconds.");
    Ok(())
}

/// Coarse "N units ago" from a unix-seconds timestamp (no chrono dependency).
fn fmt_ago(then_unix: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs = now.saturating_sub(then_unix);
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

/// `portty-host revoke <id|all>` - durably tombstone the matching pair(s).
async fn revoke_cmd(dir: &std::path::Path, target: Option<String>) -> HostResult<()> {
    let mut store = PeerStore::load(dir)?;
    let Some(target) = target else {
        eprintln!("usage: portty-host revoke <hex-prefix|all>");
        eprintln!();
        eprintln!("  List known devices first with: portty-host peers");
        std::process::exit(2);
    };
    let ids = match resolve_revoke_target(&store, &target) {
        Ok(ids) => ids,
        Err(msg) => {
            eprintln!("revoke: {msg}");
            eprintln!();
            eprintln!("  List known devices with: portty-host peers");
            std::process::exit(1);
        }
    };
    if ids.is_empty() {
        println!("No paired devices to revoke.");
        return Ok(());
    }
    let n = ids.len();
    let daemon_running = read_pid(dir).is_some_and(pid_alive);
    if daemon_running {
        let raw_ids: Vec<[u8; 16]> = ids.iter().map(|id| id.0).collect();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            send_daemon_control(RelayToHost::RevokeDevices {
                device_ids: raw_ids,
            }),
        )
        .await;
        let response = match result {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                eprintln!(
                    "revoke: running daemon did not accept the secure control request: {error}"
                );
                eprintln!(
                    "  No direct file fallback was attempted because it could race a handshake."
                );
                std::process::exit(1);
            }
            Err(_) => {
                eprintln!("revoke: running daemon did not answer within 5 seconds.");
                eprintln!(
                    "  No direct file fallback was attempted because it could race a handshake."
                );
                std::process::exit(1);
            }
        };
        match response {
            HostToRelay::RevocationResult {
                revoked,
                error: None,
            } if revoked.len() == n => {}
            HostToRelay::RevocationResult { revoked, error } => {
                eprintln!(
                    "revoke: daemon committed {} of {n} revocation(s): {}",
                    revoked.len(),
                    error.unwrap_or_else(|| "incomplete response".into())
                );
                std::process::exit(1);
            }
            _ => {
                eprintln!("revoke: daemon returned an unexpected control response");
                std::process::exit(1);
            }
        }
    } else {
        // Offline mutation is safe: there is no daemon handshake that can race
        // this write. The tombstone commits before token cleanup.
        for id in &ids {
            if let Err(e) = store.revoke(id) {
                eprintln!(
                    "revoke: FAILED to commit tombstone for {}: {e}",
                    id.as_hex()
                );
                eprintln!("  The device may still be able to reconnect - check disk/permissions.");
                std::process::exit(1);
            }
        }
    }
    println!(
        "Revoked {n} device(s): {}",
        ids.iter()
            .map(|d| d.as_hex())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();
    println!("The durable tombstone is active now. Reconnect-token authentication");
    println!("is blocked even if stale token cleanup is interrupted.");
    Ok(())
}

/// Speak one request/response exchange on the daemon's local management pipe.
///
/// The version handshake is NOT optional. The daemon gates every relay-pipe
/// connection on the relay-pipe version as its FIRST frame (#36), and
/// `portty-host`'s own control commands are peers on that same pipe. Without it
/// the daemon read the postcard `Shutdown` byte AS the version frame, rejected
/// the connection as skewed, and closed WITHOUT replying - so `stop` and
/// `revoke` died with a bare `UnexpectedEof` while the daemon kept running, and
/// the readiness `Ping` in `wait_for_windows_daemon` timed out on a host that
/// was actually up. The `portty` CLI always sent it; only this client did not.
async fn exchange_daemon_control<S>(mut stream: S, request: RelayToHost) -> HostResult<HostToRelay>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    relay_pipe::write_framed(
        &mut stream,
        &portty_protocol::relay::RELAY_PIPE_VERSION.to_le_bytes(),
    )
    .await?;
    let request = postcard::to_allocvec(&request)
        .map_err(|e| error::HostError::Serialization(e.to_string()))?;
    relay_pipe::write_framed(&mut stream, &request).await?;
    let response = relay_pipe::read_framed(&mut stream).await?;
    postcard::from_bytes(&response).map_err(|e| error::HostError::Serialization(e.to_string()))
}

#[cfg(unix)]
async fn send_daemon_control(request: RelayToHost) -> HostResult<HostToRelay> {
    portty_protocol::relay::validate_socket_endpoint()?;
    let stream = tokio::net::UnixStream::connect(portty_protocol::relay::socket_path()).await?;
    let peer = stream.peer_cred()?;
    // SAFETY: getuid is always safe and cannot fail.
    if peer.uid() != unsafe { libc::getuid() } {
        return Err(error::HostError::Relay(
            "daemon control peer belongs to another user".into(),
        ));
    }
    exchange_daemon_control(stream, request).await
}

#[cfg(windows)]
async fn send_daemon_control(request: RelayToHost) -> HostResult<HostToRelay> {
    use portty_protocol::relay::{verify_named_pipe_peer, NamedPipePeer};
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::ClientOptions;

    let stream = ClientOptions::new().open(portty_protocol::relay::pipe_name()?)?;
    verify_named_pipe_peer(stream.as_raw_handle(), NamedPipePeer::Server)?;
    exchange_daemon_control(stream, request).await
}

#[cfg(not(any(unix, windows)))]
async fn send_daemon_control(_request: RelayToHost) -> HostResult<HostToRelay> {
    Err(error::HostError::Relay(
        "secure local daemon control is unsupported on this platform".into(),
    ))
}

/// Resolve a revoke target - `all`, an exact 32-char hex DeviceId, or a unique
/// hex prefix (so the short `abcd1234…` form the host logs is enough). Pure +
/// testable: never mutates the store.
fn resolve_revoke_target(store: &PeerStore, target: &str) -> Result<Vec<DeviceId>, String> {
    if target.eq_ignore_ascii_case("all") {
        return Ok(store.records().into_iter().map(|(d, _)| d).collect());
    }
    let records = store.records();
    // Exact full-id match wins outright.
    if let Some(id) = DeviceId::from_hex(target) {
        if records.iter().any(|(d, _)| *d == id) || store.is_revoked(&id) {
            return Ok(vec![id]);
        }
    }
    // Otherwise treat it as a case-insensitive hex prefix.
    let needle = target.to_ascii_lowercase();
    let hits: Vec<DeviceId> = records
        .into_iter()
        .map(|(d, _)| d)
        .filter(|d| d.as_hex().starts_with(&needle))
        .collect();
    match hits.len() {
        0 => Err(format!("no paired device matches `{target}`")),
        1 => Ok(hits),
        n => Err(format!(
            "`{target}` is ambiguous - {n} devices match; use more hex chars"
        )),
    }
}

#[cfg(test)]
mod pidfile_tests {
    use super::*;

    #[test]
    fn ipv6_loopback_origin_matches_bound_page() {
        let origins = allowed_origins("[::1]:9876");
        assert!(origins.iter().any(|origin| origin == "http://[::1]:9876"));
    }

    #[test]
    fn pidfile_write_read_and_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_pid(dir.path()).is_none(), "no pid file yet");
        {
            let _pid = PidFile::create(dir.path()).expect("create");
            let got = read_pid(dir.path()).expect("pid written");
            assert_eq!(got, std::process::id());
            assert!(pid_alive(got), "our own pid is alive");
        } // Drop removes the file.
        assert!(read_pid(dir.path()).is_none(), "pid file removed on drop");
    }

    #[test]
    fn stale_pid_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        // A pid that is (almost certainly) not a live process.
        std::fs::write(pid_path(dir.path()), "999999999").unwrap();
        assert!(
            !pid_alive(read_pid(dir.path()).unwrap()),
            "bogus pid not alive"
        );
    }

    /// A process that has exited is not alive even while someone still holds an
    /// open handle to it. On Windows that handle keeps the pid resolvable, so an
    /// `OpenProcess`-only probe called a force-killed daemon "running" forever:
    /// `status` lied, `stop` died on the missing control pipe, and a new host
    /// refused to start. `child` stays in scope on purpose - dropping it would
    /// close the handle and hide the bug.
    #[test]
    fn exited_process_with_a_live_handle_is_not_alive() {
        let mut child = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/C", "exit 0"])
                .spawn()
        } else {
            std::process::Command::new("true").spawn()
        }
        .expect("spawn helper process");
        let pid = child.id();
        child.wait().expect("helper exits");
        assert!(
            !pid_alive(pid),
            "pid {pid} exited, so it must not read as alive"
        );
        drop(child);
    }

    #[test]
    fn clearing_daemon_state_drops_pid_and_connections_but_keeps_history() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(pid_path(dir.path()), "999999999").unwrap();
        let device = DeviceId([7; 16]);
        let stale = active::ActiveState {
            daemon_pid: 999999999,
            connected: vec![active::ConnEntry {
                device_id: device,
                name: "phone".into(),
                since: 100,
            }],
            last_seen: HashMap::from([(device, 200)]),
        };
        std::fs::write(
            dir.path().join("portty-active.dat"),
            postcard::to_allocvec(&stale).unwrap(),
        )
        .unwrap();

        clear_daemon_state(dir.path());

        assert!(read_pid(dir.path()).is_none(), "pid file removed");
        let after = active::ActiveState::load(dir.path());
        assert!(after.connected.is_empty(), "stale connections dropped");
        assert!(!after.daemon_alive(), "no daemon claimed");
        assert_eq!(after.last_seen(&device), Some(200), "history preserved");
    }

    #[test]
    fn bare_host_backgrounds_but_service_mode_stays_foreground() {
        assert!(should_detach(false, false, false));
        assert!(!should_detach(false, false, true));
        assert!(!should_detach(true, false, false));
        assert!(should_detach(true, true, false));
    }

    /// The control client must send the relay-pipe version FIRST, then the
    /// request. This asserted only the request before, so the missing handshake
    /// that broke `stop`/`revoke`/readiness in production looked fine here.
    /// `relay_pipe::tests::daemon_control_survives_the_real_version_gate` drives
    /// the real daemon handler so the two halves cannot drift apart again.
    #[tokio::test]
    async fn daemon_control_round_trips_shutdown_ack() {
        let (client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let version = relay_pipe::read_framed(&mut server).await.unwrap();
            assert_eq!(
                version,
                portty_protocol::relay::RELAY_PIPE_VERSION
                    .to_le_bytes()
                    .to_vec(),
                "the version handshake is the first frame, like the CLI sends"
            );
            let frame = relay_pipe::read_framed(&mut server).await.unwrap();
            assert!(matches!(
                postcard::from_bytes::<RelayToHost>(&frame).unwrap(),
                RelayToHost::Shutdown
            ));
            let reply = postcard::to_allocvec(&HostToRelay::ShutdownAccepted).unwrap();
            relay_pipe::write_framed(&mut server, &reply).await.unwrap();
        });

        let reply = exchange_daemon_control(client, RelayToHost::Shutdown)
            .await
            .unwrap();
        assert!(matches!(reply, HostToRelay::ShutdownAccepted));
        server_task.await.unwrap();
    }
}

#[cfg(test)]
mod revoke_tests {
    use super::*;

    fn store_with(dids: &[DeviceId]) -> (tempfile::TempDir, PeerStore) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        for d in dids {
            // host side: remember with no ticket, a throwaway token.
            store.remember(*d, None, [0x01; 32]).unwrap();
        }
        (dir, store)
    }

    #[test]
    fn revoke_all_targets_every_device() {
        let (_guard, store) = store_with(&[DeviceId([1; 16]), DeviceId([2; 16])]);
        let ids = resolve_revoke_target(&store, "all").unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn revoke_by_exact_hex_matches_one() {
        let did = DeviceId([0xab; 16]);
        let (_guard, store) = store_with(&[DeviceId([1; 16]), did]);
        let hex = did.as_hex();
        let ids = resolve_revoke_target(&store, &hex).unwrap();
        assert_eq!(ids, vec![did]);
    }

    #[test]
    fn revoke_by_short_prefix_matches_one() {
        // The host logs DeviceId as the first 8 hex chars - that must be enough.
        let did = DeviceId([0xcd; 16]);
        let (_guard, store) = store_with(&[DeviceId([0x11; 16]), did]);
        let prefix = &did.as_hex()[..8];
        let ids = resolve_revoke_target(&store, prefix).unwrap();
        assert_eq!(ids, vec![did]);
    }

    #[test]
    fn revoke_ambiguous_prefix_errors() {
        // Both ids share the first byte (00...), so "00" is ambiguous.
        let a = DeviceId([0x00; 16]);
        let mut b = [0x00u8; 16];
        b[15] = 0xff;
        let (_guard, store) = store_with(&[a, DeviceId(b)]);
        let err = resolve_revoke_target(&store, "00").unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn revoke_unknown_target_errors() {
        let (_guard, store) = store_with(&[DeviceId([1; 16])]);
        let err = resolve_revoke_target(&store, "deadbeef").unwrap_err();
        assert!(err.contains("no paired device"), "{err}");
    }

    /// Windows shipped credentials in the ROAMING profile, which a domain
    /// profile service can replicate to every machine the user logs into. An
    /// existing install must end up with its identity local-only, with no copy
    /// left behind to roam.
    #[test]
    fn credentials_are_moved_out_of_the_roaming_profile_once() {
        use portty_transport::credential_store::{IDENTITY_RECORD, PEERS_RECORD};
        let base = tempfile::tempdir().unwrap();
        let roaming = base.path().join("Roaming");
        let local = base.path().join("Local");
        std::fs::create_dir_all(&roaming).unwrap();
        std::fs::write(roaming.join(IDENTITY_RECORD), b"identity-key").unwrap();
        std::fs::write(roaming.join(PEERS_RECORD), b"peer-tokens").unwrap();

        migrate_credentials_off_roaming(&roaming, &local);

        assert_eq!(
            std::fs::read(local.join(IDENTITY_RECORD)).unwrap(),
            b"identity-key"
        );
        assert_eq!(
            std::fs::read(local.join(PEERS_RECORD)).unwrap(),
            b"peer-tokens"
        );
        // Nothing left to roam.
        assert!(!roaming.join(IDENTITY_RECORD).exists());
        assert!(!roaming.join(PEERS_RECORD).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&local).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "local credential dir: {mode:o}");
        }
    }

    /// A machine that already has its own local identity keeps it: the roaming
    /// copy is stale and must never clobber a live credential.
    #[test]
    fn migration_never_overwrites_an_existing_local_identity() {
        use portty_transport::credential_store::IDENTITY_RECORD;
        let base = tempfile::tempdir().unwrap();
        let roaming = base.path().join("Roaming");
        let local = base.path().join("Local");
        std::fs::create_dir_all(&roaming).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(roaming.join(IDENTITY_RECORD), b"stale").unwrap();
        std::fs::write(local.join(IDENTITY_RECORD), b"live").unwrap();

        migrate_credentials_off_roaming(&roaming, &local);

        assert_eq!(std::fs::read(local.join(IDENTITY_RECORD)).unwrap(), b"live");
    }

    /// Where the two paths coincide (Linux, macOS) the migration must do nothing
    /// at all - not rewrite, not delete.
    #[test]
    fn migration_is_a_no_op_when_both_paths_are_the_same_dir() {
        use portty_transport::credential_store::IDENTITY_RECORD;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IDENTITY_RECORD), b"identity").unwrap();

        migrate_credentials_off_roaming(dir.path(), dir.path());

        assert_eq!(
            std::fs::read(dir.path().join(IDENTITY_RECORD)).unwrap(),
            b"identity"
        );
    }

    #[test]
    fn revoke_tombstones_persist_and_exact_id_can_refresh_them() {
        let (dir, mut store) = store_with(&[DeviceId([7; 16]), DeviceId([8; 16])]);
        let ids = resolve_revoke_target(&store, "all").unwrap();
        for id in &ids {
            store.revoke(id).unwrap();
        }
        // Reload from disk - both are absent from active peers but their
        // authoritative tombstones remain targetable by exact id.
        let reloaded = PeerStore::load(dir.path()).unwrap();
        assert!(reloaded.is_empty());
        assert!(reloaded.is_revoked(&ids[0]));
        assert_eq!(
            resolve_revoke_target(&reloaded, &ids[0].as_hex()).unwrap(),
            vec![ids[0]]
        );
    }
}
