//! Local relay-pipe messages: the `portty` relay CLI ↔ the host daemon.
//!
//! This is a SEPARATE wire contract from the phone `Frame` protocol. It rides a
//! local named pipe (Windows) / unix socket, never the iroh channel, so it can
//! evolve on its own. Still postcard-encoded; still treat it append-only
//! (add variants at the end) to avoid breaking a running daemon vs a new relay.
//!
//! Framing on the pipe is a `u32` little-endian length prefix followed by the
//! postcard bytes of one message (implemented in the host + cli, not here).

use serde::{Deserialize, Serialize};

use crate::{
    AgentConfigValue, AgentProvider, AgentTimelineEvent, PermissionOption, SessionId, ToolCallCard,
};

/// Maximum postcard message carried by the local relay pipe. Normal output
/// chunks are 4 KiB. The bound must also cover one agent message: an
/// `AgentEvent` carries up to 64 KiB of clamped text plus a similarly clamped
/// tool detail, and an `AgentPermission` carries up to 32 clamped options -
/// 256 KiB covers the worst case while still fitting inside the 1 MiB
/// encrypted phone frame after protocol and envelope overhead are added.
/// Raising this is skew-safe: old relays/daemons only ever exchange the small
/// terminal messages, and only a new CLI opts into the agent messages.
pub const MAX_RELAY_FRAME_BYTES: u32 = 256 * 1024;

/// Version of the LOCAL relay-pipe wire (host daemon ↔ `portty` CLI). This is
/// same-machine, same-binary - but a long-running daemon can face a
/// freshly-upgraded CLI. The CLI sends this as the first framed message on
/// every connection and the daemon rejects a mismatch, so skew fails fast
/// instead of silently mis-decoding the versioned ACP types these messages
/// embed (#36). Independent of the phone `PROTOCOL_VERSION`; bump on any
/// `RelayToHost` / `HostToRelay` schema change.
pub const RELAY_PIPE_VERSION: u16 = 2;

// v2 (2026-08-02): the pairing PIN is gone, and `Ping`/`Pong` were appended so a
// launcher can wait for a daemon without arming pairing as a side effect. `HostToRelay::PairingInfo` lost its
// `pin` field, and `portty pair` now stays connected to act as the console that
// confirms the post-exchange comparison code - see the appended
// `HostToRelay::PairingConfirmRequest` / `RelayToHost::PairingConfirmResponse`.
// Dropping a field from an existing variant is a hard break, hence the bump.

/// Windows named-pipe prefix. The concrete pipe name includes the current
/// user's SID so different logged-in users never contend for one global name.
#[cfg(windows)]
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\portty-relay-";

/// Per-user directory that holds the Unix relay socket. NEVER a world-shared
/// location like bare `/tmp` - the relay is a control channel that can inject
/// input into terminals, so it must be reachable only by its owner:
///   * `$XDG_RUNTIME_DIR/portty` - Linux; the runtime dir is already 0700/per-user.
///   * `$TMPDIR/portty` - macOS; `TMPDIR` is a per-user sandbox dir.
///   * `/tmp/portty-<uid>` - last resort; the host creates it 0700 and verifies
///     the peer's uid on every connection.
#[cfg(unix)]
pub fn socket_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(x).join("portty");
    }
    if let Some(t) = std::env::var_os("TMPDIR") {
        return PathBuf::from(t).join("portty");
    }
    // SAFETY: getuid is always safe and never fails.
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/portty-{uid}"))
}

/// Full path to the Unix relay socket (see [`socket_dir`]).
#[cfg(unix)]
pub fn socket_path() -> std::path::PathBuf {
    socket_dir().join("relay.sock")
}

/// Create (or tighten) the Unix relay directory, but only after proving that a
/// pre-existing entry is a real directory owned by this uid. In particular we
/// never chmod an attacker-controlled directory or follow a final-component
/// symlink in a shared parent such as `/tmp`.
#[cfg(unix)]
pub fn prepare_socket_dir() -> std::io::Result<std::path::PathBuf> {
    let dir = socket_dir();
    prepare_socket_dir_at(&dir)?;
    Ok(dir)
}

#[cfg(unix)]
fn prepare_socket_dir_at(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !dir.is_absolute() {
        return Err(relay_security_error(
            std::io::ErrorKind::InvalidInput,
            "relay socket directory must be an absolute path",
        ));
    }

    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    // Check ownership/type before changing permissions. `symlink_metadata`
    // deliberately inspects the final path component instead of following it.
    validate_socket_dir_at(dir, false)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    validate_socket_dir_at(dir, true)
}

/// Validate the existing Unix relay directory before a client connects.
#[cfg(unix)]
pub fn validate_socket_dir() -> std::io::Result<()> {
    validate_socket_dir_at(&socket_dir(), true)
}

#[cfg(unix)]
fn validate_socket_dir_at(dir: &std::path::Path, require_private: bool) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !dir.is_absolute() {
        return Err(relay_security_error(
            std::io::ErrorKind::InvalidInput,
            "relay socket directory must be an absolute path",
        ));
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(relay_security_error(
            std::io::ErrorKind::PermissionDenied,
            "relay socket directory is not a real directory",
        ));
    }
    // SAFETY: getuid is always safe and never fails.
    let our_uid = unsafe { libc::getuid() };
    if meta.uid() != our_uid {
        return Err(relay_security_error(
            std::io::ErrorKind::PermissionDenied,
            "relay socket directory is owned by another user",
        ));
    }
    if require_private && meta.mode() & 0o077 != 0 {
        return Err(relay_security_error(
            std::io::ErrorKind::PermissionDenied,
            "relay socket directory is accessible by another user",
        ));
    }
    Ok(())
}

/// Validate the socket file itself before connecting. This is paired with a
/// post-connect peer-uid check in the CLI, which closes the validation/connect
/// race and proves that the server process belongs to this user.
#[cfg(unix)]
pub fn validate_socket_endpoint() -> std::io::Result<()> {
    validate_socket_endpoint_at(&socket_path())
}

#[cfg(unix)]
fn validate_socket_endpoint_at(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let dir = path.parent().ok_or_else(|| {
        relay_security_error(
            std::io::ErrorKind::InvalidInput,
            "relay socket has no parent directory",
        )
    })?;
    validate_socket_dir_at(dir, true)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.file_type().is_symlink() {
        return Err(relay_security_error(
            std::io::ErrorKind::PermissionDenied,
            "relay endpoint is not a Unix socket",
        ));
    }
    // SAFETY: getuid is always safe and never fails.
    let our_uid = unsafe { libc::getuid() };
    if meta.uid() != our_uid || meta.mode() & 0o077 != 0 {
        return Err(relay_security_error(
            std::io::ErrorKind::PermissionDenied,
            "relay socket is not private to the current user",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn relay_security_error(kind: std::io::ErrorKind, message: &'static str) -> std::io::Error {
    std::io::Error::new(kind, message)
}

/// Return the Windows per-user pipe name. Encoding the caller's SID in the
/// name prevents cross-user collisions; connected-process SID verification
/// still provides the actual authorization check.
#[cfg(windows)]
pub fn pipe_name() -> std::io::Result<String> {
    let sid = windows_security::current_user_sid()?;
    let mut suffix = String::with_capacity(sid.len() * 2);
    for byte in sid {
        use std::fmt::Write as _;
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    Ok(format!("{PIPE_NAME_PREFIX}{suffix}"))
}

/// Verify that the process at the other end of a Windows named pipe runs as
/// the same Windows user as this process.
#[cfg(windows)]
// `HANDLE` is a pointer-shaped opaque kernel handle, not memory we dereference.
// Win32 validates it against the process handle table and returns
// ERROR_INVALID_HANDLE for a bogus value, so a wrong `pipe` is an error, not UB —
// the function stays safe.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn verify_named_pipe_peer(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    peer: NamedPipePeer,
) -> std::io::Result<()> {
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    };

    let mut pid = 0u32;
    // SAFETY: `pipe` is a live named-pipe handle and `pid` is writable.
    let ok = unsafe {
        match peer {
            NamedPipePeer::Client => GetNamedPipeClientProcessId(pipe, &mut pid),
            NamedPipePeer::Server => GetNamedPipeServerProcessId(pipe, &mut pid),
        }
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if windows_security::process_user_sid(pid)? != windows_security::current_user_sid()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "named-pipe peer belongs to another Windows user",
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
pub enum NamedPipePeer {
    Client,
    Server,
}

#[cfg(windows)]
mod windows_security {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper is constructed only from owned, non-null
            // process/token handles returned by Windows.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn current_user_sid() -> std::io::Result<Vec<u8>> {
        let mut token = ptr::null_mut();
        // SAFETY: the pseudo process handle is always valid for this process;
        // `token` receives an owned handle on success.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        token_user_sid(OwnedHandle(token))
    }

    pub(super) fn process_user_sid(pid: u32) -> std::io::Result<Vec<u8>> {
        // SAFETY: no pointers are involved; Windows validates the pid/access.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let process = OwnedHandle(process);
        let mut token = ptr::null_mut();
        // SAFETY: `process` is live and `token` receives an owned handle.
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        token_user_sid(OwnedHandle(token))
    }

    fn token_user_sid(token: OwnedHandle) -> std::io::Result<Vec<u8>> {
        let mut needed = 0u32;
        // First call obtains the required variable-size TOKEN_USER buffer.
        unsafe {
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Allocate as u64, not u8: the buffer is read back as a `TOKEN_USER`,
        // which contains a pointer and so needs pointer alignment. A `Vec<u8>`
        // has alignment 1, and dereferencing a `*const TOKEN_USER` derived from
        // it is undefined behaviour even where the allocator happens to hand back
        // an aligned block. `u64` satisfies the alignment on every Windows target
        // Portty builds for; rounding up keeps the capacity Windows asked for.
        let words = (needed as usize).div_ceil(std::mem::size_of::<u64>());
        let mut buffer = vec![0u64; words.max(1)];
        debug_assert!(buffer.as_ptr().cast::<TOKEN_USER>().is_aligned());
        // SAFETY: `buffer` is writable for at least `needed` bytes, is aligned for
        // TOKEN_USER, and lives until the SID has been copied below.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a successful TokenUser query initializes TOKEN_USER and its
        // SID pointer into the same live, correctly aligned allocation.
        let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        if sid_len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: Windows reports the exact valid SID byte length.
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_len) }.to_vec())
    }
}

/// relay → host. The relay owns a PTY in its own process; it registers that
/// terminal with the daemon and then streams its output.
#[derive(Clone, Serialize, Deserialize)]
pub enum RelayToHost {
    /// First message on the pipe: adopt this terminal. `cols`/`rows` seed the
    /// session size so a viewer attaching immediately renders sanely.
    Register { title: String, cols: u16, rows: u16 },
    /// Raw PTY output bytes (host never parses them - dumb byte pipe).
    Output(Vec<u8>),
    /// The wrapped shell exited; the daemon should drop the session.
    Exited,
    /// LEGACY (fixed-size model): part of the retired follow-the-typist size
    /// hand-off. New relays send `SizeChanged` instead; the daemon ignores this.
    /// The variant stays for wire compatibility (append-only enum).
    LocalTookSize,
    /// `portty pair`: reopen the daemon's first-pair enrollment window and
    /// return the current pairing credentials (`HostToRelay::PairingInfo`) so
    /// a NEW phone can pair without restarting the daemon. Sent as the FIRST
    /// frame instead of `Register`; the connection closes after the reply.
    /// Same-user-only via the socket's 0600/uid checks, like everything on
    /// this pipe. Append-only: after LocalTookSize.
    ReopenPairing,
    /// The LOCAL terminal was resized, so the relay resized its PTY to match.
    /// The laptop is the sole size owner for adopted sessions (fixed-size
    /// model); the daemon records this as the session's authoritative size and
    /// broadcasts it to viewers (`Frame::SessionSize`) so a phone in
    /// match-width mode follows. Append-only: after ReopenPairing.
    SizeChanged { cols: u16, rows: u16 },
    /// `portty agent`: open a structured coding-agent chat on this connection
    /// instead of adopting a terminal. Sent as the FIRST frame instead of
    /// `Register`. With `join`, the newest LIVE session of this provider is
    /// reused (laptop and phone then drive ONE conversation); otherwise a new
    /// session starts. Append-only: after SizeChanged.
    OpenAgent { provider: AgentProvider, join: bool },
    /// One complete user prompt for the agent bound to this connection.
    AgentPrompt { text: String },
    /// Approval decision for a pending permission on this connection's agent.
    /// `None` mirrors the phone's cancel. Append-only: after AgentPrompt.
    AgentDecision {
        tool_call_id: String,
        option_id: Option<String>,
    },
    /// Cancel the active turn without closing the shared agent session.
    AgentCancel,
    /// Same-user management command: revoke these exact phone identities in the
    /// running daemon. Append-only after AgentCancel.
    RevokeDevices { device_ids: Vec<[u8; 16]> },
    /// Change the ACP session mode from `portty agent`. Append-only after
    /// RevokeDevices so older daemon/CLI pairs keep their established tags.
    AgentSetMode { mode_id: String },
    /// Change one ACP configuration option (including the model selector).
    AgentSetConfig {
        config_id: String,
        value: AgentConfigValue,
    },
    /// Start one of the authentication methods announced by the ACP agent.
    AgentAuthenticate { method_id: String },
    /// Change the option advertised with ACP's `model` category without making
    /// the CLI guess the provider-specific configuration id.
    AgentSetModel { model_id: String },
    /// Same-user daemon-management command. The host acknowledges the request
    /// before triggering its graceful shutdown path, so PID files and other
    /// RAII-managed resources are cleaned up on every supported desktop OS.
    /// Append-only after AgentSetModel.
    Shutdown,
    /// A human's answer to `HostToRelay::PairingConfirmRequest`: does the code on
    /// the phone match the one this CLI printed?
    ///
    /// Only ever sent by a `portty pair` session that is acting as the approval
    /// console. Anything other than `accept: true` - including never replying, or
    /// closing the pipe - denies the pairing. Append-only after Shutdown.
    PairingConfirmResponse { accept: bool },
    /// "Are you up?" - answered with `HostToRelay::Pong` and nothing else.
    ///
    /// Exists so a launcher can wait for a freshly-spawned daemon without any
    /// side effect. Every other first frame does something: `Register` adopts a
    /// terminal, `OpenAgent` starts an agent, `Shutdown` stops the daemon, and
    /// `ReopenPairing` mints a credential - which is precisely what a readiness
    /// probe must not do. Append-only after PairingConfirmResponse.
    Ping,
}

/// host → relay. Viewer (browser/phone) actions the daemon forwards to the
/// process that actually owns the PTY.
#[derive(Clone, Serialize, Deserialize)]
pub enum HostToRelay {
    /// Keystrokes/taps to write into the PTY.
    Input(Vec<u8>),
    /// LEGACY (fixed-size model): the daemon no longer forwards viewer resizes -
    /// the laptop terminal is the sole size owner for adopted sessions. The
    /// variant stays for wire compatibility (append-only enum); relays ignore it.
    Resize { cols: u16, rows: u16 },
    /// Viewer asked to kill this session.
    Kill,
    /// LEGACY (fixed-size model): part of the retired follow-the-typist size
    /// hand-off. The daemon no longer sends it; relays ignore it. The variant
    /// stays for wire compatibility (append-only enum).
    RestoreLocalSize,
    /// Reply to `RelayToHost::ReopenPairing`: the daemon's current pairing
    /// credentials, freshly re-armed. `qr` is the compact `portty3:` code to
    /// render as a QR; `window_secs` says how long first-pair stays open.
    /// Append-only: after RestoreLocalSize.
    PairingInfo {
        ticket: String,
        qr: String,
        phrase: String,
        window_secs: u64,
    },
    /// Reply to `OpenAgent`: which session this connection is now bound to.
    /// `created` distinguishes "started fresh" from "joined the live one".
    /// Append-only: after PairingInfo.
    AgentOpened {
        id: SessionId,
        title: String,
        created: bool,
    },
    /// One timeline event - bounded history is replayed first, then live
    /// updates follow. The CLI de-duplicates by `seq`, phone-style.
    AgentEvent { event: AgentTimelineEvent },
    /// An approval is waiting (replayed on open, live afterwards).
    AgentPermission {
        tool_call: ToolCallCard,
        options: Vec<PermissionOption>,
    },
    /// A pending approval was answered - possibly from the phone. Dismiss it.
    AgentPermissionResolved { tool_call_id: String },
    /// The agent session is gone (killed from a viewer); the CLI should exit.
    AgentGone { message: String },
    /// A command on this connection failed (e.g. prompt queue full). Non-fatal.
    AgentError { message: String },
    /// Durable result for `RevokeDevices`. `error=None` means every returned
    /// identity has a committed revocation tombstone.
    RevocationResult {
        revoked: Vec<[u8; 16]>,
        error: Option<String>,
    },
    /// Acknowledges `RelayToHost::Shutdown`. Append-only after
    /// `RevocationResult` so new management clients remain compatible with a
    /// still-running daemon from the previous build.
    ShutdownAccepted,
    /// A phone finished the pairing exchange and is waiting to be confirmed.
    ///
    /// The CLI shows `code` to the operator, who checks it against the phone's
    /// screen and answers with `RelayToHost::PairingConfirmResponse`. `code` is
    /// NOT secret - it is derived from the completed session purely so two
    /// screens can be compared, and it is useless to anyone who did not run the
    /// exchange. `device_name` is peer-supplied text: display it, never trust it.
    /// Append-only after ShutdownAccepted.
    PairingConfirmRequest { device_name: String, code: String },
    /// Reply to `RelayToHost::Ping`. Carries nothing - its arrival is the answer.
    /// Append-only after PairingConfirmRequest.
    Pong,
}

/// Redacting `Debug` for the local control channel - same reasoning as
/// `Frame`'s, and here one variant is worse than anything on the wire:
/// `HostToRelay::PairingInfo` carries the LIVE ticket, QR code, phrase, and PIN.
/// A single `debug!(?msg)` while debugging the relay pipe would have put working
/// pairing credentials into a log file that outlives the pairing window.
///
/// Both matches are exhaustive so a new variant has to be classified before it
/// compiles.
impl core::fmt::Debug for RelayToHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Register { title, cols, rows } => write!(
                f,
                "Register {{ title: {} chars, cols: {cols}, rows: {rows} }}",
                title.len()
            ),
            Self::Output(bytes) => write!(f, "Output({} bytes)", bytes.len()),
            Self::Exited => f.write_str("Exited"),
            Self::LocalTookSize => f.write_str("LocalTookSize"),
            Self::ReopenPairing => f.write_str("ReopenPairing"),
            Self::SizeChanged { cols, rows } => {
                write!(f, "SizeChanged {{ cols: {cols}, rows: {rows} }}")
            }
            Self::OpenAgent { provider, join } => {
                write!(f, "OpenAgent {{ provider: {provider:?}, join: {join} }}")
            }
            Self::AgentPrompt { text } => write!(f, "AgentPrompt {{ text: {} chars }}", text.len()),
            Self::AgentDecision {
                tool_call_id,
                option_id,
            } => write!(
                f,
                "AgentDecision {{ tool_call_id: {tool_call_id:?}, option_id: {option_id:?} }}"
            ),
            Self::AgentCancel => f.write_str("AgentCancel"),
            Self::RevokeDevices { device_ids } => {
                write!(f, "RevokeDevices {{ device_ids: {} }}", device_ids.len())
            }
            Self::AgentSetMode { mode_id } => write!(f, "AgentSetMode {{ mode_id: {mode_id:?} }}"),
            Self::AgentSetConfig { config_id, .. } => {
                write!(f, "AgentSetConfig {{ config_id: {config_id:?} }}")
            }
            Self::AgentAuthenticate { method_id } => {
                write!(f, "AgentAuthenticate {{ method_id: {method_id:?} }}")
            }
            Self::AgentSetModel { model_id } => {
                write!(f, "AgentSetModel {{ model_id: {model_id:?} }}")
            }
            Self::Shutdown => f.write_str("Shutdown"),
            // The answer, never the code it answers.
            Self::PairingConfirmResponse { accept } => {
                write!(f, "PairingConfirmResponse {{ accept: {accept} }}")
            }
            Self::Ping => f.write_str("Ping"),
        }
    }
}

impl core::fmt::Debug for HostToRelay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Input(bytes) => write!(f, "Input({} bytes)", bytes.len()),
            Self::Resize { cols, rows } => write!(f, "Resize {{ cols: {cols}, rows: {rows} }}"),
            Self::Kill => f.write_str("Kill"),
            Self::RestoreLocalSize => f.write_str("RestoreLocalSize"),
            // Live pairing credentials: never any detail, not even lengths.
            Self::PairingInfo { window_secs, .. } => {
                write!(
                    f,
                    "PairingInfo {{ <redacted>, window_secs: {window_secs} }}"
                )
            }
            // The comparison code is not a credential, but it is still a live
            // pairing value and the peer name is attacker-supplied - so neither
            // reaches a log.
            Self::PairingConfirmRequest { .. } => {
                f.write_str("PairingConfirmRequest { <redacted> }")
            }
            Self::Pong => f.write_str("Pong"),
            Self::AgentOpened { id, title, created } => write!(
                f,
                "AgentOpened {{ id: {id:?}, title: {} chars, created: {created} }}",
                title.len()
            ),
            Self::AgentEvent { .. } => f.write_str("AgentEvent { .. }"),
            Self::AgentPermission { options, .. } => {
                write!(f, "AgentPermission {{ options: {} }}", options.len())
            }
            Self::AgentPermissionResolved { tool_call_id } => write!(
                f,
                "AgentPermissionResolved {{ tool_call_id: {tool_call_id:?} }}"
            ),
            Self::AgentGone { message } => {
                write!(f, "AgentGone {{ message: {} chars }}", message.len())
            }
            Self::AgentError { message } => {
                write!(f, "AgentError {{ message: {} chars }}", message.len())
            }
            Self::RevocationResult { revoked, error } => write!(
                f,
                "RevocationResult {{ revoked: {}, error: {} }}",
                revoked.len(),
                error.is_some()
            ),
            Self::ShutdownAccepted => f.write_str("ShutdownAccepted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worst leak in this file: `PairingInfo` carries the LIVE ticket, QR,
    /// and phrase - each a COMPLETE first-pair credential since the PIN was
    /// removed. Debug must show none of it.
    #[test]
    fn pairing_info_debug_shows_no_credential() {
        let msg = HostToRelay::PairingInfo {
            ticket: "portty1:eyJuaWQiOiJzZWNyZXQifQ".into(),
            qr: "portty3:AAAABBBBCCCC".into(),
            phrase: "correct horse battery staple pin down".into(),
            window_secs: 300,
        };
        let rendered = format!("{msg:?}");
        for secret in ["portty1:", "portty3:", "correct horse"] {
            assert!(!rendered.contains(secret), "leaked {secret:?}: {rendered}");
        }
        assert!(rendered.contains("window_secs: 300"), "{rendered}");
    }

    /// The comparison code is not a credential, but it IS a live pairing value,
    /// and the device name beside it is attacker-controlled text. Neither
    /// belongs in a log line.
    #[test]
    fn pairing_confirm_request_debug_shows_no_detail() {
        let msg = HostToRelay::PairingConfirmRequest {
            device_name: "sudo rm -rf".into(),
            code: "483920".into(),
        };
        let rendered = format!("{msg:?}");
        assert!(!rendered.contains("483920"), "{rendered}");
        assert!(!rendered.contains("sudo"), "{rendered}");
    }

    /// The readiness probe must be a genuine no-op on the wire and decode at its
    /// appended tag. It exists because every OTHER first frame has a side effect.
    #[test]
    fn ping_pong_round_trips_at_appended_tags() {
        let ping: RelayToHost =
            postcard::from_bytes(&postcard::to_allocvec(&RelayToHost::Ping).unwrap()).unwrap();
        assert!(matches!(ping, RelayToHost::Ping));
        let pong: HostToRelay =
            postcard::from_bytes(&postcard::to_allocvec(&HostToRelay::Pong).unwrap()).unwrap();
        assert!(matches!(pong, HostToRelay::Pong));
    }

    /// Both halves of the confirmation round-trip must decode at their APPENDED
    /// tags, after every pre-existing variant.
    #[test]
    fn pairing_confirmation_msgs_are_appended() {
        let ask = HostToRelay::PairingConfirmRequest {
            device_name: "phone".into(),
            code: "001234".into(),
        };
        let back: HostToRelay =
            postcard::from_bytes(&postcard::to_allocvec(&ask).unwrap()).unwrap();
        match back {
            HostToRelay::PairingConfirmRequest { device_name, code } => {
                assert_eq!(device_name, "phone");
                assert_eq!(code, "001234", "leading zeros must survive the wire");
            }
            other => panic!("wrong variant: {other:?}"),
        }

        for accept in [true, false] {
            let answer = RelayToHost::PairingConfirmResponse { accept };
            let back: RelayToHost =
                postcard::from_bytes(&postcard::to_allocvec(&answer).unwrap()).unwrap();
            assert!(matches!(
                back,
                RelayToHost::PairingConfirmResponse { accept: a } if a == accept
            ));
        }
    }

    /// Keystrokes, terminal bytes, and prompt text stay out too.
    #[test]
    fn relay_debug_redacts_payloads() {
        let input = HostToRelay::Input(b"sudo hunter2".to_vec());
        assert_eq!(format!("{input:?}"), "Input(12 bytes)");
        let output = RelayToHost::Output(b"BEGIN PRIVATE KEY".to_vec());
        assert_eq!(format!("{output:?}"), "Output(17 bytes)");
        let prompt = RelayToHost::AgentPrompt {
            text: "my api key is sk-live-123".into(),
        };
        let rendered = format!("{prompt:?}");
        assert!(!rendered.contains("sk-live"), "{rendered}");
    }

    #[test]
    fn relay_msgs_roundtrip() {
        let reg = RelayToHost::Register {
            title: "build".into(),
            cols: 120,
            rows: 40,
        };
        let back: RelayToHost =
            postcard::from_bytes(&postcard::to_allocvec(&reg).unwrap()).unwrap();
        match back {
            RelayToHost::Register { title, cols, rows } => {
                assert_eq!(title, "build");
                assert_eq!((cols, rows), (120, 40));
            }
            _ => panic!("wrong variant"),
        }

        let inp = HostToRelay::Input(vec![9, 9, 9]);
        let back: HostToRelay =
            postcard::from_bytes(&postcard::to_allocvec(&inp).unwrap()).unwrap();
        assert!(matches!(back, HostToRelay::Input(b) if b == vec![9, 9, 9]));

        // SizeChanged must decode at its appended position (after ReopenPairing).
        let sz = RelayToHost::SizeChanged {
            cols: 190,
            rows: 52,
        };
        let back: RelayToHost = postcard::from_bytes(&postcard::to_allocvec(&sz).unwrap()).unwrap();
        assert!(matches!(
            back,
            RelayToHost::SizeChanged {
                cols: 190,
                rows: 52
            }
        ));
    }

    /// The agent chat messages are appended after every terminal-era variant -
    /// postcard tags by declaration order, so these indices are load-bearing.
    #[test]
    fn agent_relay_msgs_are_appended() {
        let open = RelayToHost::OpenAgent {
            provider: AgentProvider::ClaudeCode,
            join: true,
        };
        assert_eq!(postcard::to_allocvec(&open).unwrap()[0], 6);
        let prompt = RelayToHost::AgentPrompt { text: "hi".into() };
        assert_eq!(postcard::to_allocvec(&prompt).unwrap()[0], 7);
        let decision = RelayToHost::AgentDecision {
            tool_call_id: "tool-1".into(),
            option_id: None,
        };
        assert_eq!(postcard::to_allocvec(&decision).unwrap()[0], 8);
        assert_eq!(
            postcard::to_allocvec(&RelayToHost::AgentCancel).unwrap()[0],
            9
        );

        let opened = HostToRelay::AgentOpened {
            id: SessionId(4),
            title: "Claude Code".into(),
            created: false,
        };
        assert_eq!(postcard::to_allocvec(&opened).unwrap()[0], 5);
        let event = HostToRelay::AgentEvent {
            event: AgentTimelineEvent {
                seq: 1,
                event: crate::AgentEvent::TurnStarted,
            },
        };
        assert_eq!(postcard::to_allocvec(&event).unwrap()[0], 6);
        let gone = HostToRelay::AgentGone {
            message: "closed".into(),
        };
        assert_eq!(postcard::to_allocvec(&gone).unwrap()[0], 9);

        // Round-trip one composite to prove nested agent types ride the pipe.
        let perm = HostToRelay::AgentPermission {
            tool_call: ToolCallCard {
                tool_call_id: "tool-1".into(),
                title: "git push --force".into(),
            },
            options: vec![],
        };
        let back: HostToRelay =
            postcard::from_bytes(&postcard::to_allocvec(&perm).unwrap()).unwrap();
        assert!(matches!(
            back,
            HostToRelay::AgentPermission { tool_call, .. } if tool_call.title == "git push --force"
        ));

        assert_eq!(
            postcard::to_allocvec(&RelayToHost::RevokeDevices {
                device_ids: vec![[1; 16]],
            })
            .unwrap()[0],
            10,
            "daemon revocation control must remain append-only"
        );
        assert_eq!(
            postcard::to_allocvec(&HostToRelay::RevocationResult {
                revoked: vec![[1; 16]],
                error: None,
            })
            .unwrap()[0],
            11,
            "daemon revocation result must remain append-only"
        );
        assert_eq!(
            postcard::to_allocvec(&RelayToHost::AgentSetMode {
                mode_id: "plan".into(),
            })
            .unwrap()[0],
            11
        );
        assert_eq!(
            postcard::to_allocvec(&RelayToHost::AgentSetConfig {
                config_id: "model".into(),
                value: AgentConfigValue::Select("gpt-5".into()),
            })
            .unwrap()[0],
            12
        );
        assert_eq!(
            postcard::to_allocvec(&RelayToHost::AgentAuthenticate {
                method_id: "browser".into(),
            })
            .unwrap()[0],
            13
        );
        assert_eq!(
            postcard::to_allocvec(&RelayToHost::AgentSetModel {
                model_id: "gpt-5".into(),
            })
            .unwrap()[0],
            14
        );
        assert_eq!(
            postcard::to_allocvec(&RelayToHost::Shutdown).unwrap()[0],
            15,
            "daemon shutdown control must remain append-only"
        );
        assert_eq!(
            postcard::to_allocvec(&HostToRelay::ShutdownAccepted).unwrap()[0],
            12,
            "daemon shutdown acknowledgement must remain append-only"
        );
    }

    #[cfg(unix)]
    #[test]
    fn relay_directory_is_created_private() {
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("portty");
        prepare_socket_dir_at(&dir).unwrap();

        let meta = std::fs::symlink_metadata(dir).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn relay_directory_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let link = root.path().join("portty");
        std::fs::create_dir(&target).unwrap();
        symlink(target, &link).unwrap();

        let err = prepare_socket_dir_at(&link).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn relay_endpoint_requires_private_socket() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("portty");
        prepare_socket_dir_at(&dir).unwrap();
        let socket = dir.join("relay.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        validate_socket_endpoint_at(&socket).unwrap();

        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = validate_socket_endpoint_at(&socket).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
