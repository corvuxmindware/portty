//! Local relay pipe - the front door for `portty share`.
//!
//! A `portty` relay running in another terminal connects here and hands its PTY
//! to the daemon as an **adopted** session (see `session.rs`). It then streams
//! `RelayToHost::Output` (+ `SizeChanged` when its terminal is resized); the
//! daemon forwards viewer `Input`/`Kill` back as `HostToRelay`.
//!
//! SECURITY: this is a control channel into the machine (it can inject input
//! into terminals), so it MUST stay per-user. Both ends authenticate the OS
//! identity of the connected process; path/pipe permissions are defense in
//! depth. Do NOT swap this for an unauthenticated loopback TCP port.

use portty_protocol::relay::{HostToRelay, RelayToHost, MAX_RELAY_FRAME_BYTES, RELAY_PIPE_VERSION};
use portty_protocol::{AgentProvider, PermissionResolver};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::session::{AgentResume, ManagerEvent, SessionManager};

const MAX_RELAY_CONNECTIONS: usize = 128;
const RELAY_REGISTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Shared handle for `portty pair` re-arming; `None` in proof mode (no iroh).
type Pairing = Option<std::sync::Arc<crate::iroh_serve::PairingReopen>>;
type Peers = Option<std::sync::Arc<tokio::sync::Mutex<portty_transport::PeerStore>>>;
type Active = Option<crate::active::ActiveDevices>;
type Push = Option<crate::push::PushCtx>;

/// Spawn the listener as a background task. Errors are logged, not fatal - the
/// daemon still serves its own spawned shells if the relay pipe can't bind.
/// `pairing` lets a same-user `portty pair` re-arm the first-pair enrollment
/// window without restarting the daemon.
pub fn spawn(mgr: SessionManager, pairing: Pairing, peers: Peers, active: Active, push: Push) {
    tokio::spawn(async move {
        if let Err(e) = listen(mgr, pairing, peers, active, push).await {
            warn!("relay pipe listener stopped: {e}");
        }
    });
}

#[cfg(windows)]
async fn listen(
    mgr: SessionManager,
    pairing: Pairing,
    peers: Peers,
    active: Active,
    push: Push,
) -> crate::error::HostResult<()> {
    use std::os::windows::io::AsRawHandle;

    use portty_protocol::relay::{verify_named_pipe_peer, NamedPipePeer};
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = portty_protocol::relay::pipe_name()?;
    info!(
        pipe = %pipe_name,
        "relay pipe listening (run `portty share` in a terminal)"
    );
    let connections = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_RELAY_CONNECTIONS));
    let mut first_instance = true;
    loop {
        // Create an instance, wait for a relay to connect, then hand it off and
        // immediately create the next instance so connections never queue.
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true);
        let server = options.create(&pipe_name)?;
        first_instance = false;
        server.connect().await?;
        if let Err(e) = verify_named_pipe_peer(server.as_raw_handle(), NamedPipePeer::Client) {
            warn!(error = %e, "rejected relay connection from another Windows user");
            continue;
        }
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            warn!(
                max = MAX_RELAY_CONNECTIONS,
                "relay connection limit reached"
            );
            continue;
        };
        let mgr = mgr.clone();
        let pairing = pairing.clone();
        let peers = peers.clone();
        let active = active.clone();
        let push = push.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_conn(server, mgr, pairing, peers, active, push).await {
                warn!("relay connection ended: {e}");
            }
        });
    }
}

#[cfg(not(windows))]
async fn listen(
    mgr: SessionManager,
    pairing: Pairing,
    peers: Peers,
    active: Active,
    push: Push,
) -> crate::error::HostResult<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    let path = portty_protocol::relay::socket_path();
    // Prove a pre-existing directory is ours before tightening it; this rejects
    // attacker-owned entries and final-component symlinks in shared `/tmp`.
    portty_protocol::relay::prepare_socket_dir()?;
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    // Force the socket itself to 0600 (owner-only) regardless of umask.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    portty_protocol::relay::validate_socket_endpoint()?;
    info!(
        sock = %path.display(),
        "relay socket listening (run `portty share` in a terminal)"
    );

    // SAFETY: getuid is always safe and never fails.
    let our_uid = unsafe { libc::getuid() };
    let connections = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_RELAY_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        // Ownership check: only this same user may drive terminals through the
        // relay. Reject a connection from any other uid outright.
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == our_uid => {}
            Ok(cred) => {
                warn!(
                    peer_uid = cred.uid(),
                    our_uid, "rejected relay connection from another user"
                );
                continue;
            }
            Err(e) => {
                warn!(error = %e, "could not read relay peer credentials; rejecting");
                continue;
            }
        }
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            warn!(
                max = MAX_RELAY_CONNECTIONS,
                "relay connection limit reached"
            );
            continue;
        };
        let mgr = mgr.clone();
        let pairing = pairing.clone();
        let peers = peers.clone();
        let active = active.clone();
        let push = push.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_conn(stream, mgr, pairing, peers, active, push).await {
                warn!("relay connection ended: {e}");
            }
        });
    }
}

/// Drive one relay connection: Register → adopt a session → pump output in and
/// control out until the pipe closes or the shell exits. Management messages
/// (`ReopenPairing`, `RevokeDevices`, `Shutdown`) are also valid first frames;
/// they return one response and close.
pub async fn handle_conn<S>(
    stream: S,
    mgr: SessionManager,
    pairing: Pairing,
    peers: Peers,
    active: Active,
    push: Push,
) -> crate::error::HostResult<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);

    // Version handshake FIRST: the CLI sends its relay-pipe protocol version as
    // the first framed message. Reject a skewed peer up front instead of letting
    // it silently mis-decode the versioned messages that follow (#36).
    let ver = tokio::time::timeout(RELAY_REGISTER_TIMEOUT, read_framed(&mut rd))
        .await
        .map_err(|_| {
            crate::error::HostError::Relay("relay version handshake timed out".into())
        })??;
    if ver.len() != 2 || u16::from_le_bytes([ver[0], ver[1]]) != RELAY_PIPE_VERSION {
        return Err(crate::error::HostError::Relay(format!(
            "relay pipe version mismatch (daemon speaks v{RELAY_PIPE_VERSION}); rebuild the \
             portty CLI and daemon from the same version"
        )));
    }

    // First frame MUST be Register (adopt a terminal) or ReopenPairing.
    let first = tokio::time::timeout(RELAY_REGISTER_TIMEOUT, read_framed(&mut rd))
        .await
        .map_err(|_| crate::error::HostError::Relay("relay Register timed out".into()))??;
    let (title, cols, rows) = match postcard::from_bytes::<RelayToHost>(&first)
        .map_err(|e| crate::error::HostError::Serialization(e.to_string()))?
    {
        RelayToHost::Register { title, cols, rows } => (title, cols, rows),
        RelayToHost::ReopenPairing => {
            let Some(p) = pairing else {
                return Err(crate::error::HostError::Relay(
                    "pairing is not available in this mode".into(),
                ));
            };
            // Mints fresh ticket/manual secrets (the startup banner's pair stops
            // working) and re-arms the window - read live by the accept path.
            let fresh = p.reopen()?;
            info!(
                window_secs = fresh.window_secs,
                "pairing window reopened with fresh credentials via `portty pair`"
            );
            let reply = HostToRelay::PairingInfo {
                ticket: fresh.ticket,
                qr: fresh.qr,
                phrase: fresh.phrase,
                window_secs: fresh.window_secs,
            };
            let bytes = postcard::to_allocvec(&reply)
                .map_err(|e| crate::error::HostError::Serialization(e.to_string()))?;
            write_framed(&mut wr, &bytes).await?;
            // The connection no longer closes here. `portty pair` stays on as the
            // console that confirms the comparison code, which is the ONLY
            // approval channel a daemonised host has - it owns no terminal to
            // prompt on. Returning would leave such a host unable to pair at all.
            return serve_pairing_console(rd, wr, p).await;
        }
        RelayToHost::Ping => {
            // Readiness probe: answer and close. Deliberately touches nothing -
            // no session, no pairing state, no peer store.
            send_msg(&mut wr, &HostToRelay::Pong).await?;
            let _ = wr.shutdown().await;
            return Ok(());
        }
        RelayToHost::OpenAgent { provider, join } => {
            return handle_agent_conn(rd, wr, mgr, provider, join).await;
        }
        RelayToHost::RevokeDevices { device_ids } => {
            let Some(peers) = peers else {
                send_msg(
                    &mut wr,
                    &HostToRelay::RevocationResult {
                        revoked: vec![],
                        error: Some("phone pairing is not available in this host mode".into()),
                    },
                )
                .await?;
                return Ok(());
            };
            if device_ids.is_empty() || device_ids.len() > 256 {
                send_msg(
                    &mut wr,
                    &HostToRelay::RevocationResult {
                        revoked: vec![],
                        error: Some("revocation request must contain 1..=256 devices".into()),
                    },
                )
                .await?;
                return Ok(());
            }

            let mut unique = std::collections::HashSet::new();
            let mut revoked = Vec::new();
            let mut notices = Vec::new();
            let mut store = peers.lock().await;
            for raw in device_ids {
                if !unique.insert(raw) {
                    continue;
                }
                let device = portty_transport::DeviceId(raw);
                match store.revoke(&device) {
                    Ok(record) => notices.push((device, record)),
                    Err(error) => {
                        drop(store);
                        send_msg(
                            &mut wr,
                            &HostToRelay::RevocationResult {
                                revoked,
                                error: Some(format!(
                                    "could not commit revocation for {device}: {error}"
                                )),
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                }
                revoked.push(raw);
            }
            drop(store);
            if let Some(active) = active {
                for (device, record) in &notices {
                    if let Some(pair_id) = record.pair_id {
                        let _ = active
                            .notify_revoked(*device, pair_id.0, record.event_id)
                            .await;
                    }
                }
            }
            if let Some(push) = push {
                for (device, _) in notices {
                    let push = push.clone();
                    tokio::spawn(async move { push.notify_revoked(device).await });
                }
            }
            send_msg(
                &mut wr,
                &HostToRelay::RevocationResult {
                    revoked,
                    error: None,
                },
            )
            .await?;
            let _ = wr.shutdown().await;
            return Ok(());
        }
        RelayToHost::Shutdown => {
            send_msg(&mut wr, &HostToRelay::ShutdownAccepted).await?;
            let _ = wr.shutdown().await;
            crate::iroh_serve::request_shutdown();
            return Ok(());
        }
        _ => {
            return Err(crate::error::HostError::Relay(
                "relay did not Register first".into(),
            ))
        }
    };

    let (to_relay_tx, mut to_relay_rx) =
        mpsc::channel::<HostToRelay>(crate::session::ADOPTED_CTRL_QUEUE);
    let (id, session) = match mgr.register_adopted(title, cols, rows, to_relay_tx).await {
        Ok(pair) => pair,
        Err(e) => {
            // At the session cap - refuse this relay rather than overload the host.
            warn!("refusing relay adoption: {e}");
            return Err(crate::error::HostError::Relay(e.to_string()));
        }
    };
    info!(id = id.0, "adopted a relay terminal");

    // Writer task: viewer control (Input/Resize/Kill) → pipe.
    let writer = tokio::spawn(async move {
        while let Some(msg) = to_relay_rx.recv().await {
            let Ok(bytes) = postcard::to_allocvec(&msg) else {
                continue;
            };
            if write_framed(&mut wr, &bytes).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    // Reader loop: relay output → the session's ring + broadcast.
    loop {
        let frame = match read_framed(&mut rd).await {
            Ok(f) => f,
            Err(_) => break, // pipe closed = relay/shell gone
        };
        match postcard::from_bytes::<RelayToHost>(&frame) {
            Ok(RelayToHost::Output(bytes)) => session.push_output(&bytes),
            Ok(RelayToHost::Exited) => break,
            // The laptop terminal was resized - record the new authoritative
            // size and broadcast it to viewers (→ `Frame::SessionSize`).
            Ok(RelayToHost::SizeChanged { cols, rows }) => session.set_size(cols, rows),
            // Legacy follow-the-typist signal from an old relay; the fixed-size
            // model has no size ownership to track - ignore.
            Ok(RelayToHost::LocalTookSize) => {}
            Ok(RelayToHost::Register { .. }) => {} // ignore a duplicate Register
            // Only valid as a FIRST frame (handled above); ignore mid-stream.
            Ok(RelayToHost::ReopenPairing) => {}
            // Only valid on a pairing-console connection; a terminal relay has
            // no pending confirmation, so this can never approve anything.
            Ok(RelayToHost::PairingConfirmResponse { .. }) => {}
            // Only valid as a FIRST frame; ignore mid-stream.
            Ok(RelayToHost::Ping) => {}
            // Agent-chat messages are only valid on an OpenAgent connection.
            Ok(
                RelayToHost::OpenAgent { .. }
                | RelayToHost::AgentPrompt { .. }
                | RelayToHost::AgentDecision { .. }
                | RelayToHost::AgentCancel
                | RelayToHost::RevokeDevices { .. }
                | RelayToHost::AgentSetMode { .. }
                | RelayToHost::AgentSetConfig { .. }
                | RelayToHost::AgentAuthenticate { .. }
                | RelayToHost::AgentSetModel { .. }
                | RelayToHost::Shutdown,
            ) => {}
            // An undecodable frame on the local relay pipe means version skew or
            // corruption. Fail CLOSED (like the iroh path) instead of silently
            // skipping it, which could desync the adopted session (#37).
            Err(e) => {
                tracing::warn!(id = id.0, "closing relay pipe on undecodable frame: {e}");
                break;
            }
        }
    }

    mgr.remove_dead(id).await;
    writer.abort();
    info!(id = id.0, "relay terminal removed");
    Ok(())
}

/// Act as the pairing-confirmation console for as long as this `portty pair`
/// session is connected.
///
/// A daemonised host has no terminal, so this pipe is where a human is asked
/// whether the phone is showing the same comparison code. The console detaches
/// when this function returns - dropping the guard - after which the host has no
/// approval channel and refuses first pairs outright, which is the correct
/// fail-closed behaviour rather than a silent regression to no confirmation.
///
/// Returns once the CLI hangs up, or once one pairing has been answered: a
/// `portty pair` run is one deliberate pairing act, and the enrollment window is
/// consumed by a successful one anyway.
async fn serve_pairing_console<S>(
    mut rd: tokio::io::ReadHalf<S>,
    mut wr: tokio::io::WriteHalf<S>,
    pairing: std::sync::Arc<crate::iroh_serve::PairingReopen>,
) -> crate::error::HostResult<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (_console, mut requests) = pairing.confirm().attach();
    info!("`portty pair` attached as the pairing-confirmation console");

    // One `portty pair` run confirms exactly one pairing, so this is a single
    // decision rather than a loop: a successful pair consumes the enrollment
    // window anyway, and leaving a stale console attached would let a later
    // unrelated pairing be approved by whoever still had this terminal open.
    if let Some(request) = requests.recv().await {
        let ask = HostToRelay::PairingConfirmRequest {
            device_name: request.display_name.clone(),
            code: request.code.clone(),
        };
        let bytes = postcard::to_allocvec(&ask)
            .map_err(|e| crate::error::HostError::Serialization(e.to_string()))?;
        // Read exactly one answer. Anything else - a failed write, a wrong
        // variant, a decode failure, EOF - is a refusal, never an approval.
        let accept = if write_framed(&mut wr, &bytes).await.is_err() {
            false
        } else {
            match read_framed(&mut rd).await {
                Ok(frame) => matches!(
                    postcard::from_bytes::<RelayToHost>(&frame),
                    Ok(RelayToHost::PairingConfirmResponse { accept: true })
                ),
                Err(_) => false,
            }
        };
        request.answer(accept).await;
    }

    let _ = wr.shutdown().await;
    info!("`portty pair` console detached");
    Ok(())
}

/// Drive one `portty agent` chat connection: bind to a live agent session (or
/// start one), replay its bounded history + pending approvals, then pump live
/// events out and prompts/decisions in until the CLI hangs up.
///
/// Deliberately does NOT kill the session when the CLI leaves - the phone (or
/// a later `portty agent`) may still be driving the same conversation. This is
/// the laptop half of dual-control: one ACP session, two viewers.
async fn handle_agent_conn<S>(
    mut rd: tokio::io::ReadHalf<S>,
    mut wr: tokio::io::WriteHalf<S>,
    mgr: SessionManager,
    provider: AgentProvider,
    join: bool,
) -> crate::error::HostResult<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    // Subscribe BEFORE the snapshot so nothing falls in between; the CLI
    // de-duplicates the overlap by sequence number, phone-style.
    let mut events = mgr.subscribe_events();
    let (session, created) = match if join {
        mgr.newest_live_agent(provider).await
    } else {
        None
    } {
        Some(session) => (session, false),
        None => {
            // `--new` (join=false) is an explicit request for a separate
            // fresh conversation; plain open keeps conversation continuity.
            // `None` cwd: the laptop CLI has always meant the workspace root,
            // and only the phone's picker chooses anything narrower.
            let id = mgr
                .spawn_agent_provider(
                    provider,
                    None,
                    if join {
                        AgentResume::Latest
                    } else {
                        AgentResume::Fresh
                    },
                    None,
                )
                .await?;
            let session = mgr.get(id).await.ok_or_else(|| {
                crate::error::HostError::Relay("agent session vanished during start".into())
            })?;
            (session, true)
        }
    };
    let id = session.id();
    info!(id = id.0, ?provider, created, "agent chat connected");
    send_msg(
        &mut wr,
        &HostToRelay::AgentOpened {
            id,
            title: session.info().title,
            created,
        },
    )
    .await?;
    for event in session.agent_snapshot().unwrap_or_default() {
        send_msg(&mut wr, &HostToRelay::AgentEvent { event }).await?;
    }
    for (tool_call, options, _) in session.agent_permissions() {
        send_msg(
            &mut wr,
            &HostToRelay::AgentPermission { tool_call, options },
        )
        .await?;
    }

    // Inbound frames arrive via a dedicated task: `read_framed` is not
    // cancel-safe (a length prefix could be consumed and the payload dropped),
    // so it must never sit in a select! arm.
    let (in_tx, mut in_rx) = mpsc::channel::<RelayToHost>(16);
    let reader = tokio::spawn(async move {
        loop {
            let Ok(frame) = read_framed(&mut rd).await else {
                break;
            };
            let Ok(msg) = postcard::from_bytes::<RelayToHost>(&frame) else {
                continue;
            };
            if in_tx.send(msg).await.is_err() {
                break;
            }
        }
    });
    // Mode/config calls wait for an ACP response. Keep those waits outside the
    // pipe select loop so approvals and live events can continue flowing while
    // an agent processes the control request.
    let (control_tx, mut control_rx) = mpsc::channel::<Result<(), String>>(8);

    loop {
        tokio::select! {
            msg = in_rx.recv() => {
                let Some(msg) = msg else { break }; // CLI hung up; agent lives on
                match msg {
                    RelayToHost::AgentPrompt { text } => {
                        if let Err(e) = session.agent_prompt(text) {
                            send_msg(&mut wr, &HostToRelay::AgentError {
                                message: e.to_string(),
                            })
                            .await?;
                        }
                    }
                    RelayToHost::AgentDecision { tool_call_id, option_id } => {
                        session.resolve_permission(
                            &tool_call_id,
                            option_id,
                            PermissionResolver::Laptop,
                        );
                    }
                    RelayToHost::AgentCancel => {
                        if let Err(e) = session.agent_cancel() {
                            send_msg(&mut wr, &HostToRelay::AgentError {
                                message: e.to_string(),
                            })
                            .await?;
                        }
                    }
                    RelayToHost::AgentSetMode { mode_id } => {
                        let session = session.clone();
                        let result_tx = control_tx.clone();
                        tokio::spawn(async move {
                            let result = session
                                .agent_set_mode(mode_id)
                                .await
                                .map_err(|e| format!("could not change mode: {e}"));
                            let _ = result_tx.send(result).await;
                        });
                    }
                    RelayToHost::AgentSetConfig { config_id, value } => {
                        let session = session.clone();
                        let result_tx = control_tx.clone();
                        tokio::spawn(async move {
                            let result = session
                                .agent_set_config(config_id, value)
                                .await
                                .map_err(|e| format!("could not change agent setting: {e}"));
                            let _ = result_tx.send(result).await;
                        });
                    }
                    RelayToHost::AgentAuthenticate { method_id } => {
                        if let Err(e) = session.agent_authenticate(method_id) {
                            send_msg(&mut wr, &HostToRelay::AgentError {
                                message: format!("could not authenticate agent: {e}"),
                            })
                            .await?;
                        }
                    }
                    RelayToHost::AgentSetModel { model_id } => {
                        let session = session.clone();
                        let result_tx = control_tx.clone();
                        tokio::spawn(async move {
                            let result = session
                                .agent_set_model(model_id)
                                .await
                                .map_err(|e| format!("could not change model: {e}"));
                            let _ = result_tx.send(result).await;
                        });
                    }
                    // Terminal-mode frames are invalid on an agent connection.
                    _ => {}
                }
            }
            result = control_rx.recv() => {
                if let Some(Err(message)) = result {
                    send_msg(&mut wr, &HostToRelay::AgentError { message }).await?;
                }
            }
            evt = events.recv() => {
                use tokio::sync::broadcast::error::RecvError;
                match evt {
                    Ok(ManagerEvent::AgentTimeline { id: eid, event }) if eid == id => {
                        send_msg(&mut wr, &HostToRelay::AgentEvent { event }).await?;
                    }
                    Ok(ManagerEvent::AgentPermission { id: eid, tool_call, options, .. })
                        if eid == id =>
                    {
                        send_msg(&mut wr, &HostToRelay::AgentPermission { tool_call, options })
                            .await?;
                    }
                    // The laptop-chat relay wire (HostToRelay) is deliberately
                    // left frozen: the chat still dismisses the card, it just
                    // doesn't carry the richer outcome/resolver the phone gets.
                    Ok(ManagerEvent::AgentPermissionResolved {
                        id: eid,
                        tool_call_id,
                        ..
                    }) if eid == id => {
                        send_msg(&mut wr, &HostToRelay::AgentPermissionResolved { tool_call_id })
                            .await?;
                    }
                    Ok(ManagerEvent::Removed(eid)) if eid == id => {
                        let _ = send_msg(&mut wr, &HostToRelay::AgentGone {
                            message: "the agent session was closed".into(),
                        })
                        .await;
                        break;
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        // Same recovery contract as the phone path: replay the
                        // bounded history (CLI dedups by seq) AND the pending
                        // approvals (the dropped event may have been one).
                        for event in session.agent_snapshot().unwrap_or_default() {
                            send_msg(&mut wr, &HostToRelay::AgentEvent { event }).await?;
                        }
                        for (tool_call, options, _) in session.agent_permissions() {
                            send_msg(&mut wr, &HostToRelay::AgentPermission { tool_call, options })
                                .await?;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
    reader.abort();
    let _ = wr.shutdown().await;
    info!(id = id.0, "agent chat disconnected");
    Ok(())
}

async fn send_msg<W: AsyncWrite + Unpin>(
    wr: &mut W,
    msg: &HostToRelay,
) -> crate::error::HostResult<()> {
    let bytes = postcard::to_allocvec(msg)
        .map_err(|e| crate::error::HostError::Serialization(e.to_string()))?;
    write_framed(wr, &bytes).await?;
    Ok(())
}

pub(crate) async fn read_framed<R: AsyncRead + Unpin>(rd: &mut R) -> std::io::Result<Vec<u8>> {
    let len = rd.read_u32_le().await?;
    if len > MAX_RELAY_FRAME_BYTES {
        return Err(std::io::Error::other("relay frame too large"));
    }
    let mut buf = vec![0u8; len as usize];
    rd.read_exact(&mut buf).await?;
    Ok(buf)
}

pub(crate) async fn write_framed<W: AsyncWrite + Unpin>(
    wr: &mut W,
    bytes: &[u8],
) -> std::io::Result<()> {
    if bytes.len() > MAX_RELAY_FRAME_BYTES as usize {
        return Err(std::io::Error::other("relay frame too large"));
    }
    wr.write_u32_le(bytes.len() as u32).await?;
    wr.write_all(bytes).await?;
    wr.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use portty_protocol::AgentEvent;

    #[tokio::test]
    async fn relay_framing_rejects_oversized_messages_both_directions() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client
            .write_u32_le(MAX_RELAY_FRAME_BYTES + 1)
            .await
            .unwrap();
        assert_eq!(
            read_framed(&mut server).await.unwrap_err().kind(),
            std::io::ErrorKind::Other
        );

        let mut sink = tokio::io::sink();
        let oversized = vec![0; MAX_RELAY_FRAME_BYTES as usize + 1];
        assert_eq!(
            write_framed(&mut sink, &oversized)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Other
        );
    }

    /// End-to-end over an in-memory duplex pipe (no OS pipe needed): a mock relay
    /// registers, streams output, and receives forwarded input - proving the
    /// adopt path without a real terminal.
    #[tokio::test]
    async fn relay_pipe_rejects_version_skew() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mgr = SessionManager::new();
        let host = tokio::spawn(handle_conn(server, mgr.clone(), None, None, None, None));
        let (_crd, mut cwr) = tokio::io::split(client);

        // A CLI built at a different relay-pipe version sends the wrong version
        // as its first frame (#36).
        write_framed(&mut cwr, &RELAY_PIPE_VERSION.wrapping_add(1).to_le_bytes())
            .await
            .unwrap();
        // Even a valid Register after it must not adopt anything - the daemon
        // rejected the connection at the version gate.
        let reg = postcard::to_allocvec(&RelayToHost::Register {
            title: "skewed".into(),
            cols: 80,
            rows: 24,
        })
        .unwrap();
        let _ = write_framed(&mut cwr, &reg).await; // may fail once the host closes

        let result = host.await.unwrap();
        assert!(
            result.is_err(),
            "a version-skewed relay peer must be rejected"
        );
        assert!(
            mgr.list().await.is_empty(),
            "no session may be adopted on version skew"
        );
    }

    /// `portty-host stop` against the REAL daemon handler, using the REAL control
    /// client - no hand-rolled server that might be more forgiving than the
    /// daemon.
    ///
    /// This is the test that was missing. The daemon's version gate (#36) and the
    /// control client lived in different files, the only coverage mocked the
    /// daemon side, and so `stop` shipped rejecting itself at the gate: the
    /// connection closed unanswered, the caller saw `UnexpectedEof`, and the
    /// daemon stayed up. Driving both real halves is the only thing that catches
    /// that class of drift.
    ///
    /// The `Shutdown` arm sets the process-global shutdown bit. Nothing else in
    /// this test binary awaits `shutdown_signal`, so it stays inert here.
    #[tokio::test]
    async fn daemon_control_survives_the_real_version_gate() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mgr = SessionManager::new();
        let host = tokio::spawn(handle_conn(server, mgr, None, None, None, None));

        let reply = crate::exchange_daemon_control(client, RelayToHost::Shutdown)
            .await
            .expect("the daemon must answer its own control client");

        assert!(
            matches!(reply, HostToRelay::ShutdownAccepted),
            "stop is acknowledged, not silently dropped at the version gate"
        );
        host.await
            .unwrap()
            .expect("the daemon accepted the request");
    }

    #[tokio::test]
    async fn mock_relay_adopts_streams_and_receives_input() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mgr = SessionManager::new();

        // Host side.
        let host = tokio::spawn(handle_conn(server, mgr.clone(), None, None, None, None));

        // Mock relay side.
        let (mut crd, mut cwr) = tokio::io::split(client);

        // Version handshake - the CLI always sends this as its first frame (#36).
        write_framed(&mut cwr, &RELAY_PIPE_VERSION.to_le_bytes())
            .await
            .unwrap();

        // Register.
        let reg = postcard::to_allocvec(&RelayToHost::Register {
            title: "agent-1".into(),
            cols: 80,
            rows: 24,
        })
        .unwrap();
        write_framed(&mut cwr, &reg).await.unwrap();

        // The daemon should now list our adopted session.
        // (small spin: registration happens right after the first frame)
        let mut listed = None;
        for _ in 0..50 {
            let l = mgr.list().await;
            if !l.is_empty() {
                listed = Some(l);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let list = listed.expect("adopted session never appeared");
        assert_eq!(list[0].title, "agent-1");
        let id = list[0].id;

        // Viewer subscribes; relay streams output; viewer sees it.
        let session = mgr.get(id).await.unwrap();
        let (_snap, _seq, mut rx) = session.snapshot_and_subscribe();
        let out = postcard::to_allocvec(&RelayToHost::Output(b"hello phone\n".to_vec())).unwrap();
        write_framed(&mut cwr, &out).await.unwrap();
        let got = rx.recv().await.unwrap();
        assert_eq!(got.bytes.as_slice(), b"hello phone\n");

        // Viewer input is forwarded to the relay over the pipe.
        session.write_input(b"ls\n").unwrap();
        let frame = read_framed(&mut crd).await.unwrap();
        match postcard::from_bytes::<HostToRelay>(&frame).unwrap() {
            HostToRelay::Input(b) => assert_eq!(b, b"ls\n"),
            other => panic!("expected Input, got {other:?}"),
        }

        // The relay reporting a laptop resize updates the authoritative size.
        assert_eq!(session.size(), (80, 24)); // seeded by Register
        let sz = postcard::to_allocvec(&RelayToHost::SizeChanged {
            cols: 200,
            rows: 55,
        })
        .unwrap();
        write_framed(&mut cwr, &sz).await.unwrap();
        for _ in 0..50 {
            if session.size() == (200, 55) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(session.size(), (200, 55));

        // Relay says the shell exited → session is dropped.
        let exited = postcard::to_allocvec(&RelayToHost::Exited).unwrap();
        write_framed(&mut cwr, &exited).await.unwrap();
        for _ in 0..50 {
            if mgr.list().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            mgr.list().await.is_empty(),
            "session should be gone after Exited"
        );

        let _ = host.await;
    }

    /// End-to-end `portty agent` proof over an in-memory pipe: join a live
    /// agent session, replay its history, prompt it, receive the approval
    /// card, answer it, and hear the resolution echoed back - the laptop half
    /// of dual-control, using the deterministic mock ACP agent (no AI, no auth).
    #[tokio::test]
    async fn agent_pipe_joins_prompts_and_answers_approvals() {
        use std::time::Duration;

        let mgr = SessionManager::new();

        // A live "Claude Code" session, as if the phone had started it - but
        // backed by the mock agent so the test is hermetic.
        let py = if cfg!(windows) { "python" } else { "python3" };
        let mock = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("acp-probe")
            .join("mock_agent.py")
            .display()
            .to_string()
            .replace('\\', "/");
        let id = mgr
            .spawn_agent(
                &format!("{py} {mock}"),
                Some("mock claude".into()),
                Some(AgentProvider::ClaudeCode),
            )
            .await
            .expect("spawn mock agent");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(handle_conn(server, mgr.clone(), None, None, None, None));
        let (mut crd, mut cwr) = tokio::io::split(client);

        // Version handshake - always the CLI's first frame (#36).
        write_framed(&mut cwr, &RELAY_PIPE_VERSION.to_le_bytes())
            .await
            .unwrap();

        // Open the laptop chat: join the live session instead of starting one.
        let open = postcard::to_allocvec(&RelayToHost::OpenAgent {
            provider: AgentProvider::ClaudeCode,
            join: true,
        })
        .unwrap();
        write_framed(&mut cwr, &open).await.unwrap();

        async fn next_msg<R: AsyncRead + Unpin>(rd: &mut R) -> HostToRelay {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(10), read_framed(rd))
                .await
                .expect("pipe read timed out")
                .expect("pipe closed");
            postcard::from_bytes::<HostToRelay>(&frame).expect("decode")
        }

        match next_msg(&mut crd).await {
            HostToRelay::AgentOpened {
                id: oid,
                title,
                created,
            } => {
                assert_eq!(oid, id, "joined the pre-existing session");
                assert_eq!(title, "mock claude");
                assert!(!created, "must join, not create");
            }
            other => panic!("expected AgentOpened, got {other:?}"),
        }
        // History replay starts with the SessionStarted card.
        match next_msg(&mut crd).await {
            HostToRelay::AgentEvent { event } => {
                assert!(matches!(event.event, AgentEvent::SessionStarted { .. }));
            }
            other => panic!("expected replayed SessionStarted, got {other:?}"),
        }

        // Laptop controls ride explicit relay variants (not user prompts), and
        // the resulting authoritative ACP state is broadcast back.
        let set_mode = postcard::to_allocvec(&RelayToHost::AgentSetMode {
            mode_id: "plan".into(),
        })
        .unwrap();
        write_framed(&mut cwr, &set_mode).await.unwrap();
        loop {
            match next_msg(&mut crd).await {
                HostToRelay::AgentEvent { event }
                    if matches!(
                        event.event,
                        AgentEvent::ModeState { ref current_mode_id, .. }
                            if current_mode_id == "plan"
                    ) =>
                {
                    break
                }
                HostToRelay::AgentEvent { .. } => continue,
                other => panic!("expected updated ModeState, got {other:?}"),
            }
        }

        let set_model = postcard::to_allocvec(&RelayToHost::AgentSetModel {
            model_id: "mock-deep".into(),
        })
        .unwrap();
        write_framed(&mut cwr, &set_model).await.unwrap();
        loop {
            match next_msg(&mut crd).await {
                HostToRelay::AgentEvent { event } => {
                    let AgentEvent::ConfigOptions { options } = event.event else {
                        continue;
                    };
                    if options.iter().any(|option| {
                        option.category.as_deref() == Some("model")
                            && matches!(
                                &option.current_value,
                                portty_protocol::AgentConfigValue::Select(value)
                                    if value == "mock-deep"
                            )
                    }) {
                        break;
                    }
                }
                other => panic!("expected updated ConfigOptions, got {other:?}"),
            }
        }

        // Prompt from the laptop → echoed UserMessage, TurnStarted, then the
        // mock's approval card.
        let prompt = postcard::to_allocvec(&RelayToHost::AgentPrompt {
            text: "do the thing".into(),
        })
        .unwrap();
        write_framed(&mut cwr, &prompt).await.unwrap();

        let tool_call_id = loop {
            match next_msg(&mut crd).await {
                HostToRelay::AgentPermission { tool_call, options } => {
                    assert_eq!(tool_call.title, "Write acp_probe_test.txt");
                    assert_eq!(options.len(), 2);
                    break tool_call.tool_call_id;
                }
                HostToRelay::AgentEvent { .. } => continue, // UserMessage/TurnStarted/…
                other => panic!("expected AgentPermission, got {other:?}"),
            }
        };

        // Answer from the laptop → the resolution is broadcast back (this is
        // what dismisses the card on the phone).
        let decision = postcard::to_allocvec(&RelayToHost::AgentDecision {
            tool_call_id: tool_call_id.clone(),
            option_id: None,
        })
        .unwrap();
        write_framed(&mut cwr, &decision).await.unwrap();
        loop {
            match next_msg(&mut crd).await {
                HostToRelay::AgentPermissionResolved { tool_call_id: rid } => {
                    assert_eq!(rid, tool_call_id);
                    break;
                }
                HostToRelay::AgentEvent { .. } => continue,
                other => panic!("expected AgentPermissionResolved, got {other:?}"),
            }
        }

        // Leaving the chat must NOT kill the session - the phone still owns it.
        drop(cwr);
        drop(crd);
        let _ = tokio::time::timeout(Duration::from_secs(5), host).await;
        assert!(
            mgr.get(id).await.is_some(),
            "agent session must survive the laptop leaving"
        );
        mgr.kill(id).await;
    }
}
