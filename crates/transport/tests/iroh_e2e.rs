//! End-to-end transport test: two iroh endpoints connect, run the real pairing
//! handshake (same out-of-band ticket secret), then exchange a sealed `Frame`.
//! Proves the "swap localhost → iroh" step is wired.

use std::time::Duration;

use iroh::RelayMode;
use portty_protocol::Frame;
use portty_transport::{
    build_endpoint, confirm_server_handshake, decode_ticket, encode_ticket, open_msg, read_frame,
    run_client_handshake, run_server_handshake, seal_msg, write_frame, ClientHandshake,
    HandshakeMessage, HandshakeOutcome, Identity, IrohTransport, PairingFailure, PairingSecret,
    ResumptionToken, SealedEnvelope, ServerHandshake, SyncError, Transport, TransportError,
    PROTOCOL_VERSION, SYNC_ALPN,
};

/// The out-of-band credential the joiner scanned. Since PROTOCOL_VERSION 8 this
/// is the entire first-pair credential - there is no PIN beside it.
fn ticket_secret() -> PairingSecret {
    PairingSecret::from_ticket_bytes([0x42; 16])
}
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_handshake_and_exchange_sealed_frame() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("iroh=info,portty_transport=debug")
        .with_writer(std::io::stderr)
        .try_init();

    let res = tokio::time::timeout(Duration::from_secs(60), async {
        let host_dir = tempdir()?;
        let client_dir = tempdir()?;
        let host_id = Identity::load_or_create(host_dir.path())?;
        let client_id = Identity::load_or_create(client_dir.path())?;

        let host_ep = build_endpoint(&host_id, RelayMode::Disabled).await?;
        let client_ep = build_endpoint(&client_id, RelayMode::Disabled).await?;

        let port = host_ep
            .bound_sockets()
            .into_iter()
            .find_map(|s| if s.is_ipv4() { Some(s.port()) } else { None })
            .expect("an IPv4 bound socket");
        let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let host_addr = iroh::EndpointAddr::new(host_ep.id()).with_ip_addr(loopback);
        eprintln!("[test] host loopback addr: {:?}", host_addr);
        let ticket = encode_ticket(&host_addr, Some(&ticket_secret()))?;
        assert!(ticket.starts_with("portty1:"));

        // Server side.
        let host_ep2 = host_ep.clone();
        let host_did = host_id.device_id();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            eprintln!("[server] awaiting accept");
            let incoming = match host_ep2.accept().await {
                Some(i) => i,
                None => {
                    eprintln!("[server] accept() returned None");
                    return Err(SyncError::Transport(TransportError::Closed));
                }
            };
            let conn = incoming.await.map_err(|e| {
                eprintln!("[server] incoming.await error: {e:?}");
                TransportError::Iroh(format!("incoming: {e:?}"))
            })?;
            eprintln!("[server] connection accepted");
            let mut tport = IrohTransport::accept(conn).await?;
            eprintln!("[server] accept_bi ok");
            let mut hs = ServerHandshake::new(host_did, "host".into())
                .with_unwindowed_pairing_secrets([ticket_secret()]);
            let HandshakeOutcome { cipher, .. } = run_server_handshake(&mut tport, &mut hs).await?;
            // Production commits the pairing between these two calls; a test has
            // nothing to persist, so it confirms immediately.
            confirm_server_handshake(&mut tport, &hs).await?;
            eprintln!("[server] handshake done");
            let frame = Frame::SessionList { sessions: vec![] };
            let sealed: SealedEnvelope = seal_msg(&cipher, &frame, b"")?;
            tport.send(&sealed).await?;
            eprintln!("[server] sent sealed frame");
            // Hold the connection open until the client confirms receipt, so the
            // ungraceful drop on task exit doesn't discard in-flight data. (The
            // real host keeps connections alive for the whole app phase.)
            let _ = done_rx.await;
            eprintln!("[server] client confirmed; closing");
            Ok::<(), SyncError>(())
        });

        // Client side.
        let peer_addr = decode_ticket(&ticket)?;
        eprintln!("[client] connecting");
        let mut ctport = IrohTransport::connect(&client_ep, peer_addr).await?;
        eprintln!("[client] connected + open_bi ok");
        let mut chs =
            ClientHandshake::first_pair(client_id.device_id(), "phone".into(), ticket_secret());
        let HandshakeOutcome {
            cipher,
            peer_display_name: peer_name,
            ..
        } = run_client_handshake(&mut ctport, &mut chs).await?;
        eprintln!("[client] handshake done; peer={peer_name}");
        assert_eq!(peer_name, "host");

        let env: SealedEnvelope = ctport.recv().await?;
        let frame: Frame = open_msg(&cipher, &env, b"")?;
        match frame {
            Frame::SessionList { sessions } => assert!(sessions.is_empty()),
            _ => panic!("expected SessionList, got another variant"),
        }
        eprintln!("[client] received + opened SessionList");
        let _ = done_tx.send(());

        // Surface any server-side error before we declare success.
        server.await.map_err(|e| {
            eprintln!("[test] server task panicked: {e:?}");
            TransportError::Iroh(format!("server task: {e:?}"))
        })??;
        drop(ctport);
        tokio::join!(host_ep.close(), client_ep.close());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;

    match res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("test failed: {e}"),
        Err(_) => panic!("test timed out after 60s"),
    }
}

// Second connection resumes by the SEC-2 token - no PIN. Proves reconnect auth
// works over the real iroh transport: first pair (PIN) derives a token both
// sides agree on; a second connection authenticates by that token with
// DIFFERENT PINs on each side, and the resumed cipher round-trips a frame.
#[tokio::test(flavor = "multi_thread")]
async fn reconnect_by_token_after_first_pair() {
    use std::collections::HashMap;

    let _ = tracing_subscriber::fmt()
        .with_env_filter("iroh=info,portty_transport=debug")
        .with_writer(std::io::stderr)
        .try_init();

    let res = tokio::time::timeout(Duration::from_secs(60), async {
        let host_dir = tempdir()?;
        let client_dir = tempdir()?;
        let host_id = Identity::load_or_create(host_dir.path())?;
        let client_id = Identity::load_or_create(client_dir.path())?;
        let client_did = client_id.device_id();

        let host_ep = build_endpoint(&host_id, RelayMode::Disabled).await?;
        let client_ep = build_endpoint(&client_id, RelayMode::Disabled).await?;

        let port = host_ep
            .bound_sockets()
            .into_iter()
            .find_map(|s| if s.is_ipv4() { Some(s.port()) } else { None })
            .expect("an IPv4 bound socket");
        let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let host_addr = iroh::EndpointAddr::new(host_ep.id()).with_ip_addr(loopback);
        let ticket = encode_ticket(&host_addr, Some(&ticket_secret()))?;

        // ── Phase 1: first pair by ticket secret. Both derive the reconnect token. ──
        let host_ep1 = host_ep.clone();
        let host_did = host_id.device_id();
        let (pair_done_tx, pair_done_rx) = tokio::sync::oneshot::channel::<()>();
        let (server_token_tx, server_token_rx) = tokio::sync::oneshot::channel::<ResumptionToken>();

        let server1 = tokio::spawn(async move {
            let incoming = host_ep1.accept().await.expect("accept");
            let conn = incoming.await.expect("incoming");
            let mut tport = IrohTransport::accept(conn).await?;
            let mut hs = ServerHandshake::new(host_did, "host".into())
                .with_unwindowed_pairing_secrets([ticket_secret()]);
            let outcome = run_server_handshake(&mut tport, &mut hs).await?;
            confirm_server_handshake(&mut tport, &hs).await?;
            eprintln!("[server1] first pair done; token derived");
            let _ = server_token_tx.send(outcome.reconnect_token);
            // Hold the connection briefly so the client's handshake cleanly finishes.
            let _ = pair_done_rx.await;
            Ok::<(), SyncError>(())
        });

        let peer_addr = decode_ticket(&ticket)?;
        let mut ctport = IrohTransport::connect(&client_ep, peer_addr).await?;
        let mut chs = ClientHandshake::first_pair(client_did, "phone".into(), ticket_secret());
        let outcome1 = run_client_handshake(&mut ctport, &mut chs).await?;
        let client_token = outcome1.reconnect_token.clone();
        let server_token = server_token_rx.await.expect("server token");
        assert_eq!(
            client_token, server_token,
            "both sides must derive the SAME reconnect token from the first pair"
        );
        drop(ctport);
        let _ = pair_done_tx.send(());
        server1.await??;

        // ── Phase 2: reconnect by the token, with NO pairing secret armed. ──
        let host_ep2 = host_ep.clone();
        let (resume_done_tx, resume_done_rx) = tokio::sync::oneshot::channel::<()>();
        let mut tokens = HashMap::new();
        tokens.insert(client_did, client_token.clone());

        let server2 = tokio::spawn(async move {
            let incoming = host_ep2.accept().await.expect("accept");
            let conn = incoming.await.expect("incoming");
            let mut tport = IrohTransport::accept(conn).await?;
            // No armed pairing secret at all on the server - a reconnect must
            // succeed by the token alone, and must not be gated on the credential
            // that only a FIRST pair needs.
            let mut hs =
                ServerHandshake::new(host_did, "host".into()).with_resumption_tokens(tokens);
            let outcome = run_server_handshake(&mut tport, &mut hs).await?;
            confirm_server_handshake(&mut tport, &hs).await?;
            eprintln!("[server2] resume by token succeeded");
            // Prove the resumed cipher round-trips a frame.
            let frame = Frame::SessionList { sessions: vec![] };
            let sealed: SealedEnvelope = seal_msg(&outcome.cipher, &frame, b"")?;
            tport.send(&sealed).await?;
            let _ = resume_done_rx.await;
            Ok::<(), SyncError>(())
        });

        let mut ctport2 = IrohTransport::connect(&client_ep, decode_ticket(&ticket)?).await?;
        // The client presents only its token - it holds no ticket secret now.
        let mut chs2 = ClientHandshake::resume(client_did, "phone".into(), client_token);
        let outcome2 = run_client_handshake(&mut ctport2, &mut chs2).await?;
        eprintln!("[client2] resume handshake done");

        let env: SealedEnvelope = ctport2.recv().await?;
        let frame: Frame = open_msg(&outcome2.cipher, &env, b"")?;
        match frame {
            Frame::SessionList { sessions } => assert!(sessions.is_empty()),
            _ => panic!("expected SessionList over the resumed channel"),
        }
        let _ = resume_done_tx.send(());
        server2.await??;

        // Forward secrecy: the resumed session key differs from the first-pair key.
        // (Both sides rotated the token too - outcome1/2.reconnect_token differ.)
        assert_ne!(
            outcome1.reconnect_token, outcome2.reconnect_token,
            "a resume must derive a fresh (rotated) token"
        );
        drop(ctport2);
        tokio::join!(host_ep.close(), client_ep.close());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;

    match res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("resume test failed: {e}"),
        Err(_) => panic!("resume test timed out after 60s"),
    }
}

/// A peer on ANOTHER protocol version is told ours, then closed cleanly.
///
/// It used to get no answer at all: the host's frame layer refused the Hello
/// inside `recv` and the connection simply dropped, so the phone could only say
/// "connection lost". Now the peer reads exactly one frame - stamped with the
/// host's version, so its own frame layer reports `found: <host version>` and
/// can name the older side - followed by a clean end of stream rather than a
/// reset or a lost connection. And the host stops waiting the moment the peer
/// hangs up, instead of sitting out its whole linger.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_on_another_protocol_version_is_answered_then_closed_cleanly() {
    let res = tokio::time::timeout(Duration::from_secs(60), async {
        let host_dir = tempdir()?;
        let client_dir = tempdir()?;
        let host_id = Identity::load_or_create(host_dir.path())?;
        let client_id = Identity::load_or_create(client_dir.path())?;
        let host_ep = build_endpoint(&host_id, RelayMode::Disabled).await?;
        let client_ep = build_endpoint(&client_id, RelayMode::Disabled).await?;
        let port = host_ep
            .bound_sockets()
            .into_iter()
            .find_map(|s| if s.is_ipv4() { Some(s.port()) } else { None })
            .expect("an IPv4 bound socket");
        let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let host_addr = iroh::EndpointAddr::new(host_ep.id()).with_ip_addr(loopback);

        // One version ahead (a newer phone) and one behind (an older one).
        for theirs in [PROTOCOL_VERSION + 1, PROTOCOL_VERSION - 1] {
            let accept_ep = host_ep.clone();
            let host_did = host_id.device_id();
            let server = tokio::spawn(async move {
                let incoming = accept_ep.accept().await.expect("accept");
                let conn = incoming.await.expect("incoming");
                let mut tport = IrohTransport::accept(conn).await?;
                let mut hs = ServerHandshake::new(host_did, "host".into())
                    .with_unwindowed_pairing_secrets([ticket_secret()]);
                let refused = run_server_handshake(&mut tport, &mut hs).await.err();
                let lingering = std::time::Instant::now();
                tport.finish_and_close(Duration::from_secs(30)).await;
                Ok::<_, SyncError>((refused, lingering.elapsed()))
            });

            // A raw peer: exactly what a Portty build on `theirs` puts on the wire.
            let conn = client_ep.connect(host_addr.clone(), SYNC_ALPN).await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let hello = HandshakeMessage::Hello {
                device_id: client_id.device_id().0,
                protocol_version: theirs,
                display_name: "phone".into(),
                client_eph_pub: [9; 32],
            };
            write_frame(&mut send, theirs, &postcard::to_allocvec(&hello).unwrap()).await?;

            let (version, payload) = read_frame(&mut recv).await?;
            assert_eq!(
                version, PROTOCOL_VERSION,
                "the reply is stamped with the host's own version"
            );
            assert!(matches!(
                postcard::from_bytes::<HandshakeMessage>(&payload).unwrap(),
                HandshakeMessage::PairingFailed {
                    reason: PairingFailure::UnsupportedVersion
                }
            ));
            // Then a clean end of stream (FIN) - not a reset, not a lost connection.
            let next = read_frame(&mut recv).await;
            assert!(
                matches!(next, Err(TransportError::Closed)),
                "expected a clean end of stream, got {next:?}"
            );
            // The side that received the last message hangs up, as QUIC wants.
            conn.close(0u32.into(), b"done");

            let (refused, lingered) = server.await??;
            assert!(
                matches!(
                    &refused,
                    Some(SyncError::Transport(TransportError::UnsupportedProtocolVersion {
                        expected: PROTOCOL_VERSION,
                        found,
                    })) if *found == theirs
                ),
                "{refused:?}"
            );
            assert!(
                lingered < Duration::from_secs(10),
                "the host should stop waiting once the peer hangs up; waited {lingered:?}"
            );
        }
        tokio::join!(host_ep.close(), client_ep.close());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;

    match res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("version-reply test failed: {e}"),
        Err(_) => panic!("version-reply test timed out after 60s"),
    }
}
