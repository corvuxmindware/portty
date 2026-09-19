//! iroh QUIC transport. (Forked + adapted from Corvux `sync/transport/iroh.rs`.)
//!
//! Adaptations vs Corvux:
//!   - **ALPN** `corvux/sync/1` → **`portty/sync/1`**.
//!   - **Ticket scheme** `corvux1:` → **`portty1:`**.
//!   - **Dropped the mDNS/LAN `address_lookup`** param from `build_endpoint`
//!     (Portty LAN discovery is a later step); the N0 preset's DNS discovery is
//!     kept so a peer holding just a NodeId can still resolve.
//!   - `Transport<M>` is generic over the message type - impl below covers every
//!     postcard `M` (handshake messages AND post-handshake `SealedEnvelope`).
//!
//! iroh handles NAT hole-punching + relay fallback so the host needs no open
//! ports. iroh's NodeId is an Ed25519 pubkey - same primitive as our `Identity`,
//! so we seed iroh's `SecretKey` from the existing keypair (one key on disk).

use async_trait::async_trait;
use iroh::endpoint::presets;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr as NodeAddr, EndpointId as NodeId, RelayMode, SecretKey};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroize;

use crate::crypto::envelope::EnvelopeCipher;
use crate::crypto::pairing::pair_verification_code;
use crate::error::{ProtocolError, SyncResult, TransportError};
use crate::frame::{read_frame, validate_protocol_version, write_frame, PROTOCOL_VERSION};
use crate::handshake::{
    derive_pair_material, derive_reconnect_token, ClientHandshake, HandshakeMessage, Outcome,
    PairEventKey, PairId, ResumptionToken, ServerHandshake,
};
use crate::identity::{DeviceId, Identity};
use crate::transport::Transport;

/// ALPN advertised on iroh QUIC connections. Tied to the wire-protocol
/// generation; per-frame `PROTOCOL_VERSION` handles finer-grained upgrades.
pub const SYNC_ALPN: &[u8] = b"portty/sync/1";

const DEFAULT_KEEPALIVE_SECS: u64 = 10;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;
const DEFAULT_STREAM_WINDOW_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_CONNECTION_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_SEND_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// Bounded QUIC knobs. The 4 MiB stream window covers roughly 100 Mbit/s at
/// 300 ms RTT without starving file transfer, while the connection and send
/// caps keep worst-case memory predictable across concurrent peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QuicTuning {
    keepalive_secs: u64,
    idle_timeout_secs: u64,
    stream_window_bytes: u64,
    connection_window_bytes: u64,
    send_window_bytes: u64,
}

impl QuicTuning {
    fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        fn bounded(value: Option<String>, default: u64, minimum: u64, maximum: u64) -> u64 {
            value
                .and_then(|raw| raw.parse::<u64>().ok())
                .unwrap_or(default)
                .clamp(minimum, maximum)
        }

        let keepalive_secs = bounded(
            lookup("PORTTY_QUIC_KEEPALIVE_SECS"),
            DEFAULT_KEEPALIVE_SECS,
            2,
            60,
        );
        let idle_timeout_secs = bounded(
            lookup("PORTTY_QUIC_IDLE_TIMEOUT_SECS"),
            DEFAULT_IDLE_TIMEOUT_SECS,
            10,
            300,
        )
        .max(keepalive_secs.saturating_mul(2));
        let stream_window_bytes = bounded(
            lookup("PORTTY_QUIC_STREAM_WINDOW_BYTES"),
            DEFAULT_STREAM_WINDOW_BYTES,
            256 * 1024,
            32 * 1024 * 1024,
        );
        let connection_window_bytes = bounded(
            lookup("PORTTY_QUIC_CONNECTION_WINDOW_BYTES"),
            DEFAULT_CONNECTION_WINDOW_BYTES,
            1024 * 1024,
            64 * 1024 * 1024,
        )
        .max(stream_window_bytes);
        let send_window_bytes = bounded(
            lookup("PORTTY_QUIC_SEND_WINDOW_BYTES"),
            DEFAULT_SEND_WINDOW_BYTES,
            256 * 1024,
            64 * 1024 * 1024,
        );
        Self {
            keepalive_secs,
            idle_timeout_secs,
            stream_window_bytes,
            connection_window_bytes,
            send_window_bytes,
        }
    }
}

/// A finished handshake: the sealed-channel cipher + the peer's identity + the
/// SEC-2 reconnect token derived from this session (persist it keyed by the
/// peer's `DeviceId` so the next reconnect needs no out-of-band secret at all).
pub struct HandshakeOutcome {
    pub cipher: EnvelopeCipher,
    pub peer_device_id: DeviceId,
    pub peer_display_name: String,
    pub reconnect_token: ResumptionToken,
    /// Whether this session proved an existing rotating token. False means a
    /// first/manual pair and therefore authorizes a new pair generation.
    pub resumed: bool,
    /// Candidate generation material derived from this session. Callers retain
    /// the existing durable material on resume and install this on a fresh pair.
    pub pair_id: PairId,
    pub pair_event_key: PairEventKey,
    /// Server side, FIRST pair only: the enrollment opportunity this handshake was
    /// verified under. The caller must claim it with
    /// `PairingState::consume_first_pair` in the same step that persists the
    /// pairing, and abandon the connection if the claim fails. `None` on the client
    /// and on a reconnect.
    pub enrollment_epoch: Option<u64>,
    /// The 6-digit comparison code for this exchange, identical on both peers.
    ///
    /// Show it to the human on a FIRST pair and let them confirm it matches the
    /// other screen before the pairing is committed. Both sides derive it from
    /// the finished session, which mixes the ephemeral ECDH, so a peer in the
    /// middle - running two different exchanges - cannot make the two displays
    /// agree. Meaningless on a reconnect, where the rotating token already
    /// authenticated both ends.
    ///
    /// Not secret and not key material: it is designed to be read aloud.
    pub verification_code: String,
}

/// Build an iroh `SecretKey` seeded from our existing Ed25519 device key, so
/// `DeviceId` and iroh `NodeId` stay in lockstep with one keypair on disk.
fn iroh_secret_from_identity(id: &Identity) -> SecretKey {
    let mut bytes = id.signing_key_bytes();
    let secret = SecretKey::from_bytes(&bytes);
    bytes.zeroize();
    secret
}

/// Convert an authenticated iroh `NodeId` to our internal `DeviceId`
/// (first 16 bytes of SHA256(pubkey)). Deterministic per pubkey.
pub fn device_id_from_node_id(node_id: NodeId) -> Result<DeviceId, TransportError> {
    use ed25519_dalek::VerifyingKey;
    let bytes: [u8; 32] = *node_id.as_bytes();
    let vk = VerifyingKey::from_bytes(&bytes)
        .map_err(|e| TransportError::Iroh(format!("invalid NodeId pubkey: {e}")))?;
    Ok(DeviceId::from_pubkey(&vk))
}

/// One iroh-backed message channel: a single QUIC bidirectional stream over an
/// `iroh::Endpoint` connection. The `Connection` is held to keep the QUIC
/// session alive while either stream is in use.
pub struct IrohTransport {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    peer_node_id: NodeId,
}

impl IrohTransport {
    /// NodeId of the peer - authenticated by iroh's QUIC handshake.
    pub fn peer_node_id(&self) -> NodeId {
        self.peer_node_id
    }

    /// Server-side accept: take an inbound `Connection` and accept its bi-stream.
    pub async fn accept(connection: Connection) -> Result<Self, TransportError> {
        let peer_node_id = connection.remote_id();
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| TransportError::Iroh(format!("accept_bi: {e}")))?;
        Ok(Self {
            connection,
            send,
            recv,
            peer_node_id,
        })
    }

    /// Client-side dial: resolve the peer + open the bi-stream.
    pub async fn connect(endpoint: &Endpoint, peer: NodeAddr) -> Result<Self, TransportError> {
        let peer_node_id = peer.id;
        let connection = endpoint
            .connect(peer, SYNC_ALPN)
            .await
            .map_err(|e| TransportError::Iroh(format!("connect: {e}")))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| TransportError::Iroh(format!("open_bi: {e}")))?;
        Ok(Self {
            connection,
            send,
            recv,
            peer_node_id,
        })
    }

    /// Split into independent read/write halves. Use this once the handshake is
    /// done so a dedicated reader task and a writer can run concurrently - a
    /// single `Transport::recv` future polled under `select!` would be cancelled
    /// mid-frame and corrupt the framing; splitting avoids that. Each half holds
    /// a clone of the `Connection` so the QUIC session stays alive for both.
    pub fn split(self) -> (IrohWriter, IrohReader) {
        (
            IrohWriter {
                _conn: self.connection.clone(),
                send: self.send,
            },
            IrohReader {
                _conn: self.connection,
                recv: self.recv,
            },
        )
    }
}

/// Write half of an iroh transport. Carries raw framed bytes (postcard payload).
pub struct IrohWriter {
    _conn: Connection,
    send: SendStream,
}

/// Read half of an iroh transport. Carries raw framed bytes (postcard payload).
pub struct IrohReader {
    _conn: Connection,
    recv: RecvStream,
}

impl IrohWriter {
    /// Write one framed postcard payload.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        write_frame(&mut self.send, PROTOCOL_VERSION, bytes).await
    }

    /// Gracefully FIN the send stream so the peer's reader sees EOF, not a reset.
    pub async fn shutdown(&mut self) -> Result<(), TransportError> {
        self.send.shutdown().await.map_err(TransportError::Io)?;
        Ok(())
    }
}

impl IrohReader {
    /// Read one framed postcard payload.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, TransportError> {
        let (version, bytes) = read_frame(&mut self.recv).await?;
        validate_protocol_version(version)?;
        Ok(bytes)
    }
}

/// Generic transport: any postcard `M` (handshake messages, or post-handshake
/// `SealedEnvelope`). Length-prefixed framing with a version per frame.
#[async_trait]
impl<M> Transport<M> for IrohTransport
where
    M: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
{
    async fn send(&mut self, msg: &M) -> Result<(), TransportError> {
        let bytes =
            postcard::to_allocvec(msg).map_err(|e| TransportError::Iroh(format!("encode: {e}")))?;
        write_frame(&mut self.send, PROTOCOL_VERSION, &bytes).await
    }

    async fn recv(&mut self) -> Result<M, TransportError> {
        let (ver, bytes) = read_frame(&mut self.recv).await?;
        validate_protocol_version(ver)?;
        postcard::from_bytes(&bytes).map_err(|e| TransportError::Iroh(format!("decode: {e}")))
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        // FIN the send side so the peer's recv() returns EOF, not a reset.
        self.send.shutdown().await.ok();
        self.connection.close(0u32.into(), b"portty: shutting down");
        Ok(())
    }
}

/// Build an iroh `Endpoint` for this device. One per running host.
///
/// `relay_mode`: `Default` (Number0 public relays), `Custom` (self-hosted), or
/// `Disabled` (LAN/local only - used by tests). Bounded environment tuning
/// controls keepalive, dead-peer detection, and BDP-sized flow-control windows.
pub async fn build_endpoint(
    identity: &Identity,
    relay_mode: RelayMode,
) -> Result<Endpoint, TransportError> {
    let secret = iroh_secret_from_identity(identity);
    let tuning = QuicTuning::from_env();
    tracing::debug!(?tuning, "using bounded QUIC transport tuning");
    let transport_config = iroh::endpoint::QuicTransportConfig::builder()
        .keep_alive_interval(std::time::Duration::from_secs(tuning.keepalive_secs))
        .max_idle_timeout(Some(
            std::time::Duration::from_secs(tuning.idle_timeout_secs)
                .try_into()
                .expect("bounded idle timeout fits in a QUIC VarInt"),
        ))
        .stream_receive_window((tuning.stream_window_bytes as u32).into())
        .receive_window((tuning.connection_window_bytes as u32).into())
        .send_window(tuning.send_window_bytes)
        .build();
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![SYNC_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .transport_config(transport_config)
        .bind()
        .await
        .map_err(|e| TransportError::Iroh(format!("bind: {e}")))
}

// ── Pairing ticket (`portty1:`) ──────────────────────────────────────
//
// What lives in a QR code / paste buffer. Wraps a NodeAddr so the joiner gets
// node_id + direct addrs + relay URL enough to connect immediately. Hand-keyed
// JSON (`nid`/`a`/`r`) decoupled from iroh's internal serde shape for stability
// across iroh minor versions. Format: `portty1:<base64url-nopad(json)>`.

/// Cap on a pasted or scanned pairing code, applied BEFORE it is decoded.
///
/// A full `portty1:` ticket is ~330 characters and the compact QR form is ~72, so
/// this is roughly ten times the largest legitimate code. The bound belongs here
/// rather than downstream because everything downstream allocates from this
/// string: it is base64-decoded into a fresh buffer, and that buffer is then
/// parsed as JSON. The input is a paste buffer or a camera decode - neither has
/// any size of its own - so an unbounded code turned "the user pasted the wrong
/// thing" into megabytes of decode work.
const MAX_TICKET_CHARS: usize = 4096;

/// Cap on the direct addresses one ticket may carry.
///
/// The addrs are a connect-SPEED hint; discovery resolves the host from its
/// NodeId without any of them. So a ticket listing thousands is not a faster
/// connect - it is a list of endpoints someone asked this phone to dial. Extras
/// past the cap are dropped rather than rejected: the NodeId still connects, and
/// failing a pair outright over a cosmetic field would be the worse outcome.
const MAX_TICKET_ADDRS: usize = 16;

#[derive(serde::Serialize, serde::Deserialize)]
struct TicketWire {
    nid: String,
    #[serde(default)]
    a: Vec<String>,
    #[serde(default)]
    r: Option<String>,
    /// base64url of the one-time [`PairingSecret`] the host minted for
    /// this serve session. Carried inside the ticket (like the PIN, never on the
    /// wire); the joiner folds it into the first-pair key so ticket pairing
    /// can't be brute-forced. `None` on legacy tickets and on listeners that
    /// never minted one. `#[serde(default)]` keeps old tickets decodable and old
    /// decoders tolerant of the new field.
    #[serde(default)]
    s: Option<String>,
}

/// Encode a `NodeAddr` to the pairing-ticket string format, optionally carrying
/// the session's one-time [`PairingSecret`] so the joiner can fold it into the
/// first-pair proof.
pub fn encode_ticket(
    addr: &NodeAddr,
    secret: Option<&crate::crypto::pairing::PairingSecret>,
) -> Result<String, TransportError> {
    use base64::Engine;
    let mut wire = TicketWire {
        nid: addr.id.to_string(),
        a: addr.ip_addrs().map(|sa| sa.to_string()).collect(),
        r: addr.relay_urls().next().map(|u| u.to_string()),
        s: secret.map(|sec| sec.to_b64()),
    };
    // Every step here copies the one-time secret into a fresh heap buffer, and
    // each of those is dropped without being cleared unless we say so. The final
    // ticket string legitimately contains the secret (that is what a ticket IS,
    // and the caller owns its lifetime); these intermediates have no reason to
    // outlive the call in freed memory.
    let json = serde_json::to_string(&wire)
        .map(zeroize::Zeroizing::new)
        .map_err(|e| TransportError::Iroh(format!("ticket encode: {e}")))?;
    if let Some(encoded_secret) = wire.s.as_mut() {
        encoded_secret.zeroize();
    }
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
    Ok(format!("portty1:{encoded}"))
}

/// Encode a COMPACT pairing code for a small QR: just the 32-byte NodeId plus the
/// 16-byte one-time [`PairingSecret`], base64url-nopad, `portty3:`-prefixed.
///
/// Unlike [`encode_ticket`], this carries NO direct addrs or relay URL - the
/// joiner resolves the NodeId via iroh's DNS discovery (the same path a bare
/// NodeId or the typed phrase uses). That drops the payload from ~330 chars to
/// ~72, so the terminal QR shrinks to a fraction of the module count and fits in
/// a small on-screen square. First connect may be a touch slower (discovery vs.
/// embedded addrs), but the QR is scannable at ~2 cm. The full `portty1:` ticket
/// is still printed for paste (faster connect); this is only the QR form.
pub fn encode_compact_ticket(
    addr: &NodeAddr,
    secret: &crate::crypto::pairing::PairingSecret,
) -> Result<String, TransportError> {
    use base64::Engine;
    let ticket_secret = secret.ticket_bytes().ok_or_else(|| {
        TransportError::Iroh("compact QR requires a 128-bit ticket secret".into())
    })?;
    // Zeroizing: this buffer holds the raw one-time secret, not just its base64.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(48));
    bytes.extend_from_slice(addr.id.as_bytes()); // 32-byte Ed25519 pubkey
    bytes.extend_from_slice(ticket_secret); // 16-byte one-time secret
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_slice());
    Ok(format!("portty3:{encoded}"))
}

/// Extract just the one-time [`PairingSecret`] from a ticket, if it carries one.
/// Kept separate from [`decode_ticket`] so the addr-decoding callers stay
/// unchanged; the joiner calls both. Returns `None` for a bare NodeId, a legacy
/// ticket without the field, or any malformed secret (→ PIN-only fallback).
pub fn decode_ticket_secret(s: &str) -> Option<crate::crypto::pairing::PairingSecret> {
    use base64::Engine;
    let s = s.trim();
    if s.len() > MAX_TICKET_CHARS {
        return None;
    }
    // Current compact QR: base64url(32-byte NodeId ‖ 16-byte secret).
    // Decoded buffers below hold the raw secret; `Zeroizing` clears them when the
    // extracted `PairingSecret` (itself zeroizing) takes over.
    if let Some(body) = s.strip_prefix("portty3:") {
        let raw = zeroize::Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body.as_bytes())
                .ok()?,
        );
        if raw.len() != 48 {
            return None;
        }
        let mut sec = [0u8; 16];
        sec.copy_from_slice(&raw[32..48]);
        return Some(crate::crypto::pairing::PairingSecret::from_ticket_bytes(
            sec,
        ));
    }
    // `portty2:` (32-bit secret) is deliberately NOT decoded here. Its secret is
    // below the entropy floor the PIN-free first pair depends on, and since
    // MIN == PROTOCOL_VERSION such a peer cannot connect anyway - so honouring
    // the bytes could only produce a confusing failure later instead of a clear
    // one now. `decode_ticket` still reads its NodeId, so the user gets
    // "no pairing secret" rather than "invalid code".
    let body = s.strip_prefix("portty1:")?;
    let json = zeroize::Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body.as_bytes())
            .ok()?,
    );
    let mut wire: TicketWire = serde_json::from_slice(&json).ok()?;
    let parsed = wire
        .s
        .as_deref()
        .and_then(crate::crypto::pairing::PairingSecret::from_b64);
    // The parsed struct kept its own copy of the base64 secret.
    if let Some(encoded_secret) = wire.s.as_mut() {
        encoded_secret.zeroize();
    }
    parsed
}

pub fn decode_ticket(s: &str) -> Result<NodeAddr, TransportError> {
    use base64::Engine;
    let s = s.trim();
    if s.len() > MAX_TICKET_CHARS {
        return Err(TransportError::Iroh(format!(
            "pairing code is too long ({} chars, limit {MAX_TICKET_CHARS}) - \
             paste just the code, not the surrounding text",
            s.len()
        )));
    }
    // Compact QR forms: take the NodeId from the first 32 bytes and resolve it
    // via discovery (no embedded addrs). `portty3` carries the current 128-bit
    // secret; `portty2` remains readable for migration.
    let compact = s
        .strip_prefix("portty3:")
        .map(|body| (body, 48usize))
        .or_else(|| s.strip_prefix("portty2:").map(|body| (body, 36usize)));
    if let Some((body, expected_len)) = compact {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body.as_bytes())
            .map_err(|e| TransportError::Iroh(format!("compact b64: {e}")))?;
        if raw.len() != expected_len {
            return Err(TransportError::Iroh(format!(
                "compact ticket: expected {expected_len} bytes, got {}",
                raw.len()
            )));
        }
        let hex_id = hex::encode(&raw[..32]);
        let node_id: NodeId = hex_id
            .parse()
            .map_err(|e| TransportError::Iroh(format!("compact NodeId: {e}")))?;
        return Ok(NodeAddr::new(node_id));
    }
    if !s.starts_with("portty1:") {
        // Graceful fallback: a bare 64-char NodeId hex → resolve via discovery.
        // Lowercased first: hex is case-insensitive by convention, but a phone
        // keyboard's autocapitalize (or a human retyping it) easily produces an
        // uppercase first letter, which the underlying decoder rejects verbatim.
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            let node_id: NodeId = s
                .to_ascii_lowercase()
                .parse()
                .map_err(|e| TransportError::Iroh(format!("bare NodeId: {e}")))?;
            return Ok(NodeAddr::new(node_id));
        }
        return Err(TransportError::Iroh(
            "invalid pairing code (expected `portty1:...`, `portty3:...`, or 64 hex NodeId)".into(),
        ));
    }
    let body = &s["portty1:".len()..];
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|e| TransportError::Iroh(format!("ticket b64: {e}")))?;
    let wire: TicketWire = serde_json::from_slice(&json)
        .map_err(|e| TransportError::Iroh(format!("ticket json: {e}")))?;
    let node_id: NodeId = wire
        .nid
        .parse()
        .map_err(|e| TransportError::Iroh(format!("ticket node_id: {e}")))?;
    let mut node_addr = NodeAddr::new(node_id);
    if let Some(relay_str) = wire.r {
        let relay_url: iroh::RelayUrl = relay_str
            .parse()
            .map_err(|e| TransportError::Iroh(format!("ticket relay: {e}")))?;
        node_addr = node_addr.with_relay_url(relay_url);
    }
    for ip in wire
        .a
        .into_iter()
        .take(MAX_TICKET_ADDRS)
        .filter_map(|s| s.parse().ok())
    {
        node_addr = node_addr.with_ip_addr(ip);
    }
    Ok(node_addr)
}

// ── Handshake runners ────────────────────────────────────────────────
//
// Drive the FSM over any `Transport<HandshakeMessage>`. On success both return
// the `EnvelopeCipher` (from the shared session secret) + the peer's identity,
// ready for the post-handshake sealed-frame phase.

pub async fn run_client_handshake<T>(
    transport: &mut T,
    client: &mut ClientHandshake,
) -> SyncResult<HandshakeOutcome>
where
    T: Transport<HandshakeMessage>,
{
    run_client_handshake_with(transport, client, |_| {}).await
}

/// As [`run_client_handshake`], but reports the comparison code as soon as it is
/// known - which on a FIRST pair is well before the handshake finishes.
///
/// The host now waits for a human to confirm the code before it acknowledges, so
/// the phone must display it *during* that wait. `on_code` fires exactly once per
/// first pair, right after the proof goes out, and never on a reconnect.
pub async fn run_client_handshake_with<T, F>(
    transport: &mut T,
    client: &mut ClientHandshake,
    mut on_code: F,
) -> SyncResult<HandshakeOutcome>
where
    T: Transport<HandshakeMessage>,
    F: FnMut(&str),
{
    let hello = client.start();
    transport.send(&hello).await?;
    loop {
        let msg = transport.recv().await?;
        match client.step(msg)? {
            Outcome::Send(m) => {
                let sent_proof = matches!(m, HandshakeMessage::PairingProof { .. });
                transport.send(&m).await?;
                // Only after the proof is actually on the wire: showing a code for
                // an exchange that never reached the host would invite the user to
                // "confirm" against a screen that will never light up.
                if sent_proof {
                    if let Some(code) = client.verification_code() {
                        on_code(&code);
                    }
                }
            }
            Outcome::Done {
                session,
                peer_device_id,
                peer_display_name,
                resumed,
                ..
            } => {
                let cipher = EnvelopeCipher::for_client(&session)?;
                let reconnect_token = derive_reconnect_token(&session)?;
                let (pair_id, pair_event_key) = derive_pair_material(&session)?;
                let verification_code = pair_verification_code(&session)?;
                return Ok(HandshakeOutcome {
                    cipher,
                    peer_device_id,
                    peer_display_name,
                    reconnect_token,
                    resumed,
                    pair_id,
                    pair_event_key,
                    enrollment_epoch: None,
                    verification_code,
                });
            }
            Outcome::Failed(f) => {
                return Err(ProtocolError::PairingFailed(f).into());
            }
        }
    }
}

/// Tell the client its pairing is COMMITTED.
///
/// Split out of [`run_server_handshake`] so the host can claim the enrollment
/// opportunity, take capacity, and persist the rotated token BEFORE the phone is
/// told anything succeeded. Everything between the proof and this call is
/// abandonable: the phone stores nothing until it sees `PairingOk`.
pub async fn confirm_server_handshake<T>(
    transport: &mut T,
    server: &ServerHandshake,
) -> SyncResult<()>
where
    T: Transport<HandshakeMessage>,
{
    let ok = HandshakeMessage::PairingOk {
        device_id: server.own_device_id().0,
        display_name: server.own_display_name().to_string(),
    };
    transport.send(&ok).await.map_err(Into::into)
}

/// Drive the server handshake to a verified proof.
///
/// On success the pairing is authenticated but NOT yet acknowledged to the client
/// - call [`confirm_server_handshake`] once it is durably committed.
pub async fn run_server_handshake<T>(
    transport: &mut T,
    server: &mut ServerHandshake,
) -> SyncResult<HandshakeOutcome>
where
    T: Transport<HandshakeMessage>,
{
    loop {
        let msg = transport.recv().await?;
        match server.step(msg)? {
            Outcome::Send(m) => {
                if let HandshakeMessage::PairingFailed { reason } = &m {
                    tracing::warn!("host rejected pairing: reason={reason:?}");
                }
                let failed = match &m {
                    HandshakeMessage::PairingFailed { reason } => Some(reason.clone()),
                    _ => None,
                };
                transport.send(&m).await?;
                if let Some(reason) = failed {
                    return Err(ProtocolError::PairingFailed(reason).into());
                }
            }
            Outcome::Done {
                session,
                peer_device_id,
                peer_display_name,
                resumed,
                enrollment_epoch,
            } => {
                // Deliberately does NOT send PairingOk. The caller must first claim
                // the enrollment opportunity, take whatever capacity it needs, and
                // PERSIST the pairing - then call `confirm_server_handshake`.
                //
                // Sending it here made the phone's success the first thing that
                // happened: it stored its rotated token, and any later failure on
                // the host left the two sides holding different credentials, with
                // the phone locked out until the user re-paired. Confirmation is now
                // the last step, so a host that cannot finish simply never confirms
                // and the phone treats the attempt as failed.
                let cipher = EnvelopeCipher::for_server(&session)?;
                let reconnect_token = derive_reconnect_token(&session)?;
                let (pair_id, pair_event_key) = derive_pair_material(&session)?;
                let verification_code = pair_verification_code(&session)?;
                return Ok(HandshakeOutcome {
                    cipher,
                    peer_device_id,
                    peer_display_name,
                    reconnect_token,
                    resumed,
                    pair_id,
                    pair_event_key,
                    enrollment_epoch,
                    verification_code,
                });
            }
            Outcome::Failed(f) => {
                return Err(ProtocolError::PairingFailed(f).into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn node_id_to_device_id_matches_identity_derivation() {
        let sk_bytes = [7u8; 32];
        let sk = SigningKey::from_bytes(&sk_bytes);
        let vk = sk.verifying_key();
        let our_device_id = DeviceId::from_pubkey(&vk);

        let iroh_secret = SecretKey::from_bytes(&sk_bytes);
        let node_id = iroh_secret.public();
        let derived = device_id_from_node_id(node_id).unwrap();
        assert_eq!(our_device_id, derived);
    }

    #[test]
    fn quic_tuning_defaults_cover_mobile_bdp_with_bounded_memory() {
        let tuning = QuicTuning::from_lookup(|_| None);
        assert_eq!(tuning.keepalive_secs, 10);
        assert_eq!(tuning.idle_timeout_secs, 30);
        assert_eq!(tuning.stream_window_bytes, 4 * 1024 * 1024);
        assert_eq!(tuning.connection_window_bytes, 16 * 1024 * 1024);
        assert_eq!(tuning.send_window_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn quic_tuning_clamps_hostile_or_inconsistent_values() {
        let values = std::collections::HashMap::from([
            ("PORTTY_QUIC_KEEPALIVE_SECS", "999"),
            ("PORTTY_QUIC_IDLE_TIMEOUT_SECS", "1"),
            ("PORTTY_QUIC_STREAM_WINDOW_BYTES", "999999999999"),
            ("PORTTY_QUIC_CONNECTION_WINDOW_BYTES", "1"),
            ("PORTTY_QUIC_SEND_WINDOW_BYTES", "invalid"),
        ]);
        let tuning = QuicTuning::from_lookup(|name| values.get(name).map(ToString::to_string));
        assert_eq!(tuning.keepalive_secs, 60);
        assert_eq!(tuning.idle_timeout_secs, 120);
        assert_eq!(tuning.stream_window_bytes, 32 * 1024 * 1024);
        assert_eq!(tuning.connection_window_bytes, 32 * 1024 * 1024);
        assert_eq!(tuning.send_window_bytes, DEFAULT_SEND_WINDOW_BYTES);
    }

    #[test]
    fn ticket_roundtrip() {
        let secret = SecretKey::from_bytes(&[3u8; 32]);
        let node_id = secret.public();
        let addr = NodeAddr::new(node_id);
        let ticket = encode_ticket(&addr, None).unwrap();
        assert!(ticket.starts_with("portty1:"));
        let back = decode_ticket(&ticket).unwrap();
        assert_eq!(back.id, node_id);
    }

    #[test]
    fn bare_nodeid_fallback() {
        let secret = SecretKey::from_bytes(&[5u8; 32]);
        let node_id = secret.public();
        let hex = node_id.to_string();
        let back = decode_ticket(&hex).unwrap();
        assert_eq!(back.id, node_id);
    }

    #[test]
    fn invalid_ticket_rejected() {
        assert!(decode_ticket("not-a-ticket").is_err());
    }

    /// The input is a paste buffer or a camera decode, so it has no size of its
    /// own. Both decoders must refuse an oversized code BEFORE base64-decoding it
    /// into a buffer and parsing that buffer as JSON.
    #[test]
    fn an_oversized_pairing_code_is_refused_before_it_is_decoded() {
        // Valid base64url that would decode happily if it were ever allowed to.
        let huge = format!("portty1:{}", "A".repeat(MAX_TICKET_CHARS));
        let error = decode_ticket(&huge).unwrap_err().to_string();
        assert!(error.contains("too long"), "{error}");
        assert!(decode_ticket_secret(&huge).is_none());

        // The bound is generous: a real ticket carrying a secret and several
        // addrs is nowhere near it.
        let node_id = SecretKey::from_bytes(&[11u8; 32]).public();
        let mut addr = NodeAddr::new(node_id);
        for i in 0..8u8 {
            addr = addr.with_ip_addr(format!("10.0.0.{i}:4433").parse().unwrap());
        }
        let secret = crate::crypto::pairing::PairingSecret::from_ticket_bytes([0x5a; 16]);
        let real = encode_ticket(&addr, Some(&secret)).unwrap();
        assert!(
            real.len() < MAX_TICKET_CHARS / 2,
            "a real ticket is {} chars; the cap must stay well clear of it",
            real.len()
        );
        assert_eq!(decode_ticket(&real).unwrap().id, node_id);
    }

    /// Direct addrs are a connect-speed hint, not a requirement - so a ticket
    /// listing far too many of them is a list of endpoints we were asked to dial.
    /// The NodeId still has to work.
    ///
    /// 60 addrs, not thousands: `MAX_TICKET_CHARS` already refuses a ticket long
    /// enough to hold thousands, so this covers the case the length cap lets
    /// through - a code of ordinary size whose addr list is still absurd.
    #[test]
    fn a_ticket_carrying_too_many_addrs_keeps_only_the_capped_number() {
        use base64::Engine;
        let node_id = SecretKey::from_bytes(&[13u8; 32]).public();
        let wire = TicketWire {
            nid: node_id.to_string(),
            a: (0..60u8).map(|i| format!("10.1.0.{i}:4433")).collect(),
            r: None,
            s: None,
        };
        let json = serde_json::to_string(&wire).unwrap();
        let ticket = format!(
            "portty1:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
        );

        let back = decode_ticket(&ticket).expect("the NodeId must still decode");
        assert_eq!(back.id, node_id);
        assert!(
            back.ip_addrs().count() <= MAX_TICKET_ADDRS,
            "kept {} addrs, cap is {MAX_TICKET_ADDRS}",
            back.ip_addrs().count()
        );
    }

    /// A ticket carrying a pairing secret must round-trip both the NodeAddr AND
    /// the secret, so the joiner can fold the secret into the proof.
    #[test]
    fn ticket_round_trips_pairing_secret() {
        use crate::crypto::pairing::PairingSecret;
        let node_id = SecretKey::from_bytes(&[9u8; 32]).public();
        let addr = NodeAddr::new(node_id);
        let secret = PairingSecret::from_ticket_bytes([0x7c; 16]);
        let ticket = encode_ticket(&addr, Some(&secret)).unwrap();

        // The addr still decodes (existing callers unaffected).
        assert_eq!(decode_ticket(&ticket).unwrap().id, node_id);
        // And the secret comes back intact.
        let got = decode_ticket_secret(&ticket).expect("secret must round-trip");
        assert_eq!(got.as_bytes(), secret.as_bytes());
    }

    /// A ticket WITHOUT a secret (legacy / non-QR listener), and a bare-NodeId
    /// paste, both yield `None` - the PIN-only fallback path.
    #[test]
    fn ticket_without_secret_yields_none() {
        let node_id = SecretKey::from_bytes(&[6u8; 32]).public();
        let ticket = encode_ticket(&NodeAddr::new(node_id), None).unwrap();
        assert!(decode_ticket_secret(&ticket).is_none());
        // A bare 64-hex NodeId paste has no envelope, so no secret.
        assert!(decode_ticket_secret(&node_id.to_string()).is_none());
    }

    /// The compact `portty3:` QR code round-trips both the NodeId (via the first
    /// 32 bytes → discovery) and the 16-byte secret (the trailing bytes), and is
    /// dramatically shorter than the full `portty1:` ticket.
    #[test]
    fn compact_ticket_round_trips_nodeid_and_secret() {
        use crate::crypto::pairing::PairingSecret;
        let node_id = SecretKey::from_bytes(&[0x5c; 32]).public();
        let addr = NodeAddr::new(node_id);
        let secret = PairingSecret::from_ticket_bytes([0xab; 16]);
        let compact = encode_compact_ticket(&addr, &secret).unwrap();

        assert!(compact.starts_with("portty3:"));
        // Much shorter than the full ticket - the whole point (small QR).
        let full = encode_ticket(&addr, Some(&secret)).unwrap();
        assert!(compact.len() < full.len());
        assert!(
            compact.len() < 80,
            "compact code was {} chars",
            compact.len()
        );

        // NodeId resolves and the secret comes back intact.
        assert_eq!(decode_ticket(&compact).unwrap().id, node_id);
        let got = decode_ticket_secret(&compact).expect("compact secret must round-trip");
        assert_eq!(got.as_bytes(), secret.as_bytes());
    }

    /// A truncated/wrong-length compact code is rejected, not silently accepted.
    #[test]
    fn compact_ticket_wrong_length_rejected() {
        use base64::Engine;
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 10]);
        let code = format!("portty3:{short}");
        assert!(decode_ticket(&code).is_err());
        assert!(decode_ticket_secret(&code).is_none());
    }

    /// A `portty2:` code still yields its NodeId, but NO LONGER yields its
    /// 32-bit secret.
    ///
    /// Since v8 the secret is the entire first-pair credential, so 32 bits is
    /// below the floor - a proof over it is offline-recoverable. Returning the
    /// NodeId keeps the failure legible ("this code carries no usable pairing
    /// secret") instead of "invalid pairing code", while
    /// `PairingSecret::from_b64` refusing the length is what actually stops the
    /// weak credential being used.
    #[test]
    fn legacy_portty2_compact_ticket_yields_no_secret() {
        use base64::Engine;
        let node_id = SecretKey::from_bytes(&[0x2d; 32]).public();
        let mut raw = Vec::from(node_id.as_bytes());
        raw.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let code = format!("portty2:{body}");

        assert_eq!(decode_ticket(&code).unwrap().id, node_id);
        assert!(
            decode_ticket_secret(&code).is_none(),
            "a retired 32-bit secret must not be usable as a first-pair credential"
        );
    }

    #[test]
    fn compact_encoder_rejects_manual_secret() {
        use crate::crypto::pairing::PairingSecret;
        let node_id = SecretKey::from_bytes(&[0x3e; 32]).public();
        let manual =
            PairingSecret::from_bytes([0x55; crate::crypto::pairing::MANUAL_PAIRING_SECRET_BYTES]);
        assert!(encode_compact_ticket(&NodeAddr::new(node_id), &manual).is_err());
    }

    /// A NEW decoder must still read an OLD ticket that predates the secret field
    /// (forward/backward compatibility via `#[serde(default)]`).
    #[test]
    fn legacy_ticket_without_secret_field_still_decodes() {
        use base64::Engine;
        let node_id = SecretKey::from_bytes(&[7u8; 32]).public();
        // Hand-craft a pre-secret ticket JSON with no `s` field.
        let json = format!(r#"{{"nid":"{node_id}","a":[],"r":null}}"#);
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
        let ticket = format!("portty1:{body}");
        assert_eq!(decode_ticket(&ticket).unwrap().id, node_id);
        assert!(decode_ticket_secret(&ticket).is_none());
    }
}
