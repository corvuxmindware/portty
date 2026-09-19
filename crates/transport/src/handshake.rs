//! Pairing handshake as an explicit state machine. (Forked + simplified from
//! Corvux `sync/protocol/handshake.rs`.)
//!
//! # Portty simplifications vs Corvux
//! The Corvux original carries `roost_name` and `vault_id` - features for
//! re-syncing an already-paired second brain. Those are dropped here.
//! Resumption-token reconnect auth (SEC-2) was later re-introduced in Portty
//! form: first pair proves the out-of-band [`PairingSecret`]; every subsequent
//! connect proves the rotating [`ResumptionToken`] instead, with forward secrecy
//! preserved by the fresh ECDH mix on every handshake. A [`ClientHandshake`] is
//! built as exactly one of the two ([`ClientHandshake::first_pair`] /
//! [`ClientHandshake::resume`]), so "no credential" is not a representable state.
//!
//! # Kept (load-bearing security)
//! - Ephemeral X25519 forward secrecy (H-2/H-3): each handshake mixes a fresh
//!   one-shot ECDH secret into the session key, so a later credential leak can't
//!   decrypt past sessions.
//! - Channel-binding transcript (H-1/H-2): the proof is HMAC'd over both
//!   ephemeral pubkeys + a domain label + the wire version, so an active MITM
//!   that substitutes either key breaks the proof.
//! - Engine-shared per-source rate limiting (AUDIT-077): exponential backoff on
//!   repeated failures from one source.
//!
//! # Changed at PROTOCOL_VERSION 8
//! The human PIN is gone from the key path entirely. It used to be folded into
//! the first-pair key beside the ticket secret, which made a captured proof an
//! offline dictionary over 900,000 candidates for anyone already holding the
//! ticket. The first-pair key is now derived from the secret alone, and the human
//! step moved AFTER the exchange as a comparison code
//! (`pairing::pair_verification_code`) that the operator confirms at the host.
//! The FSM does not gate on that confirmation - like the enrollment claim, it
//! belongs to the caller, between [`Outcome::Done`] and the acknowledgement.
//!
//! # Flow
//! ```text
//!     Client                          Server
//!     send Hello ──────────────────▶  recv Hello → SawHello
//!                                     send PairingChallenge
//!     recv Challenge → sent proof   ◀──────────────── SentChallenge
//!     send PairingProof ───────────▶  verify → send PairingOk → Done
//!     recv Ok → Done
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::pairing::{
    derive_resumption_token, derive_session_from_key, derive_subkey, ecdh_shared, first_pair_key,
    generate_ephemeral, proof_from_key, verify_proof_with_key, FirstPairGate,
    KeyedPairingRateLimiter, Nonce, PairingSecret, PairingSnapshot, SessionSecret,
    SharedPairingState,
};
use crate::error::{ProtocolError, SyncResult};
use crate::frame::{supports_protocol_version, PROTOCOL_VERSION};
use crate::identity::DeviceId;

/// Re-export so callers (host/phone) can persist the reconnect credential
/// without reaching into the crypto submodule.
pub use crate::crypto::pairing::RESUMPTION_TOKEN_LABEL;

/// Stable identifier for one explicit pairing generation. A delayed revoke for
/// an older generation must never delete a newly-created relationship between
/// the same two long-lived device identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PairId(pub [u8; 16]);

/// Pair-scoped key reserved exclusively for authenticated asynchronous control
/// events (for example an opaque revocation event delivered through push).
/// It is deliberately separate from both the rotating resumption token and the
/// live envelope key, and its bytes are never included in Debug output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct PairEventKey([u8; 32]);

impl PairEventKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PairEventKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for PairEventKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairEventKey(<redacted>)")
    }
}

const PAIR_ID_LABEL: &[u8] = b"portty-pair-id-v1";
const PAIR_EVENT_KEY_LABEL: &[u8] = b"portty-pair-event-key-v1";

/// Derive pair-generation material from the mutually authenticated handshake
/// session. On a first pair it becomes the durable generation. On reconnect it
/// is only a migration candidate when a legacy record has no generation yet.
pub fn derive_pair_material(session: &SessionSecret) -> SyncResult<(PairId, PairEventKey)> {
    let id_key = derive_subkey(session, PAIR_ID_LABEL)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&id_key.expose()[..16]);
    let event_key = derive_subkey(session, PAIR_EVENT_KEY_LABEL)?;
    Ok((PairId(id), PairEventKey(*event_key.expose())))
}

/// A persisted per-peer reconnect credential: 32 high-entropy bytes derived from
/// the first-pair session. Stored keyed by peer `DeviceId`. Secret material -
/// never log it. It is intentionally not `Copy`; every explicit clone owns a
/// buffer that is wiped when dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct ResumptionToken([u8; 32]);

impl ResumptionToken {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for ResumptionToken {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<&ResumptionToken> for ResumptionToken {
    fn from(token: &ResumptionToken) -> Self {
        token.clone()
    }
}

impl std::fmt::Debug for ResumptionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResumptionToken(<redacted>)")
    }
}

impl PartialEq<[u8; 32]> for ResumptionToken {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0 == *other
    }
}

/// Derive the reconnect token from a just-finished first-pair session. Both
/// sides call this after `Outcome::Done` and persist the result.
pub fn derive_reconnect_token(session: &SessionSecret) -> SyncResult<ResumptionToken> {
    derive_resumption_token(session).map(ResumptionToken::from)
}

/// Domain-separation label for the channel-binding transcript.
const TRANSCRIPT_DOMAIN: &[u8] = b"portty-handshake-transcript-v1";

/// Engine-scoped shared rate limiter (so backoff spans every accepted connection,
/// not a fresh counter per handshake). See Corvux AUDIT-077.
pub type SharedRateLimiter = Arc<Mutex<KeyedPairingRateLimiter>>;

/// The handshake message set. Postcard-encoded, exchanged BEFORE the envelope
/// kicks in. Distinct from the post-handshake app `portty_protocol::Frame`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    Hello {
        device_id: [u8; 16],
        protocol_version: u16,
        display_name: String,
        client_eph_pub: [u8; 32],
    },
    PairingChallenge {
        nonce: [u8; 32],
        server_eph_pub: [u8; 32],
    },
    PairingProof {
        proof: [u8; 32],
    },
    PairingOk {
        device_id: [u8; 16],
        display_name: String,
    },
    PairingFailed {
        reason: PairingFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairingFailure {
    WrongPin,
    RateLimited,
    UnsupportedVersion,
    Cancelled,
    /// First-pair attempted outside an open enrollment window (brute-force
    /// hardening). Appended at index 4 - old peers that don't know it fail
    /// closed on deserialization, which is safe.
    PairingClosed,
    /// The transport-authenticated device was explicitly revoked. Appended at
    /// index 5 so old peers fail closed if they cannot decode the reason.
    Revoked,
}

/// Build the channel-binding transcript the proof is keyed over. Built in ONE
/// place so both peers produce identical bytes. Binds the domain label + wire
/// PROTOCOL_VERSION + both ephemeral X25519 pubkeys.
fn build_transcript(client_eph_pub: &[u8; 32], server_eph_pub: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + 2 + 64);
    t.extend_from_slice(TRANSCRIPT_DOMAIN);
    t.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    t.extend_from_slice(client_eph_pub);
    t.extend_from_slice(server_eph_pub);
    t
}

/// What the FSM wants to happen next.
pub enum Outcome {
    /// Send this message, then call `step` again on the next received one.
    Send(HandshakeMessage),
    /// Handshake succeeded; session key is ready. Move on to the app phase.
    Done {
        session: SessionSecret,
        peer_device_id: DeviceId,
        peer_display_name: String,
        /// True only when the resumption token authenticated this handshake.
        /// A token→PIN manual repair is a fresh pair, not a resume.
        resumed: bool,
        /// For a FIRST pair, the enrollment opportunity this proof was verified
        /// under. The caller must claim it with
        /// [`crate::crypto::pairing::PairingState::consume_first_pair`] and
        /// abandon the connection if the claim fails. The FSM deliberately does
        /// not claim it: the claim has to be one atomic step with persisting the
        /// pairing, which only the caller can do. `None` for a reconnect and for
        /// the B4 exemption.
        enrollment_epoch: Option<u64>,
    },
    /// Handshake failed; tear down the transport.
    Failed(PairingFailure),
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Send(m) => f.debug_tuple("Send").field(&variant_name(m)).finish(),
            Outcome::Done {
                peer_device_id,
                peer_display_name,
                ..
            } => f
                .debug_struct("Done")
                .field("peer_device_id", peer_device_id)
                .field("peer_display_name", peer_display_name)
                .finish_non_exhaustive(),
            Outcome::Failed(r) => f.debug_tuple("Failed").field(r).finish(),
        }
    }
}

fn variant_name(m: &HandshakeMessage) -> &'static str {
    match m {
        HandshakeMessage::Hello { .. } => "Hello",
        HandshakeMessage::PairingChallenge { .. } => "PairingChallenge",
        HandshakeMessage::PairingProof { .. } => "PairingProof",
        HandshakeMessage::PairingOk { .. } => "PairingOk",
        HandshakeMessage::PairingFailed { .. } => "PairingFailed",
    }
}

// ── Client side ──────────────────────────────────────────────────────

pub enum ClientState {
    Init,
    SentHello,
    SentProof { session: Option<SessionSecret> },
    Done,
    Failed,
}

/// Which credential this client will authenticate with. Exactly one, chosen at
/// construction: a first pair without a [`PairingSecret`] is not representable,
/// because the secretless fallback it would have used no longer exists.
enum ClientCredential {
    /// First pair: prove the out-of-band secret from the scanned/pasted ticket
    /// or the typed phrase.
    FirstPair(PairingSecret),
    /// SEC-2 reconnect: prove the stored rotating token instead.
    Resume(ResumptionToken),
}

pub struct ClientHandshake {
    state: ClientState,
    device_id: DeviceId,
    display_name: String,
    credential: ClientCredential,
    eph_secret: Option<x25519_dalek::EphemeralSecret>,
    client_eph_pub: [u8; 32],
}

impl ClientHandshake {
    /// FIRST pair: authenticate with the out-of-band secret carried in the
    /// scanned/pasted ticket or typed as the manual phrase. The caller must have
    /// obtained a secret; there is deliberately no constructor that pairs
    /// without one.
    pub fn first_pair(device_id: DeviceId, display_name: String, secret: PairingSecret) -> Self {
        Self::with_credential(device_id, display_name, ClientCredential::FirstPair(secret))
    }

    /// SEC-2 RECONNECT: authenticate with the stored resumption token for this
    /// peer, from a prior first pair.
    pub fn resume(
        device_id: DeviceId,
        display_name: String,
        token: impl Into<ResumptionToken>,
    ) -> Self {
        Self::with_credential(
            device_id,
            display_name,
            ClientCredential::Resume(token.into()),
        )
    }

    fn with_credential(
        device_id: DeviceId,
        display_name: String,
        credential: ClientCredential,
    ) -> Self {
        Self {
            state: ClientState::Init,
            device_id,
            display_name,
            credential,
            eph_secret: None,
            client_eph_pub: [0u8; 32],
        }
    }

    /// Whether this handshake is a reconnect rather than a first pair.
    fn is_resume(&self) -> bool {
        matches!(self.credential, ClientCredential::Resume(_))
    }

    /// The six-digit comparison code for this exchange, available as soon as the
    /// proof has been sent and BEFORE the host acknowledges.
    ///
    /// The wait for `PairingOk` is now however long a human takes to confirm at
    /// the host, so the phone has to be able to show the code during it - which
    /// means reading it out of the in-progress handshake rather than waiting for
    /// [`Outcome::Done`]. `None` in every other state, and `None` on a reconnect,
    /// where there is nothing for a human to compare.
    pub fn verification_code(&self) -> Option<String> {
        if self.is_resume() {
            return None;
        }
        match &self.state {
            ClientState::SentProof { session: Some(s) } => {
                crate::crypto::pairing::pair_verification_code(s).ok()
            }
            _ => None,
        }
    }

    /// Produce the opening message. Call once, before any `step`.
    pub fn start(&mut self) -> HandshakeMessage {
        self.state = ClientState::SentHello;
        let (eph_secret, client_eph_pub) = generate_ephemeral();
        self.eph_secret = Some(eph_secret);
        self.client_eph_pub = client_eph_pub;
        HandshakeMessage::Hello {
            device_id: self.device_id.0,
            protocol_version: PROTOCOL_VERSION,
            display_name: self.display_name.clone(),
            client_eph_pub,
        }
    }

    pub fn step(&mut self, incoming: HandshakeMessage) -> SyncResult<Outcome> {
        match (&self.state, incoming) {
            (
                ClientState::SentHello | ClientState::SentProof { .. },
                HandshakeMessage::PairingFailed { reason },
            ) => {
                self.state = ClientState::Failed;
                Ok(Outcome::Failed(reason))
            }
            (
                ClientState::SentHello,
                HandshakeMessage::PairingChallenge {
                    nonce,
                    server_eph_pub,
                },
            ) => {
                let nonce = Nonce(nonce);
                let eph = self
                    .eph_secret
                    .take()
                    .ok_or(ProtocolError::UnexpectedMessage {
                        state: "SentHello",
                        actual: "challenge before ephemeral key was generated",
                    })?;
                let ecdh = ecdh_shared(eph, &server_eph_pub)?;
                let transcript = build_transcript(&self.client_eph_pub, &server_eph_pub);
                // Authenticate with whichever single credential we were built
                // with. The session secret derives from the same key material
                // (plus the ECDH secret), so the envelope stays consistent and
                // keeps forward secrecy either way.
                let key = match &self.credential {
                    ClientCredential::Resume(tok) => Zeroizing::new(tok.as_bytes().to_vec()),
                    // First-pair key = the out-of-band secret alone. No PIN is
                    // folded in: a human-sized value here is what made a captured
                    // proof offline-attackable before v8.
                    ClientCredential::FirstPair(secret) => first_pair_key(secret),
                };
                let (proof, session) = (
                    proof_from_key(&key, &nonce, &transcript)?,
                    derive_session_from_key(&key, &nonce, &ecdh)?,
                );
                self.state = ClientState::SentProof {
                    session: Some(session),
                };
                Ok(Outcome::Send(HandshakeMessage::PairingProof {
                    proof: proof.0,
                }))
            }
            (
                ClientState::SentProof { .. },
                HandshakeMessage::PairingOk {
                    device_id,
                    display_name,
                },
            ) => {
                let mut s = ClientState::Done;
                std::mem::swap(&mut self.state, &mut s);
                let session = match s {
                    ClientState::SentProof { session, .. } => session,
                    _ => unreachable!(),
                }
                .ok_or(ProtocolError::UnexpectedMessage {
                    state: "SentProof",
                    actual: "session already taken",
                })?;
                Ok(Outcome::Done {
                    session,
                    peer_device_id: DeviceId(device_id),
                    peer_display_name: display_name,
                    resumed: self.is_resume(),
                    // Client side: enrollment gating is the host's business.
                    enrollment_epoch: None,
                })
            }
            (_, other) => Err(ProtocolError::UnexpectedMessage {
                state: client_state_name(&self.state),
                actual: variant_name(&other),
            }
            .into()),
        }
    }
}

// ── Server side ──────────────────────────────────────────────────────

// One instance per connection, alive for the few round trips of a handshake, and
// the payload is exactly the forward-secrecy material this step has to hold
// (nonce, session secret, ECDH root). Boxing it to even the variants out would add
// an allocation and a pointer indirection to zeroizing secrets for no benefit.
#[allow(clippy::large_enum_variant)]
pub enum ServerState {
    AwaitingHello,
    SentChallenge {
        nonce: Nonce,
        session: SessionSecret,
        peer_device_id: DeviceId,
        peer_display_name: String,
        /// SEC-2: `Some(token)` if we're authenticating this connection by a
        /// stored resumption token (reconnect); `None` = verify the PIN.
        auth_token: Option<ResumptionToken>,
        /// The enrollment opportunity this FIRST-PAIR challenge was gated under,
        /// re-checked when the proof arrives so a challenge issued before another
        /// client consumed the window cannot still enrol. `None` for a reconnect
        /// (never gated) and for the B4 exemption.
        enrollment_epoch: Option<u64>,
        /// The ECDH shared secret, kept so we can re-derive the session from the
        /// PIN if a manual re-pair arrives while we hold a (now-mismatched)
        /// token - see the token→PIN fallback in the proof-verify arm. Held in
        /// `Zeroizing` so this forward-secrecy root is wiped when the state is
        /// dropped rather than lingering in freed memory (#22).
        ecdh: Zeroizing<[u8; 32]>,
        transcript: Vec<u8>,
    },
    Done,
    Failed,
}

pub struct ServerHandshake {
    state: ServerState,
    device_id: DeviceId,
    display_name: String,
    rate_limiter: SharedRateLimiter,
    rate_limit_key: String,
    /// The host-shared first-pair enrollment window. When set (production accept
    /// paths inject it), an inbound FIRST-PAIR handshake is refused unless the
    /// window is open, and a source-independent global cap trips a hard lockout
    /// during the window - defeating the fresh-NodeId spraying that beats the
    /// per-key rate limiter. `None` (tests) leaves first-pair ungated. Reconnects
    /// (resumption token) are never gated regardless.
    pairing_state: Option<SharedPairingState>,
    /// The enrollment generation whose credentials this connection verifies
    /// against, captured together with them under one lock. Binding the gate to it
    /// is what stops a snapshot taken before a `portty pair` from enrolling after.
    snapshot_epoch: Option<u64>,
    /// The first-pair secrets valid for this serve session. Production supplies
    /// a 128-bit QR/full-ticket secret and a separate 48-bit six-word manual
    /// fallback. Accepting both here keeps manual entry usable without reducing
    /// the entropy of the secret embedded in a QR code.
    ///
    /// EMPTY MEANS NO FIRST PAIR IS POSSIBLE. It used to mean "fall back to
    /// PIN-only", which is exactly the path that made proofs offline-attackable;
    /// an unarmed host now refuses first pair outright rather than degrading.
    pairing_secrets: Vec<PairingSecret>,
    /// The peer device this connection is allowed to first-pair OUTSIDE the
    /// enrollment window - set ONLY when the accept path has already
    /// cryptographically authenticated the peer (the iroh QUIC NodeId) AND finds
    /// that device already in our peer store. It exists to let a device paired
    /// BEFORE resumption tokens shipped (`resumption_token == None`) reconnect
    /// and acquire a token, without forcing the user to re-open pairing. It MUST
    /// be derived from the authenticated NodeId, NEVER from the self-asserted
    /// `Hello.device_id` (which is spoofable). `None` = fully gated (default).
    enrollment_exempt_device: Option<DeviceId>,
    /// SEC-2: resumption tokens we hold, keyed by peer device id. When an
    /// incoming `Hello` names a device we have a token for, we authenticate that
    /// connection by the token (reconnect) instead of the human PIN. Pre-loaded
    /// by the accept path from the persisted peer store.
    resumption_tokens: HashMap<DeviceId, ResumptionToken>,
    /// DeviceId derived from the authenticated iroh NodeId. This binds the
    /// self-asserted Hello identity before any revocation state is revealed.
    authenticated_device: Option<DeviceId>,
    authenticated_device_revoked: bool,
}

impl ServerHandshake {
    pub fn new(device_id: DeviceId, display_name: String) -> Self {
        Self {
            state: ServerState::AwaitingHello,
            device_id,
            display_name,
            rate_limiter: Arc::new(Mutex::new(KeyedPairingRateLimiter::new())),
            rate_limit_key: String::new(),
            pairing_state: None,
            snapshot_epoch: None,
            pairing_secrets: Vec::new(),
            enrollment_exempt_device: None,
            resumption_tokens: HashMap::new(),
            authenticated_device: None,
            authenticated_device_revoked: false,
        }
    }

    /// Source key (remote IP) this connection is rate-limited under.
    pub fn with_rate_limit_key(mut self, key: String) -> Self {
        self.rate_limit_key = key;
        self
    }

    /// Inject the host's shared rate limiter (production accept path).
    pub fn with_shared_rate_limiter(mut self, shared: SharedRateLimiter) -> Self {
        self.rate_limiter = shared;
        self
    }

    /// Arm first pair: the credentials to accept AND the enrollment window that
    /// bounds them, from one [`PairingSnapshot`].
    ///
    /// One call on purpose. These used to be two builders, and a caller who armed
    /// secrets but forgot the window got a first pair with no time box and no
    /// global failure cap - permissive by omission, which is the shape of default
    /// nobody notices. Taking the snapshot whole also means the secrets and the
    /// epoch can never come from different generations, which is the reason
    /// `PairingState::snapshot` returns them together under one lock.
    pub fn with_first_pair(mut self, state: SharedPairingState, snapshot: PairingSnapshot) -> Self {
        self.pairing_state = Some(state);
        self.snapshot_epoch = snapshot.epoch;
        self.pairing_secrets = snapshot.secrets;
        self
    }

    /// Arm the enrollment window with NO first-pair credentials.
    ///
    /// The mirror of [`Self::with_unwindowed_pairing_secrets`], and equally
    /// explicit about what it leaves out. Useful for exercising the window gate
    /// on its own: an unarmed host refuses first pair before the window is even
    /// consulted, so a test about window behaviour needs one half and a test
    /// about credentials needs the other. Production wants both, from
    /// [`Self::with_first_pair`].
    pub fn with_pairing_window(
        mut self,
        state: SharedPairingState,
        snapshot_epoch: Option<u64>,
    ) -> Self {
        self.pairing_state = Some(state);
        self.snapshot_epoch = snapshot_epoch;
        self
    }

    /// Arm first-pair credentials with NO enrollment window.
    ///
    /// The name is the warning. First pair is then bounded only by the credential
    /// itself - no five-minute window, no source-independent failure cap - which
    /// is fine for a test driving the FSM directly and wrong for anything serving
    /// a real endpoint. Production uses [`Self::with_first_pair`].
    pub fn with_unwindowed_pairing_secrets(
        mut self,
        secrets: impl IntoIterator<Item = PairingSecret>,
    ) -> Self {
        self.pairing_secrets = secrets.into_iter().collect();
        self
    }

    /// Mark the QUIC-authenticated peer device as exempt from the enrollment
    /// window for a one-time token-acquisition first-pair. The accept path MUST
    /// pass the device derived from the authenticated iroh NodeId (and only if
    /// it's already in the peer store), never the self-asserted `Hello`
    /// device_id - see the field docs. `None` keeps first-pair fully gated.
    ///
    /// NOTE (#24): production accept paths deliberately do NOT call this yet. On
    /// its own the exemption only lets a known device REACH the challenge without
    /// an open window - a tokenless legacy peer must still prove the *current*
    /// session PIN, which it does not have, so it delivers no zero-touch migration
    /// while widening the window-bypass surface. Completing that migration
    /// (persisting a one-time migration token at the last pre-token pairing) is the
    /// prerequisite for wiring this; until then the mechanism and its tests are
    /// kept as the tested foundation for that work, not dead-code to delete blindly.
    pub fn with_enrollment_exempt_device(mut self, device: Option<DeviceId>) -> Self {
        self.enrollment_exempt_device = device;
        self
    }

    /// SEC-2: supply the resumption tokens we hold (keyed by peer device id) so
    /// an incoming reconnect from a known peer authenticates by its token
    /// instead of the human PIN.
    pub fn with_resumption_tokens<T>(mut self, tokens: HashMap<DeviceId, T>) -> Self
    where
        T: Into<ResumptionToken>,
    {
        self.resumption_tokens = tokens
            .into_iter()
            .map(|(device, token)| (device, token.into()))
            .collect();
        self
    }

    /// Bind the Hello identity to the peer identity authenticated by QUIC.
    pub fn with_authenticated_device(mut self, device: DeviceId, revoked: bool) -> Self {
        self.authenticated_device = Some(device);
        self.authenticated_device_revoked = revoked;
        self
    }

    /// The server's own device id - used by the runner to build `PairingOk`.
    pub fn own_device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The server's own display name - sent in `PairingOk`.
    pub fn own_display_name(&self) -> &str {
        &self.display_name
    }

    pub fn step(&mut self, incoming: HandshakeMessage) -> SyncResult<Outcome> {
        match (&self.state, incoming) {
            (
                ServerState::AwaitingHello,
                HandshakeMessage::Hello {
                    device_id,
                    protocol_version,
                    display_name,
                    client_eph_pub,
                },
            ) => {
                if !supports_protocol_version(protocol_version) {
                    self.state = ServerState::Failed;
                    return Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                        reason: PairingFailure::UnsupportedVersion,
                    }));
                }
                if self
                    .authenticated_device
                    .is_some_and(|authenticated| authenticated != DeviceId(device_id))
                {
                    self.state = ServerState::Failed;
                    return Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                        reason: PairingFailure::WrongPin,
                    }));
                }
                // Gate FIRST-PAIR (not reconnect) on the enrollment window BEFORE
                // the per-key rate limiter. A reconnect (we hold a resumption
                // token for this device) authenticates by token and is never
                // gated. First-pair is refused outside an active pairing window,
                // and a source-independent global cap trips inside it - closing
                // the fresh-NodeId spraying hole that beats the per-key limiter.
                // `check_and_reserve_first_pair` reserves the slot at
                // challenge-issue time (mirroring the per-key limiter) so
                // concurrently-opened connections can't all pass a read-only
                // check. Poisoned mutex → fail closed (reject).
                //
                // B4 exemption: a device the transport already authenticated
                // (iroh NodeId) AND that we already hold in the peer store skips
                // the window - how a pre-resumption-token peer reconnects to
                // acquire a token. Bound to `enrollment_exempt_device` (from the
                // AUTHENTICATED NodeId), so matching it against the Hello's
                // `device_id` here is safe: a stranger who spoofs a known id
                // won't match unless it also holds that NodeId's private key.
                let is_first_pair = !self.resumption_tokens.contains_key(&DeviceId(device_id));
                let enrollment_exempt = self.enrollment_exempt_device == Some(DeviceId(device_id));
                // A host with no armed secret cannot first-pair at all. This is
                // ahead of the exemption on purpose: the B4 exemption only waives
                // the WINDOW, never the credential, and before v8 an unarmed host
                // silently fell through to a PIN-only proof instead.
                if is_first_pair && self.pairing_secrets.is_empty() {
                    self.state = ServerState::Failed;
                    return Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                        reason: PairingFailure::PairingClosed,
                    }));
                }
                let mut enrollment_epoch = None;
                if is_first_pair && !enrollment_exempt {
                    if let Some(state) = &self.pairing_state {
                        let gate = match state.lock() {
                            Ok(mut s) => s.gate_first_pair(self.snapshot_epoch),
                            Err(_) => FirstPairGate::Closed,
                        };
                        match gate {
                            // Remember WHICH opportunity allowed this; the proof
                            // step will require it to still be the live one.
                            FirstPairGate::Allow { epoch } => enrollment_epoch = Some(epoch),
                            FirstPairGate::Closed => {
                                self.state = ServerState::Failed;
                                return Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                                    reason: if self.authenticated_device_revoked {
                                        PairingFailure::Revoked
                                    } else {
                                        PairingFailure::PairingClosed
                                    },
                                }));
                            }
                            FirstPairGate::Locked => {
                                self.state = ServerState::Failed;
                                return Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                                    reason: PairingFailure::RateLimited,
                                }));
                            }
                        }
                    }
                }
                // AUDIT-077: check-and-reserve at challenge-issue time so
                // concurrently-opened connections can't all pass a read-only
                // check before any records a failure. Poisoned mutex → deny.
                let limited = match self.rate_limiter.lock() {
                    Ok(mut rl) => rl.check_and_reserve(&self.rate_limit_key).is_err(),
                    Err(_) => true,
                };
                if limited {
                    self.state = ServerState::Failed;
                    return Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                        reason: PairingFailure::RateLimited,
                    }));
                }
                let nonce = Nonce::generate();
                let (server_eph_secret, server_eph_pub) = generate_ephemeral();
                let ecdh = ecdh_shared(server_eph_secret, &client_eph_pub)?;
                let transcript = build_transcript(&client_eph_pub, &server_eph_pub);
                // SEC-2: if we hold a resumption token for this device, this is
                // a reconnect - authenticate + derive the session from the token
                // (plus the fresh ECDH) instead of the human PIN.
                let auth_token = self.resumption_tokens.get(&DeviceId(device_id)).cloned();
                let session = match auth_token.as_ref() {
                    Some(tok) => derive_session_from_key(tok.as_bytes(), &nonce, &ecdh)?,
                    None => {
                        // First-pair key = the secret we minted and embedded in
                        // the ticket. A caller that never obtained it derives a
                        // different key and its proof will not match.
                        let Some(secret) = self.pairing_secrets.first() else {
                            // Unreachable: the gate above already refused an
                            // unarmed first pair. Fail closed anyway rather than
                            // panic if that ever stops holding.
                            self.state = ServerState::Failed;
                            return Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                                reason: PairingFailure::PairingClosed,
                            }));
                        };
                        derive_session_from_key(&first_pair_key(secret), &nonce, &ecdh)?
                    }
                };
                self.state = ServerState::SentChallenge {
                    nonce,
                    session,
                    peer_device_id: DeviceId(device_id),
                    peer_display_name: display_name,
                    auth_token,
                    enrollment_epoch,
                    ecdh,
                    transcript,
                };
                Ok(Outcome::Send(HandshakeMessage::PairingChallenge {
                    nonce: self.challenge_nonce(),
                    server_eph_pub,
                }))
            }
            (
                ServerState::SentChallenge {
                    nonce,
                    transcript,
                    auth_token,
                    enrollment_epoch,
                    ..
                },
                HandshakeMessage::PairingProof { proof },
            ) => {
                let nonce = *nonce;
                let transcript = transcript.clone();
                let auth_token = auth_token.clone();
                let enrollment_epoch = *enrollment_epoch;
                let claimed = crate::crypto::pairing::Proof(proof);
                // Verify a reconnect token first. Otherwise accept whichever
                // current first-pair candidate the client proved: the strong
                // QR ticket secret or the separately displayed manual phrase.
                // Keeping the candidate material zeroizing also avoids retaining
                // derived authentication keys beyond this proof step.
                let token_verified = auth_token.as_ref().is_some_and(|tok| {
                    verify_proof_with_key(tok.as_bytes(), &nonce, &transcript, &claimed).is_ok()
                });
                // No armed secret → no candidates → nothing can verify. That is
                // the intended fail-closed shape: an unarmed host must never
                // accept a first pair.
                let fp_keys: Vec<_> = self.pairing_secrets.iter().map(first_pair_key).collect();
                let matched_first_pair = (!token_verified).then(|| {
                    fp_keys.iter().position(|key| {
                        verify_proof_with_key(key, &nonce, &transcript, &claimed).is_ok()
                    })
                });
                let matched_first_pair = matched_first_pair.flatten();
                if token_verified || matched_first_pair.is_some() {
                    if let Ok(mut rl) = self.rate_limiter.lock() {
                        rl.record_success(&self.rate_limit_key);
                    }
                    // The enrollment opportunity is deliberately NOT claimed
                    // here - see `Outcome::Done::enrollment_epoch`. Claiming it at
                    // this point burned the opportunity even when the caller then
                    // failed to persist anything.
                    let mut s = ServerState::Done;
                    std::mem::swap(&mut self.state, &mut s);
                    let (session, peer_device_id, peer_display_name) = match s {
                        ServerState::SentChallenge {
                            session,
                            peer_device_id,
                            peer_display_name,
                            ecdh,
                            ..
                        } => {
                            let s_secret = match matched_first_pair {
                                Some(index) => {
                                    derive_session_from_key(&fp_keys[index], &nonce, &ecdh)?
                                }
                                None => session,
                            };
                            (s_secret, peer_device_id, peer_display_name)
                        }
                        _ => unreachable!(),
                    };
                    Ok(Outcome::Done {
                        session,
                        peer_device_id,
                        peer_display_name,
                        resumed: token_verified,
                        // Only a first pair has an opportunity to claim.
                        enrollment_epoch: auth_token
                            .is_none()
                            .then_some(enrollment_epoch)
                            .flatten(),
                    })
                } else {
                    // The attempt was already counted by check_and_reserve.
                    self.state = ServerState::Failed;
                    Ok(Outcome::Send(HandshakeMessage::PairingFailed {
                        // The QUIC identity is already bound to the Hello,
                        // so this reveals revocation only to that revoked
                        // device. It lets a stale-token reconnect clean up
                        // even while an enrollment window happens to be
                        // open; a legitimate fresh manual repair proves the
                        // PIN+ticket key above and succeeds instead.
                        reason: if self.authenticated_device_revoked {
                            PairingFailure::Revoked
                        } else {
                            PairingFailure::WrongPin
                        },
                    }))
                }
            }
            (_, other) => Err(ProtocolError::UnexpectedMessage {
                state: server_state_name(&self.state),
                actual: variant_name(&other),
            }
            .into()),
        }
    }
}

impl ServerHandshake {
    /// Helper to read the nonce out of SentChallenge for the challenge frame,
    /// without consuming state.
    fn challenge_nonce(&self) -> [u8; 32] {
        match &self.state {
            ServerState::SentChallenge { nonce, .. } => nonce.0,
            _ => unreachable!("challenge_nonce called outside SentChallenge state"),
        }
    }
}

fn client_state_name(s: &ClientState) -> &'static str {
    match s {
        ClientState::Init => "Init",
        ClientState::SentHello => "SentHello",
        ClientState::SentProof { .. } => "SentProof",
        ClientState::Done => "Done",
        ClientState::Failed => "Failed",
    }
}

fn server_state_name(s: &ServerState) -> &'static str {
    match s {
        ServerState::AwaitingHello => "AwaitingHello",
        ServerState::SentChallenge { .. } => "SentChallenge",
        ServerState::Done => "Done",
        ServerState::Failed => "Failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pairing::MANUAL_PAIRING_SECRET_BYTES;

    fn dev(n: u8) -> DeviceId {
        DeviceId([n; 16])
    }
    /// The out-of-band credential a legitimate joiner scanned. This is now the
    /// WHOLE first-pair credential, so every test that pairs must arm it on the
    /// host and present it on the client.
    fn secret() -> PairingSecret {
        PairingSecret::from_ticket_bytes([0x42; 16])
    }

    /// A credential the host never minted - what an attacker presents.
    fn other_secret() -> PairingSecret {
        PairingSecret::from_ticket_bytes([0x99; 16])
    }

    /// Drive a full client↔server exchange through the FSM in memory.
    fn run() -> (Outcome, Outcome) {
        let mut client = ClientHandshake::first_pair(dev(1), "laptop".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "phone".into())
            .with_unwindowed_pairing_secrets([secret()]);

        let hello = client.start();
        let Outcome::Send(challenge) = server.step(hello).unwrap() else {
            panic!("expected challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        let server_out = server.step(proof).unwrap();
        // server reaches Done; in the wire runner it then sends PairingOk.
        let ok = match &server_out {
            Outcome::Done { .. } => HandshakeMessage::PairingOk {
                device_id: dev(2).0,
                display_name: "phone".into(),
            },
            _ => panic!("expected server Done"),
        };
        let client_out = client.step(ok).unwrap();
        (server_out, client_out)
    }

    #[test]
    fn transcript_binds_keys_domain_and_version() {
        let c = [1u8; 32];
        let s = [2u8; 32];
        let t = build_transcript(&c, &s);
        assert_eq!(t.len(), TRANSCRIPT_DOMAIN.len() + 2 + 64);
        assert!(t.starts_with(TRANSCRIPT_DOMAIN));
        assert_ne!(t, build_transcript(&s, &c)); // order-sensitive
        assert_ne!(t, build_transcript(&[9u8; 32], &s));
        assert_ne!(t, build_transcript(&c, &[9u8; 32]));
    }

    #[test]
    fn happy_path_completes() {
        let (server_out, client_out) = run();
        match (server_out, client_out) {
            (
                Outcome::Done {
                    peer_device_id: s_peer,
                    ..
                },
                Outcome::Done {
                    peer_device_id: c_peer,
                    ..
                },
            ) => {
                assert_eq!(s_peer, dev(1), "server sees client device id");
                assert_eq!(c_peer, dev(2), "client sees server device id");
            }
            other => panic!("both should be Done, got {other:?}"),
        }
    }

    #[test]
    fn ephemeral_keys_make_each_session_unique() {
        let once = || -> [u8; 32] {
            let mut c = ClientHandshake::first_pair(dev(1), "a".into(), secret());
            let mut s = ServerHandshake::new(dev(2), "b".into())
                .with_unwindowed_pairing_secrets([secret()]);
            let hello = c.start();
            let Outcome::Send(challenge) = s.step(hello).unwrap() else {
                panic!()
            };
            let Outcome::Send(proof) = c.step(challenge).unwrap() else {
                panic!()
            };
            match s.step(proof).unwrap() {
                Outcome::Done { session, .. } => session.0,
                _ => panic!(),
            }
        };
        assert_ne!(
            once(),
            once(),
            "same PIN but fresh ephemerals → distinct keys"
        );
    }

    /// A wrong credential must fail with the GENERIC reason, identical to every
    /// other proof failure. `WrongPin` keeps its wire tag (the enum is
    /// append-only) even though there is no PIN any more - what matters is that
    /// the reason does not tell a caller WHY it failed, so probing cannot
    /// distinguish "wrong secret" from "host armed a different secret".
    #[test]
    fn wrong_credential_is_rejected_with_a_generic_reason() {
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), other_secret());
        let mut server =
            ServerHandshake::new(dev(2), "b".into()).with_unwindowed_pairing_secrets([secret()]);
        let hello = client.start();
        let Outcome::Send(challenge) = server.step(hello).unwrap() else {
            panic!()
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!()
        };
        match server.step(proof).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert_eq!(reason, PairingFailure::WrongPin);
            }
            _ => panic!("expected a generic proof failure"),
        }
    }

    /// H-1/H-2: a MITM swapping the server's ephemeral pubkey breaks the proof.
    #[test]
    fn mitm_substituting_ephemeral_key_fails_proof() {
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server =
            ServerHandshake::new(dev(2), "b".into()).with_unwindowed_pairing_secrets([secret()]);
        let hello = client.start();
        let Outcome::Send(challenge) = server.step(hello).unwrap() else {
            panic!()
        };
        let tampered = match challenge {
            HandshakeMessage::PairingChallenge { nonce, .. } => {
                HandshakeMessage::PairingChallenge {
                    nonce,
                    server_eph_pub: [0xAB; 32],
                }
            }
            _ => panic!(),
        };
        let Outcome::Send(proof) = client.step(tampered).unwrap() else {
            panic!()
        };
        match server.step(proof).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert_eq!(reason, PairingFailure::WrongPin);
            }
            _ => panic!("MITM must fail the proof"),
        }
    }

    #[test]
    fn unsupported_protocol_version_rejected() {
        let mut server =
            ServerHandshake::new(dev(2), "b".into()).with_unwindowed_pairing_secrets([secret()]);
        let hello = HandshakeMessage::Hello {
            device_id: [1u8; 16],
            protocol_version: 999,
            display_name: "x".into(),
            client_eph_pub: [0u8; 32],
        };
        match server.step(hello).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert_eq!(reason, PairingFailure::UnsupportedVersion);
            }
            _ => panic!(),
        }
    }

    /// The test above covers a version from the FUTURE. This covers a peer one
    /// version BEHIND, which is the case that actually happens: every flag day
    /// leaves phones and hosts on different builds for a while.
    ///
    /// `MIN_SUPPORTED_PROTOCOL_VERSION == PROTOCOL_VERSION`, so there is no
    /// negotiation and no grace - refusing the older peer IS the guarantee behind
    /// telling operators to upgrade host and phone together. A silent accept here
    /// would mean two peers agreeing on a wire neither actually speaks.
    #[test]
    fn a_peer_one_version_behind_is_rejected() {
        let mut server =
            ServerHandshake::new(dev(2), "b".into()).with_unwindowed_pairing_secrets([secret()]);
        let hello = HandshakeMessage::Hello {
            device_id: [1u8; 16],
            protocol_version: PROTOCOL_VERSION - 1,
            display_name: "an older phone".into(),
            client_eph_pub: [0u8; 32],
        };
        match server.step(hello).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert_eq!(reason, PairingFailure::UnsupportedVersion);
            }
            other => panic!("an older peer must be refused, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_message_errors() {
        let mut server =
            ServerHandshake::new(dev(2), "b".into()).with_unwindowed_pairing_secrets([secret()]);
        let err = server
            .step(HandshakeMessage::PairingProof { proof: [0u8; 32] })
            .unwrap_err();
        assert!(err.to_string().contains("protocol"));
    }

    #[test]
    fn rate_limiter_map_smoke() {
        let mut rl = KeyedPairingRateLimiter::new();
        rl.check_and_reserve("1.2.3.4").unwrap();
        assert_eq!(rl.tracked_keys(), 1);
        rl.record_success("1.2.3.4");
    }

    // ── SEC-2: resumption / reconnect ──────────────────────────────────

    /// Run a first-pair PIN handshake and return both session secrets so a test
    /// can derive + compare the reconnect token each side computes.
    fn first_pair_sessions() -> (SessionSecret, SessionSecret) {
        let mut client = ClientHandshake::first_pair(dev(1), "laptop".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "phone".into())
            .with_unwindowed_pairing_secrets([secret()]);
        let hello = client.start();
        let Outcome::Send(challenge) = server.step(hello).unwrap() else {
            panic!("expected challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        let server_session = match server.step(proof).unwrap() {
            Outcome::Done { session, .. } => session,
            o => panic!("expected server Done, got {o:?}"),
        };
        let ok = HandshakeMessage::PairingOk {
            device_id: dev(2).0,
            display_name: "phone".into(),
        };
        let client_session = match client.step(ok).unwrap() {
            Outcome::Done { session, .. } => session,
            o => panic!("expected client Done, got {o:?}"),
        };
        (client_session, server_session)
    }

    #[test]
    fn first_pair_derives_matching_resumption_token() {
        let (client_session, server_session) = first_pair_sessions();
        let ct = derive_reconnect_token(&client_session).unwrap();
        let st = derive_reconnect_token(&server_session).unwrap();
        assert_eq!(
            ct, st,
            "both sides must derive the SAME reconnect token from the shared session"
        );
        assert_ne!(ct, [0u8; 32]);
    }

    #[test]
    fn resumption_token_keeps_wire_format_and_redacts_debug() {
        let raw = [0x42; 32];
        let token = ResumptionToken::from(raw);
        assert_eq!(
            postcard::to_allocvec(&token).unwrap(),
            postcard::to_allocvec(&raw).unwrap(),
            "opaque secret wrapper must remain postcard-compatible"
        );
        let debug = format!("{token:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("66"));
    }

    #[test]
    fn reconnect_authenticates_by_token_not_by_the_pairing_secret() {
        let tok = derive_reconnect_token(&first_pair_sessions().1).unwrap();
        // Deliberately DIFFERENT PINs on each side: a reconnect must succeed on
        // the token alone - the human PIN is no longer the reconnect credential.
        let mut client = ClientHandshake::resume(dev(1), "laptop".into(), &tok);
        let mut server = ServerHandshake::new(dev(2), "phone".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_resumption_tokens(HashMap::from([(dev(1), tok)]));

        let hello = client.start();
        let Outcome::Send(challenge) = server.step(hello).unwrap() else {
            panic!("expected challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        assert!(
            matches!(server.step(proof).unwrap(), Outcome::Done { .. }),
            "a matching token must authenticate regardless of the PIN"
        );
    }

    #[test]
    fn reconnect_with_wrong_token_is_rejected() {
        let mut client = ClientHandshake::resume(dev(1), "laptop".into(), [0xAA; 32]);
        let mut server = ServerHandshake::new(dev(2), "phone".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_resumption_tokens(HashMap::from([(dev(1), [0xBB; 32])]));
        let hello = client.start();
        let Outcome::Send(challenge) = server.step(hello).unwrap() else {
            panic!("expected challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        match server.step(proof).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert_eq!(reason, PairingFailure::WrongPin);
            }
            o => panic!("a wrong token must be rejected, got {o:?}"),
        }
    }

    #[test]
    fn reconnect_keeps_forward_secrecy() {
        // Same token, two reconnects → distinct session keys (fresh ephemeral
        // ECDH each time). Compromising the token later can't recover past keys.
        let tok = derive_reconnect_token(&first_pair_sessions().1).unwrap();
        let resume = || -> [u8; 32] {
            let mut client = ClientHandshake::resume(dev(1), "l".into(), &tok);
            let mut server = ServerHandshake::new(dev(2), "p".into())
                .with_unwindowed_pairing_secrets([secret()])
                .with_resumption_tokens(HashMap::from([(dev(1), &tok)]));
            let hello = client.start();
            let Outcome::Send(challenge) = server.step(hello).unwrap() else {
                panic!()
            };
            let Outcome::Send(proof) = client.step(challenge).unwrap() else {
                panic!()
            };
            match server.step(proof).unwrap() {
                Outcome::Done { session, .. } => session.0,
                _ => panic!(),
            }
        };
        assert_ne!(
            resume(),
            resume(),
            "fresh ephemerals → distinct resumed keys"
        );
    }

    // ── Out-of-band secret + enrollment window ─────────────────────────────

    /// Headline: someone with the PUBLIC NodeId who never obtained the ticket
    /// cannot complete a first pair. Since v8 there is no PIN to also guess -
    /// the secret is the whole credential, so this is now the ONLY thing
    /// standing in an attacker's way, and it must hold absolutely.
    #[test]
    fn first_pair_with_a_credential_the_host_never_minted_fails() {
        let mut attacker = ClientHandshake::first_pair(dev(1), "a".into(), other_secret());
        let mut server =
            ServerHandshake::new(dev(2), "p".into()).with_unwindowed_pairing_secrets([secret()]);
        let Outcome::Send(challenge) = server.step(attacker.start()).unwrap() else {
            panic!("expected challenge");
        };
        let Outcome::Send(proof) = attacker.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        match server.step(proof).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => assert!(
                matches!(reason, PairingFailure::WrongPin),
                "a first pair without the minted secret must fail, got {reason:?}"
            ),
            other => panic!("expected PairingFailed, got {other:?}"),
        }
    }

    /// The legitimate joiner who scanned the ticket presents the matching secret
    /// and completes the pair.
    #[test]
    fn first_pair_with_matching_ticket_secret_succeeds() {
        let mut client = ClientHandshake::first_pair(dev(1), "l".into(), secret());
        let mut server =
            ServerHandshake::new(dev(2), "p".into()).with_unwindowed_pairing_secrets([secret()]);
        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("expected challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        assert!(
            matches!(server.step(proof).unwrap(), Outcome::Done { .. }),
            "a matching ticket secret must complete the first pair"
        );
    }

    /// A joiner presenting a secret from a different or stale ticket is rejected.
    #[test]
    fn first_pair_with_wrong_ticket_secret_fails() {
        let mut client = ClientHandshake::first_pair(
            dev(1),
            "a".into(),
            PairingSecret::from_ticket_bytes([0xAA; 16]),
        );
        let mut server = ServerHandshake::new(dev(2), "p".into())
            .with_unwindowed_pairing_secrets([PairingSecret::from_ticket_bytes([0xBB; 16])]);
        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("expected challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        assert!(
            matches!(
                server.step(proof).unwrap(),
                Outcome::Send(HandshakeMessage::PairingFailed {
                    reason: PairingFailure::WrongPin
                })
            ),
            "a mismatched ticket secret must fail the proof"
        );
    }

    #[test]
    fn server_accepts_strong_ticket_and_separate_manual_secret() {
        let ticket = PairingSecret::from_ticket_bytes([0x51; 16]);
        let manual = PairingSecret::from_bytes([0x62; MANUAL_PAIRING_SECRET_BYTES]);

        for presented in [ticket.clone(), manual.clone()] {
            let mut client = ClientHandshake::first_pair(dev(1), "l".into(), presented);
            let mut server = ServerHandshake::new(dev(2), "p".into())
                .with_unwindowed_pairing_secrets([ticket.clone(), manual.clone()]);
            let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
                panic!("expected challenge");
            };
            let Outcome::Send(proof) = client.step(challenge).unwrap() else {
                panic!("expected proof");
            };
            assert!(matches!(server.step(proof).unwrap(), Outcome::Done { .. }));
        }
    }

    /// The replacement for the old "PIN-only pairing still works" test, and the
    /// inversion of it. A host with NO armed secret must refuse first pair
    /// outright. Before v8 this case silently degraded to a PIN-only proof, which
    /// is the weakest path in the old design and the one whose proof was directly
    /// offline-attackable by anyone at all.
    #[test]
    fn an_unarmed_host_refuses_first_pair_instead_of_degrading() {
        let mut client = ClientHandshake::first_pair(dev(1), "l".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "p".into()); // no secrets armed
        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => assert!(
                matches!(reason, PairingFailure::PairingClosed),
                "an unarmed host must refuse before issuing a challenge, got {reason:?}"
            ),
            other => panic!("expected PairingClosed, got {other:?}"),
        }
    }

    /// `with_first_pair` must arm BOTH halves from one snapshot.
    ///
    /// This is the whole point of collapsing the two builders: arming credentials
    /// while forgetting the window used to be a one-line omission that produced a
    /// first pair with no time box and no global failure cap. A caller that wants
    /// only one half now has to say so by name.
    #[test]
    fn with_first_pair_arms_the_credential_and_the_window_together() {
        use crate::crypto::pairing::{PairingState, ENROLLMENT_WINDOW};
        let mut state = PairingState::new([secret()]);
        state.open(ENROLLMENT_WINDOW);
        let state = Arc::new(Mutex::new(state));
        let snapshot = state.lock().unwrap().snapshot();
        assert!(snapshot.epoch.is_some() && !snapshot.secrets.is_empty());

        let mut server =
            ServerHandshake::new(dev(2), "host".into()).with_first_pair(state.clone(), snapshot);
        let mut client = ClientHandshake::first_pair(dev(1), "phone".into(), secret());

        // The credential half is armed: a challenge is issued at all.
        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("an armed, open host must challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("client proves");
        };
        // The window half is armed: the proof yields an epoch to claim, which an
        // unwindowed host would report as None.
        match server.step(proof).unwrap() {
            Outcome::Done {
                enrollment_epoch, ..
            } => assert!(
                enrollment_epoch.is_some(),
                "a first pair through with_first_pair must be windowed"
            ),
            other => panic!("expected Done, got {other:?}"),
        }
    }

    /// The B4 exemption waives the enrollment WINDOW, never the credential. An
    /// exempt device against an unarmed host still gets nothing.
    #[test]
    fn an_unarmed_host_refuses_even_an_enrollment_exempt_device() {
        let mut client = ClientHandshake::first_pair(dev(1), "l".into(), secret());
        let mut server =
            ServerHandshake::new(dev(2), "p".into()).with_enrollment_exempt_device(Some(dev(1)));
        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert!(
                    matches!(reason, PairingFailure::PairingClosed),
                    "{reason:?}"
                )
            }
            other => panic!("expected PairingClosed, got {other:?}"),
        }
    }

    // ── The v8 comparison code ─────────────────────────────────────────────

    /// Both peers must display the SAME code after a successful first pair -
    /// otherwise the operator confirming it would reject every legitimate pair.
    #[test]
    fn both_peers_derive_the_same_verification_code() {
        let (client_session, server_session) = first_pair_sessions();
        assert_eq!(
            crate::crypto::pairing::pair_verification_code(&client_session).unwrap(),
            crate::crypto::pairing::pair_verification_code(&server_session).unwrap(),
        );
    }

    /// The load-bearing property of the confirmation step: a peer in the middle
    /// runs two SEPARATE exchanges, so the code the victim sees cannot match the
    /// code the real host would show. This is what a human comparing the two
    /// screens actually detects.
    ///
    /// Modelled here as two independent pairs against the same credential - which
    /// is exactly what a relay attacker ends up holding, since it must terminate
    /// one exchange to read the traffic and originate another to reach the host.
    #[test]
    fn a_middle_peer_cannot_make_both_ends_show_the_same_code() {
        let a = crate::crypto::pairing::pair_verification_code(&first_pair_sessions().0).unwrap();
        let b = crate::crypto::pairing::pair_verification_code(&first_pair_sessions().0).unwrap();
        assert_ne!(
            a, b,
            "two distinct exchanges must not agree on a code (1-in-10^6 flake)"
        );
    }

    /// Pairing state with NO open opportunity - what a host looks like when
    /// nobody ran `portty pair`. Returns the state and the epoch a connection
    /// would have snapshotted (`None`).
    fn closed_pairing_state() -> (SharedPairingState, Option<u64>) {
        use crate::crypto::pairing::PairingState;
        let state = Arc::new(Mutex::new(PairingState::new(Vec::new())));
        let epoch = state.lock().unwrap().snapshot().epoch;
        (state, epoch)
    }

    /// Pairing state with a live opportunity, plus the epoch a connection would
    /// have snapshotted with the credentials. The FSM verifies against its own
    /// pin/secrets fields, so the state's copies go unused here.
    fn open_pairing_state() -> (SharedPairingState, Option<u64>) {
        use crate::crypto::pairing::{PairingState, ENROLLMENT_WINDOW};
        let mut state = PairingState::new(Vec::new());
        state.open(ENROLLMENT_WINDOW);
        let state = Arc::new(Mutex::new(state));
        let epoch = state.lock().unwrap().snapshot().epoch;
        assert!(epoch.is_some(), "an open window must yield an epoch");
        (state, epoch)
    }

    /// SRX: with an enrollment window injected but CLOSED (no active pairing),
    /// an inbound FIRST-PAIR Hello is refused with `PairingClosed` before any
    /// challenge is issued - the attacker never even gets to guess a PIN.
    #[test]
    fn first_pair_rejected_when_enrollment_window_closed() {
        let (state, epoch) = closed_pairing_state();
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch);
        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => assert!(
                matches!(reason, PairingFailure::PairingClosed),
                "a closed window must refuse first-pair with PairingClosed, got {reason:?}"
            ),
            other => panic!("expected PairingFailed::PairingClosed, got {other:?}"),
        }
    }

    #[test]
    fn revoked_authenticated_device_gets_typed_failure_when_pairing_is_closed() {
        let (state, epoch) = closed_pairing_state();
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_authenticated_device(dev(1), true);

        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert_eq!(reason, PairingFailure::Revoked);
            }
            other => panic!("expected typed revoked failure, got {other:?}"),
        }
    }

    #[test]
    fn authenticated_identity_mismatch_does_not_reveal_revocation_state() {
        let (state, epoch) = closed_pairing_state();
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_authenticated_device(dev(9), true);

        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => {
                assert_eq!(reason, PairingFailure::WrongPin);
            }
            other => panic!("identity mismatch must be generic, got {other:?}"),
        }
    }

    #[test]
    fn revoked_device_can_only_repair_in_an_open_enrollment_window() {
        let (state, epoch) = open_pairing_state();
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_authenticated_device(dev(1), true);

        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("open enrollment must challenge a fresh manual repair");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("client must answer the repair challenge");
        };
        assert!(matches!(server.step(proof).unwrap(), Outcome::Done { .. }));
    }

    #[test]
    fn revoked_stale_token_gets_typed_failure_even_while_enrollment_is_open() {
        let (state, epoch) = open_pairing_state();
        let mut client = ClientHandshake::resume(dev(1), "a".into(), [0x91; 32]);
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_authenticated_device(dev(1), true);

        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("open enrollment reaches proof verification");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("stale client answers using its revoked token");
        };
        assert!(matches!(
            server.step(proof).unwrap(),
            Outcome::Send(HandshakeMessage::PairingFailed {
                reason: PairingFailure::Revoked
            })
        ));
    }

    /// SRX: with the window OPEN, a first-pair Hello proceeds to a challenge -
    /// the gate doesn't break legitimate pairing.
    #[test]
    fn first_pair_proceeds_when_enrollment_window_open() {
        let (state, epoch) = open_pairing_state();
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch);
        assert!(
            matches!(
                server.step(client.start()).unwrap(),
                Outcome::Send(HandshakeMessage::PairingChallenge { .. })
            ),
            "an open window must let a legitimate first-pair reach the challenge"
        );
    }

    /// Drive one complete first-pair handshake against a shared pairing state and
    /// return the enrollment epoch its proof was verified under, i.e. what the
    /// caller would have to claim. `None` means the handshake never got that far.
    fn first_pair_to_verified_proof(
        device: DeviceId,
        state: &SharedPairingState,
        snapshot_epoch: Option<u64>,
    ) -> Option<u64> {
        let mut client = ClientHandshake::first_pair(device, "phone".into(), secret());
        let mut server = ServerHandshake::new(dev(200), "host".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state.clone(), snapshot_epoch);
        let Outcome::Send(challenge) = server.step(client.start()).ok()? else {
            return None;
        };
        let Outcome::Send(proof) = client.step(challenge).ok()? else {
            return None;
        };
        match server.step(proof).ok()? {
            Outcome::Done {
                enrollment_epoch, ..
            } => enrollment_epoch,
            _ => None,
        }
    }

    /// TWO clients with the same QR/PIN pairing at the same time, on real threads.
    ///
    /// What this asserts: under genuine concurrency, exactly ONE device ends up
    /// enrolled per opportunity.
    ///
    /// What it does NOT do is detect a non-atomic claim, and it is worth being
    /// precise about that rather than trusting a green test. The guarantee is
    /// structural: [`PairingState`] exposes no way to test an epoch without
    /// consuming it, so "check then act" cannot be written through its API. This
    /// test was measured against a deliberately non-atomic claim spliced in behind
    /// that API and still passed, because the two threads drift apart during the
    /// ECDH and HMAC work and rarely interleave at the claim itself. The shape that
    /// DID fail reliably - measured at 50/50 rounds - was the original one, where
    /// the check happened at challenge-issue and the close only after proof
    /// verification, leaving milliseconds of real work between them. That split no
    /// longer exists in this path, which is why it cannot be reproduced here.
    ///
    /// So: keep this as a regression guard on the observable property, and keep the
    /// property enforced by the API rather than by this test.
    #[test]
    fn only_one_of_two_simultaneous_first_pairs_can_claim_the_window() {
        for _ in 0..50 {
            let (state, epoch) = open_pairing_state();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let handles: Vec<_> = [dev(1), dev(2)]
                .into_iter()
                .map(|device| {
                    let state = state.clone();
                    let barrier = barrier.clone();
                    let winners = winners.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        // Gate + verify + claim, exactly as the accept path does.
                        if let Some(claim) = first_pair_to_verified_proof(device, &state, epoch) {
                            if state.lock().unwrap().consume_first_pair(claim) {
                                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("pairing thread");
            }

            assert_eq!(
                winners.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "exactly one device may enrol per opportunity"
            );
            assert!(!state.lock().unwrap().is_open());
        }
    }

    /// The host must be able to abandon a VERIFIED handshake without the phone
    /// having committed anything.
    ///
    /// This is the token-desync guard. `run_server_handshake` returning does not
    /// acknowledge the pairing - `confirm_server_handshake` does - so every failure
    /// between the two (no capacity, lost enrollment race, failed persist) leaves
    /// the phone still waiting rather than holding a rotated token the host never
    /// stored. A client only finalizes on `PairingOk`.
    #[test]
    fn a_verified_proof_does_not_by_itself_finalize_the_client() {
        let (state, epoch) = open_pairing_state();
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state.clone(), epoch);

        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("open window challenges");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("client proves");
        };
        // The host is satisfied...
        let Outcome::Done { .. } = server.step(proof).unwrap() else {
            panic!("server verifies the proof");
        };
        // ...and the FSM emitted NOTHING for the client. The only message that
        // finalizes it is PairingOk, which the caller sends after committing.
        assert_eq!(
            client_state_name(&client.state),
            "SentProof",
            "the client must still be waiting, not finalized"
        );

        // Ending here - as the accept path does when it cannot take a serving slot
        // or loses the enrollment race - leaves the window claimable and the client
        // with no credential to mismatch on.
        assert!(state.lock().unwrap().is_open());
    }

    /// A connection that snapshotted credentials BEFORE `portty pair` rotated them
    /// must not enrol afterwards. Its QR and PIN have been retired.
    #[test]
    fn a_stale_credential_snapshot_cannot_enrol_after_a_rotation() {
        use crate::crypto::pairing::ENROLLMENT_WINDOW;
        let (state, stale_epoch) = open_pairing_state();

        // `portty pair`: fresh secrets + PIN + a new opportunity, in one step.
        state.lock().unwrap().rotate([secret()], ENROLLMENT_WINDOW);

        // The delayed connection now presents its OLD snapshot. It is refused at
        // the challenge gate - it never even reaches a proof.
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state.clone(), stale_epoch);
        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => assert!(
                matches!(reason, PairingFailure::PairingClosed),
                "a retired credential snapshot must be refused, got {reason:?}"
            ),
            other => panic!("expected PairingClosed for a stale snapshot, got {other:?}"),
        }

        // A connection that snapshotted AFTER the rotation pairs normally.
        let fresh_epoch = state.lock().unwrap().snapshot().epoch;
        assert_ne!(fresh_epoch, stale_epoch);
        assert!(first_pair_to_verified_proof(dev(3), &state, fresh_epoch).is_some());
    }

    /// The FSM must not claim the opportunity itself - the caller does, at the
    /// point it persists. Otherwise a caller that fails afterwards has burned the
    /// window with nothing stored.
    #[test]
    fn a_verified_first_pair_leaves_the_window_open_until_the_caller_claims_it() {
        let (state, epoch) = open_pairing_state();
        let claim = first_pair_to_verified_proof(dev(1), &state, epoch).expect("verifies");

        assert!(
            state.lock().unwrap().is_open(),
            "the FSM must leave claiming to the caller"
        );
        assert!(state.lock().unwrap().consume_first_pair(claim));
        assert!(!state.lock().unwrap().is_open());
    }

    /// A reconnect has no enrollment opportunity to claim, so nothing about the
    /// window changes - a paired phone reconnecting must never consume pairing
    /// capacity.
    #[test]
    fn a_token_reconnect_reports_no_enrollment_claim() {
        let tok = [0x5a; 32];
        let (state, epoch) = open_pairing_state();
        let mut client = ClientHandshake::resume(dev(1), "l".into(), tok);
        let mut server = ServerHandshake::new(dev(2), "p".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state.clone(), epoch)
            .with_resumption_tokens(HashMap::from([(dev(1), tok)]));
        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("a known peer reaches a challenge");
        };
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("client answers");
        };
        match server.step(proof).unwrap() {
            Outcome::Done {
                enrollment_epoch,
                resumed,
                ..
            } => {
                assert!(resumed);
                assert_eq!(enrollment_epoch, None, "a reconnect claims nothing");
            }
            other => panic!("expected Done, got {other:?}"),
        }
        assert!(
            state.lock().unwrap().is_open(),
            "a reconnect must leave the pairing window untouched"
        );
    }

    /// SRX: a RECONNECT (we hold a resumption token for this device) is NEVER
    /// gated by the enrollment window - even with the window closed, a known
    /// peer authenticates by token and reaches a challenge.
    #[test]
    fn reconnect_not_gated_by_enrollment_window() {
        let tok = [0x5a; 32];
        let (state, epoch) = closed_pairing_state();
        let mut client = ClientHandshake::resume(dev(1), "l".into(), tok);
        let mut server = ServerHandshake::new(dev(2), "p".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_resumption_tokens(HashMap::from([(dev(1), tok)]));
        assert!(
            matches!(
                server.step(client.start()).unwrap(),
                Outcome::Send(HandshakeMessage::PairingChallenge { .. })
            ),
            "a token reconnect must not be gated by a closed enrollment window"
        );
    }

    /// SRX: fresh-NodeId spraying - the attack the per-key limiter can't stop -
    /// must trip the source-independent global cap. Each attempt uses a brand-new
    /// rate-limit key (fresh NodeId) so the per-key limiter never bites; only the
    /// global cap can stop it.
    #[test]
    fn fresh_source_spray_trips_global_enrollment_cap() {
        use crate::crypto::pairing::GLOBAL_FIRST_PAIR_CAP;
        let (state, epoch) = open_pairing_state();
        for i in 0..GLOBAL_FIRST_PAIR_CAP {
            let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
            let mut server = ServerHandshake::new(dev(2), "b".into())
                .with_unwindowed_pairing_secrets([secret()])
                .with_pairing_window(state.clone(), epoch)
                .with_rate_limit_key(format!("iroh:fresh-node-{i}"));
            assert!(
                matches!(
                    server.step(client.start()).unwrap(),
                    Outcome::Send(HandshakeMessage::PairingChallenge { .. })
                ),
                "attempt {i} (under the cap) should still reach a challenge"
            );
        }
        // The (cap+1)th fresh source is refused by the GLOBAL cap.
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_rate_limit_key("iroh:fresh-node-final".into());
        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => assert!(
                matches!(reason, PairingFailure::RateLimited),
                "fresh-NodeId spray past the global cap must be RateLimited, got {reason:?}"
            ),
            other => panic!("expected PairingFailed::RateLimited, got {other:?}"),
        }
    }

    /// B4: a device paired before resumption tokens shipped has no token, so it
    /// looks like a first-pair and a closed enrollment window would reject it.
    /// When the accept path has authenticated the peer's NodeId AND found it in
    /// the store, it marks the device enrollment-exempt - the closed window is
    /// then skipped and the handshake completes, letting the peer acquire a token.
    #[test]
    fn known_authenticated_device_bypasses_closed_enrollment_window() {
        let (state, epoch) = closed_pairing_state(); // closed
        let mut client = ClientHandshake::first_pair(dev(1), "l".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "p".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_enrollment_exempt_device(Some(dev(1)));
        let Outcome::Send(challenge) = server.step(client.start()).unwrap() else {
            panic!("exempt known device must reach a challenge, not PairingClosed");
        };
        assert!(matches!(
            challenge,
            HandshakeMessage::PairingChallenge { .. }
        ));
        let Outcome::Send(proof) = client.step(challenge).unwrap() else {
            panic!("expected proof");
        };
        assert!(
            matches!(server.step(proof).unwrap(), Outcome::Done { .. }),
            "an exempt known device with a matching PIN must complete the handshake"
        );
    }

    /// B4 (safety): with no exempt device set (the default), a first-pair against
    /// a closed window is still refused.
    #[test]
    fn unknown_device_still_gated_when_enrollment_window_closed() {
        let (state, epoch) = closed_pairing_state(); // closed
        let mut client = ClientHandshake::first_pair(dev(1), "a".into(), secret());
        let mut server = ServerHandshake::new(dev(2), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_enrollment_exempt_device(None);
        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => assert!(
                matches!(reason, PairingFailure::PairingClosed),
                "an unexempted first-pair must still be refused, got {reason:?}"
            ),
            other => panic!("expected PairingClosed, got {other:?}"),
        }
    }

    /// B4 (anti-spoof): the exemption keys on the AUTHENTICATED device, matched
    /// against the Hello's claimed device_id - so a connection cannot ride device
    /// X's exemption while its Hello claims to be device Y. Here the exempt device
    /// is dev(1) but the client's Hello claims dev(2); the mismatch means the gate
    /// still applies.
    #[test]
    fn mismatched_hello_device_id_is_not_exempt() {
        let (state, epoch) = closed_pairing_state(); // closed
                                                     // Client's Hello claims dev(2)...
        let mut client = ClientHandshake::first_pair(dev(2), "a".into(), secret());
        // ...but only dev(1) is exempt (that's who the NodeId would authenticate to).
        let mut server = ServerHandshake::new(dev(3), "b".into())
            .with_unwindowed_pairing_secrets([secret()])
            .with_pairing_window(state, epoch)
            .with_enrollment_exempt_device(Some(dev(1)));
        match server.step(client.start()).unwrap() {
            Outcome::Send(HandshakeMessage::PairingFailed { reason }) => assert!(
                matches!(reason, PairingFailure::PairingClosed),
                "a Hello claiming a device other than the exempt one must stay gated, got {reason:?}"
            ),
            other => panic!("expected PairingClosed, got {other:?}"),
        }
    }
}
