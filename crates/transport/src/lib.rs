//! Portty secure transport - fork-copied from Corvux's sync layer and adapted.
//! See the `lift-from-corvux` skill for the adaptation rules applied here.
//!
//! # Layering
//!
//! ```text
//!   error        - typed errors (Identity / Crypto / Transport / Protocol)
//!   identity     - Ed25519 device keypair (automerge stripped from the Corvux original)
//!   frame        - length-prefixed framed I/O, version per frame
//!   transport    - generic `Transport<M>` message-channel trait
//!   crypto/      - pairing (PIN → session secret), envelope (XChaCha20-Poly1305),
//!                  wordlist (diceware tables for the pairing phrase). Domain-separated (`portty-*`).
//!   secure       - best-effort file-permission tightening for the identity at rest.
//! ```

pub mod credential_store;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod identity;
pub mod iroh;
pub mod peers;
pub mod secure;
pub mod transport;
pub mod wire;

pub use credential_store::{CredentialStore, Durability, FileCredentialStore};
pub use crypto::envelope::EnvelopeCipher;
pub use crypto::pairing::{
    pair_verification_code, EnrollmentWindow, FirstPairGate, KeyedPairingRateLimiter,
    PairingSecret, PairingSnapshot, PairingState, SharedPairingState, ENROLLMENT_WINDOW,
    GLOBAL_FIRST_PAIR_CAP, MANUAL_PAIRING_SECRET_BYTES, PAIR_VERIFICATION_CODE_DIGITS,
    TICKET_PAIRING_SECRET_BYTES,
};
pub use error::{CryptoError, IdentityError, ProtocolError, SyncError, SyncResult, TransportError};
pub use frame::{
    read_frame, supports_protocol_version, validate_protocol_version, write_frame, MAX_FRAME_BYTES,
    MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
pub use handshake::{
    derive_pair_material, derive_reconnect_token, ClientHandshake, HandshakeMessage, Outcome,
    PairEventKey, PairId, PairingFailure, ResumptionToken, ServerHandshake, SharedRateLimiter,
};
pub use identity::{DeviceId, Identity};
pub use iroh::{
    build_endpoint, confirm_server_handshake, decode_ticket, decode_ticket_secret,
    device_id_from_node_id, encode_compact_ticket, encode_ticket, run_client_handshake,
    run_client_handshake_with, run_server_handshake, HandshakeOutcome, IrohReader, IrohTransport,
    IrohWriter, SYNC_ALPN,
};
pub use peers::{HandshakeCommit, PairState, PeerRecord, PeerStore, RevocationRecord};
pub use transport::Transport;
pub use wire::{open, open_msg, seal, seal_msg, SealedEnvelope};
