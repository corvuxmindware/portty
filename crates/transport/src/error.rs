//! Typed error hierarchy for the transport layer (forked + trimmed from Corvux).
//!
//! Kept: Identity / Crypto / Transport / Protocol. Dropped: Crdt / Store / Engine
//! and the Corvux-IPC `SyncCommandError` - none apply to Portty's transport crate.

use std::io;
use thiserror::Error;

/// Top-level error returned from every public transport API.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),

    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Identity layer - keypair generation, loading, signing.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to generate keypair")]
    Generate,

    #[error("identity file corrupt or unreadable")]
    Corrupt,

    #[error("identity version {found} unsupported (expected {expected})")]
    UnsupportedVersion { expected: u16, found: u16 },
}

/// Crypto layer - pairing, session keys, fingerprints.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("pin verification failed")]
    WrongPin,

    #[error("pairing is rate-limited; wait before retrying")]
    RateLimited,

    #[error("hmac length mismatch")]
    HmacLength,

    #[error("key derivation failed")]
    Kdf,

    #[error("ecdh shared secret is non-contributory (peer sent a low-order point)")]
    NonContributoryEcdh,

    #[error("envelope decryption failed (wrong key, tampered ciphertext, or wrong nonce)")]
    Decrypt,

    #[error("replayed or out-of-order envelope (expected sequence {expected}, found {found})")]
    Replay { expected: u64, found: u64 },

    #[error("envelope sequence exhausted; reconnect before sending more data")]
    NonceExhausted,

    /// The OS entropy source refused. Every caller here is minting key material
    /// or a nonce, so there is no degraded mode to fall back to: a predictable
    /// nonce breaks AEAD outright, and a predictable identity key is not an
    /// identity. Fail closed instead.
    ///
    /// `rand` 0.10 is what surfaced this - `SysRng` is fallible (`TryRng`),
    /// where 0.8's `OsRng.fill_bytes` panicked. Same event, typed now.
    #[error("the operating system random number generator failed")]
    Rng,
}

/// Transport layer - framing, TLS, connection lifecycle.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("peer closed connection")]
    Closed,

    #[error("frame exceeds max size ({0} bytes)")]
    FrameTooLarge(u32),

    #[error("frame header malformed")]
    MalformedFrame,

    #[error("protocol version {found} unsupported (this build speaks {expected})")]
    UnsupportedProtocolVersion { expected: u16, found: u16 },

    #[error("tls handshake failed: {0}")]
    TlsHandshake(String),

    #[error("iroh transport: {0}")]
    Iroh(String),

    #[error("connect timeout")]
    ConnectTimeout,

    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Protocol layer - message parsing, handshake state machine.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("decoding postcard payload: {0}")]
    Decode(String),

    #[error("encoding postcard payload: {0}")]
    Encode(String),

    #[error("unexpected message {actual} in state {state}")]
    UnexpectedMessage {
        state: &'static str,
        actual: &'static str,
    },

    #[error("handshake already complete")]
    HandshakeComplete,

    #[error("handshake aborted by peer: {0}")]
    Aborted(String),

    #[error("pairing failed: {0:?}")]
    PairingFailed(crate::handshake::PairingFailure),
}

/// Convenience alias.
pub type SyncResult<T> = Result<T, SyncError>;
