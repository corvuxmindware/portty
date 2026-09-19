//! Crypto primitives for the transport layer. (Forked from Corvux `sync/crypto/`.)
//!
//! Two responsibilities:
//! - `pairing` - take a 6-digit PIN + server nonce and derive a 32-byte session
//!   secret via HMAC-SHA256 challenge-response → HKDF-SHA256 (with ephemeral
//!   X25519 forward secrecy mixed in).
//! - `envelope` - XChaCha20-Poly1305 sealed wrapper for post-handshake frames.
//! - `wordlist` - even/odd diceware tables backing pairing's manual 4-word codec.
//!
//! HKDF/envelope labels are domain-separated `portty-*` so Portty keys can never
//! cross with Corvux keys.

pub mod envelope;
pub mod pairing;
pub mod wordlist;
