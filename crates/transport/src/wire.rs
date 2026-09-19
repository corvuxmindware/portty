//! Post-handshake wire envelope.
//!
//! After the pairing handshake completes, both sides hold an [`EnvelopeCipher`]
//! (derived from the session secret). Every app message is postcard-encoded,
//! sealed into a [`SealedEnvelope`], and carried as one framed transport
//! message of type `SealedEnvelope` (i.e. `Transport<SealedEnvelope>`). This
//! keeps the transport crate generic over the app message type - Portty's
//! `portty_protocol::Frame` plugs in at the host layer.

use serde::{Deserialize, Serialize};

use crate::crypto::envelope::EnvelopeCipher;
use crate::error::{ProtocolError, SyncResult};

/// XChaCha20-Poly1305 sealed wrapper around a postcard-encoded app message.
/// This is what crosses the wire after the handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Seal an already-postcard-encoded app payload into a wire envelope.
pub fn seal(cipher: &EnvelopeCipher, plaintext: &[u8], aad: &[u8]) -> SyncResult<SealedEnvelope> {
    let sealed = cipher.seal(plaintext, aad)?;
    Ok(SealedEnvelope {
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    })
}

/// Open a wire envelope back to plaintext bytes.
pub fn open(cipher: &EnvelopeCipher, env: &SealedEnvelope, aad: &[u8]) -> SyncResult<Vec<u8>> {
    cipher.open(&env.nonce, &env.ciphertext, aad)
}

/// Convenience: seal a `Serialize` message → wire envelope.
pub fn seal_msg<M: Serialize>(
    cipher: &EnvelopeCipher,
    msg: &M,
    aad: &[u8],
) -> SyncResult<SealedEnvelope> {
    let bytes = postcard::to_allocvec(msg).map_err(|e| ProtocolError::Encode(e.to_string()))?;
    seal(cipher, &bytes, aad)
}

/// Convenience: open a wire envelope → decoded message `M`.
pub fn open_msg<M: for<'de> Deserialize<'de>>(
    cipher: &EnvelopeCipher,
    env: &SealedEnvelope,
    aad: &[u8],
) -> SyncResult<M> {
    let bytes = open(cipher, env, aad)?;
    postcard::from_bytes(&bytes).map_err(|e| ProtocolError::Decode(e.to_string()).into())
}
