//! App-layer message envelope: XChaCha20-Poly1305. (Forked from Corvux
//! `sync/crypto/envelope.rs`; label re-branded `portty-*`.)
//!
//! iroh QUIC already encrypts the wire (TLS 1.3). This second sealed layer is
//! forward defence: (1) the (deferred) store-and-forward queue must never see
//! plaintext, (2) any future application-aware relay must not read frames, and
//! (3) a TLS-stack compromise alone doesn't reveal content.
//!
//! Cipher: XChaCha20-Poly1305 with a monotonic sequence and 128 random nonce
//! bits per frame. Client→server and server→client keys are distinct HKDF-SHA256
//! subkeys of the pairing `SessionSecret`; direction + sequence are also bound
//! into AAD. The receiver rejects replays and out-of-order envelopes.

use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroize;

use super::pairing::{derive_subkey, SessionSecret};
use crate::error::{CryptoError, SyncResult};

const CLIENT_TO_SERVER_KEY_LABEL: &[u8] = b"portty-app-envelope-v2/client-to-server";
const SERVER_TO_CLIENT_KEY_LABEL: &[u8] = b"portty-app-envelope-v2/server-to-client";
const CLIENT_TO_SERVER_AAD: &[u8] = b"portty-envelope/client-to-server";
const SERVER_TO_CLIENT_AAD: &[u8] = b"portty-envelope/server-to-client";

/// A sealed app-layer frame. `(nonce, ciphertext)` is what crosses the wire.
pub struct SealedFrame {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// XChaCha20-Poly1305 cipher keyed off the pairing session secret. Cloning
/// disallowed - one cipher per peer connection.
pub struct EnvelopeCipher {
    seal_key: ZeroizingKey,
    open_key: ZeroizingKey,
    seal_aad: &'static [u8],
    open_aad: &'static [u8],
    next_seal_sequence: AtomicU64,
    last_open_sequence: AtomicU64,
}

struct ZeroizingKey([u8; 32]);

impl Drop for ZeroizingKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl EnvelopeCipher {
    /// Client role: seal phone→host and open host→phone.
    pub fn for_client(session: &SessionSecret) -> SyncResult<Self> {
        Self::from_session_labels(
            session,
            CLIENT_TO_SERVER_KEY_LABEL,
            SERVER_TO_CLIENT_KEY_LABEL,
            CLIENT_TO_SERVER_AAD,
            SERVER_TO_CLIENT_AAD,
        )
    }

    /// Server role: seal host→phone and open phone→host.
    pub fn for_server(session: &SessionSecret) -> SyncResult<Self> {
        Self::from_session_labels(
            session,
            SERVER_TO_CLIENT_KEY_LABEL,
            CLIENT_TO_SERVER_KEY_LABEL,
            SERVER_TO_CLIENT_AAD,
            CLIENT_TO_SERVER_AAD,
        )
    }

    fn from_session_labels(
        session: &SessionSecret,
        seal_key_label: &[u8],
        open_key_label: &[u8],
        seal_aad: &'static [u8],
        open_aad: &'static [u8],
    ) -> SyncResult<Self> {
        let seal_key = derive_subkey(session, seal_key_label)?;
        let open_key = derive_subkey(session, open_key_label)?;
        Ok(Self {
            seal_key: ZeroizingKey(*seal_key.expose()),
            open_key: ZeroizingKey(*open_key.expose()),
            seal_aad,
            open_aad,
            next_seal_sequence: AtomicU64::new(1),
            last_open_sequence: AtomicU64::new(0),
        })
    }

    /// Seal `plaintext` with a monotonic sequence plus 128 random nonce bits.
    /// Direction, sequence, and caller `aad` are authenticated, not encrypted.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> SyncResult<SealedFrame> {
        let sequence = self.next_seal_sequence.fetch_add(1, Ordering::Relaxed);
        if sequence == u64::MAX {
            return Err(CryptoError::NonceExhausted.into());
        }
        let cipher = XChaCha20Poly1305::new((&self.seal_key.0).into());
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        // A partly-filled nonce would repeat under the same key, which is fatal
        // for ChaCha20-Poly1305 - so entropy failure aborts the seal rather than
        // shipping a frame. (`rand` 0.8 panicked here; 0.10 lets us type it.)
        SysRng
            .try_fill_bytes(&mut nonce[8..])
            .map_err(|_| CryptoError::Rng)?;
        let bound_aad = envelope_aad(self.seal_aad, sequence, aad);
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &bound_aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(SealedFrame { nonce, ciphertext })
    }

    /// Open the next `SealedFrame`, rejecting duplicates and gaps before
    /// decryption. Authentication failure does not advance replay state.
    pub fn open(&self, nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> SyncResult<Vec<u8>> {
        let sequence = u64::from_be_bytes(nonce[..8].try_into().expect("fixed nonce prefix"));
        let last = self.last_open_sequence.load(Ordering::Relaxed);
        let expected = last.checked_add(1).ok_or(CryptoError::NonceExhausted)?;
        if sequence != expected {
            return Err(CryptoError::Replay {
                expected,
                found: sequence,
            }
            .into());
        }
        let cipher = XChaCha20Poly1305::new((&self.open_key.0).into());
        let bound_aad = envelope_aad(self.open_aad, sequence, aad);
        let plaintext = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &bound_aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)?;
        match self.last_open_sequence.compare_exchange(
            last,
            sequence,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(plaintext),
            Err(observed) => Err(CryptoError::Replay {
                expected: observed.saturating_add(1),
                found: sequence,
            }
            .into()),
        }
    }
}

fn envelope_aad(direction: &[u8], sequence: u64, caller_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(direction.len() + 8 + caller_aad.len());
    aad.extend_from_slice(direction);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(caller_aad);
    aad
}

impl std::fmt::Debug for EnvelopeCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvelopeCipher(****)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pairing::{derive_session_from_key, first_pair_key, Nonce, PairingSecret};

    fn make_pair() -> (EnvelopeCipher, EnvelopeCipher) {
        let key = first_pair_key(&PairingSecret::from_ticket_bytes([0x42; 16]));
        let nonce = Nonce::generate();
        let session = derive_session_from_key(&key, &nonce, &[0u8; 32]).unwrap();
        (
            EnvelopeCipher::for_client(&session).unwrap(),
            EnvelopeCipher::for_server(&session).unwrap(),
        )
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let (client, server) = make_pair();
        let plaintext = b"hello, sync";
        let sealed = client.seal(plaintext, b"aad").unwrap();
        let recovered = server
            .open(&sealed.nonce, &sealed.ciphertext, b"aad")
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn two_peers_with_same_session_secret_open_each_others_frames() {
        let key = first_pair_key(&PairingSecret::from_ticket_bytes([0x24; 16]));
        let nonce = Nonce::generate();
        let session_a = derive_session_from_key(&key, &nonce, &[0u8; 32]).unwrap();
        let session_b = derive_session_from_key(&key, &nonce, &[0u8; 32]).unwrap();
        let client = EnvelopeCipher::for_client(&session_a).unwrap();
        let server = EnvelopeCipher::for_server(&session_b).unwrap();

        let plaintext = b"crossing the pair boundary";
        let sealed = client.seal(plaintext, b"").unwrap();
        let recovered = server.open(&sealed.nonce, &sealed.ciphertext, b"").unwrap();
        assert_eq!(recovered, plaintext);

        let reply = server.seal(b"crossing back", b"").unwrap();
        assert_eq!(
            client.open(&reply.nonce, &reply.ciphertext, b"").unwrap(),
            b"crossing back"
        );
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let (client_a, _) = make_pair();
        let (_, server_b) = make_pair();

        let sealed = client_a.seal(b"secret", b"").unwrap();
        let err = server_b
            .open(&sealed.nonce, &sealed.ciphertext, b"")
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::SyncError::Crypto(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn mismatched_aad_fails_to_open() {
        let (client, server) = make_pair();
        let sealed = client.seal(b"bound to aad", b"context-A").unwrap();
        let err = server
            .open(&sealed.nonce, &sealed.ciphertext, b"context-B")
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::SyncError::Crypto(CryptoError::Decrypt)
        ));
        assert_eq!(
            server
                .open(&sealed.nonce, &sealed.ciphertext, b"context-A")
                .unwrap(),
            b"bound to aad"
        );
    }

    #[test]
    fn nonces_differ_between_seals() {
        let (client, _) = make_pair();
        let s1 = client.seal(b"a", b"").unwrap();
        let s2 = client.seal(b"a", b"").unwrap();
        assert_ne!(s1.nonce, s2.nonce);
        assert_ne!(s1.ciphertext, s2.ciphertext);
    }

    #[test]
    fn ciphertext_is_longer_than_plaintext_by_tag_size() {
        let (client, _) = make_pair();
        let plaintext = b"abc";
        let sealed = client.seal(plaintext, b"").unwrap();
        assert_eq!(sealed.ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn replayed_envelope_is_rejected() {
        let (client, server) = make_pair();
        let sealed = client.seal(b"once", b"").unwrap();
        assert_eq!(
            server.open(&sealed.nonce, &sealed.ciphertext, b"").unwrap(),
            b"once"
        );
        assert!(matches!(
            server
                .open(&sealed.nonce, &sealed.ciphertext, b"")
                .unwrap_err(),
            crate::error::SyncError::Crypto(CryptoError::Replay { .. })
        ));
    }

    #[test]
    fn concurrent_replay_can_only_open_once() {
        let (client, server) = make_pair();
        let sealed = client.seal(b"single consumer", b"").unwrap();
        let server = std::sync::Arc::new(server);
        let sealed = std::sync::Arc::new(sealed);

        let results = std::thread::scope(|scope| {
            let first_server = server.clone();
            let first_sealed = sealed.clone();
            let first = scope.spawn(move || {
                first_server.open(&first_sealed.nonce, &first_sealed.ciphertext, b"")
            });
            let second_server = server.clone();
            let second_sealed = sealed.clone();
            let second = scope.spawn(move || {
                second_server.open(&second_sealed.nonce, &second_sealed.ciphertext, b"")
            });
            [first.join().unwrap(), second.join().unwrap()]
        });

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(crate::error::SyncError::Crypto(CryptoError::Replay { .. }))
                ))
                .count(),
            1
        );
    }

    #[test]
    fn out_of_order_envelope_is_rejected_without_advancing_state() {
        let (client, server) = make_pair();
        let first = client.seal(b"first", b"").unwrap();
        let second = client.seal(b"second", b"").unwrap();

        assert!(matches!(
            server
                .open(&second.nonce, &second.ciphertext, b"")
                .unwrap_err(),
            crate::error::SyncError::Crypto(CryptoError::Replay {
                expected: 1,
                found: 2
            })
        ));
        assert_eq!(
            server.open(&first.nonce, &first.ciphertext, b"").unwrap(),
            b"first"
        );
    }

    #[test]
    fn reflected_client_ciphertext_cannot_be_opened_by_client() {
        let (client, _) = make_pair();
        let sealed = client.seal(b"do not reflect", b"").unwrap();
        assert!(matches!(
            client
                .open(&sealed.nonce, &sealed.ciphertext, b"")
                .unwrap_err(),
            crate::error::SyncError::Crypto(CryptoError::Decrypt)
        ));
    }
}
