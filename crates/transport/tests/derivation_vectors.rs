//! Known-answer vectors for the pairing derivation chain.
//!
//! Every other crypto test in this crate is a round-trip: derive, then verify
//! with the same build. Those pass whether or not the derived bytes are what
//! they were yesterday, so they cannot answer the one question that matters when
//! a crypto dependency moves - *does an already-paired device still work?*
//!
//! This file answers it. The constants below were captured from the
//! ed25519-dalek 2 / sha2 0.10 / hkdf 0.12 / hmac 0.12 generation and must not
//! change. They are not secrets and not chosen for any cryptographic property:
//! they are fixed inputs whose outputs are pinned.
//!
//! The chain is standards-defined end to end - HKDF-SHA256 (RFC 5869),
//! HMAC-SHA256 (RFC 2104), SHA-256 (FIPS 180-4) - so a crate upgrade must not
//! move these bytes. If one of these assertions fails, the upgrade changed the
//! key schedule: every paired device is about to stop verifying, and the fix is
//! to understand why, not to re-capture the constants.

use portty_transport::crypto::pairing::{
    derive_resumption_token, derive_session_from_key, derive_subkey, first_pair_key,
    pair_verification_code, proof_from_key, Nonce, PairingSecret,
};

const TICKET_SECRET: [u8; 16] = [0x42; 16];
const NONCE: [u8; 32] = [0x11; 32];
const ECDH: [u8; 32] = [0x22; 32];
const TRANSCRIPT: &[u8] = b"portty-kat-transcript";

const FIRST_PAIR_KEY: &str = "75b90e6739f0d15a44b24b3a5403966c4906b97608c585660f1e516bde1c8397";
const PROOF: &str = "40e14cd45d4756d0d3a2deb5f79bc83dbc5bb7e80312ee7c1286cb054dfaec69";
const SESSION_SECRET: &str = "44b245da43ad01d5345369dbcefe1fab8ba82f569e74cab074e9b194eec9fe53";
const SUBKEY_C2S: &str = "789c18d1ff0a80b15a92541cf7e99d036c782521bb708b9ee7204fe3385fd28f";
const SUBKEY_S2C: &str = "98d767a0600b54652bd2124ac9d0d620a4f5cd173d789d67830ff1899913d84f";
const RESUMPTION_TOKEN: &str = "dc53b7dad6e0a70b354364613ccb318c372b6f2cb62c6670bea88e4f9580aa30";
const VERIFICATION_CODE: &str = "218853";

/// The full first-pair chain, in the order the handshake walks it.
#[test]
fn pairing_derivation_matches_pinned_vectors() {
    let secret = PairingSecret::from_ticket_bytes(TICKET_SECRET);
    let nonce = Nonce(NONCE);

    let key = first_pair_key(&secret);
    assert_eq!(hex::encode(&*key), FIRST_PAIR_KEY, "first_pair_key moved");

    let proof = proof_from_key(&key, &nonce, TRANSCRIPT).unwrap();
    assert_eq!(hex::encode(proof.0), PROOF, "proof_from_key moved");

    let session = derive_session_from_key(&key, &nonce, &ECDH).unwrap();
    assert_eq!(
        hex::encode(session.0),
        SESSION_SECRET,
        "session secret moved"
    );

    // Both envelope directions, because a single swapped label would still
    // round-trip against itself while breaking a real peer.
    let c2s = derive_subkey(&session, b"portty-app-envelope-v2/client-to-server").unwrap();
    assert_eq!(hex::encode(c2s.expose()), SUBKEY_C2S, "c2s subkey moved");

    let s2c = derive_subkey(&session, b"portty-app-envelope-v2/server-to-client").unwrap();
    assert_eq!(hex::encode(s2c.expose()), SUBKEY_S2C, "s2c subkey moved");

    let token = derive_resumption_token(&session).unwrap();
    assert_eq!(
        hex::encode(token),
        RESUMPTION_TOKEN,
        "resumption token moved - every stored token would be rejected"
    );

    // The digits an operator physically compares. A change here is silent: both
    // ends would still agree with each other, just not with a prior build.
    assert_eq!(
        pair_verification_code(&session).unwrap(),
        VERIFICATION_CODE,
        "pair verification code moved"
    );
}

/// The subkey labels are the domain separation. Distinct labels must give
/// distinct keys, or the two directions collapse into one.
#[test]
fn envelope_directions_derive_distinct_keys() {
    let secret = PairingSecret::from_ticket_bytes(TICKET_SECRET);
    let key = first_pair_key(&secret);
    let session = derive_session_from_key(&key, &Nonce(NONCE), &ECDH).unwrap();

    let c2s = derive_subkey(&session, b"portty-app-envelope-v2/client-to-server").unwrap();
    let s2c = derive_subkey(&session, b"portty-app-envelope-v2/server-to-client").unwrap();
    assert_ne!(c2s.expose(), s2c.expose());
}
