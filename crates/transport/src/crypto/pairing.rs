//! Secret-based pairing: challenge-response → session keys, then a human
//! comparison code. (Forked from Corvux `sync/crypto/pairing.rs`; labels
//! re-branded `portty-*`.)
//!
//! # Threat model
//!
//! The first-pair credential is the high-entropy out-of-band [`PairingSecret`]
//! carried in the QR/ticket (128 bits) or read aloud as a phrase (48 bits). It is
//! **never sent over the wire** - only an HMAC-SHA256 proof over a server-supplied
//! 256-bit nonce and the channel-binding transcript. Session keys derive from
//! secret+nonce via HKDF-SHA256 with ephemeral X25519 forward secrecy mixed in.
//!
//! **There is deliberately no PIN.** Until PROTOCOL_VERSION 8 the first-pair key
//! was `HMAC(secret, PIN)` over a 6-digit PIN, and that was broken: against an
//! attacker who already held the ticket, the secret contributed zero entropy, so
//! a single captured proof reduced to a 900,000-entry offline dictionary. An
//! attacker who copied a live ticket, substituted their own NodeId, and got the
//! victim to use it collected one proof, recovered the PIN in well under a
//! second, and then paired with the real host inside its enrollment window.
//!
//! Note the shape of that bug, because it rules out the obvious cheap fixes: in
//! any HMAC-over-a-nonce exchange, whichever side proves FIRST hands the other an
//! offline dictionary of its own credential. Reordering the messages just moves
//! the oracle - making the host prove first would let anyone who dials during an
//! open window crack the credential with no social engineering at all. Only two
//! things actually close it: a PAKE, or a credential with no dictionary to search.
//! Portty takes the second route, so the low-entropy human value moves to AFTER
//! the key exchange, where it is a comparison and not a key.
//!
//! # Protocol (happy path)
//!
//! ```text
//!     Client                              Server
//!       │    OPEN (iroh QUIC)              │
//!       │──────────────────────────────────▶│ generate nonce N (32 B, OsRng)
//!       │    PairingChallenge{N, eph}       │
//!       │ ◀──────────────────────────────────│
//!       │ k     = HMAC(label, secret)       │
//!       │ proof = HMAC(k, N‖transcript)     │
//!       │ sk    = HKDF(k, N‖ecdh)           │
//!       │    PairingProof{proof}            │
//!       │──────────────────────────────────▶│ verify; derive the same sk
//!       │                                   │
//!       │  both sides now show the SAME     │ operator compares the two codes
//!       │  6-digit code from HKDF(sk, sas)  │ and confirms at the host
//!       │    PairingOk{}                    │
//!       │ ◀──────────────────────────────────│ (only after confirmation)
//! ```
//!
//! The comparison code ([`pair_verification_code`]) is derived from the session
//! secret, so it already covers the ephemeral ECDH. A peer in the middle cannot
//! make both ends display the same digits - which is what makes it a real check
//! and not decoration. It is not secret, and it is never key material.

use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::rngs::SysRng;
use rand::TryRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, SyncResult};

type HmacSha256 = Hmac<Sha256>;

/// Fill `dst` from OS entropy, panicking if the OS refuses.
///
/// Deliberately scoped. `rand` 0.10's `SysRng` is fallible, and the two places
/// where a `Result` was already in hand (envelope sealing, identity generation)
/// now return typed errors. The constructors below are infallible by signature
/// and their 19 call sites reach into the handshake FSM, so widening them is a
/// separate change - not something to smuggle into a version bump. rand 0.8's
/// `OsRng.fill_bytes` panicked on this same event, so behaviour is unchanged.
fn fill_from_os(dst: &mut [u8]) {
    SysRng
        .try_fill_bytes(dst)
        .expect("OS entropy source unavailable");
}

pub const TICKET_PAIRING_SECRET_BYTES: usize = 16;
pub const MANUAL_PAIRING_SECRET_BYTES: usize = 6;

/// Out-of-band first-pair secret, always zeroized on drop. This is the ONLY
/// first-pair credential - see the module threat model for why there is no PIN
/// folded in beside it.
///
/// QR/full tickets carry 128 random bits. The manual fallback carries 48 bits as
/// six words, because it has to be typeable or readable aloud.
///
/// 48 bits is a deliberate floor, and the reasoning changed at PROTOCOL_VERSION
/// 8. It used to be 32 bits, justified by the phrase only ever being guessable
/// ONLINE behind the ten-attempt cap. That justification died with the PIN: now
/// that the secret alone keys the proof, an attacker who can get the phone to
/// dial a substituted NodeId collects a proof over the phrase itself and attacks
/// it offline. At 48 bits that search outlives the five-minute enrollment window
/// by orders of magnitude, and [`pair_verification_code`] still has to match at a
/// human afterwards. Scanning the QR yields the full 128 bits; the words exist
/// purely for when a camera cannot.
#[derive(Clone)]
pub struct PairingSecret(PairingSecretBytes);

#[derive(Clone)]
enum PairingSecretBytes {
    Ticket(Zeroizing<[u8; TICKET_PAIRING_SECRET_BYTES]>),
    Manual(Zeroizing<[u8; MANUAL_PAIRING_SECRET_BYTES]>),
}

impl PairingSecret {
    /// Mint the high-entropy secret embedded in new QR/full tickets.
    pub fn generate_ticket() -> Self {
        let mut b = [0u8; TICKET_PAIRING_SECRET_BYTES];
        fill_from_os(&mut b);
        Self(PairingSecretBytes::Ticket(Zeroizing::new(b)))
    }

    /// Mint the six-word manual fallback.
    pub fn generate_manual() -> Self {
        let mut b = [0u8; MANUAL_PAIRING_SECRET_BYTES];
        fill_from_os(&mut b);
        Self(PairingSecretBytes::Manual(Zeroizing::new(b)))
    }

    /// Construct a manual 48-bit secret.
    pub fn from_bytes(b: [u8; MANUAL_PAIRING_SECRET_BYTES]) -> Self {
        Self(PairingSecretBytes::Manual(Zeroizing::new(b)))
    }

    /// Construct a current 128-bit ticket secret.
    pub fn from_ticket_bytes(b: [u8; TICKET_PAIRING_SECRET_BYTES]) -> Self {
        Self(PairingSecretBytes::Ticket(Zeroizing::new(b)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            PairingSecretBytes::Ticket(bytes) => &bytes[..],
            PairingSecretBytes::Manual(bytes) => &bytes[..],
        }
    }

    pub(crate) fn ticket_bytes(&self) -> Option<&[u8; TICKET_PAIRING_SECRET_BYTES]> {
        match &self.0 {
            PairingSecretBytes::Ticket(bytes) => Some(bytes),
            PairingSecretBytes::Manual(_) => None,
        }
    }

    /// URL-safe, unpadded base64 - the form embedded in the ticket JSON.
    pub fn to_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.as_bytes())
    }

    /// Parse the ticket-embedded base64 form. `None` on any malformed input or
    /// wrong length. A ticket that carries no valid secret now yields NO usable
    /// credential at all: first pair fails closed rather than silently degrading
    /// to a weaker path (the PIN-only fallback this used to fall back to is gone).
    ///
    /// Pre-v8 32-bit secrets are deliberately NOT decoded. They are below the
    /// entropy floor this scheme now depends on, and MIN == PROTOCOL_VERSION means
    /// such a peer cannot connect anyway - so accepting the bytes could only
    /// mislead.
    pub fn from_b64(s: &str) -> Option<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .ok()?;
        match bytes.len() {
            TICKET_PAIRING_SECRET_BYTES => Some(Self::from_ticket_bytes(bytes.try_into().ok()?)),
            MANUAL_PAIRING_SECRET_BYTES => Some(Self::from_bytes(bytes.try_into().ok()?)),
            _ => None,
        }
    }

    /// Render as a six-word phrase for manual pairing (typed or read aloud
    /// alongside a bare NodeId, instead of pasting the full ticket). Uses the
    /// even/odd diceware tables from [`super::wordlist`] as a *codec* that
    /// round-trips back to bytes via [`Self::from_phrase`] - the phrase and the
    /// host that minted it are always the same running process checking its own
    /// secret, so no cross-device wordlist-version negotiation is needed.
    ///
    /// Six words, not four: the phrase is now the whole first-pair credential,
    /// so its 48 bits are what stands between a captured proof and an offline
    /// recovery of the secret. See [`MANUAL_PAIRING_SECRET_BYTES`].
    pub fn to_phrase(&self) -> Option<String> {
        use super::wordlist::{EVEN_WORDS, ODD_WORDS};
        let PairingSecretBytes::Manual(b) = &self.0 else {
            return None;
        };
        // Even positions come from EVEN_WORDS, odd from ODD_WORDS, so a word in
        // the wrong slot is rejected rather than silently decoding to other bytes.
        let words: Vec<&str> = b
            .iter()
            .enumerate()
            .map(|(i, &byte)| {
                if i % 2 == 0 {
                    EVEN_WORDS[byte as usize]
                } else {
                    ODD_WORDS[byte as usize]
                }
            })
            .collect();
        Some(words.join("-"))
    }

    /// Parse a six-word phrase back into a secret. Case-insensitive; accepts
    /// `-`, whitespace, or a mix as separators. `None` if it isn't exactly
    /// [`MANUAL_PAIRING_SECRET_BYTES`] words or any word isn't in the table its
    /// position requires.
    pub fn from_phrase(s: &str) -> Option<Self> {
        use super::wordlist::{EVEN_WORDS, ODD_WORDS};
        let words: Vec<&str> = s
            .split(|c: char| c == '-' || c.is_whitespace())
            .filter(|w| !w.is_empty())
            .collect();
        if words.len() != MANUAL_PAIRING_SECRET_BYTES {
            return None;
        }
        let mut bytes = [0u8; MANUAL_PAIRING_SECRET_BYTES];
        for (i, word) in words.iter().enumerate() {
            let list = if i % 2 == 0 { &EVEN_WORDS } else { &ODD_WORDS };
            let index = list
                .iter()
                .position(|&candidate| candidate.eq_ignore_ascii_case(word))?;
            bytes[i] = index as u8;
        }
        Some(Self(PairingSecretBytes::Manual(Zeroizing::new(bytes))))
    }
}

impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret, even in debug logs.
        f.write_str("PairingSecret(****)")
    }
}

/// 32-byte HMAC-SHA256 pairing proof. Attacker-observable; single-use (bound to
/// a fresh nonce per attempt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof(pub [u8; 32]);

/// 32-byte pairing nonce from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; 32]);

impl Nonce {
    pub fn generate() -> Self {
        let mut n = [0u8; 32];
        fill_from_os(&mut n);
        Self(n)
    }
}

/// 32-byte derived session secret. Zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionSecret(pub [u8; 32]);

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSecret(****)")
    }
}

/// Domain-separation constant for HKDF. `portty-*` so Portty keys never cross
/// with Corvux keys. Folds the ephemeral X25519 ECDH secret into the IKM for
/// per-handshake forward secrecy.
const HKDF_INFO: &[u8] = b"portty-pairing-v1";

/// Generate a one-shot ephemeral X25519 keypair for a single handshake.
/// Returns the secret (held until the peer's public key arrives) and our
/// public-key bytes to put on the wire.
pub fn generate_ephemeral() -> (x25519_dalek::EphemeralSecret, [u8; 32]) {
    // `random()` draws straight from the OS via getrandom, which is what the old
    // `random_from_rng(OsRng)` did - rand 0.10's fallible `SysRng` no longer
    // satisfies dalek's infallible `CryptoRng` bound, and routing through a
    // thread CSPRNG instead would quietly weaken where this key comes from.
    let secret = x25519_dalek::EphemeralSecret::random();
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret, *public.as_bytes())
}

/// Complete the X25519 exchange. Rejects non-contributory (low-order) peer
/// points that would force a predictable shared secret.
///
/// Returns the shared secret wrapped in `Zeroizing`: it is the forward-secrecy
/// root, so once the caller has folded it into the session key it must be wiped
/// rather than left lingering in freed memory (#22). (`dalek`'s own
/// `SharedSecret` zeroizes on drop, but the plain `[u8; 32]` we copy out did
/// not until this wrapper.)
pub fn ecdh_shared(
    secret: x25519_dalek::EphemeralSecret,
    peer_public: &[u8; 32],
) -> SyncResult<Zeroizing<[u8; 32]>> {
    let peer = x25519_dalek::PublicKey::from(*peer_public);
    let shared = secret.diffie_hellman(&peer);
    if !shared.was_contributory() {
        return Err(CryptoError::NonContributoryEcdh.into());
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

/// HKDF label for the per-peer resumption token. Both sides derive it from the
/// first-pair `SessionSecret` and persist it; reconnects authenticate with the
/// token instead of re-proving the one-time pairing secret.
pub const RESUMPTION_TOKEN_LABEL: &[u8] = b"portty-resumption-token-v1";

/// HMAC-SHA256 proof keyed by arbitrary key material (the first-pair key derived
/// from the one-time pairing secret, or a 32-byte resumption token for
/// reconnect), over `nonce ‖ transcript`.
/// Binding the ephemeral-DH transcript here is channel binding: an active MITM
/// that substitutes its own ephemeral keys makes the proof it relays invalid.
pub fn proof_from_key(key: &[u8], nonce: &Nonce, transcript: &[u8]) -> SyncResult<Proof> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::HmacLength)?;
    mac.update(&nonce.0);
    mac.update(transcript);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(Proof(out))
}

/// Derive a 32-byte session secret from arbitrary key material + nonce + the
/// ephemeral ECDH shared secret.
pub fn derive_session_from_key(
    key: &[u8],
    nonce: &Nonce,
    ecdh: &[u8; 32],
) -> SyncResult<SessionSecret> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&nonce.0);
    ikm.extend_from_slice(ecdh);
    let hk = Hkdf::<Sha256>::new(Some(key), &ikm);
    let mut okm = [0u8; 32];
    let result = hk.expand(HKDF_INFO, &mut okm).map_err(|_| CryptoError::Kdf);
    ikm.zeroize();
    result?;
    Ok(SessionSecret(okm))
}

/// Verify a proof against arbitrary key material. Constant-time compare.
pub fn verify_proof_with_key(
    key: &[u8],
    nonce: &Nonce,
    transcript: &[u8],
    claimed: &Proof,
) -> SyncResult<()> {
    let expected = proof_from_key(key, nonce, transcript)?;
    if expected.0.ct_eq(&claimed.0).into() {
        Ok(())
    } else {
        Err(CryptoError::WrongPin.into())
    }
}

/// Domain-separation label for [`first_pair_key`]. Keyed by the label rather
/// than by the secret so the derived key is a fixed 32 bytes whatever the
/// credential's length, and so raw ticket bytes are never used directly as an
/// HMAC key or an HKDF salt.
const FIRST_PAIR_KEY_LABEL: &[u8] = b"portty-first-pair-key-v1";

/// Derive the FIRST-PAIR key material from the out-of-band [`PairingSecret`]
/// carried in the QR ticket or the manual phrase.
///
/// The secret is the whole credential. There is no PIN, and this function takes
/// no other input, which is the point: a key with a human-sized value folded into
/// it is a key with an offline dictionary behind it, and that is precisely the
/// hole this replaced (see the module threat model).
///
/// Enforcement stays emergent rather than being a wire flag - the host derives
/// from the secret it minted, so a caller that never obtained the ticket derives
/// a different key and its proof simply fails to verify. What is NOT emergent,
/// and must be enforced by the caller, is that a first pair has a secret at all:
/// there is no longer a secretless fallback to degrade into.
///
/// Returned zeroizing so the derived material is wiped once the proof/session
/// derivation has consumed it.
pub fn first_pair_key(secret: &PairingSecret) -> Zeroizing<Vec<u8>> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(FIRST_PAIR_KEY_LABEL)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(secret.as_bytes());
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

/// 32-byte symmetric key with enforced HKDF domain separation. The only way to
/// construct one is via [`derive_subkey`], so the type system prevents feeding
/// the raw `SessionSecret` bytes directly into a downstream cipher.
pub struct DomainSeparatedKey([u8; 32]);

impl DomainSeparatedKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Escape hatch for re-wrapping bytes that were ORIGINALLY produced by
    /// [`derive_subkey`] and persisted. Crate-private.
    #[allow(dead_code)] // used by the deferred iroh/handshake step
    pub(crate) fn from_derived_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Drop for DomainSeparatedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for DomainSeparatedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DomainSeparatedKey(****)")
    }
}

/// Derive a domain-separated 32-byte subkey from the session secret.
pub fn derive_subkey(session: &SessionSecret, label: &[u8]) -> SyncResult<DomainSeparatedKey> {
    let hk = Hkdf::<Sha256>::new(None, &session.0);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm).map_err(|_| CryptoError::Kdf)?;
    Ok(DomainSeparatedKey(okm))
}

/// Derive the per-peer resumption token from a **first-pair** session secret.
/// Both sides run this and persist the 32-byte result; reconnects then
/// authenticate by proving the token instead of re-presenting the pairing secret,
/// so a secret that leaks AFTER pairing is not a permanent credential (SEC-2).
/// The token is high-entropy (folded from the ephemeral ECDH) and one-way under
/// HKDF - leaking it reveals nothing about the pairing secret.
pub fn derive_resumption_token(session: &SessionSecret) -> SyncResult<[u8; 32]> {
    Ok(*derive_subkey(session, RESUMPTION_TOKEN_LABEL)?.expose())
}

/// HKDF label for the human comparison code shown at the end of a first pair.
pub const PAIR_SAS_LABEL: &[u8] = b"portty-pair-sas-v1";

/// Number of digits in the comparison code. Six is the ceiling on what a person
/// will reliably compare across two screens; the code's job is to be checked, not
/// to be a key, and it buys a 1-in-a-million chance for an attacker who has
/// already had to defeat the out-of-band secret to also land a matching display.
pub const PAIR_VERIFICATION_CODE_DIGITS: u32 = 6;

/// Derive the 6-digit comparison code both peers display after a first pair.
///
/// This is a short authentication string, not a secret and never key material.
/// It is derived from the finished session secret, which already mixes the
/// ephemeral X25519 ECDH, so two peers only ever show the same digits if they
/// completed the SAME exchange. A peer in the middle - who by definition runs two
/// distinct exchanges - cannot make both ends agree, which is what turns this
/// from decoration into a real check.
///
/// The digits are read from the derived subkey as a big-endian u64 reduced mod
/// 10^6. The modulo bias is negligible (2^64 is ~1.8e13 times 10^6, so the
/// residual skew is on the order of 1e-13) and, unlike a rejection sample, this
/// is deterministic - both sides must arrive at the same code from the same
/// session with no shared retry state.
pub fn pair_verification_code(session: &SessionSecret) -> SyncResult<String> {
    let key = derive_subkey(session, PAIR_SAS_LABEL)?;
    let mut head = [0u8; 8];
    head.copy_from_slice(&key.expose()[..8]);
    let modulus = 10u64.pow(PAIR_VERIFICATION_CODE_DIGITS);
    let value = u64::from_be_bytes(head) % modulus;
    Ok(format!(
        "{value:0width$}",
        width = PAIR_VERIFICATION_CODE_DIGITS as usize
    ))
}

// ── Rate limiter for failed pairings ──────────────────────────────────

/// Exponential-backoff rate limiter. base 1s, doubles each failure, capped 10 min.
/// 10 consecutive failures → ~10 min lockout, so one source gets roughly 6
/// attempts an hour once it is in the penalty box.
///
/// This is the per-SOURCE half of the defence and it is not the load-bearing one:
/// an attacker who mints a fresh iroh NodeId per guess gets a fresh empty bucket
/// every time. [`GLOBAL_FIRST_PAIR_CAP`] is what stops that. What this limiter is
/// good at is the honest case - a device retrying a mistyped phrase - which it
/// slows without ever consuming the window's global budget faster than one source
/// deserves.
#[derive(Debug, Default, Clone)]
pub struct PairingRateLimiter {
    failures: u32,
    last_attempt: Option<std::time::Instant>,
}

impl PairingRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self) -> SyncResult<()> {
        let Some(last) = self.last_attempt else {
            return Ok(());
        };
        let wait = self.current_wait();
        if last.elapsed() < wait {
            Err(CryptoError::RateLimited.into())
        } else {
            Ok(())
        }
    }

    /// Atomically check the limit AND reserve a slot by recording a provisional
    /// failure. Closes the concurrent-handshake bypass.
    pub fn check_and_reserve(&mut self) -> SyncResult<()> {
        self.check()?;
        self.failures = self.failures.saturating_add(1);
        self.last_attempt = Some(std::time::Instant::now());
        Ok(())
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.last_attempt = None;
    }

    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.last_attempt = Some(std::time::Instant::now());
    }

    fn current_wait(&self) -> std::time::Duration {
        if self.failures == 0 {
            return std::time::Duration::ZERO;
        }
        let exp = (self.failures - 1).min(10);
        std::time::Duration::from_secs(1u64 << exp).min(std::time::Duration::from_secs(600))
    }

    fn is_cold(&self) -> bool {
        match self.last_attempt {
            None => true,
            Some(t) => t.elapsed() > std::time::Duration::from_secs(1200),
        }
    }
}

/// Per-source pairing rate limiter. Backoff tracked per key so one abusive
/// source can't deny pairing to every other peer. Cold entries are GC'd.
#[derive(Debug, Default)]
pub struct KeyedPairingRateLimiter {
    per_key: std::collections::HashMap<String, PairingRateLimiter>,
}

impl KeyedPairingRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_reserve(&mut self, key: &str) -> SyncResult<()> {
        self.gc_cold();
        self.per_key
            .entry(key.to_string())
            .or_default()
            .check_and_reserve()
    }

    pub fn record_success(&mut self, key: &str) {
        self.per_key.remove(key);
    }

    pub fn tracked_keys(&self) -> usize {
        self.per_key.len()
    }

    fn gc_cold(&mut self) {
        self.per_key.retain(|_, rl| !rl.is_cold());
    }
}

// ── First-pair enrollment window (brute-force hardening) ──────────────

/// How long a first-pair enrollment window stays open after the host starts
/// serving (the explicit pairing action - you run `portty-host serve` when you
/// want to pair). Long enough to scan the QR or type the six-word phrase on the
/// phone and compare the code, short enough that the first-pair attack surface is
/// a few minutes rather than "whenever the host is running".
pub const ENROLLMENT_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

/// Global cap on FIRST-PAIR attempts within a single open window, across ALL
/// sources. The per-source [`KeyedPairingRateLimiter`] is defeated by an attacker
/// who mints a fresh iroh NodeId per guess (each gets an always-empty per-key
/// bucket); this counter is keyed on nothing, so fresh-NodeId spraying trips a
/// hard lockout regardless. Scoped to the open window so it can never deny
/// pairing permanently - reopening it (`portty pair`) resets the count.
///
/// **Why this is 1024 and no longer 10.** The cap used to be the last line
/// against guessing a 6-digit PIN: at 10^6 possibilities, every extra attempt per
/// window measurably helped the attacker, so the cap had to be tight. The PIN is
/// gone (v8). The first-pair credential is now the one-time pairing secret -
/// 48 bits typed as a six-word phrase, 128 bits when scanned or pasted - so the
/// arithmetic changed completely:
///
/// | attempts/window | chance against a 48-bit secret |
/// |-----------------|--------------------------------|
/// | 10              | 1 in 2.8e13                    |
/// | 1024            | 1 in 2.7e11                    |
///
/// Both are far past unreachable, and the attacker gets one window before the
/// user notices nothing paired. A hundredfold looser cap buys them nothing.
///
/// **What it does buy: the DoS gets 100x more expensive.** Because the cap is
/// source-independent, anyone who can reach the host during an open window can
/// burn it with junk and deny that window's legitimate pairing. At 10 that was
/// ten packets - cheaper than the pairing it denied. At 1024 the attacker needs
/// 1024 completed QUIC handshakes inside a 300-second window, each with a fresh
/// NodeId (a repeated one hits the per-key exponential backoff), while the user
/// simply re-runs `portty pair`.
///
/// The denial is therefore bounded but NOT eliminated, and that is the accepted
/// residual (#23): it bites only inside a window the user explicitly opened,
/// requires reaching the iroh endpoint, and self-heals on reopen. Removing the
/// global cap altogether would reopen the fresh-NodeId hole above, which is the
/// worse failure.
pub const GLOBAL_FIRST_PAIR_CAP: u32 = 1024;

/// Outcome of gating a first-pair attempt against the enrollment window.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstPairGate {
    /// Proceed - the window is open and under the global cap. `epoch` identifies
    /// the enrollment opportunity and must be re-checked when the proof arrives.
    Allow { epoch: u64 },
    /// The window is not open (no active pairing). Reject before the proof check.
    Closed,
    /// The window is open but the global failure cap tripped. Reject.
    Locked,
}

/// First-pair enrollment window + source-independent global failure counter.
/// One per host, shared across every accepted connection (like
/// [`KeyedPairingRateLimiter`]).
///
/// Rationale: the per-source rate limiter keys backoff on the caller's iroh
/// NodeId, which an attacker regenerates per guess for an always-empty bucket -
/// so a sticky 6-digit PIN was brute-forceable *whenever the host was running*.
/// Gating first-pair on an explicit, time-boxed window plus a source-independent
/// global cap closes that: outside the window first-pair is refused entirely,
/// and inside it fresh-NodeId spraying trips the global lock. Known peers
/// reconnect via resumption token and are NEVER gated by this.
#[derive(Debug, Default)]
pub struct EnrollmentWindow {
    open_until: Option<std::time::Instant>,
    global_failures: u32,
    /// Monotonic id of the CURRENT enrollment opportunity. Bumped every time the
    /// window opens or closes, so a first-pair attempt that was gated under one
    /// opportunity can be told apart from one gated under the next.
    ///
    /// Closing on first success is not enough on its own: the gate runs when a
    /// challenge is ISSUED, and several clients can be issued challenges before
    /// any of them proves anything. Whoever proved second would then still be
    /// enrolled against a window that had already been consumed. Carrying the
    /// epoch from challenge to proof, and checking it there, makes "one-time"
    /// actually mean one device.
    epoch: u64,
}

impl EnrollmentWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open (or extend) the window for `dur` and clear the global failure
    /// counter. Called when the host starts serving (the explicit pairing
    /// action).
    pub fn open(&mut self, dur: std::time::Duration) {
        self.open_until = Some(std::time::Instant::now() + dur);
        self.global_failures = 0;
        // A reopen is a NEW opportunity: challenges issued under the previous one
        // must not be provable against this one.
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Close the window and clear the counter.
    ///
    /// Private on purpose: exposing "close" next to a separate "is this epoch
    /// current?" is what let a caller rebuild the check-then-act race this type
    /// exists to prevent. Claiming goes through [`Self::consume_first_pair`], which
    /// does both under one lock. Reachable from this module's tests only.
    fn close(&mut self) {
        self.open_until = None;
        self.global_failures = 0;
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// The current enrollment opportunity's id. `None` when the window is shut,
    /// so a caller cannot capture an epoch there is no opportunity for.
    fn epoch(&self) -> Option<u64> {
        self.is_open().then_some(self.epoch)
    }

    /// Is `epoch` still the live enrollment opportunity?
    ///
    /// Private: a public "is it still current?" invites a caller to act on the
    /// answer in a second lock acquisition. See [`Self::consume_first_pair`].
    fn epoch_is_current(&self, epoch: u64) -> bool {
        self.is_open() && self.epoch == epoch
    }

    /// Whether the window is currently open (and not expired).
    pub fn is_open(&self) -> bool {
        match self.open_until {
            Some(deadline) => std::time::Instant::now() < deadline,
            None => false,
        }
    }

    /// Gate a first-pair attempt AND, if allowed, reserve the slot by counting
    /// it - mirroring [`PairingRateLimiter::check_and_reserve`], so
    /// concurrently-opened connections can't all pass a read-only check before
    /// any records a failure. A successful proof MUST call [`Self::record_success`];
    /// an abandoned attempt or a wrong secret leaves the reservation as the
    /// failure count (so callers must NOT double-count on the failure path).
    pub(crate) fn check_and_reserve_first_pair(&mut self) -> FirstPairGate {
        if !self.is_open() {
            return FirstPairGate::Closed;
        }
        if self.global_failures >= GLOBAL_FIRST_PAIR_CAP {
            return FirstPairGate::Locked;
        }
        self.global_failures = self.global_failures.saturating_add(1);
        // Hand back the opportunity this reservation belongs to; the proof step
        // must present it again.
        FirstPairGate::Allow { epoch: self.epoch }
    }

    /// CLAIM the enrollment opportunity `epoch`, all under one lock.
    ///
    /// Returns true for exactly ONE caller per opportunity. False means the epoch
    /// is no longer live - the window expired, `portty pair` reopened it, or
    /// another client already claimed it.
    ///
    /// Check-and-claim must be a single operation. Reading `epoch_is_current` and
    /// then closing in a separate lock acquisition let two connections both see a
    /// live epoch, both verify their proofs, and both enrol - the same
    /// check-then-act race the challenge-issue gate already avoids, one step
    /// further along. There is deliberately no way to test the epoch without
    /// consuming it.
    ///
    /// The pairing secret is single-use: anyone who photographed the QR or read
    /// the phrase over your shoulder must not be able to enrol a second device
    /// after your phone paired. Pairing another device is a deliberate new
    /// `portty pair`, which mints fresh material.
    ///
    /// Reconnects are unaffected - they authenticate by resumption token and never
    /// consult the window.
    pub(crate) fn consume_first_pair(&mut self, epoch: u64) -> bool {
        if !self.is_open() || self.epoch != epoch {
            return false;
        }
        self.close();
        true
    }

    /// Current global failure count (diagnostics / tests).
    pub fn failure_count(&self) -> u32 {
        self.global_failures
    }
}

/// Credentials AND the enrollment window behind ONE lock.
///
/// These were two independent mutexes, which is what made the reopen race
/// possible: a connection snapshotted the credentials at setup, `portty pair`
/// replaced them and reopened the window, and the connection then captured the
/// NEW epoch while holding the OLD secrets - so retired material enrolled
/// against a fresh opportunity. One lock means a snapshot always carries the
/// generation its credentials belong to, and [`Self::rotate`] replaces both in a
/// single step that nothing can interleave with.
pub struct PairingState {
    secrets: Vec<PairingSecret>,
    window: EnrollmentWindow,
}

/// What one connection attempt captured: the credentials it will verify against
/// and the enrollment generation they belong to.
#[derive(Clone)]
pub struct PairingSnapshot {
    pub secrets: Vec<PairingSecret>,
    /// `None` when pairing was closed at snapshot time.
    pub epoch: Option<u64>,
}

impl PairingState {
    /// Fresh state with pairing CLOSED. Call [`Self::open`] to start an
    /// enrollment opportunity.
    pub fn new(secrets: impl IntoIterator<Item = PairingSecret>) -> Self {
        Self {
            secrets: secrets.into_iter().collect(),
            window: EnrollmentWindow::new(),
        }
    }

    /// Open an enrollment opportunity for `dur` with the current credentials.
    pub fn open(&mut self, dur: std::time::Duration) {
        self.window.open(dur);
    }

    /// Replace the credentials AND open a fresh opportunity, atomically.
    ///
    /// This is what `portty pair` performs. Doing it as two steps left a gap in
    /// which a connection could pick up one generation's secret and the other's
    /// epoch.
    pub fn rotate(
        &mut self,
        secrets: impl IntoIterator<Item = PairingSecret>,
        dur: std::time::Duration,
    ) {
        self.secrets = secrets.into_iter().collect();
        self.window.open(dur);
    }

    /// Capture the credentials for one connection attempt together with the
    /// generation they belong to.
    pub fn snapshot(&self) -> PairingSnapshot {
        PairingSnapshot {
            secrets: self.secrets.clone(),
            epoch: self.window.epoch(),
        }
    }

    /// Gate a first-pair attempt, bound to the generation the caller snapshotted.
    ///
    /// A snapshot from a previous generation is refused: its QR/PIN has been
    /// retired by a `portty pair` since, and must not enrol against the new
    /// opportunity.
    pub fn gate_first_pair(&mut self, snapshot_epoch: Option<u64>) -> FirstPairGate {
        match snapshot_epoch {
            Some(epoch) if self.window.epoch_is_current(epoch) => {
                self.window.check_and_reserve_first_pair()
            }
            // No opportunity when the credentials were read, or a different one
            // now - either way these credentials cannot enrol.
            _ => FirstPairGate::Closed,
        }
    }

    /// See [`EnrollmentWindow::consume_first_pair`].
    pub fn consume_first_pair(&mut self, epoch: u64) -> bool {
        self.window.consume_first_pair(epoch)
    }

    /// Whether an enrollment opportunity is open (diagnostics / tests).
    pub fn is_open(&self) -> bool {
        self.window.is_open()
    }
}

/// Host-shared pairing state handle. See [`PairingState`].
pub type SharedPairingState = std::sync::Arc<std::sync::Mutex<PairingState>>;

/// Host-shared enrollment window handle. See [`EnrollmentWindow`].
pub type SharedEnrollmentWindow = std::sync::Arc<std::sync::Mutex<EnrollmentWindow>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_agrees_on_both_sides() {
        let (a_secret, a_pub) = generate_ephemeral();
        let (b_secret, b_pub) = generate_ephemeral();
        let a = ecdh_shared(a_secret, &b_pub).unwrap();
        let b = ecdh_shared(b_secret, &a_pub).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, [0u8; 32]);
    }

    #[test]
    fn ecdh_rejects_low_order_point() {
        let (secret, _pub) = generate_ephemeral();
        let res = ecdh_shared(secret, &[0u8; 32]);
        assert!(matches!(
            res,
            Err(crate::error::SyncError::Crypto(
                CryptoError::NonContributoryEcdh
            ))
        ));
    }

    fn ticket() -> PairingSecret {
        PairingSecret::from_ticket_bytes([0x5c; TICKET_PAIRING_SECRET_BYTES])
    }

    #[test]
    fn verify_accepts_correct_proof() {
        let key = first_pair_key(&ticket());
        let nonce = Nonce::generate();
        let proof = proof_from_key(&key, &nonce, b"").unwrap();
        verify_proof_with_key(&key, &nonce, b"", &proof).unwrap();
    }

    #[test]
    fn verify_rejects_a_proof_from_a_different_secret() {
        let nonce = Nonce::generate();
        let proof = proof_from_key(&first_pair_key(&ticket()), &nonce, b"").unwrap();
        let other = first_pair_key(&PairingSecret::from_ticket_bytes([0x11; 16]));
        assert!(verify_proof_with_key(&other, &nonce, b"", &proof).is_err());
    }

    #[test]
    fn session_keys_agree_and_differ_from_proof() {
        let key = first_pair_key(&ticket());
        let nonce = Nonce::generate();
        let sk1 = derive_session_from_key(&key, &nonce, &[0u8; 32]).unwrap();
        let sk2 = derive_session_from_key(&key, &nonce, &[0u8; 32]).unwrap();
        let proof = proof_from_key(&key, &nonce, b"").unwrap();
        assert_eq!(sk1.0, sk2.0);
        assert_ne!(sk1.0, proof.0);
    }

    #[test]
    fn subkeys_differ_by_label() {
        let nonce = Nonce::generate();
        let sk = derive_session_from_key(&first_pair_key(&ticket()), &nonce, &[0u8; 32]).unwrap();
        let a = derive_subkey(&sk, b"a").unwrap();
        let b = derive_subkey(&sk, b"b").unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    // ── Comparison code (SAS) ─────────────────────────────────────────

    #[test]
    fn verification_code_is_six_digits_and_deterministic() {
        let sk = SessionSecret([0x3b; 32]);
        let code = pair_verification_code(&sk).unwrap();
        assert_eq!(code.len(), PAIR_VERIFICATION_CODE_DIGITS as usize);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            code,
            pair_verification_code(&SessionSecret([0x3b; 32])).unwrap(),
            "both peers must derive the same code from the same session"
        );
    }

    /// The property the whole confirmation step rests on: different sessions show
    /// different codes. A peer in the middle runs two distinct exchanges, so it
    /// cannot make both ends display the same digits.
    #[test]
    fn verification_code_differs_across_sessions() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..256u16 {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&i.to_be_bytes());
            seen.insert(pair_verification_code(&SessionSecret(bytes)).unwrap());
        }
        // 256 distinct sessions into a 10^6 space: collisions are possible but
        // vanishingly unlikely, and total collapse would mean the code ignores
        // the session entirely.
        assert!(
            seen.len() > 250,
            "codes must track the session, got {} distinct",
            seen.len()
        );
    }

    /// A leading-zero code must keep all six digits, or two peers rendering
    /// "012345" and "12345" would read as a mismatch to the human comparing them.
    #[test]
    fn verification_code_keeps_leading_zeros() {
        for i in 0..2_000u32 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            let code = pair_verification_code(&SessionSecret(bytes)).unwrap();
            assert_eq!(code.len(), PAIR_VERIFICATION_CODE_DIGITS as usize, "{code}");
        }
    }

    /// The code must not be the session secret, the resumption token, or anything
    /// else derived beside it - it is displayed in the clear.
    #[test]
    fn verification_code_is_domain_separated_from_key_material() {
        let sk = SessionSecret([0x77; 32]);
        let sas = derive_subkey(&sk, PAIR_SAS_LABEL).unwrap();
        assert_ne!(sas.expose(), &sk.0);
        assert_ne!(sas.expose(), &derive_resumption_token(&sk).unwrap());
    }

    #[test]
    fn rate_limiter_blocks_after_failure() {
        let mut rl = PairingRateLimiter::new();
        rl.check().unwrap();
        rl.record_failure();
        assert!(rl.check().is_err());
    }

    #[test]
    fn pairing_secret_b64_round_trips() {
        let ticket = PairingSecret::from_ticket_bytes([0x2b; TICKET_PAIRING_SECRET_BYTES]);
        let ticket_back = PairingSecret::from_b64(&ticket.to_b64()).unwrap();
        assert_eq!(ticket.as_bytes(), ticket_back.as_bytes());
        let manual = PairingSecret::from_bytes([0x3c; MANUAL_PAIRING_SECRET_BYTES]);
        let manual_back = PairingSecret::from_b64(&manual.to_b64()).unwrap();
        assert_eq!(manual.as_bytes(), manual_back.as_bytes());
        // Garbage / wrong length → None. There is no weaker path to fall back to,
        // so the caller must treat this as "cannot pair".
        assert!(PairingSecret::from_b64("not base64!!").is_none());
        assert!(PairingSecret::from_b64("YWJj").is_none()); // decodes to 3 bytes
    }

    /// A pre-v8 32-bit secret must not decode. It is below the entropy floor the
    /// PIN-free scheme depends on, so accepting it would silently reintroduce an
    /// offline-attackable credential.
    #[test]
    fn pairing_secret_b64_rejects_the_retired_32_bit_secret() {
        use base64::Engine;
        let legacy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xAAu8; 4]);
        assert!(PairingSecret::from_b64(&legacy).is_none());
    }

    #[test]
    fn pairing_secret_phrase_round_trips() {
        let s = PairingSecret::from_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let phrase = s.to_phrase().unwrap();
        assert_eq!(
            phrase.split('-').count(),
            MANUAL_PAIRING_SECRET_BYTES,
            "the manual phrase carries one word per secret byte"
        );
        let back = PairingSecret::from_phrase(&phrase).unwrap();
        assert_eq!(s.as_bytes(), back.as_bytes());
        // Tolerant of whitespace separators and mixed case.
        let spaced = phrase.replace('-', " ").to_uppercase();
        let back2 = PairingSecret::from_phrase(&spaced).unwrap();
        assert_eq!(s.as_bytes(), back2.as_bytes());
        assert!(PairingSecret::generate_ticket().to_phrase().is_none());
    }

    /// Every byte position must round-trip, including the two added at v8 - an
    /// off-by-one in the even/odd table choice would silently truncate entropy.
    #[test]
    fn pairing_secret_phrase_round_trips_every_generated_value() {
        for _ in 0..1_000 {
            let s = PairingSecret::generate_manual();
            let back = PairingSecret::from_phrase(&s.to_phrase().unwrap()).unwrap();
            assert_eq!(s.as_bytes(), back.as_bytes());
        }
    }

    #[test]
    fn pairing_secret_phrase_rejects_garbage() {
        assert!(PairingSecret::from_phrase("not-a-real-phrase-at-all").is_none());
        assert!(PairingSecret::from_phrase("only-two").is_none());
        // A four-word pre-v8 phrase is the right shape but the wrong length.
        let six = PairingSecret::from_bytes([1, 2, 3, 4, 5, 6])
            .to_phrase()
            .unwrap();
        let four: Vec<&str> = six.split('-').take(4).collect();
        assert!(PairingSecret::from_phrase(&four.join("-")).is_none());
    }

    #[test]
    fn first_pair_key_is_determined_by_the_secret_alone() {
        let sec = PairingSecret::from_bytes([9u8; MANUAL_PAIRING_SECRET_BYTES]);
        let key = first_pair_key(&sec);
        // Deterministic - both sides derive the same key from the same secret.
        assert_eq!(key.as_slice(), first_pair_key(&sec).as_slice());
        // A different secret gives a different key.
        let other = first_pair_key(&PairingSecret::from_bytes(
            [1u8; MANUAL_PAIRING_SECRET_BYTES],
        ));
        assert_ne!(key.as_slice(), other.as_slice());
        // Domain-separated: never the raw secret bytes on the wire-facing key.
        assert_ne!(key.as_slice(), sec.as_bytes());
        assert_eq!(
            key.len(),
            32,
            "HMAC-SHA256 output, whatever the input length"
        );
    }

    /// A ticket secret and a manual secret that happen to share a prefix must not
    /// derive the same key. HMAC over the raw bytes makes this hold; a naive
    /// concatenation-based construction would not.
    #[test]
    fn first_pair_key_separates_ticket_and_manual_credentials() {
        let manual = PairingSecret::from_bytes([0u8; MANUAL_PAIRING_SECRET_BYTES]);
        let ticket = PairingSecret::from_ticket_bytes([0u8; TICKET_PAIRING_SECRET_BYTES]);
        assert_ne!(
            first_pair_key(&manual).as_slice(),
            first_pair_key(&ticket).as_slice()
        );
    }

    #[test]
    fn enrollment_window_rejects_first_pair_when_closed() {
        // The headline property: outside an active pairing window, a first-pair
        // attempt is refused BEFORE the PIN is ever checked.
        let mut win = EnrollmentWindow::new();
        assert!(!win.is_open());
        assert_eq!(win.check_and_reserve_first_pair(), FirstPairGate::Closed);
    }

    #[test]
    fn enrollment_window_allows_first_pair_when_open() {
        let mut win = EnrollmentWindow::new();
        win.open(std::time::Duration::from_secs(60));
        assert!(win.is_open());
        assert!(matches!(
            win.check_and_reserve_first_pair(),
            FirstPairGate::Allow { .. }
        ));
    }

    #[test]
    fn enrollment_window_global_cap_trips_regardless_of_source() {
        // Fresh-NodeId spraying defeats the per-KEY limiter (empty bucket per
        // guess). The global counter is keyed on nothing, so GLOBAL_FIRST_PAIR_CAP
        // consecutive first-pair attempts trip a hard lockout inside the window.
        let mut win = EnrollmentWindow::new();
        win.open(std::time::Duration::from_secs(60));
        for _ in 0..GLOBAL_FIRST_PAIR_CAP {
            assert!(matches!(
                win.check_and_reserve_first_pair(),
                FirstPairGate::Allow { .. }
            ));
        }
        assert_eq!(win.check_and_reserve_first_pair(), FirstPairGate::Locked);
    }

    #[test]
    fn enrollment_window_success_clears_counter() {
        let mut win = EnrollmentWindow::new();
        win.open(std::time::Duration::from_secs(60));
        let _ = win.check_and_reserve_first_pair();
        let _ = win.check_and_reserve_first_pair();
        assert_eq!(win.failure_count(), 2);
        let FirstPairGate::Allow { epoch } = win.check_and_reserve_first_pair() else {
            panic!("still under the cap");
        };
        assert!(win.consume_first_pair(epoch));
        assert_eq!(win.failure_count(), 0);
    }

    /// The race the epoch closes: TWO clients holding the same QR/PIN can both be
    /// issued a challenge before either proves anything. Closing the window on the
    /// first success is not enough on its own - the second client already passed
    /// the challenge-issue gate, so its proof has to be rejected at proof time.
    #[test]
    fn a_challenge_issued_before_someone_else_paired_can_no_longer_enrol() {
        let mut win = EnrollmentWindow::new();
        win.open(std::time::Duration::from_secs(60));

        // Both clients get challenges under the SAME opportunity.
        let FirstPairGate::Allow { epoch: first } = win.check_and_reserve_first_pair() else {
            panic!("first client must be allowed to try");
        };
        let FirstPairGate::Allow { epoch: second } = win.check_and_reserve_first_pair() else {
            panic!("second client must also be allowed to try");
        };
        assert_eq!(first, second, "both were gated under one opportunity");
        assert!(win.epoch_is_current(first));

        // The first one proves and CLAIMS the opportunity.
        assert!(win.consume_first_pair(first));

        // The second one's claim fails, even though its challenge was legitimately
        // issued and the clock has not run out. Check-and-claim is one operation,
        // so this holds however the two interleave.
        assert!(!win.consume_first_pair(second));
        assert!(!win.is_open());
    }

    /// A reopen is a NEW opportunity, so a challenge held over from the previous
    /// one cannot be redeemed against it.
    #[test]
    fn a_challenge_does_not_carry_over_into_the_next_pairing_window() {
        let mut win = EnrollmentWindow::new();
        win.open(std::time::Duration::from_secs(60));
        let FirstPairGate::Allow { epoch: stale } = win.check_and_reserve_first_pair() else {
            panic!("allowed");
        };

        assert!(win.consume_first_pair(stale)); // claims and closes
        win.open(std::time::Duration::from_secs(60)); // `portty pair` again

        assert!(win.is_open());
        assert!(
            !win.consume_first_pair(stale),
            "a challenge from the previous window must not enrol in this one"
        );
        let FirstPairGate::Allow { epoch: fresh } = win.check_and_reserve_first_pair() else {
            panic!("a fresh attempt is allowed");
        };
        assert!(win.epoch_is_current(fresh));
        assert_ne!(stale, fresh);
    }

    /// No open window means no opportunity to capture.
    #[test]
    fn a_closed_window_has_no_epoch() {
        let mut win = EnrollmentWindow::new();
        assert_eq!(win.epoch(), None);
        win.open(std::time::Duration::from_secs(60));
        assert!(win.epoch().is_some());
        win.close();
        assert_eq!(win.epoch(), None);
        assert!(!win.consume_first_pair(0), "a closed window claims nothing");
    }

    /// Enrollment material is ONE-TIME. A shoulder-surfed PIN or a photographed
    /// QR must not enrol a second device just because the legitimate phone
    /// already paired inside the same five-minute window.
    #[test]
    fn enrollment_window_closes_after_the_first_successful_pair() {
        let mut win = EnrollmentWindow::new();
        win.open(std::time::Duration::from_secs(60));
        let FirstPairGate::Allow { epoch } = win.check_and_reserve_first_pair() else {
            panic!("an open window allows a first attempt");
        };

        assert!(win.consume_first_pair(epoch));

        assert!(!win.is_open(), "the window must not outlive its first pair");
        assert_eq!(win.check_and_reserve_first_pair(), FirstPairGate::Closed);
        // Pairing another device is a deliberate `portty pair`, which reopens.
        win.open(std::time::Duration::from_secs(60));
        assert!(matches!(
            win.check_and_reserve_first_pair(),
            FirstPairGate::Allow { .. }
        ));
    }

    #[test]
    fn enrollment_window_reopen_resets_lockout() {
        // Re-opening (a fresh `portty-host serve`) must clear a tripped global
        // lock, so the cap can never deny pairing permanently.
        let mut win = EnrollmentWindow::new();
        win.open(std::time::Duration::from_secs(60));
        for _ in 0..GLOBAL_FIRST_PAIR_CAP {
            let _ = win.check_and_reserve_first_pair();
        }
        assert_eq!(win.check_and_reserve_first_pair(), FirstPairGate::Locked);
        win.open(std::time::Duration::from_secs(60));
        assert!(matches!(
            win.check_and_reserve_first_pair(),
            FirstPairGate::Allow { .. }
        ));
    }
}
