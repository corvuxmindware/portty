//! Phone-side push wake plumbing.
//!
//! Two jobs:
//!
//! 1. **Seal/open the wake blob.** The blob rides push notifications so the
//!    phone can learn WHICH paired host rang without the relay or APNs/FCM
//!    learning anything: it is XChaCha20-Poly1305 ciphertext over the host's
//!    device id, keyed by a random 32-byte key that never leaves this phone.
//!    The host and relay store/forward it opaquely.
//!
//! 2. **Bridge files to the native layer.** Remote-notification callbacks are
//!    platform code (Swift/Kotlin), which cannot call Tauri commands. The
//!    native layer writes two small files under `<bridge dir>/push/` instead:
//!      - `native_token.json` - `{"provider":"apns"|"fcm","token":"…"}`,
//!        written on (re)registration with APNs/FCM.
//!      - `wake_blob.txt` - newline-separated hex `wake` payloads of recent
//!        tapped/received push notifications, newest first. A list rather than
//!        one value because the Android tap path is an exported activity anyone
//!        can post to; see [`consume_wake_blobs`].
//!
//!    Rust polls both at well-defined moments (connect, app resume). Several
//!    candidate directories are scanned because Tauri's data-dir mapping
//!    differs per platform - see `bridge_dirs`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::rngs::SysRng;
use rand::TryRng;
use std::path::PathBuf;
use zeroize::Zeroize;

use portty_transport::DeviceId;

/// AAD binding the blob to its one purpose (never reuse the key for more).
const WAKE_AAD: &[u8] = b"portty-wake-blob-v1";
const WAKE_KEY_FILE: &str = "wake_key.bin";
pub const BRIDGE_SUBDIR: &str = "push";
pub const TOKEN_FILE: &str = "native_token.json";
pub const WAKE_FILE: &str = "wake_blob.txt";

/// Load (or create once) the phone-local wake key. Lives in the app data dir
/// next to the identity; 0600 on unix.
///
/// On iOS the credentials live in the Keychain, so on a fresh install NOTHING
/// has created the app-data dir yet - create it here instead of assuming it
/// (assuming it crashed the app at launch: ENOENT → setup error → panic).
pub fn load_or_create_wake_key(data_dir: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let path = data_dir.join(WAKE_KEY_FILE);
    if let Ok(mut bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            bytes.zeroize();
            // Re-assert protection on an existing key: an install created before
            // this ran, or one restored from an old backup, would otherwise keep
            // whatever mode and backup flag it was written with.
            protect_wake_file(&path);
            return Ok(key);
        }
        bytes.zeroize();
    }
    let mut key = [0u8; 32];
    // This key is the capability that turns an opaque blob back into "which
    // laptop rang", so a failed entropy draw must not write a weak one.
    SysRng.try_fill_bytes(&mut key).map_err(|_| {
        std::io::Error::other("the operating system random number generator failed")
    })?;
    std::fs::create_dir_all(data_dir)?;
    // Owner-only from CREATION, and excluded from iCloud/iTunes backup and
    // device-to-device transfer. The wake key is what turns an opaque push blob
    // back into "which of your laptops rang"; a copy of it in a backup is a copy
    // of that capability, and it is phone-local by design - a restored one on
    // another device is useless anyway. Mirrors how the identity and peer store
    // are stored (portty_transport::secure).
    portty_transport::secure::write_owner_only(&path, &key)?;
    protect_wake_file(&path);
    Ok(key)
}

/// Best-effort owner-only + no-backup marking for a phone-local secret file.
///
/// Best-effort on purpose: push is a convenience, and a phone whose filesystem
/// refuses one of these must still start and still pair. The failure is logged so
/// it is not silent.
fn protect_wake_file(path: &std::path::Path) {
    if let Err(error) = portty_transport::secure::restrict_to_current_user(path) {
        tracing::warn!(%error, "could not restrict permissions on the wake key");
    }
    if let Err(error) = portty_transport::secure::exclude_from_backup(path) {
        tracing::warn!(%error, "could not exclude the wake key from device backups");
    }
}

/// Seal a host device id into an opaque wake blob: `nonce || ciphertext`.
pub fn seal_wake_blob(key: &[u8; 32], host: &DeviceId) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    // A repeated nonce under this key would break the AEAD, so refuse to seal
    // rather than emit a blob with a partly-filled nonce.
    SysRng.try_fill_bytes(&mut nonce).ok()?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &host.0,
                aad: WAKE_AAD,
            },
        )
        .ok()?;
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Some(blob)
}

/// Open a wake blob back into the host device id. `None` on any mismatch -
/// including a blob sealed by a different phone/key (treat as "just open the
/// app normally").
pub fn open_wake_blob(key: &[u8; 32], blob: &[u8]) -> Option<DeviceId> {
    if blob.len() < 24 {
        return None;
    }
    let (nonce, ciphertext) = blob.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let plain = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad: WAKE_AAD,
            },
        )
        .ok()?;
    let bytes: [u8; 16] = plain.as_slice().try_into().ok()?;
    Some(DeviceId(bytes))
}

/// Directories the native layer might have used for the bridge files, most
/// likely first. Tauri's `app_data_dir` maps to Application Support on iOS and
/// the internal files dir on Android, but the exact mapping is a Tauri
/// implementation detail - scanning the small candidate set makes the pickup
/// robust to it. All candidates are inside the app sandbox.
pub fn bridge_dirs(app: &tauri::AppHandle) -> Vec<PathBuf> {
    use tauri::Manager;
    let mut dirs = Vec::new();
    let resolver = app.path();
    for dir in [
        resolver.app_data_dir().ok(),
        resolver.app_local_data_dir().ok(),
        resolver.app_config_dir().ok(),
    ]
    .into_iter()
    .flatten()
    {
        let candidate = dir.join(BRIDGE_SUBDIR);
        if !dirs.contains(&candidate) {
            dirs.push(candidate);
        }
    }
    dirs
}

/// Create the push bridge directory and mark it owner-only and no-backup BEFORE
/// the platform push callbacks can write into it. Called once at setup.
///
/// The bridge files are written by Swift/Kotlin, which cannot call into Rust, so
/// Rust used to protect them on its next READ - which is whenever the app happens
/// to reconnect. On a phone that backs up nightly, "eventually" is not a bound: a
/// device push token and the sealed wake blob could sit in an iCloud backup for a
/// day before anything marked them. Marking the DIRECTORY up front closes the gap,
/// because the exclusion covers files created inside it afterwards.
///
/// The per-file marking on read is deliberately kept as well: it repairs an
/// install that predates this, and a directory restored from an old backup.
///
/// Entirely best-effort. Push is a convenience; a phone whose filesystem refuses
/// any of this must still start and still pair.
pub fn prepare_bridge_dirs(app: &tauri::AppHandle) {
    for (index, dir) in bridge_dirs(app).into_iter().enumerate() {
        // Candidate 0 is where both platforms actually write, so create it. The
        // others are only touched if some earlier build already used them - no
        // point minting empty directories to guard against a mapping we are not on.
        if index > 0 && !dir.is_dir() {
            continue;
        }
        if let Err(error) = portty_transport::secure::prepare_secret_dir(&dir) {
            tracing::warn!(%error, "could not prepare the push bridge directory");
            continue;
        }
        if let Err(error) = portty_transport::secure::exclude_dir_from_backup(&dir) {
            tracing::warn!(%error, "could not exclude the push bridge directory from backups");
        }
    }
}

#[derive(serde::Deserialize)]
pub struct NativeToken {
    pub provider: String,
    pub token: String,
}

/// The push token the native layer registered, if any.
pub fn read_native_token(app: &tauri::AppHandle) -> Option<NativeToken> {
    for dir in bridge_dirs(app) {
        let path = dir.join(TOKEN_FILE);
        if let Ok(mut bytes) = std::fs::read(&path) {
            // The native layer writes these files, so this is the first chance
            // Rust gets to protect them. The APNs/FCM token identifies this
            // device to the push provider, and the wake blob is ciphertext whose
            // key lives here too - neither belongs in a device backup.
            protect_wake_file(&path);
            let parsed = serde_json::from_slice::<NativeToken>(&bytes)
                .ok()
                .filter(|token| !token.token.is_empty());
            bytes.zeroize();
            if parsed.is_some() {
                return parsed;
            }
        }
    }
    None
}

/// How many wake-blob candidates one bridge file may offer.
///
/// See [`consume_wake_blobs`] for why there is a list at all. Small on purpose:
/// this is a doorbell, and the only blob that matters is a recent one.
pub const MAX_WAKE_CANDIDATES: usize = 4;

/// Size ceiling on the wake bridge file, checked before it is read.
///
/// Written by platform code, and on Android by anything that can start our
/// exported launcher activity - so its size is not ours to assume. Four
/// candidates of ~112 hex characters is under 500 bytes; 8 KiB is far above any
/// legitimate content and still nothing to read.
const MAX_WAKE_FILE_BYTES: u64 = 8 * 1024;

/// Read AND consume the wake-blob candidates the native layer left behind.
/// Deleting on read keeps one tap from re-triggering host switches forever.
///
/// Returns candidateS, not one blob. On Android the notification-tap payload
/// arrives as an Intent extra on an **exported** launcher activity (it has to be
/// exported - it is the launcher), so any app on the device can hand us one. When
/// the native layer overwrote a single file, a junk intent silently displaced a
/// genuine pending wake and the doorbell was lost. It now keeps a short
/// newest-first list, and the decision about which blob is REAL is made here, by
/// whether it opens under this phone's wake key.
///
/// This bounds the damage rather than authenticating the sender: Android offers no
/// trustworthy caller identity for `startActivity` (`getReferrer` is caller-
/// supplied). It does not need to. The blob is XChaCha20-Poly1305 sealed with a
/// key that never leaves this phone, so a spoofed blob can never name a host - the
/// most it can do is occupy a slot in this list. A local app determined to spam
/// all four slots still costs the user only a missed doorbell tap, never a
/// connection to somewhere they did not choose.
///
/// Both platforms write this format (`PorttyWakeStore.kt`, `push_glue.mm`). A
/// single-line file - what older builds wrote - is simply one candidate, so an
/// install that predates this reads the same way.
///
/// iOS has no cross-app intent path, so the spoofing above is Android-only. It
/// keeps the same format anyway for two reasons of its own: the payload arrives
/// from APNs via a relay that may not be ours, so its size is not ours to assume;
/// and two hosts ringing within a few seconds no longer cost the user the earlier
/// doorbell. One format also means one reader contract here instead of two.
pub fn consume_wake_blobs(app: &tauri::AppHandle) -> Vec<Vec<u8>> {
    for dir in bridge_dirs(app) {
        let path = dir.join(WAKE_FILE);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() > MAX_WAKE_FILE_BYTES {
            // Oversized means "not written by our native layer". Drop it instead
            // of parsing it.
            tracing::warn!("discarding an oversized push wake bridge file");
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(mut text) = std::fs::read_to_string(&path) else {
            continue;
        };
        protect_wake_file(&path);
        let _ = std::fs::remove_file(&path);
        let candidates = parse_wake_candidates(&text);
        text.zeroize();
        if !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

/// Split a bridge file into decoded candidates, newest first.
///
/// Malformed lines are skipped rather than failing the batch: the whole point of
/// the list is that one bad entry must not cost the user a real wake.
fn parse_wake_candidates(text: &str) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    for line in text.lines().take(MAX_WAKE_CANDIDATES) {
        let mut hex_str = line.trim().to_string();
        if let Some(blob) = decode_hex(&hex_str) {
            candidates.push(blob);
        }
        hex_str.zeroize();
    }
    candidates
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng as _;

    #[test]
    fn wake_blob_round_trips_and_rejects_tampering() {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        let host = DeviceId([5u8; 16]);
        let blob = seal_wake_blob(&key, &host).unwrap();
        assert_eq!(open_wake_blob(&key, &blob), Some(host));
        // Flip one ciphertext bit → must not decrypt.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(open_wake_blob(&key, &bad), None);
        // A different phone's key must not open it either.
        let mut other = [0u8; 32];
        rand::rng().fill_bytes(&mut other);
        assert_eq!(open_wake_blob(&other, &blob), None);
    }

    /// The Android notification-tap payload arrives as an Intent extra on an
    /// exported launcher activity, so any app can write one. A spoofed blob must
    /// not be able to displace a genuine pending wake - which it did while the
    /// bridge file held exactly one value.
    #[test]
    fn a_spoofed_candidate_cannot_hide_the_genuine_wake() {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        let host = DeviceId([7u8; 16]);
        let genuine: String = seal_wake_blob(&key, &host)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        // A hostile app got its blob in FIRST - it is well-formed hex, so nothing
        // before the AEAD can tell it apart from the real one.
        let spoofed = "ab".repeat(56);
        let file = format!("{spoofed}\n{genuine}\n");

        let candidates = parse_wake_candidates(&file);
        assert_eq!(candidates.len(), 2);
        // The genuine one still wins, because opening is what decides.
        let opened = candidates
            .iter()
            .find_map(|blob| open_wake_blob(&key, blob));
        assert_eq!(opened, Some(host));
    }

    #[test]
    fn wake_candidates_are_bounded_and_malformed_lines_are_skipped() {
        // More lines than the cap: only the newest `MAX_WAKE_CANDIDATES` are read,
        // so a flood cannot make us parse an unbounded list.
        let many = (0..50)
            .map(|_| "cd".repeat(56))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_wake_candidates(&many).len(), MAX_WAKE_CANDIDATES);

        // A bad line is skipped, not fatal - one junk entry must not cost the user
        // a real wake.
        let mixed = "not-hex\n\nabc\n0011223344\n";
        assert_eq!(
            parse_wake_candidates(mixed),
            vec![vec![0x00, 0x11, 0x22, 0x33, 0x44]]
        );
        assert!(parse_wake_candidates("").is_empty());
    }

    #[test]
    fn wake_key_is_created_once_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create_wake_key(dir.path()).unwrap();
        let b = load_or_create_wake_key(dir.path()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn wake_key_creates_the_data_dir_itself() {
        // Regression: on iOS the Keychain owns the credentials, so on a fresh
        // install the app-data dir does not exist yet. Key creation crashed
        // the app at launch (ENOENT → setup error → panic) in build 1.4.
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("nested").join("data-dir");
        assert!(!missing.exists());
        let a = load_or_create_wake_key(&missing).unwrap();
        let b = load_or_create_wake_key(&missing).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hex_decoding_is_strict() {
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(decode_hex("xyz").is_none());
        assert!(decode_hex("abc").is_none()); // odd length
        assert!(decode_hex("").is_none());
    }
}
