//! Stable per-device identity. (Forked from Corvux `sync/identity.rs`.)
//!
//! Adaptations vs Corvux original:
//!   - **`automerge` stripped** - Portty has no CRDT, so `DeviceId::as_actor_id`
//!     and the `automerge::ActorId` import are removed.
//!   - paths re-rooted to `crate::error` / `crate::secure`.
//!
//! Each Portty installation generates an Ed25519 keypair on first launch and
//! persists it in the platform app-data dir. The identity serves:
//!
//! 1. **DeviceId** - `SHA256(pubkey)[..16]`, a stable 16-byte handle.
//! 2. **Signing** - future protocol extensions (signed device advertisements).
//! 3. **iroh `NodeId` seeding** - the iroh transport seeds its
//!    `SecretKey` from this same keypair so `DeviceId` and `NodeId` stay in
//!    lockstep with one key on disk.
//!
//! **Privacy:** the keypair is NOT synced. It lives in per-device app storage.

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::credential_store::{CredentialStore, Durability, FileCredentialStore, IDENTITY_RECORD};
use crate::error::{IdentityError, SyncResult};

/// Current on-disk identity format version. Bump when the layout changes.
const IDENTITY_VERSION: u16 = 1;

/// Stable 16-byte device handle. First half of SHA256(pubkey).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    pub fn from_pubkey(pubkey: &VerifyingKey) -> Self {
        let digest = Sha256::digest(pubkey.as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        Self(out)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 32-char hex string (the inverse of `as_hex`). Returns `None` on a
    /// wrong length or non-hex chars. Used by `portty-host revoke <id>`.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 16 {
            return None;
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Some(Self(out))
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}…", &self.as_hex()[..8])
    }
}

/// Complete per-device identity - keypair plus derived IDs.
/// Never clone this gratuitously; the signing key is secret material.
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    device_id: DeviceId,
}

impl Identity {
    /// Generate a fresh identity straight from OS entropy (never reproducible).
    ///
    /// The seed is drawn explicitly rather than via `SigningKey::generate` so the
    /// entropy failure is a typed error instead of a panic: `rand` 0.10's
    /// `SysRng` is fallible where 0.8's `OsRng` panicked internally, and a
    /// half-random signing key is not an identity. `Generate` already names this
    /// outcome. The seed is zeroized on drop; `SigningKey` owns its own copy.
    pub fn generate() -> SyncResult<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        SysRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| IdentityError::Generate)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let device_id = DeviceId::from_pubkey(&verifying_key);
        Ok(Self {
            signing_key,
            verifying_key,
            device_id,
        })
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// Raw Ed25519 secret-key bytes. Crate-private - exists so the iroh transport
    /// can seed its `SecretKey` from the same keypair, keeping `DeviceId` and iroh
    /// `NodeId` in lockstep without persisting two keys.
    pub(crate) fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Load from disk if present, otherwise generate and persist. Idempotent.
    pub fn load_or_create(dir: &Path) -> SyncResult<Self> {
        Self::load_or_create_in(Arc::new(FileCredentialStore::new(dir)))
    }

    /// Load or create an identity in an arbitrary credential store. Mobile apps
    /// use this with Android Keystore / iOS Keychain-backed implementations.
    pub fn load_or_create_in(store: Arc<dyn CredentialStore>) -> SyncResult<Self> {
        match store.read(IDENTITY_RECORD)? {
            Some(bytes) => Self::decode(bytes),
            None => {
                let id = Self::generate()?;
                id.persist(store.as_ref())?;
                Ok(id)
            }
        }
    }

    fn decode(mut bytes: Vec<u8>) -> SyncResult<Self> {
        // `disk` zeroizes its secret on drop (ZeroizeOnDrop); the raw file buffer
        // is zeroized explicitly below - neither leaves key material in freed heap.
        let disk: DiskIdentity = postcard::from_bytes(&bytes).map_err(|_| {
            bytes.zeroize();
            IdentityError::Corrupt
        })?;
        if disk.version != IDENTITY_VERSION {
            bytes.zeroize();
            return Err(IdentityError::UnsupportedVersion {
                expected: IDENTITY_VERSION,
                found: disk.version,
            }
            .into());
        }
        let signing_key = SigningKey::from_bytes(&disk.signing_key);
        let verifying_key = signing_key.verifying_key();
        if verifying_key.to_bytes() != disk.verifying_key {
            bytes.zeroize();
            return Err(IdentityError::Corrupt.into());
        }
        let device_id = DeviceId::from_pubkey(&verifying_key);
        bytes.zeroize();
        Ok(Self {
            signing_key,
            verifying_key,
            device_id,
        })
    }

    fn persist(&self, store: &dyn CredentialStore) -> SyncResult<()> {
        let disk = DiskIdentity {
            version: IDENTITY_VERSION,
            signing_key: self.signing_key.to_bytes(),
            verifying_key: self.verifying_key.to_bytes(),
        };
        let mut bytes = postcard::to_allocvec(&disk).map_err(|_| IdentityError::Corrupt)?;
        // The device identity is written once and never rotated; losing it means
        // losing every pairing, so it is worth reporting an undurable write.
        let res = store.write(IDENTITY_RECORD, &bytes, Durability::Required);
        bytes.zeroize();
        res.map_err(Into::into)
    }
}

/// On-disk representation. Keep minimal and stable. `ZeroizeOnDrop` wipes the
/// deserialized secret key when the struct is dropped, so a decoded identity
/// never lingers in freed memory.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DiskIdentity {
    version: u16,
    signing_key: [u8; 32],
    verifying_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_identity() {
        let dir = tempdir().unwrap();
        let a = Identity::load_or_create(dir.path()).unwrap();
        let b = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(a.device_id(), b.device_id());
        assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    fn device_id_is_deterministic_from_pubkey() {
        let id = Identity::generate().unwrap();
        let derived = DeviceId::from_pubkey(id.verifying_key());
        assert_eq!(id.device_id(), derived);
    }

    #[test]
    fn two_generates_produce_distinct_ids() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.device_id(), b.device_id());
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        Identity::load_or_create(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("identity.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the private key file must be owner-only");
    }
}
