//! OS-backed credential persistence for the phone app.
//!
//! Android stores entries in encrypted SharedPreferences under a Keystore key.
//! iOS stores them in the protected Keychain as
//! `WhenUnlockedThisDeviceOnly`, with iCloud synchronization disabled.

#![cfg(any(target_os = "android", target_os = "ios"))]

use std::sync::Arc;

use keyring_core::{api::CredentialStoreApi, Entry, Error as KeyringError};
use portty_transport::credential_store::{
    CredentialStore, Durability, FileCredentialStore, IDENTITY_RECORD, LAST_HOST_RECORD,
    PAIR_STATE_RECORD, PEERS_RECORD, REVOCATIONS_RECORD,
};
use portty_transport::{Identity, PeerStore};
use zeroize::Zeroize;

const SERVICE: &str = "org.example.portty.credentials.v1";

struct MobileCredentialStore;

impl MobileCredentialStore {
    fn entry(&self, name: &str) -> std::io::Result<Entry> {
        #[cfg(target_os = "android")]
        {
            // `ndk_context` is initialized by MainActivity before Tauri calls
            // app setup; the backend then protects SharedPreferences values
            // with a non-exportable Android Keystore key.
            let store = android_native_keyring_store::Store::new().map_err(keyring_io)?;
            store.build(SERVICE, name, None).map_err(keyring_io)
        }

        #[cfg(target_os = "ios")]
        {
            let store = apple_native_keyring_store::protected::Store::new().map_err(keyring_io)?;
            let modifiers = std::collections::HashMap::from([(
                "access-policy",
                "when-unlocked-this-device-only",
            )]);
            store
                .build(SERVICE, name, Some(&modifiers))
                .map_err(keyring_io)
        }
    }
}

impl CredentialStore for MobileCredentialStore {
    fn read(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        match self.entry(name)?.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(keyring_io(e)),
        }
    }

    fn write(&self, name: &str, bytes: &[u8], durability: Durability) -> std::io::Result<()> {
        // The Keychain/Keystore is the durability boundary here: `set_secret`
        // hands the value to the platform daemon, which owns persisting it, and
        // there is no weaker or stronger variant to select. So both levels get the
        // same call - and that is honest rather than a shortcut, because the
        // BestEffort/Required distinction exists for the FILE store, where a
        // directory entry can outlive a crash without its rename.
        let _ = durability;
        self.entry(name)?.set_secret(bytes).map_err(keyring_io)
    }

    fn remove(&self, name: &str) -> std::io::Result<()> {
        match self.entry(name)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(keyring_io(e)),
        }
    }
}

fn keyring_io(error: KeyringError) -> std::io::Error {
    let kind = match error {
        KeyringError::NoStorageAccess(_) => std::io::ErrorKind::PermissionDenied,
        KeyringError::NoEntry => std::io::ErrorKind::NotFound,
        _ => std::io::ErrorKind::Other,
    };
    // Keyring errors contain platform diagnostics but never credential bytes.
    std::io::Error::new(kind, error)
}

/// Migrate legacy plaintext app-data records into OS secure storage, validate
/// them through the normal decoders, and only then delete the old files.
pub fn load_or_migrate(
    data_dir: &std::path::Path,
) -> Result<(Identity, PeerStore), Box<dyn std::error::Error>> {
    let files: Arc<dyn CredentialStore> = Arc::new(FileCredentialStore::new(data_dir));
    let secure: Arc<dyn CredentialStore> = Arc::new(MobileCredentialStore);
    let mut newly_migrated = Vec::new();

    for record in [
        IDENTITY_RECORD,
        PEERS_RECORD,
        LAST_HOST_RECORD,
        PAIR_STATE_RECORD,
        REVOCATIONS_RECORD,
    ] {
        if secure.read(record)?.is_none() {
            if let Some(mut bytes) = files.read(record)? {
                // Migrating a credential into secure storage: if it does not
                // land, the plaintext original is kept (see below), so a failure
                // must be reported rather than assumed.
                let write = secure.write(record, &bytes, Durability::Required);
                bytes.zeroize();
                write?;
                newly_migrated.push(record);
            }
        }
    }

    let loaded = (|| {
        let identity = Identity::load_or_create_in(secure.clone())?;
        let peers = PeerStore::load_from(secure.clone())?;
        Ok::<_, Box<dyn std::error::Error>>((identity, peers))
    })();

    let (identity, peers) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            // Preserve the legacy files and roll back entries created by this
            // attempt, so a transient platform/migration error is recoverable.
            for record in newly_migrated {
                let _ = secure.remove(record);
            }
            return Err(error);
        }
    };

    // Secure records have decoded successfully. Delete every legacy plaintext
    // copy, including leftovers from an interrupted earlier migration.
    for record in [
        IDENTITY_RECORD,
        PEERS_RECORD,
        LAST_HOST_RECORD,
        PAIR_STATE_RECORD,
        REVOCATIONS_RECORD,
    ] {
        files.remove(record)?;
    }

    Ok((identity, peers))
}
