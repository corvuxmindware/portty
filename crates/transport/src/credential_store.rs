//! Pluggable persistence for long-lived device credentials.
//!
//! Hosts use [`FileCredentialStore`]. Mobile clients can supply an OS-backed
//! implementation (Android Keystore / iOS Keychain) without teaching the
//! transport crate about either platform API.

use std::path::{Path, PathBuf};

/// Stable record names used by identity and peer persistence.
pub const IDENTITY_RECORD: &str = "identity.bin";
pub const PEERS_RECORD: &str = "portty-peers.dat";
pub const LAST_HOST_RECORD: &str = "portty-last-host.dat";
/// Version-independent sidecar records. Keeping these separate preserves the
/// existing postcard peer map while adding generation-bound revocation state.
pub const PAIR_STATE_RECORD: &str = "portty-pair-state-v1.dat";
pub const REVOCATIONS_RECORD: &str = "portty-revocations-v1.dat";

/// How durable a write must be before it may report success.
///
/// Made explicit because the two answers are a real security/availability
/// trade-off, and the trait used to promise the stronger one while one
/// implementation path deliberately provided the weaker. A caller now has to say
/// which it means, and the name says what it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// The record's own bytes are flushed, but if the containing directory entry
    /// cannot be made durable that is logged rather than reported.
    ///
    /// For records rewritten constantly whose PREVIOUS value stays valid - the
    /// rotating resumption token above all. A lost rotation after a crash means
    /// the peer re-authenticates with the token it already had. Reporting an error
    /// on every reconnect, on any filesystem where directory fsync is unreliable,
    /// would trade a working product for nothing.
    BestEffort,
    /// The record must be durable before this returns `Ok`.
    ///
    /// For records whose loss is a security regression rather than a retry:
    /// revocation tombstones and pair state. If a crash could resurrect a pairing
    /// the user revoked, the caller has to hear about it and say so.
    Required,
}

/// Minimal secret-store contract. Implementations must never log record contents.
///
/// `write` honours the requested [`Durability`]. `remove` is ALWAYS treated as
/// [`Durability::Required`]: removal is how revocation takes effect, so an
/// undurable one must not report success.
pub trait CredentialStore: Send + Sync {
    fn read(&self, name: &str) -> std::io::Result<Option<Vec<u8>>>;
    fn write(&self, name: &str, bytes: &[u8], durability: Durability) -> std::io::Result<()>;
    fn remove(&self, name: &str) -> std::io::Result<()>;
}

/// Atomic, owner-only file implementation used by the host and desktop proof.
#[derive(Debug, Clone)]
pub struct FileCredentialStore {
    dir: PathBuf,
}

impl FileCredentialStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, name: &str) -> std::io::Result<PathBuf> {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "credential record name must be one path component",
            ));
        }
        Ok(self.dir.join(name))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Random hex suffix for a staging file, so its path cannot be guessed and
/// pre-planted. Not a secret - just unpredictable.
fn temp_suffix() -> String {
    use rand::Rng as _;
    let mut bytes = [0u8; 8];
    // Infallible thread RNG, not the OS source: this is an unguessable filename,
    // not key material, so it does not need to fail closed on entropy trouble.
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl CredentialStore for FileCredentialStore {
    fn read(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        use std::io::Read as _;
        let path = self.path(name)?;
        if !path.exists() {
            return Ok(None);
        }
        // Open the record WITHOUT following a final symlink, and only then touch
        // it. The old order chmod'd (and read) whatever the path pointed at, so a
        // planted symlink could hand us a file we never wrote. The owner-only
        // parent directory below makes planting one hard; this makes it useless.
        let mut file = crate::secure::open_no_follow(&path)?;
        // Secure before consuming: a credential whose permissions or backup
        // exclusion cannot be enforced is rejected, never used. Tightened through
        // the HANDLE we already hold, not the path - a path-based chmod re-resolves
        // the name and can be pointed elsewhere between the two calls.
        crate::secure::restrict_open_file_to_current_user(&file, &path)?;
        crate::secure::exclude_from_backup(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn write(&self, name: &str, bytes: &[u8], durability: Durability) -> std::io::Result<()> {
        let path = self.path(name)?;
        // 0700 and verified, not just `create_dir_all`: see `prepare_secret_dir`.
        crate::secure::prepare_secret_dir(&self.dir)?;
        // Unpredictable temp name. `write_owner_only` unlinks then creates with
        // O_EXCL, which already defeats a pre-planted symlink, but a fixed name
        // leaves a re-plant race in that gap - one nobody can aim at a name they
        // cannot guess.
        let tmp = path.with_extension(format!("credential.tmp-{}", temp_suffix()));
        if let Err(e) = crate::secure::write_owner_only(&tmp, bytes) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = crate::secure::exclude_from_backup(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        // `replace_durably` is where the platforms differ: on Windows the
        // write-through move is the ONLY thing that makes the replacement durable,
        // since there is no directory fsync to fall back on.
        if let Err(e) = crate::secure::replace_durably(&tmp, &path, durability) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if durability == Durability::Required {
            return crate::secure::sync_parent(&path).map_err(|error| {
                tracing::error!(record = name, %error, "credential write is not durable");
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "wrote {name} but could not make it durable ({error}); a crash could \
                         lose it - retry"
                    ),
                )
            });
        }
        if let Err(e) = crate::secure::sync_parent(&path) {
            // BestEffort: the record's own bytes are already flushed, and its
            // previous value still authenticates, so a lost directory entry is
            // worth a line in the log and not a failed reconnect.
            tracing::warn!(record = name, error = %e, "credential parent directory fsync failed");
        }
        Ok(())
    }

    /// Delete a record. Always treated as [`Durability::Required`].
    ///
    /// Removal is how revocation takes effect, so an undurable one fails open: the
    /// unlink lands in the page cache, the caller is told the credential is gone,
    /// and a crash before the directory entry reaches disk brings the file - and the
    /// pairing it authenticates - back after reboot. A failed directory sync is
    /// therefore an error, so the caller can say "revocation not confirmed" instead
    /// of claiming a revocation it does not have.
    ///
    /// **Windows caveat, stated rather than hidden.** [`crate::secure::sync_parent`]
    /// is a no-op there, and Windows exposes no per-delete write-through flag
    /// (`MOVEFILE_WRITE_THROUGH` has no `DeleteFile` equivalent), so this cannot
    /// force the metadata to disk and will return `Ok` without having done so.
    /// Revocation does not depend on it: the authoritative record is the
    /// [`REVOCATIONS_RECORD`] tombstone, a `Durability::Required` WRITE, which
    /// Windows does make durable via the write-through replace. Token lookup filters
    /// every tombstoned peer, so a token file that survives a crash still
    /// authenticates nothing.
    fn remove(&self, name: &str) -> std::io::Result<()> {
        let path = self.path(name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => crate::secure::sync_parent(&path).map_err(|error| {
                tracing::error!(record = name, %error, "credential removal is not durable");
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "removed {name} but could not make the deletion durable ({error}); \
                         the record may return after a crash - retry the revocation"
                    ),
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trip_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileCredentialStore::new(dir.path());
        assert!(store.read("secret.bin").unwrap().is_none());
        store
            .write("secret.bin", b"secret", Durability::Required)
            .unwrap();
        assert_eq!(store.read("secret.bin").unwrap().unwrap(), b"secret");
        store.remove("secret.bin").unwrap();
        assert!(store.read("secret.bin").unwrap().is_none());
    }

    /// Both levels must round-trip, and `Required` must be the one that reports a
    /// durability failure rather than swallowing it. The failure itself cannot be
    /// provoked portably here, so this pins the observable contract: same bytes
    /// back, and the level is a caller decision rather than a per-record guess.
    #[test]
    fn both_durability_levels_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileCredentialStore::new(dir.path());

        store
            .write("rotating.bin", b"token-v1", Durability::BestEffort)
            .unwrap();
        assert_eq!(store.read("rotating.bin").unwrap().unwrap(), b"token-v1");

        store
            .write(REVOCATIONS_RECORD, b"tombstone", Durability::Required)
            .unwrap();
        assert_eq!(
            store.read(REVOCATIONS_RECORD).unwrap().unwrap(),
            b"tombstone"
        );

        // Replacing an existing record works at either level - the write-through
        // move on Windows keeps the same overwrite semantics as the Unix rename.
        store
            .write("rotating.bin", b"token-v2", Durability::Required)
            .unwrap();
        assert_eq!(store.read("rotating.bin").unwrap().unwrap(), b"token-v2");
    }

    /// The durability level must not leak into the stored bytes or the file mode.
    #[cfg(unix)]
    #[test]
    fn durability_does_not_change_how_the_record_is_protected() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let store = FileCredentialStore::new(dir.path());
        for (name, level) in [
            ("a.bin", Durability::BestEffort),
            ("b.bin", Durability::Required),
        ] {
            store.write(name, b"secret", level).unwrap();
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name} at {level:?}: {mode:o}");
        }
    }

    #[test]
    fn file_store_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileCredentialStore::new(dir.path());
        assert_eq!(
            store
                .write("../secret", b"no", Durability::Required)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    /// An attacker-writable parent directory is the precondition for every
    /// planting race in here, so writing a credential tightens it to 0700.
    #[cfg(unix)]
    #[test]
    fn writing_a_credential_tightens_a_group_writable_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("creds");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        FileCredentialStore::new(&dir)
            .write("secret.bin", b"s", Durability::Required)
            .unwrap();

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "credential dir left open: {mode:o}");
    }

    /// A symlinked credential directory is refused outright - following it would
    /// write secrets somewhere the owner never chose.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_credential_directory_is_refused() {
        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("elsewhere");
        std::fs::create_dir(&real).unwrap();
        let link = parent.path().join("creds");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let error = FileCredentialStore::new(&link)
            .write("secret.bin", b"s", Durability::Required)
            .expect_err("a symlinked credential dir must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("symlink"), "{error}");
    }

    /// Reading must not follow a symlink standing where a record should be: that
    /// is how a planted link gets an unrelated file consumed (and chmod'd) as a
    /// credential.
    #[cfg(unix)]
    #[test]
    fn reading_a_symlinked_record_fails_instead_of_consuming_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("victim.txt");
        std::fs::write(&outside, b"someone elses file").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join(IDENTITY_RECORD)).unwrap();

        let store = FileCredentialStore::new(dir.path());
        assert!(store.read(IDENTITY_RECORD).is_err());
        // ...and the victim file is untouched.
        assert_eq!(std::fs::read(&outside).unwrap(), b"someone elses file");
    }

    /// Two writes must not reuse one staging path, or a guesser knows where to
    /// aim.
    #[test]
    fn staging_paths_are_unpredictable() {
        let first = temp_suffix();
        assert_eq!(first.len(), 16);
        assert_ne!(first, temp_suffix());
    }
}
