//! Tightening of secret files to the current user, plus marking
//! them so the OS never copies them into a cloud/device-transfer backup.
//!
//! Port of Corvux's `secure_file::restrict_to_current_user`, trimmed to what
//! `identity.rs` needs. Unix uses mode 0600; Windows installs a protected DACL
//! containing only the current user's SID.
//!
//! Device identity must never sync or transfer to another device (a copied
//! identity is a copied credential). On Apple platforms we set
//! `NSURLIsExcludedFromBackupKey` on the file; on Android the equivalent is
//! declarative (see the manifest's `dataExtractionRules` / `allowBackup`).

use std::path::Path;

/// Create `dir` (and parents) as an owner-only directory, then verify what is
/// actually there is safe to keep secrets in.
///
/// `create_dir_all` alone leaves the directory at the process umask, typically
/// 0755. The FILES inside are 0600 so their contents stay private either way -
/// but a directory another user can write is what makes the rest of this module
/// racy: they can plant a symlink at a record or temp path between our own
/// unlink and create. So on Unix the directory is created 0700 and rejected if it
/// is a symlink, or if group/other hold any permission at all. An existing
/// too-open directory is tightened in place rather than refused, since that is
/// the shape an older Portby install left behind.
pub fn prepare_secret_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // symlink_metadata: do NOT follow, or a symlinked "directory" passes.
        let meta = std::fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "credential directory is a symlink; refusing to store secrets there",
            ));
        }
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "credential directory path is not a directory",
            ));
        }
        // OWNERSHIP before permissions. Tightening a directory we do not own is
        // worse than refusing it: the chmod succeeds, everything downstream looks
        // correct, and the secrets still land somewhere another user controls -
        // who can plant a symlink at a record path between our unlink and create,
        // which is the exact race the rest of this module is built around.
        //
        // This matters when the process is more privileged than the directory's
        // owner and has been pointed at it (`PORTTY_DATA_DIR`, a service unit with
        // a wrong WorkingDirectory, a sudo invocation). An unprivileged process
        // cannot chmod a directory it does not own anyway, so it would have failed
        // below with a confusing EPERM instead of this.
        //
        // Effective UID, not real: it is the one the filesystem will check.
        // SAFETY: geteuid cannot fail and touches no memory.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "credential directory is owned by another user; refusing to store secrets there",
            ));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(dir, perms)?;
        }
    }
    #[cfg(windows)]
    {
        windows::restrict_to_current_user(dir)?;
    }
    Ok(())
}

/// Open an existing file for reading WITHOUT following a final symlink.
///
/// Reading a credential through a symlink someone else planted would have us
/// consume a file we never wrote (and, before this, chmod it to 0600 first).
/// `O_NOFOLLOW` makes that an error instead. Windows has no per-open equivalent
/// here; its protection is the owner-only DACL on the directory.
pub fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

/// Write `bytes` to `path` as an owner-only (0600) file. On Unix the file is
/// *created* with mode 0600 so the secret is never briefly world-readable at the
/// default umask. Windows applies its owner-only DACL before writing any secret
/// bytes, so an inherited directory ACL cannot expose the credential contents.
/// Fail-closed: an error here means the secret was NOT installed.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    // A stale temp with wrong perms would not be re-chmod'd by `.mode()` (it only
    // applies on creation), so start clean.
    let _ = std::fs::remove_file(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(windows)]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        if let Err(error) = windows::restrict_to_current_user(path) {
            drop(f);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    Ok(())
}

/// Install `tmp` at `path`, atomically, and durably when asked.
///
/// The two platforms need different things here, which is why this is not just
/// `std::fs::rename`:
///
/// * **Unix** - rename is atomic; durability comes from fsyncing the containing
///   directory afterwards ([`sync_parent`]).
/// * **Windows** - there is no directory fsync to fall back on, so
///   [`sync_parent`] is a no-op and a `Required` write got NO durability at all
///   despite reporting success. `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` is the
///   primitive that fixes it: it does not return until the replacement is flushed
///   to disk. `MOVEFILE_REPLACE_EXISTING` keeps the overwrite semantics
///   `std::fs::rename` already had on Windows.
pub fn replace_durably(
    tmp: &Path,
    path: &Path,
    durability: crate::credential_store::Durability,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        windows::move_file_replace(tmp, path, durability)
    }
    #[cfg(not(windows))]
    {
        // Unix: durability is the caller's `sync_parent` after this.
        let _ = durability;
        std::fs::rename(tmp, path)
    }
}

/// After an atomic rename, sync the containing directory so the new filename is
/// durable across a sudden power loss (where the file data alone is not enough).
///
/// **Windows is a no-op**, deliberately: it exposes no directory-fsync equivalent.
/// Durability there is achieved inside [`replace_durably`] instead, so callers must
/// not read a successful return here as a durability guarantee on Windows - see
/// `Durability::Required` handling in `FileCredentialStore::write`.
pub fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Owner-only, applied through an OPEN HANDLE rather than a path.
///
/// `restrict_to_current_user` takes a path, so it re-resolves it: between the open
/// and the chmod the name can point somewhere else. On unix `File::set_permissions`
/// is `fchmod` on the descriptor we already hold, which cannot be redirected.
/// Windows has no equivalent per-handle call here, so it falls back to the
/// path-based DACL - its protection is the owner-only directory.
pub fn restrict_open_file_to_current_user(
    file: &std::fs::File,
    path: &Path,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = path;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        restrict_to_current_user(path)
    }
}

pub fn restrict_to_current_user(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        windows::restrict_to_current_user(path)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::io::{Error, Result};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
        GENERIC_ALL, HANDLE, HLOCAL,
    };
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE,
        SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct CurrentUser {
        token: HANDLE,
        // `usize` gives TOKEN_USER the alignment required by the Win32 API.
        token_info: Vec<usize>,
    }

    impl CurrentUser {
        fn open() -> Result<Self> {
            unsafe {
                let mut token = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(Error::last_os_error());
                }

                let mut required = 0;
                let first =
                    GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
                if first != 0 || required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                    let error = Error::last_os_error();
                    CloseHandle(token);
                    return Err(error);
                }

                let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
                let mut token_info = vec![0usize; words];
                if GetTokenInformation(
                    token,
                    TokenUser,
                    token_info.as_mut_ptr().cast::<c_void>(),
                    required,
                    &mut required,
                ) == 0
                {
                    let error = Error::last_os_error();
                    CloseHandle(token);
                    return Err(error);
                }

                Ok(Self { token, token_info })
            }
        }

        fn sid(&self) -> PSID {
            unsafe { (*(self.token_info.as_ptr().cast::<TOKEN_USER>())).User.Sid }
        }
    }

    impl Drop for CurrentUser {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.token);
            }
        }
    }

    struct LocalAcl(*mut ACL);

    impl Drop for LocalAcl {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0.cast::<c_void>() as HLOCAL);
                }
            }
        }
    }

    fn win32_result(code: u32) -> Result<()> {
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error::from_raw_os_error(code as i32))
        }
    }

    /// Atomic replace, flushed to disk when the caller requires durability.
    ///
    /// `std::fs::rename` on Windows already replaces an existing file, but gives no
    /// durability - and unlike Unix there is no directory handle to fsync
    /// afterwards, so `Durability::Required` was silently getting nothing here.
    /// `MOVEFILE_WRITE_THROUGH` is the documented fix: the call does not return
    /// until the move is flushed.
    pub fn move_file_replace(
        tmp: &Path,
        path: &Path,
        durability: crate::credential_store::Durability,
    ) -> Result<()> {
        use crate::credential_store::Durability;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        let mut from: Vec<u16> = tmp.as_os_str().encode_wide().collect();
        from.push(0);
        let mut to: Vec<u16> = path.as_os_str().encode_wide().collect();
        to.push(0);
        let mut flags = MOVEFILE_REPLACE_EXISTING;
        if durability == Durability::Required {
            flags |= MOVEFILE_WRITE_THROUGH;
        }
        // SAFETY: both paths are NUL-terminated wide strings that outlive the call.
        let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) };
        if ok == 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn restrict_to_current_user(path: &Path) -> Result<()> {
        let user = CurrentUser::open()?;
        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user.sid().cast::<u16>(),
        };
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        };
        let mut acl = LocalAcl(std::ptr::null_mut());
        unsafe {
            win32_result(SetEntriesInAclW(1, &access, std::ptr::null(), &mut acl.0))?;
        }

        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide_path.push(0);
        unsafe {
            win32_result(SetNamedSecurityInfoW(
                wide_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.0,
                std::ptr::null(),
            ))
        }
    }

    #[cfg(test)]
    pub fn has_owner_only_dacl(path: &Path) -> Result<bool> {
        use windows_sys::Win32::Security::Authorization::{
            GetExplicitEntriesFromAclW, GetNamedSecurityInfoW,
        };
        use windows_sys::Win32::Security::EqualSid;

        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide_path.push(0);
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        unsafe {
            win32_result(GetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            ))?;
        }
        let descriptor = LocalDescriptor(descriptor);
        if owner.is_null() || dacl.is_null() {
            return Ok(false);
        }

        let mut count = 0;
        let mut entries: *mut EXPLICIT_ACCESS_W = std::ptr::null_mut();
        unsafe {
            win32_result(GetExplicitEntriesFromAclW(dacl, &mut count, &mut entries))?;
        }
        let entries = LocalEntries(entries);
        let matches = count == 1
            && !entries.0.is_null()
            && unsafe {
                let entry = &*entries.0;
                entry.Trustee.TrusteeForm == TRUSTEE_IS_SID
                    && EqualSid(owner, entry.Trustee.ptstrName.cast::<c_void>()) != 0
            };
        drop(descriptor);
        Ok(matches)
    }

    #[cfg(test)]
    struct LocalDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

    #[cfg(test)]
    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0 as HLOCAL) };
            }
        }
    }

    #[cfg(test)]
    struct LocalEntries(*mut EXPLICIT_ACCESS_W);

    #[cfg(test)]
    impl Drop for LocalEntries {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
            }
        }
    }
}

/// Mark `path` as excluded from cloud backup / device transfer. Best-effort:
/// a no-op on platforms where exclusion is declarative (Android) or unneeded
/// (Windows/Linux, where the file already lives in per-user storage).
pub fn exclude_from_backup(path: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        apple::set_excluded_from_backup(path, false)
    }
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        let _ = path;
        Ok(())
    }
}

/// Mark a DIRECTORY as excluded from cloud backup / device transfer, which also
/// covers files created inside it afterwards.
///
/// Use this when a file will be created by code that cannot call
/// [`exclude_from_backup`] itself - notably the iOS/Android push callbacks, which
/// are platform code with no route into Rust. Marking each file on the next Rust
/// read left a gap of arbitrary length (a backup could run first, and on a phone
/// that is nightly), so the flag belongs on the directory, before anything is
/// written into it.
pub fn exclude_dir_from_backup(path: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        apple::set_excluded_from_backup(path, true)
    }
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple {
    use std::io::Error;
    use std::os::raw::{c_uchar, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFURLRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFErrorRef = *const c_void;
    type Boolean = c_uchar;
    type CFIndex = isize;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFURLIsExcludedFromBackupKey: CFStringRef;
        static kCFBooleanTrue: CFTypeRef;
        fn CFURLCreateFromFileSystemRepresentation(
            allocator: CFAllocatorRef,
            buffer: *const c_uchar,
            buf_len: CFIndex,
            is_directory: Boolean,
        ) -> CFURLRef;
        fn CFURLSetResourcePropertyForKey(
            url: CFURLRef,
            key: CFStringRef,
            value: CFTypeRef,
            error: *mut CFErrorRef,
        ) -> Boolean;
        fn CFRelease(cf: CFTypeRef);
    }

    pub fn set_excluded_from_backup(path: &Path, is_directory: bool) -> std::io::Result<()> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: CoreFoundation Create/Set/Release calls with a valid, non-null
        // URL created from the file-system path; every created ref is released.
        unsafe {
            let url = CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as CFIndex,
                Boolean::from(is_directory),
            );
            if url.is_null() {
                return Err(Error::other("CFURL create failed"));
            }
            let mut err: CFErrorRef = std::ptr::null();
            let ok = CFURLSetResourcePropertyForKey(
                url,
                kCFURLIsExcludedFromBackupKey,
                kCFBooleanTrue,
                &mut err,
            );
            CFRelease(url);
            if ok == 0 {
                if !err.is_null() {
                    CFRelease(err);
                }
                return Err(Error::other("set exclude-from-backup failed"));
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    /// The normal case must keep working: our own directory, created or tightened.
    #[test]
    fn accepts_and_tightens_a_directory_we_own() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("creds");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        prepare_secret_dir(&dir).unwrap();

        let mode = std::fs::symlink_metadata(&dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "a too-open dir we own is tightened");
    }

    /// A directory owned by someone else is REFUSED, not tightened.
    ///
    /// Skipped unless the test can actually produce one, which needs a second
    /// uid, so it runs as root in CI containers and no-ops on a developer laptop.
    /// Saying so out loud matters: a silently-skipped ownership test reads as
    /// coverage it is not providing.
    #[test]
    fn refuses_a_directory_owned_by_another_user() {
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: needs root to create a directory owned by another uid");
            return;
        }
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("theirs");
        std::fs::create_dir(&dir).unwrap();
        // Hand it to nobody-ish. 65534 is `nobody` on Debian/Alpine images.
        let c_dir = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: chown on a path we just created, as root.
        assert_eq!(unsafe { libc::chown(c_dir.as_ptr(), 65534, 65534) }, 0);

        let error = prepare_secret_dir(&dir).expect_err("must refuse a foreign-owned directory");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        // And it must NOT have been "fixed" on the way out.
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::symlink_metadata(&dir).unwrap().uid(), 65534);
    }

    /// A symlink in place of the directory is still refused - the ownership check
    /// is added in front of that, not instead of it.
    #[test]
    fn still_refuses_a_symlinked_directory() {
        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let error = prepare_secret_dir(&link).expect_err("a symlinked dir must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[cfg(all(test, any(target_os = "ios", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn exclude_sets_backup_xattr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        std::fs::write(&path, b"secret").unwrap();
        exclude_from_backup(&path).unwrap();
        // Setting NSURLIsExcludedFromBackupKey writes this extended attribute.
        let out = std::process::Command::new("xattr")
            .arg(&path)
            .output()
            .unwrap();
        let attrs = String::from_utf8_lossy(&out.stdout);
        assert!(
            attrs.contains("com.apple.metadata:com_apple_backup_excludeItem"),
            "expected backup-exclude xattr, got: {attrs:?}"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn owner_only_write_installs_a_single_owner_ace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        write_owner_only(&path, b"secret").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        assert!(super::windows::has_owner_only_dacl(&path).unwrap());
    }

    #[test]
    fn restriction_replaces_inherited_acl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.bin");
        std::fs::write(&path, b"secret").unwrap();
        restrict_to_current_user(&path).unwrap();
        assert!(super::windows::has_owner_only_dacl(&path).unwrap());
    }
}
