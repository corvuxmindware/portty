//! File transfer state for one authenticated phone connection.
//!
//! Paths are data, never shell input. Uploads are written to a private sibling
//! temporary file and committed with an atomic rename only after verification.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use blake3::Hasher;
use portty_protocol::{Frame, TransferId, FILE_CHUNK_BYTES};
use portty_transport::{CredentialStore, Durability, FileCredentialStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Completed/active downloads a connection remembers for `FileRetry`. Bounded:
/// without a cap the per-connection map grew one entry per download forever.
const MAX_REMEMBERED_DOWNLOADS: usize = 8;
/// One authenticated connection may transfer a handful of files concurrently,
/// but cannot pin an unbounded number of tasks or open temporary files.
const MAX_ACTIVE_TRANSFERS: usize = 4;
/// Safe out-of-box disk valve. Operators that intentionally move larger files
/// may raise it, or explicitly set 0 for unlimited.
const DEFAULT_MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const PENDING_UPLOADS_RECORD: &str = "pending-uploads.json";

/// Durable list of sibling `.part` files created by live uploads. Registering a
/// path happens before file creation; completing/cancelling removes it after the
/// file is gone. Reopening this registry on host start therefore removes files
/// left behind by a crash without recursively scanning the user's home.
#[derive(Clone, Debug)]
pub struct UploadCleanup {
    state: Arc<Mutex<UploadCleanupState>>,
}

#[derive(Debug)]
struct UploadCleanupState {
    store: FileCredentialStore,
    paths: HashSet<PathBuf>,
}

impl UploadCleanupState {
    fn persist(&self) -> std::io::Result<()> {
        if self.paths.is_empty() {
            return self.store.remove(PENDING_UPLOADS_RECORD);
        }
        let mut paths: Vec<&PathBuf> = self.paths.iter().collect();
        paths.sort();
        let bytes = serde_json::to_vec(&paths)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        // A journal of in-progress upload paths, used to clean up `.part` files
        // after a crash. Losing it leaves a stray temp file, nothing more.
        self.store
            .write(PENDING_UPLOADS_RECORD, &bytes, Durability::BestEffort)
    }
}

impl UploadCleanup {
    /// Load the prior process's registry and remove every still-present Portty
    /// upload temporary. A malformed/non-Portty path is rejected rather than
    /// turning an editable registry into an arbitrary-file deletion primitive.
    pub fn open(data_dir: &Path) -> std::io::Result<(Self, usize)> {
        let store = FileCredentialStore::new(data_dir);
        let paths: Vec<PathBuf> = match store.read(PENDING_UPLOADS_RECORD)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?,
            None => Vec::new(),
        };
        let mut remaining = HashSet::new();
        let mut removed = 0;
        for path in paths {
            if !valid_upload_temporary(&path) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("refusing invalid pending-upload path {}", path.display()),
                ));
            }
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    remaining.insert(path);
                }
            }
        }
        let state = UploadCleanupState {
            store,
            paths: remaining,
        };
        state.persist()?;
        Ok((
            Self {
                state: Arc::new(Mutex::new(state)),
            },
            removed,
        ))
    }

    fn track(&self, path: &Path) -> std::io::Result<()> {
        if !valid_upload_temporary(path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pending upload must be an absolute .portty-upload-*.part path",
            ));
        }
        let mut state = self.state.lock().unwrap();
        if !state.paths.insert(path.to_path_buf()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "upload temporary path is already active",
            ));
        }
        if let Err(error) = state.persist() {
            state.paths.remove(path);
            return Err(error);
        }
        Ok(())
    }

    fn forget(&self, path: &Path) -> std::io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if !state.paths.remove(path) {
            return Ok(());
        }
        if let Err(error) = state.persist() {
            // Keeping a stale entry is safe: the next startup treats a missing
            // file as already cleaned and retries persisting the empty set.
            state.paths.insert(path.to_path_buf());
            return Err(error);
        }
        Ok(())
    }
}

fn valid_upload_temporary(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(id) = name
        .strip_prefix(".portty-upload-")
        .and_then(|name| name.strip_suffix(".part"))
    else {
        return false;
    };
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
}

pub struct Transfers {
    home: PathBuf,
    /// 0 = unlimited. From `PORTTY_MAX_TRANSFER_BYTES`; a paired phone is a
    /// trusted operator, so this is a disk-safety valve, not a security wall.
    max_transfer_bytes: u64,
    downloads: HashMap<TransferId, PathBuf>,
    /// Insertion order of `downloads` (oldest evicted first).
    download_order: VecDeque<TransferId>,
    /// Live streaming tasks, so a phone-side abort (`FileErr` inbound) stops
    /// the host from pushing the rest of a large file to a peer that already
    /// gave up. Stale handles of finished tasks are harmless (abort no-ops).
    active_downloads: HashMap<TransferId, tokio::task::AbortHandle>,
    uploads: HashMap<TransferId, Upload>,
    cleanup: Option<UploadCleanup>,
}

struct Upload {
    target: PathBuf,
    temporary: PathBuf,
    file: tokio::fs::File,
    expected_size: u64,
    written: u64,
    next_seq: u64,
    // Applied only on Unix (POSIX permission bits); Windows has no analogue.
    #[cfg_attr(not(unix), allow(dead_code))]
    mode: Option<u32>,
    hasher: Hasher,
}

/// Install a verified sibling temporary file over its destination, atomically
/// and durably.
///
/// - Unix: `rename` already replaces atomically, but the new directory entry is
///   not crash-durable until the *parent directory* is fsynced - otherwise a
///   power loss right after we ack the upload can lose the rename (#41). So we
///   rename, then fsync the parent.
/// - Windows: `rename`/`fs::rename` refuse to overwrite, so the previous code
///   renamed the target aside to a `.previous` backup and then renamed the temp
///   in - a two-step dance that, if the process died between the two renames,
///   stranded the ONLY copy of the original at an untracked `.previous` path
///   (#40). `MoveFileExW(.., MOVEFILE_REPLACE_EXISTING)` replaces in a single
///   atomic step with no backup file to strand, and `MOVEFILE_WRITE_THROUGH`
///   flushes the change to disk before returning (the Windows analogue of the
///   Unix parent-dir fsync).
async fn replace_verified_file(temporary: &Path, target: &Path) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        tokio::fs::rename(temporary, target).await?;
        fsync_parent_dir(target).await
    }
    #[cfg(windows)]
    {
        move_file_replace_write_through(temporary, target).await
    }
}

/// fsync the directory that contains `target` so the freshly-renamed entry
/// survives a crash. Best-effort on the parent's own existence; a missing parent
/// would already have failed the rename above.
#[cfg(not(windows))]
async fn fsync_parent_dir(target: &Path) -> std::io::Result<()> {
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    tokio::task::spawn_blocking(move || std::fs::File::open(&parent)?.sync_all())
        .await
        .map_err(std::io::Error::other)?
}

/// Atomically replace `target` with `temporary` in one durable step (Windows).
#[cfg(windows)]
async fn move_file_replace_write_through(temporary: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
    let (from, to) = (wide(temporary), wide(target));
    tokio::task::spawn_blocking(move || {
        // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the call.
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .await
    .map_err(std::io::Error::other)?
}

impl Transfers {
    pub fn new(cleanup: UploadCleanup) -> Self {
        let home = directories::UserDirs::new()
            .map(|dirs| dirs.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let max_transfer_bytes = std::env::var("PORTTY_MAX_TRANSFER_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_TRANSFER_BYTES);
        Self::with_home_and_cleanup(home, max_transfer_bytes, Some(cleanup))
    }

    /// Test seam + explicit construction. Canonicalizes `home` so the
    /// containment check compares canonical prefixes - with a symlinked home
    /// (macOS /var, NixOS) legitimate in-home paths were refused after their
    /// canonicalization stopped matching the raw prefix (fail-closed, but
    /// wrong).
    #[cfg(test)]
    pub fn with_home(home: PathBuf, max_transfer_bytes: u64) -> Self {
        Self::with_home_and_cleanup(home, max_transfer_bytes, None)
    }

    fn with_home_and_cleanup(
        home: PathBuf,
        max_transfer_bytes: u64,
        cleanup: Option<UploadCleanup>,
    ) -> Self {
        let home = std::fs::canonicalize(&home).unwrap_or(home);
        Self {
            home,
            max_transfer_bytes,
            downloads: HashMap::new(),
            download_order: VecDeque::new(),
            active_downloads: HashMap::new(),
            uploads: HashMap::new(),
            cleanup,
        }
    }

    fn check_size(&self, bytes: u64) -> Result<(), String> {
        if self.max_transfer_bytes > 0 && bytes > self.max_transfer_bytes {
            return Err(format!(
                "transfer of {bytes} bytes exceeds the host cap of {} (PORTTY_MAX_TRANSFER_BYTES)",
                self.max_transfer_bytes
            ));
        }
        Ok(())
    }

    fn prune_finished_downloads(&mut self) {
        self.active_downloads
            .retain(|_, handle| !handle.is_finished());
    }

    fn check_active_slot(&mut self) -> Result<(), String> {
        self.prune_finished_downloads();
        if self.active_downloads.len() + self.uploads.len() >= MAX_ACTIVE_TRANSFERS {
            Err(format!(
                "connection already has {MAX_ACTIVE_TRANSFERS} active file transfers"
            ))
        } else {
            Ok(())
        }
    }

    fn remember_download(&mut self, id: TransferId, path: PathBuf) {
        if !self.downloads.contains_key(&id) {
            self.download_order.push_back(id);
            while self.download_order.len() > MAX_REMEMBERED_DOWNLOADS {
                if let Some(old) = self.download_order.pop_front() {
                    self.downloads.remove(&old);
                }
            }
        }
        self.downloads.insert(id, path);
    }

    fn candidate(&self, path: &str) -> Result<PathBuf, String> {
        if path.is_empty() {
            return Err("file path is empty".into());
        }
        let path = PathBuf::from(path);
        Ok(if path.is_absolute() {
            path
        } else {
            self.home.join(path)
        })
    }

    fn check_inside_home(&self, canonical: &Path, allow_outside: bool) -> Result<(), String> {
        if allow_outside || canonical.starts_with(&self.home) {
            Ok(())
        } else {
            Err("path is outside the host user's home directory".into())
        }
    }

    pub async fn start_download(
        &mut self,
        id: TransferId,
        path: String,
        start_seq: u64,
        allow_outside: bool,
        tx: mpsc::Sender<Frame>,
    ) {
        let result = async {
            self.check_active_slot()?;
            if self.active_downloads.contains_key(&id) || self.uploads.contains_key(&id) {
                return Err("transfer id is already active".into());
            }
            let requested = self.candidate(&path)?;
            let canonical = tokio::fs::canonicalize(&requested)
                .await
                .map_err(|e| format!("cannot open {}: {e}", requested.display()))?;
            self.check_inside_home(&canonical, allow_outside)?;
            let metadata = tokio::fs::metadata(&canonical)
                .await
                .map_err(|e| format!("cannot inspect {}: {e}", canonical.display()))?;
            if !metadata.is_file() {
                return Err("requested path is not a regular file".into());
            }
            self.check_size(metadata.len())?;
            self.remember_download(id, canonical.clone());
            let handle = spawn_download(id, canonical, start_seq, tx.clone());
            self.active_downloads.insert(id, handle);
            Ok(())
        }
        .await;
        if let Err(reason) = result {
            // `try_send` is deliberate: this runs in the connection's sole
            // inbound loop and must never wait on its own outbound consumer.
            let _ = tx.try_send(Frame::FileErr { id, reason });
        }
    }

    pub fn retry_download(&mut self, id: TransferId, from_seq: u64, tx: mpsc::Sender<Frame>) {
        if let Some(previous) = self.active_downloads.remove(&id) {
            previous.abort();
        }
        if let Err(reason) = self.check_active_slot() {
            let _ = tx.try_send(Frame::FileErr { id, reason });
            return;
        }
        match self.downloads.get(&id).cloned() {
            Some(path) => {
                let handle = spawn_download(id, path, from_seq, tx);
                self.active_downloads.insert(id, handle);
            }
            None => {
                let _ = tx.try_send(Frame::FileErr {
                    id,
                    reason: "transfer is no longer available; start it again".into(),
                });
            }
        }
    }

    /// Phone-side abort: stop streaming this download and forget it. A later
    /// `FileGetReq` with the same id starts fresh.
    pub fn cancel_download(&mut self, id: TransferId) {
        if let Some(handle) = self.active_downloads.remove(&id) {
            handle.abort();
        }
        if self.downloads.remove(&id).is_some() {
            self.download_order.retain(|d| *d != id);
        }
    }

    pub fn cancel_upload(&mut self, id: TransferId) {
        if let Some(upload) = self.uploads.remove(&id) {
            drop(upload.file);
            let removed = match std::fs::remove_file(&upload.temporary) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if removed {
                if let Some(cleanup) = &self.cleanup {
                    let _ = cleanup.forget(&upload.temporary);
                }
            }
        }
    }

    pub async fn start_upload(
        &mut self,
        id: TransferId,
        path: String,
        size: u64,
        mode: Option<u32>,
        allow_outside: bool,
    ) -> Result<(), String> {
        self.check_active_slot()?;
        if self.uploads.contains_key(&id) || self.active_downloads.contains_key(&id) {
            return Err("upload id is already active".into());
        }
        self.check_size(size)?;
        let target = self.candidate(&path)?;
        let parent = target
            .parent()
            .ok_or_else(|| "upload path has no parent directory".to_string())?;
        let parent = tokio::fs::canonicalize(parent)
            .await
            .map_err(|e| format!("cannot open upload directory: {e}"))?;
        self.check_inside_home(&parent, allow_outside)?;
        let name = target
            .file_name()
            .ok_or_else(|| "upload path has no file name".to_string())?;
        let target = parent.join(name);
        let temporary = parent.join(format!(".portty-upload-{}.part", id.0));
        if let Some(cleanup) = &self.cleanup {
            cleanup
                .track(&temporary)
                .map_err(|e| format!("cannot register upload temporary file: {e}"))?;
        }
        let file_result = {
            let mut options = tokio::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                options.mode(0o600);
            }
            options.open(&temporary).await
        };
        let file = match file_result {
            Ok(file) => file,
            Err(error) => {
                if let Some(cleanup) = &self.cleanup {
                    let _ = cleanup.forget(&temporary);
                }
                return Err(format!("cannot create upload temporary file: {error}"));
            }
        };
        self.uploads.insert(
            id,
            Upload {
                target,
                temporary,
                file,
                expected_size: size,
                written: 0,
                next_seq: 0,
                mode,
                hasher: Hasher::new(),
            },
        );
        Ok(())
    }

    pub async fn upload_chunk(
        &mut self,
        id: TransferId,
        seq: u64,
        bytes: Vec<u8>,
    ) -> Result<Option<Frame>, String> {
        let upload = self
            .uploads
            .get_mut(&id)
            .ok_or_else(|| "unknown upload id".to_string())?;
        if seq != upload.next_seq {
            return Ok(Some(Frame::FileRetry {
                id,
                from_seq: upload.next_seq,
            }));
        }
        if bytes.len() > FILE_CHUNK_BYTES {
            return Err("file chunk exceeds the 16 KiB limit".into());
        }
        let next_size = upload.written.saturating_add(bytes.len() as u64);
        if next_size > upload.expected_size {
            return Err("upload exceeds its declared size".into());
        }
        upload
            .file
            .write_all(&bytes)
            .await
            .map_err(|e| format!("could not write upload: {e}"))?;
        upload.hasher.update(&bytes);
        upload.written = next_size;
        upload.next_seq += 1;
        Ok(None)
    }

    pub async fn finish_upload(
        &mut self,
        id: TransferId,
        size: u64,
        checksum: [u8; 32],
    ) -> Result<Frame, String> {
        let Some(mut upload) = self.uploads.remove(&id) else {
            return Err("unknown upload id".into());
        };
        let result = async {
            if size != upload.expected_size || upload.written != upload.expected_size {
                return Err(format!(
                    "upload size mismatch (expected {}, received {})",
                    upload.expected_size, upload.written
                ));
            }
            let actual = *upload.hasher.finalize().as_bytes();
            if actual != checksum {
                return Err("upload checksum mismatch".into());
            }
            upload
                .file
                .flush()
                .await
                .map_err(|e| format!("could not flush upload: {e}"))?;
            upload
                .file
                .sync_all()
                .await
                .map_err(|e| format!("could not sync upload: {e}"))?;
            drop(upload.file);
            #[cfg(unix)]
            if let Some(mode) = upload.mode {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(
                    &upload.temporary,
                    std::fs::Permissions::from_mode(mode & 0o777),
                )
                .await
                .map_err(|e| format!("could not set upload mode: {e}"))?;
            }
            replace_verified_file(&upload.temporary, &upload.target)
                .await
                .map_err(|e| format!("could not commit upload: {e}"))?;
            Ok(Frame::FileDone {
                id,
                size,
                checksum: actual,
            })
        }
        .await;
        let temporary_gone = if result.is_ok() {
            true
        } else {
            match tokio::fs::remove_file(&upload.temporary).await {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            }
        };
        if temporary_gone {
            if let Some(cleanup) = &self.cleanup {
                let _ = cleanup.forget(&upload.temporary);
            }
        }
        result
    }
}

impl Drop for Transfers {
    fn drop(&mut self) {
        let cleanup = self.cleanup.clone();
        for (_, upload) in self.uploads.drain() {
            drop(upload.file);
            let removed = match std::fs::remove_file(&upload.temporary) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if removed {
                if let Some(cleanup) = &cleanup {
                    let _ = cleanup.forget(&upload.temporary);
                }
            }
        }
    }
}

fn spawn_download(
    id: TransferId,
    path: PathBuf,
    start_seq: u64,
    tx: mpsc::Sender<Frame>,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let result: Result<(), String> = async {
            let mut file = tokio::fs::File::open(&path)
                .await
                .map_err(|e| format!("cannot open download: {e}"))?;
            let metadata = file
                .metadata()
                .await
                .map_err(|e| format!("cannot inspect download: {e}"))?;
            let original_len = metadata.len();
            // Snapshot len + mtime so we can detect a concurrent write below.
            let original_mtime = metadata.modified().ok();
            let start = start_seq.saturating_mul(FILE_CHUNK_BYTES as u64);
            if start > original_len {
                return Err("resume point is beyond the end of the file".into());
            }

            // ONE consistent pass from offset 0: hash every byte, but only SEND
            // chunks at/after the resume point. The old code streamed the tail from
            // a seeked handle while a SEPARATE full-file re-read computed the
            // checksum - two independent reads that disagree if the file is written
            // mid-transfer, so the phone could receive bytes that don't match the
            // FileDone checksum. Reading once makes the checksum cover exactly the
            // bytes this transfer is based on (#42). Chunks are filled to full
            // FILE_CHUNK_BYTES (short reads coalesced) so chunk `seq` always maps to
            // byte range [seq*CHUNK, ..) - the offset the phone computes on resume.
            let mut hasher = Hasher::new();
            let mut seq = 0u64;
            let mut buf = vec![0u8; FILE_CHUNK_BYTES];
            loop {
                let mut filled = 0usize;
                while filled < buf.len() {
                    let n = file
                        .read(&mut buf[filled..])
                        .await
                        .map_err(|e| format!("cannot read download: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                hasher.update(&buf[..filled]);
                if seq >= start_seq {
                    tx.send(Frame::FileChunk {
                        id,
                        seq,
                        bytes: buf[..filled].to_vec(),
                    })
                    .await
                    .map_err(|_| "phone disconnected during download".to_string())?;
                }
                seq += 1;
                if filled < buf.len() {
                    break; // a short fill means we hit EOF
                }
            }

            // If the file changed underneath us, the checksum we just computed no
            // longer describes a file the phone can coherently reassemble (its
            // earlier chunks may be from a different version), so fail closed rather
            // than send a FileDone that either won't verify or certifies bytes we
            // never streamed (#42). Best-effort: len catches append/truncate, mtime
            // catches same-size edits modulo filesystem timestamp resolution.
            let changed = match tokio::fs::metadata(&path).await {
                Ok(current) => {
                    current.len() != original_len || current.modified().ok() != original_mtime
                }
                Err(_) => true,
            };
            if changed {
                return Err("file changed during download; start the transfer again".into());
            }

            let checksum = *hasher.finalize().as_bytes();
            tx.send(Frame::FileDone {
                id,
                size: original_len,
                checksum,
            })
            .await
            .map_err(|_| "phone disconnected during download".to_string())?;
            Ok(())
        }
        .await;
        if let Err(reason) = result {
            let _ = tx.send(Frame::FileErr { id, reason }).await;
        }
    })
    .abort_handle()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_digest_is_blake3() {
        assert_eq!(
            blake3::hash(b"abc").to_hex().as_str(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    async fn drain_download(
        mut rx: mpsc::Receiver<Frame>,
    ) -> (u64, Vec<u8>, Option<[u8; 32]>, Option<u64>) {
        let (mut first_seq, mut bytes, mut checksum, mut size) = (u64::MAX, Vec::new(), None, None);
        while let Some(frame) = rx.recv().await {
            match frame {
                Frame::FileChunk { seq, bytes: b, .. } => {
                    first_seq = first_seq.min(seq);
                    bytes.extend_from_slice(&b);
                }
                Frame::FileDone {
                    checksum: c,
                    size: s,
                    ..
                } => {
                    checksum = Some(c);
                    size = Some(s);
                    break;
                }
                Frame::FileErr { reason, .. } => panic!("unexpected download error: {reason}"),
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        (first_seq, bytes, checksum, size)
    }

    #[tokio::test]
    async fn download_resume_streams_only_the_tail_but_checksums_the_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        // Just over two chunks, so a resume can skip whole chunks and end on a
        // partial one.
        let content: Vec<u8> = (0..FILE_CHUNK_BYTES * 2 + 123)
            .map(|i| (i % 251) as u8)
            .collect();
        tokio::fs::write(&path, &content).await.unwrap();
        let full = *blake3::hash(&content).as_bytes();

        // Full download (seq 0): reassembles exactly, checksum covers everything.
        let (tx, rx) = mpsc::channel(64);
        spawn_download(TransferId(1), path.clone(), 0, tx);
        let (first_seq, bytes, checksum, size) = drain_download(rx).await;
        assert_eq!(first_seq, 0);
        assert_eq!(bytes, content);
        assert_eq!(checksum, Some(full));
        assert_eq!(size, Some(content.len() as u64));

        // Resume from seq 2 (byte offset 2*CHUNK): only the final partial chunk is
        // streamed, but the FileDone checksum still covers the WHOLE file - the fix
        // for #42, where the streamed bytes and the checksum used to come from two
        // separate reads.
        let (tx, rx) = mpsc::channel(64);
        spawn_download(TransferId(2), path.clone(), 2, tx);
        let (first_seq, tail, checksum, _) = drain_download(rx).await;
        assert_eq!(first_seq, 2, "resume must start at the requested seq");
        assert_eq!(
            tail,
            content[FILE_CHUNK_BYTES * 2..],
            "only the tail streams"
        );
        assert_eq!(
            checksum,
            Some(full),
            "resume checksum still covers the whole file"
        );
    }

    #[tokio::test]
    async fn upload_is_committed_only_after_checksum_matches() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("received.bin");
        let bytes = b"verified portty upload".to_vec();
        let mut transfers = Transfers::with_home(dir.path().to_path_buf(), 0);
        let id = TransferId(9);
        transfers
            .start_upload(
                id,
                target.to_string_lossy().into_owned(),
                bytes.len() as u64,
                Some(0o640),
                true,
            )
            .await
            .unwrap();
        assert!(!target.exists());
        assert!(transfers
            .upload_chunk(id, 0, bytes.clone())
            .await
            .unwrap()
            .is_none());
        let checksum = *blake3::hash(&bytes).as_bytes();
        assert!(matches!(
            transfers
                .finish_upload(id, bytes.len() as u64, checksum)
                .await
                .unwrap(),
            Frame::FileDone { .. }
        ));
        assert_eq!(tokio::fs::read(target).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn verified_upload_replaces_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("received.bin");
        tokio::fs::write(&target, b"old contents").await.unwrap();
        let bytes = b"verified replacement".to_vec();
        let mut transfers = Transfers::with_home(dir.path().to_path_buf(), 0);
        let id = TransferId(91);
        transfers
            .start_upload(
                id,
                target.to_string_lossy().into_owned(),
                bytes.len() as u64,
                None,
                false,
            )
            .await
            .unwrap();
        transfers.upload_chunk(id, 0, bytes.clone()).await.unwrap();
        let checksum = *blake3::hash(&bytes).as_bytes();

        transfers
            .finish_upload(id, bytes.len() as u64, checksum)
            .await
            .unwrap();

        assert_eq!(tokio::fs::read(target).await.unwrap(), bytes);
    }

    // Directly exercises the atomic+durable commit helper. On Unix this drives
    // the parent-dir fsync path (#41); the assert fails if that fsync errors.
    #[tokio::test]
    async fn replace_verified_file_commits_and_consumes_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("committed.bin");
        let temporary = dir.path().join(".portty-upload-7.part");
        tokio::fs::write(&temporary, b"durable payload")
            .await
            .unwrap();

        replace_verified_file(&temporary, &target).await.unwrap();

        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"durable payload");
        assert!(
            !temporary.exists(),
            "the atomic move consumes the temp file"
        );
    }

    #[tokio::test]
    async fn out_of_order_upload_requests_precise_retry() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("received.bin");
        let mut transfers = Transfers::with_home(dir.path().to_path_buf(), 0);
        let id = TransferId(10);
        transfers
            .start_upload(id, target.to_string_lossy().into_owned(), 1, None, true)
            .await
            .unwrap();
        assert!(matches!(
            transfers.upload_chunk(id, 3, vec![1]).await.unwrap(),
            Some(Frame::FileRetry { from_seq: 0, .. })
        ));
        assert!(!target.exists());
    }

    /// One fake "home" plus a sibling directory outside it.
    fn jail() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        (root, home, outside)
    }

    async fn download_reply(transfers: &mut Transfers, id: TransferId, path: &Path) -> Frame {
        let (tx, mut rx) = mpsc::channel(8);
        transfers
            .start_download(id, path.to_string_lossy().into_owned(), 0, false, tx)
            .await;
        rx.recv().await.expect("a frame")
    }

    #[tokio::test]
    async fn download_outside_home_is_rejected_without_the_flag() {
        let (_root, home, outside) = jail();
        let secret = outside.join("secret.txt");
        std::fs::write(&secret, b"nope").unwrap();
        let mut transfers = Transfers::with_home(home, 0);
        match download_reply(&mut transfers, TransferId(1), &secret).await {
            Frame::FileErr { reason, .. } => assert!(reason.contains("outside"), "{reason}"),
            other => panic!("expected FileErr, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_dotdot_traversal_is_rejected() {
        let (_root, home, outside) = jail();
        std::fs::write(outside.join("secret.txt"), b"nope").unwrap();
        let mut transfers = Transfers::with_home(home.clone(), 0);
        // Relative path that resolves outside home via `..`.
        let sneaky = home.join("../outside/secret.txt");
        match download_reply(&mut transfers, TransferId(2), &sneaky).await {
            Frame::FileErr { reason, .. } => assert!(reason.contains("outside"), "{reason}"),
            other => panic!("expected FileErr, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_through_inside_symlink_to_outside_is_rejected() {
        let (_root, home, outside) = jail();
        let secret = outside.join("secret.txt");
        std::fs::write(&secret, b"nope").unwrap();
        let link = home.join("innocent.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let mut transfers = Transfers::with_home(home, 0);
        match download_reply(&mut transfers, TransferId(3), &link).await {
            Frame::FileErr { reason, .. } => assert!(reason.contains("outside"), "{reason}"),
            other => panic!("expected FileErr, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn in_home_download_streams_and_upload_outside_home_is_rejected() {
        let (_root, home, outside) = jail();
        let ok_file = home.join("notes.txt");
        std::fs::write(&ok_file, b"hello").unwrap();
        let mut transfers = Transfers::with_home(home, 0);
        // Sanity: the jail lets legitimate home files through.
        match download_reply(&mut transfers, TransferId(4), &ok_file).await {
            Frame::FileChunk { bytes, .. } => assert_eq!(bytes, b"hello"),
            other => panic!("expected FileChunk, got {other:?}"),
        }
        // Uploads honor the same jail.
        let err = transfers
            .start_upload(
                TransferId(5),
                outside.join("drop.bin").to_string_lossy().into_owned(),
                1,
                None,
                false,
            )
            .await
            .unwrap_err();
        assert!(err.contains("outside"), "{err}");
    }

    #[tokio::test]
    async fn transfer_cap_rejects_oversized_both_ways() {
        let (_root, home, _outside) = jail();
        let big = home.join("big.bin");
        std::fs::write(&big, vec![0u8; 64]).unwrap();
        let mut transfers = Transfers::with_home(home.clone(), 16);
        match download_reply(&mut transfers, TransferId(6), &big).await {
            Frame::FileErr { reason, .. } => {
                assert!(reason.contains("PORTTY_MAX_TRANSFER_BYTES"), "{reason}")
            }
            other => panic!("expected FileErr, got {other:?}"),
        }
        let err = transfers
            .start_upload(
                TransferId(7),
                home.join("in.bin").to_string_lossy().into_owned(),
                17,
                None,
                false,
            )
            .await
            .unwrap_err();
        assert!(err.contains("PORTTY_MAX_TRANSFER_BYTES"), "{err}");
    }

    #[tokio::test]
    async fn remembered_downloads_are_bounded_and_evict_oldest() {
        let (_root, home, _outside) = jail();
        let mut transfers = Transfers::with_home(home.clone(), 0);
        for i in 0..(MAX_REMEMBERED_DOWNLOADS as u64 + 3) {
            let f = home.join(format!("f{i}.txt"));
            std::fs::write(&f, b"x").unwrap();
            let (tx, mut rx) = mpsc::channel(8);
            transfers
                .start_download(
                    TransferId(i),
                    f.to_string_lossy().into_owned(),
                    0,
                    false,
                    tx,
                )
                .await;
            while rx.recv().await.is_some() {} // drain chunk + done
        }
        assert_eq!(transfers.downloads.len(), MAX_REMEMBERED_DOWNLOADS);
        // The oldest id was evicted: retry now reports it unavailable.
        let (tx, mut rx) = mpsc::channel(8);
        transfers.retry_download(TransferId(0), 0, tx);
        match rx.recv().await.expect("a frame") {
            Frame::FileErr { reason, .. } => {
                assert!(reason.contains("no longer available"), "{reason}")
            }
            other => panic!("expected FileErr, got {other:?}"),
        }
        // The newest is still retryable.
        let newest = TransferId(MAX_REMEMBERED_DOWNLOADS as u64 + 2);
        let (tx, mut rx) = mpsc::channel(8);
        transfers.retry_download(newest, 0, tx);
        assert!(matches!(
            rx.recv().await.expect("a frame"),
            Frame::FileChunk { .. }
        ));
    }

    #[tokio::test]
    async fn active_uploads_are_bounded_and_cancel_removes_temporary_file() {
        let (_root, home, _outside) = jail();
        let mut transfers = Transfers::with_home(home.clone(), 0);

        for i in 0..MAX_ACTIVE_TRANSFERS as u64 {
            transfers
                .start_upload(
                    TransferId(i),
                    home.join(format!("upload-{i}.bin"))
                        .to_string_lossy()
                        .into_owned(),
                    1,
                    None,
                    false,
                )
                .await
                .unwrap();
        }
        let err = transfers
            .start_upload(
                TransferId(99),
                home.join("one-too-many.bin").to_string_lossy().into_owned(),
                1,
                None,
                false,
            )
            .await
            .unwrap_err();
        assert!(err.contains("active file transfers"), "{err}");

        let temporary = home.join(".portty-upload-0.part");
        assert!(temporary.exists());
        transfers.cancel_upload(TransferId(0));
        assert!(!temporary.exists());
        transfers
            .start_upload(
                TransferId(100),
                home.join("replacement.bin").to_string_lossy().into_owned(),
                1,
                None,
                false,
            )
            .await
            .unwrap();
    }

    #[test]
    fn crash_registry_removes_stale_upload_on_next_host_start() {
        let data = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let temporary = home.path().join(".portty-upload-42.part");
        let (cleanup, removed) = UploadCleanup::open(data.path()).unwrap();
        assert_eq!(removed, 0);
        cleanup.track(&temporary).unwrap();
        std::fs::write(&temporary, b"partial").unwrap();
        assert!(temporary.exists());

        // Simulate a process crash by dropping only the in-memory registry,
        // without the normal Transfers cleanup path.
        drop(cleanup);
        let (_cleanup, removed) = UploadCleanup::open(data.path()).unwrap();
        assert_eq!(removed, 1);
        assert!(!temporary.exists());
        assert!(!data.path().join(PENDING_UPLOADS_RECORD).exists());
    }

    #[test]
    fn crash_registry_refuses_arbitrary_cleanup_paths() {
        let data = tempfile::tempdir().unwrap();
        let victim_dir = tempfile::tempdir().unwrap();
        let victim = victim_dir.path().join("keep.txt");
        std::fs::write(&victim, b"keep").unwrap();
        let store = FileCredentialStore::new(data.path());
        store
            .write(
                PENDING_UPLOADS_RECORD,
                &serde_json::to_vec(&vec![victim.clone()]).unwrap(),
                Durability::Required,
            )
            .unwrap();

        assert_eq!(
            UploadCleanup::open(data.path()).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(victim.exists());
    }
}
