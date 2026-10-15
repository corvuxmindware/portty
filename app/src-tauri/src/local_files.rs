//! The phone's end of a file transfer: which local files the webview may name,
//! and how a verified download reaches the destination the user picked.
//!
//! Desktop and iOS name local files by path, as before. Android's system
//! pickers return `content://` documents instead - the open picker a document to
//! read, the Save dialog an empty document it has just created. Treating those
//! as paths is what broke both directions on Android: opening one failed with
//! ENOENT, and creating the download's directory beside one failed with EROFS.
//! So on Android every local file is a document, opened through
//! `android_documents.rs`, and a download is staged in the app's private cache
//! and copied into its document only after it verified.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use blake3::Hasher;
use tauri::{Emitter, Manager};

#[cfg(target_os = "android")]
use crate::android_documents as documents;

/// Off Android local files are paths, so these are never reached; they only
/// keep the shared code compiling.
#[cfg(not(target_os = "android"))]
mod documents {
    pub(crate) fn open(_uri: &str, _write: bool) -> std::io::Result<std::fs::File> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    pub(crate) fn display_name(_uri: &str) -> Option<String> {
        None
    }

    pub(crate) fn discard_if_empty(_uri: &str) -> super::Discard {
        super::Discard::Unchecked("documents exist only on Android".into())
    }
}

/// What became of a download destination nothing was saved into.
#[derive(Debug, PartialEq, Eq)]
// Built only by the Android provider code; elsewhere only matched.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) enum Discard {
    /// Its provider reports it deleted.
    Removed,
    /// It holds data, so it was left alone.
    HoldsData,
    /// It could not be checked, so it was left alone - it may be empty, or a
    /// file the user chose to overwrite. The text says why.
    Unchecked(String),
    /// It is empty, but deleting it failed; the text says why.
    Failed(String),
}

const CONTENT_SCHEME: &str = "content://";

/// The longest file name the common file systems accept, in bytes.
const MAX_FILE_NAME_BYTES: usize = 255;

/// A local file the webview named, once the platform's rules accepted it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LocalFile {
    /// Desktop and iOS: a path, used as before.
    Path(PathBuf),
    /// Android: a `content://` document from a system picker.
    Document(String),
}

/// Decide what a local file named by the webview may be.
///
/// Off Android it is a path, unchanged. On Android only a `content://` document
/// is accepted, which is all the system pickers ever return. A plain path is
/// refused: the UI never passes one there, and accepting it let the webview
/// name any file the app itself can read, its private data included. This
/// app's own providers are refused for the same reason (its FileProvider maps
/// the app's cache), and so is any authority spelled in a way that could hide
/// which provider it really is.
pub(crate) fn classify_local_file(
    raw: &str,
    android: bool,
    own_package: &str,
) -> Result<LocalFile, String> {
    if !android {
        return Ok(LocalFile::Path(PathBuf::from(raw)));
    }
    if is_foreign_document(raw, own_package) {
        Ok(LocalFile::Document(raw.to_owned()))
    } else {
        Err("only a file chosen in the system file picker can be transferred".into())
    }
}

fn is_foreign_document(uri: &str, own_package: &str) -> bool {
    if uri.chars().any(char::is_control) {
        return false;
    }
    let Some(rest) = uri.strip_prefix(CONTENT_SCHEME) else {
        return false;
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    // `<user id>@provider` is the same provider in another Android user or
    // profile; Android resolves it by the part after the `@`.
    let provider = match authority.split_once('@') {
        Some((user, provider)) if !user.is_empty() && user.bytes().all(|b| b.is_ascii_digit()) => {
            provider
        }
        Some(_) => return false,
        None => authority,
    };
    // Authorities are plain dotted names. Anything else - `%` escapes above
    // all, which Android decodes before it looks the provider up - could hide
    // this app's own name from the comparison below.
    let plain = !provider.is_empty()
        && provider
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !plain {
        return false;
    }
    let provider = provider.to_ascii_lowercase();
    let own = own_package.to_ascii_lowercase();
    provider != own && !provider.starts_with(&format!("{own}."))
}

/// The host file name to offer for an upload: the picked file's own name.
///
/// `display_name` is what the document's provider calls it (Android). Without
/// one, the name comes from the path, or from a document id that is itself a
/// path. An opaque id such as `document:83` names nothing - offering its escaped
/// form, `document%3A83`, was the bug - so the last resort is a plain "upload".
pub(crate) fn suggested_upload_name(display_name: Option<&str>, local: &str) -> String {
    display_name
        .and_then(plain_file_name)
        .or_else(|| {
            if local.starts_with(CONTENT_SCHEME) {
                name_in_document_uri(local)
            } else {
                plain_file_name(local)
            }
        })
        .unwrap_or_else(|| "upload".to_owned())
}

/// How the UI names a download's destination document.
pub(crate) fn document_label(display_name: Option<&str>, uri: &str) -> String {
    display_name
        .and_then(plain_file_name)
        .or_else(|| name_in_document_uri(uri))
        .unwrap_or_else(|| "the chosen file".to_owned())
}

/// Reduce a name from a provider, a path or a URI to one plain file name that
/// any host can create: no directories, no control characters, none of the
/// characters Windows reserves (a `:` there writes an alternate data stream),
/// and no longer than file systems allow.
fn plain_file_name(raw: &str) -> Option<String> {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return None;
    }
    let mut end = cleaned.len().min(MAX_FILE_NAME_BYTES);
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    Some(cleaned[..end].trim_end().to_owned())
}

/// The file name inside a document URI, when its document id is a path.
fn name_in_document_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix(CONTENT_SCHEME)?;
    let path = rest.split(['?', '#']).next().unwrap_or(rest);
    let (_, segment) = path.rsplit_once('/')?;
    let id = percent_decode(segment)?;
    // Path-like ids (`primary:Download/notes.txt`, `raw:/storage/.../notes.txt`)
    // end in the file's name; opaque ones (`document:83`, `msf:1000034`) do not.
    if !id.contains('/') {
        return None;
    }
    plain_file_name(&id)
}

fn percent_decode(text: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let [high, low, ..] = tail else {
                return None;
            };
            let digit = |b: u8| char::from(b).to_digit(16);
            decoded.push((digit(*high)? * 16 + digit(*low)?) as u8);
            rest = &tail[2..];
        } else {
            decoded.push(byte);
            rest = tail;
        }
    }
    String::from_utf8(decoded).ok()
}

/// The host file name to offer for an upload the user just picked.
///
/// The frontend names a picked path itself. Android's picker returns a URI whose
/// last segment is an opaque document id instead, so the name has to come from
/// the document's provider.
#[tauri::command]
pub(crate) async fn suggest_upload_name(
    app: tauri::AppHandle,
    local_path: String,
) -> Result<String, String> {
    let display_name = match classify_local_file(
        &local_path,
        cfg!(target_os = "android"),
        &app.config().identifier,
    )? {
        LocalFile::Path(_) => None,
        LocalFile::Document(uri) => {
            tokio::task::spawn_blocking(move || documents::display_name(&uri))
                .await
                .ok()
                .flatten()
        }
    };
    Ok(suggested_upload_name(display_name.as_deref(), &local_path))
}

/// An upload's source, opened.
pub(crate) struct UploadSource {
    pub(crate) file: tokio::fs::File,
    /// Picked as an Android document rather than named by a path.
    pub(crate) is_document: bool,
}

/// Open an upload's source: a path as before, or (Android) a picked document.
pub(crate) async fn open_upload_source(
    app: &tauri::AppHandle,
    local_path: &str,
) -> Result<UploadSource, String> {
    match classify_local_file(
        local_path,
        cfg!(target_os = "android"),
        &app.config().identifier,
    )? {
        LocalFile::Path(path) => Ok(UploadSource {
            file: tokio::fs::File::open(&path)
                .await
                .map_err(|e| format!("cannot open upload: {e}"))?,
            is_document: false,
        }),
        LocalFile::Document(uri) => {
            // Off the async workers: a provider may take its time (a cloud one
            // can fetch the whole file before it answers).
            let file = tokio::task::spawn_blocking(move || documents::open(&uri, false))
                .await
                .map_err(|e| format!("cannot open upload: {e}"))?
                .map_err(|e| format!("cannot open upload: {e}"))?;
            Ok(UploadSource {
                file: tokio::fs::File::from_std(file),
                is_document: true,
            })
        }
    }
}

/// Where a download lands once it has verified.
pub(crate) enum DownloadTarget {
    /// Desktop and iOS: a path. The verified `.part` beside it is renamed onto it.
    Path(PathBuf),
    /// Android: the document the Save dialog created. The download is staged
    /// in the app's private cache and copied in only after it verified.
    Document(SavedDocument),
}

impl DownloadTarget {
    /// How the UI names this destination.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Path(path) => path.to_string_lossy().into_owned(),
            Self::Document(document) => document.label.clone(),
        }
    }
}

/// A download's destination document.
///
/// The Save dialog creates it, empty, before a single byte has arrived, so a
/// download that never completes would leave a file under the chosen name that
/// looks like the download. Dropping one that was not settled therefore removes
/// the document again - but only while it is still empty. A file the user chose
/// to overwrite is not even opened until the new bytes have verified.
pub(crate) struct SavedDocument {
    uri: String,
    label: String,
    settled: bool,
    /// Shows a note after the transfer's status line (an app event). A boxed
    /// callback rather than the `AppHandle` itself: dropping a download then
    /// carries none of the app's own drop glue, which on Windows pulls menu code
    /// needing comctl32 v6 into every test binary that drops a transfer - and
    /// test binaries have no manifest to provide it.
    note: Box<dyn Fn(String) + Send + Sync>,
}

/// An addendum to a transfer's outcome, shown after the status line it follows.
#[derive(serde::Serialize, Clone)]
struct TransferNotePayload {
    message: String,
}

impl Drop for SavedDocument {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let uri = std::mem::take(&mut self.uri);
        let label = std::mem::take(&mut self.label);
        let note = std::mem::replace(&mut self.note, Box::new(|_| {}));
        // A content-provider round trip: never on the dropping (async) thread.
        tauri::async_runtime::spawn_blocking(move || {
            let outcome = documents::discard_if_empty(&uri);
            log_cleanup(&label, &outcome);
            if let Some(message) = cleanup_note(&label, &outcome) {
                note(message);
            }
        });
    }
}

/// Log what became of an unused destination. A provider's "removed" is logged
/// too, because it cannot be checked afterwards (see `discard_if_empty`).
///
/// Only the `info` lines name the file: warnings still reach logcat in release
/// builds, and a file name is the user's business.
fn log_cleanup(label: &str, outcome: &Discard) {
    match outcome {
        Discard::Removed => {
            tracing::info!(file = %label, "provider removed the unused download destination")
        }
        Discard::HoldsData => {
            tracing::info!(file = %label, "kept the download destination: it holds data")
        }
        Discard::Unchecked(error) => {
            tracing::warn!(%error, "could not check the unused download destination")
        }
        Discard::Failed(error) => {
            tracing::warn!(%error, "could not remove the unused download destination")
        }
    }
}

/// What the user is told about an unused destination, when it matters: a file
/// that may be an empty leftover would mislead them. Never told to delete what
/// may be a file they chose to overwrite.
fn cleanup_note(label: &str, outcome: &Discard) -> Option<String> {
    match outcome {
        Discard::Failed(why) => Some(format!(
            "The empty file \"{label}\" made for this download could not be removed \
             ({why}) - delete it in your files app."
        )),
        Discard::Unchecked(why) => Some(format!(
            "Could not check \"{label}\" ({why}) - if it is an empty file left by this \
             download, delete it in your files app."
        )),
        Discard::Removed | Discard::HoldsData => None,
    }
}

/// Resolve a download's destination, and the directory to stage its `.part`
/// file in (the caller creates it). A path is staged beside itself, as before.
pub(crate) async fn prepare_download_target(
    app: &tauri::AppHandle,
    local_path: &str,
) -> Result<(DownloadTarget, PathBuf), String> {
    match classify_local_file(
        local_path,
        cfg!(target_os = "android"),
        &app.config().identifier,
    )? {
        LocalFile::Path(target) => {
            let parent = target
                .parent()
                .ok_or_else(|| "download destination has no parent directory".to_string())?
                .to_path_buf();
            Ok((DownloadTarget::Path(target), parent))
        }
        LocalFile::Document(uri) => {
            // Owned from the start: any refusal below removes the empty document.
            let notes = app.clone();
            let mut document = SavedDocument {
                uri,
                label: String::new(),
                settled: false,
                note: Box::new(move |message| {
                    let _ = notes.emit("portty://transfer-note", TransferNotePayload { message });
                }),
            };
            let app = app.clone();
            let uri = document.uri.clone();
            let (label, cache) = tokio::task::spawn_blocking(move || {
                let label = document_label(documents::display_name(&uri).as_deref(), &uri);
                (label, app.path().app_cache_dir())
            })
            .await
            .map_err(|e| format!("cannot prepare the download: {e}"))?;
            document.label = label;
            // The app's private cache: nothing can be created beside a document,
            // and nothing else on the phone can read or swap a file staged here.
            let cache = cache.map_err(|e| format!("cannot find the app's cache directory: {e}"))?;
            Ok((DownloadTarget::Document(document), cache))
        }
    }
}

/// Copy a verified download into its document, off the session loop: a large
/// file takes a while, and the loop has to keep serving the link meanwhile.
pub(crate) fn spawn_document_commit(
    app: tauri::AppHandle,
    id: u64,
    staging: PathBuf,
    mut document: SavedDocument,
    size: u64,
    checksum: [u8; 32],
    slot: tokio::sync::OwnedSemaphorePermit,
) {
    tauri::async_runtime::spawn_blocking(move || {
        // The copy is still this transfer's work, so it keeps the transfer slot.
        let _slot = slot;
        let result = commit_by_copy(&staging, size, &checksum, || {
            documents::open(&document.uri, true)
        });
        // Settled either way: a success needs nothing removed, and a failure is
        // cleaned up right here, where the outcome can still be reported.
        document.settled = true;
        match result {
            Ok(()) => {
                let _ = app.emit(
                    "portty://transfer-complete",
                    crate::TransferCompletePayload {
                        id,
                        direction: "download",
                        path: document.label.clone(),
                    },
                );
            }
            Err(failure) => {
                let outcome = documents::discard_if_empty(&document.uri);
                log_cleanup(&document.label, &outcome);
                let message = commit_failure_message(&document.label, &failure, &outcome);
                let _ = app.emit(
                    "portty://transfer-error",
                    crate::TransferErrorPayload { id, message },
                );
            }
        }
    });
}

/// The error for a download that verified but could not be saved, saying what
/// was left at the destination.
fn commit_failure_message(label: &str, failure: &CommitFailure, outcome: &Discard) -> String {
    let mut message = format!(
        "could not save the download into {label}: {}",
        failure.error
    );
    let left = match outcome {
        Discard::Removed => "the unfinished file was removed".to_string(),
        Discard::Failed(why) | Discard::Unchecked(why) => {
            if matches!(outcome, Discard::Failed(_)) || failure.emptied {
                // Checked empty, or emptied here after the copy failed.
                format!("{label} was left empty and could not be removed ({why}); delete it")
            } else if failure.destination_opened {
                format!("{label} may be incomplete and could not be removed ({why}); delete it")
            } else {
                // Never opened: an empty leftover, or a file the user chose to
                // overwrite still as it was. Which one cannot be told.
                format!("nothing was written to {label}; if it is empty, delete it ({why})")
            }
        }
        Discard::HoldsData if failure.destination_opened => {
            format!("{label} may be incomplete; delete it")
        }
        // Never opened, so a file the user chose to overwrite is unchanged.
        Discard::HoldsData => return message,
    };
    message.push_str(" - ");
    message.push_str(&left);
    message
}

/// Why a verified download could not be copied into its destination.
#[derive(Debug)]
pub(crate) struct CommitFailure {
    pub(crate) error: std::io::Error,
    /// The destination had been opened - and so truncated - when it failed.
    pub(crate) destination_opened: bool,
    /// After such a failure the destination was cut back to empty, so nothing
    /// half-written is left passing for the real file.
    pub(crate) emptied: bool,
}

/// Install a verified download by copying it into a destination it cannot be
/// renamed onto, then remove its staging file - on failure too.
///
/// The destination is opened only once the staged file is open for reading, so
/// a download that is already lost never touches it. The bytes are hashed
/// again on the way through: what lands must be exactly what verified.
pub(crate) fn commit_by_copy(
    staging: &Path,
    size: u64,
    checksum: &[u8; 32],
    open_destination: impl FnOnce() -> std::io::Result<std::fs::File>,
) -> Result<(), CommitFailure> {
    let outcome = match std::fs::File::open(staging) {
        Err(error) => Err((error, None)),
        Ok(source) => match open_destination() {
            Err(error) => Err((error, None)),
            Ok(mut destination) => match copy_verified(source, &mut destination, size, checksum) {
                Ok(()) => Ok(()),
                Err(error) => Err((error, Some(destination))),
            },
        },
    };
    let _ = std::fs::remove_file(staging);
    outcome.map_err(|(error, destination)| match destination {
        None => CommitFailure {
            error,
            destination_opened: false,
            emptied: false,
        },
        Some(destination) => CommitFailure {
            error,
            destination_opened: true,
            emptied: destination.set_len(0).is_ok(),
        },
    })
}

fn copy_verified(
    mut source: std::fs::File,
    destination: &mut std::fs::File,
    size: u64,
    checksum: &[u8; 32],
) -> std::io::Result<()> {
    let mut hasher = Hasher::new();
    let mut copied = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        copied += read as u64;
        if copied > size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the staged download is larger than what was verified",
            ));
        }
        hasher.update(&buffer[..read]);
        destination.write_all(&buffer[..read])?;
    }
    if copied != size || hasher.finalize().as_bytes() != checksum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the staged download no longer matches what was verified",
        ));
    }
    destination.flush()?;
    match destination.sync_all() {
        // Some document providers hand out a pipe, which cannot be synced; the
        // provider commits what it received when the descriptor closes.
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = "org.example.portty";
    /// What the system picker returned for the upload that failed on-device.
    const PICKED: &str = "content://com.android.providers.media.documents/document/document%3A83";
    /// A Save-dialog document whose id is a path (ExternalStorageProvider).
    const SAVED: &str = "content://com.android.externalstorage.documents/document/\
                         primary%3ADownload%2Fportty-download-test.txt";

    #[test]
    fn android_transfers_picker_documents_not_paths() {
        assert_eq!(
            classify_local_file(PICKED, true, OWN),
            Ok(LocalFile::Document(PICKED.into()))
        );
        assert_eq!(
            classify_local_file(SAVED, true, OWN),
            Ok(LocalFile::Document(SAVED.into()))
        );
        // The same provider in a work profile is still a picker document.
        let profile = "content://10@com.android.providers.media.documents/document/image%3A5";
        assert!(matches!(
            classify_local_file(profile, true, OWN),
            Ok(LocalFile::Document(_))
        ));
        for refused in [
            "/data/user/0/org.example.portty/files/portty-host-names.dat",
            "/sdcard/Download/notes.txt",
            "notes.txt",
            "",
            "file:///sdcard/Download/notes.txt",
            "https://example.com/notes.txt",
            "CONTENT://com.android.providers.media.documents/document/document%3A83",
            "content:///document/1",
            "content://",
        ] {
            assert!(
                classify_local_file(refused, true, OWN).is_err(),
                "{refused:?} must be refused on Android"
            );
        }
    }

    #[test]
    fn android_refuses_the_apps_own_providers_however_they_are_spelled() {
        for refused in [
            "content://org.example.portty.fileprovider/my_cache_images/x.part",
            "content://ORG.Example.Portty.FileProvider/my_cache_images/x.part",
            "content://0@org.example.portty.fileprovider/my_cache_images/x.part",
            "content://org%2Eexample%2Eportty%2Efileprovider/my_cache_images/x.part",
            "content://org.example.portty/x",
            "content://me@com.android.providers.media.documents/document/1",
            "content://com.android.providers.media.documents:80/document/1",
            "content://com.android.providers.media.documents/document/1\n",
        ] {
            assert!(
                classify_local_file(refused, true, OWN).is_err(),
                "{refused:?} must be refused"
            );
        }
        // Sharing a prefix with the package name does not make a provider ours.
        assert!(classify_local_file("content://org.example.porttyx/d/1", true, OWN).is_ok());
    }

    #[test]
    fn desktop_and_ios_still_take_paths() {
        assert_eq!(
            classify_local_file("/home/user/notes.txt", false, OWN),
            Ok(LocalFile::Path("/home/user/notes.txt".into()))
        );
        assert_eq!(
            classify_local_file(r"C:\Users\me\notes.txt", false, OWN),
            Ok(LocalFile::Path(r"C:\Users\me\notes.txt".into()))
        );
    }

    #[test]
    fn an_upload_is_offered_under_its_own_name_never_its_document_id() {
        assert_eq!(
            suggested_upload_name(Some("portty-upload-test.txt"), PICKED),
            "portty-upload-test.txt"
        );
        // No name from the provider and an opaque id: not `document%3A83`.
        assert_eq!(suggested_upload_name(None, PICKED), "upload");
        assert_eq!(
            suggested_upload_name(None, "content://media/external/images/media/123"),
            "upload"
        );
        // Ids that are paths carry the name.
        assert_eq!(
            suggested_upload_name(None, SAVED),
            "portty-download-test.txt"
        );
        assert_eq!(
            suggested_upload_name(
                None,
                "content://com.android.providers.downloads.documents/document/\
                 raw%3A%2Fstorage%2Femulated%2F0%2FDownload%2Fnotes.txt"
            ),
            "notes.txt"
        );
        // Paths are named the way the frontend always named them.
        assert_eq!(
            suggested_upload_name(None, "/home/user/notes.txt"),
            "notes.txt"
        );
        assert_eq!(
            suggested_upload_name(None, r"C:\Users\me\notes.txt"),
            "notes.txt"
        );
    }

    #[test]
    fn a_provider_supplied_name_is_reduced_to_one_plain_file_name() {
        assert_eq!(
            suggested_upload_name(Some("../../.ssh/authorized_keys"), PICKED),
            "authorized_keys"
        );
        assert_eq!(
            suggested_upload_name(Some(r"..\..\boot.ini"), PICKED),
            "boot.ini"
        );
        assert_eq!(
            suggested_upload_name(Some("re\u{7}port\n.txt"), PICKED),
            "report.txt"
        );
        assert_eq!(
            suggested_upload_name(Some("notes.txt:hidden"), PICKED),
            "notes.txt_hidden"
        );
        for nothing in ["", "   ", ".", "..", "folder/", "\u{1b}"] {
            assert_eq!(
                suggested_upload_name(Some(nothing), PICKED),
                "upload",
                "{nothing:?}"
            );
        }
        let long = suggested_upload_name(Some(&"é".repeat(200)), PICKED);
        assert!(long.len() <= MAX_FILE_NAME_BYTES);
        assert!(!long.is_empty() && long.chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_destination_document_is_labelled_by_its_name() {
        assert_eq!(
            document_label(Some("portty-download-test (1).txt"), SAVED),
            "portty-download-test (1).txt"
        );
        assert_eq!(document_label(None, SAVED), "portty-download-test.txt");
        assert_eq!(
            document_label(
                None,
                "content://com.android.providers.downloads.documents/document/msf%3A1000034"
            ),
            "the chosen file"
        );
    }

    #[test]
    fn percent_decoding_refuses_what_it_cannot_read() {
        assert_eq!(
            percent_decode("primary%3ADownload%2Fn%C3%A9.txt").as_deref(),
            Some("primary:Download/né.txt")
        );
        assert_eq!(percent_decode("cut%2"), None);
        assert_eq!(percent_decode("bad%zz"), None);
        assert_eq!(percent_decode("%FF"), None);
    }

    fn checksum(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn overwrite(path: &Path) -> impl FnOnce() -> std::io::Result<std::fs::File> + '_ {
        move || {
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
        }
    }

    #[test]
    fn a_verified_download_is_copied_in_exactly_and_its_staging_file_removed() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join(".portty-download-1-0123456789abcdef.part");
        let destination = dir.path().join("notes.txt");
        // Several copy buffers' worth, replacing a longer file the user chose to
        // overwrite: nothing of the old tail may survive.
        let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&staging, &bytes).unwrap();
        std::fs::write(&destination, vec![0xAA; 300_000]).unwrap();

        commit_by_copy(
            &staging,
            bytes.len() as u64,
            &checksum(&bytes),
            overwrite(&destination),
        )
        .unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        assert!(!staging.exists());
    }

    #[test]
    fn the_destination_is_not_opened_once_the_staged_file_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("notes.txt");
        std::fs::write(&destination, b"keep me").unwrap();

        let failure = commit_by_copy(
            &dir.path().join("missing.part"),
            4,
            &checksum(b"data"),
            || -> std::io::Result<std::fs::File> {
                panic!("the destination was opened for a download that is already lost")
            },
        )
        .unwrap_err();

        assert!(!failure.destination_opened);
        assert_eq!(std::fs::read(&destination).unwrap(), b"keep me");
    }

    #[test]
    fn a_destination_that_cannot_be_opened_is_reported_and_the_staging_file_removed() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("download.part");
        std::fs::write(&staging, b"data").unwrap();

        let failure = commit_by_copy(&staging, 4, &checksum(b"data"), || {
            Err(std::io::ErrorKind::PermissionDenied.into())
        })
        .unwrap_err();

        assert_eq!(failure.error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!failure.destination_opened);
        assert!(!staging.exists());
    }

    #[test]
    fn staged_bytes_that_no_longer_verify_leave_the_destination_empty() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("notes.txt");
        let verified = b"the bytes that verified".to_vec();
        for staged in [
            b"the bytes that DID NOT!".to_vec(), // same length, other bytes
            b"the bytes that".to_vec(),          // cut short
            [verified.as_slice(), b" and more"].concat(), // grown
        ] {
            let staging = dir.path().join("download.part");
            std::fs::write(&staging, &staged).unwrap();
            std::fs::write(&destination, b"old contents").unwrap();

            let failure = commit_by_copy(
                &staging,
                verified.len() as u64,
                &checksum(&verified),
                overwrite(&destination),
            )
            .unwrap_err();

            assert_eq!(failure.error.kind(), std::io::ErrorKind::InvalidData);
            assert!(failure.destination_opened && failure.emptied);
            assert_eq!(std::fs::metadata(&destination).unwrap().len(), 0);
            assert!(!staging.exists());
        }
    }

    /// The on-device failure: an empty Save-dialog file left behind with the
    /// user told nothing. Only a failed removal is worth a word; a provider's
    /// "removed" and a file holding data are not.
    #[test]
    fn only_a_leftover_empty_file_is_reported() {
        let failed = Discard::Failed("java.lang.IllegalStateException: busy".into());
        let note = cleanup_note("does-not-exist.txt", &failed).expect("a note");
        assert!(note.contains("\"does-not-exist.txt\""));
        assert!(note.contains("could not be removed (java.lang.IllegalStateException: busy)"));
        assert_eq!(cleanup_note("a.txt", &Discard::Removed), None);
        assert_eq!(cleanup_note("a.txt", &Discard::HoldsData), None);
        // Unchecked may be a file the user chose to overwrite: never "delete
        // it" unconditionally.
        let unchecked = cleanup_note("a.txt", &Discard::Unchecked("no access".into()));
        let unchecked = unchecked.expect("a note");
        assert!(unchecked.contains("if it is an empty file left by this download, delete it"));
    }

    fn failure(destination_opened: bool, emptied: bool) -> CommitFailure {
        CommitFailure {
            error: std::io::Error::other("disk full"),
            destination_opened,
            emptied,
        }
    }

    #[test]
    fn a_failed_save_says_what_was_left_at_the_destination() {
        let message = |opened, emptied, outcome| {
            commit_failure_message("notes.txt", &failure(opened, emptied), &outcome)
        };
        let busy = || Discard::Failed("busy".into());
        assert_eq!(
            message(true, true, Discard::Removed),
            "could not save the download into notes.txt: disk full \
             - the unfinished file was removed"
        );
        assert!(message(true, true, busy())
            .ends_with("notes.txt was left empty and could not be removed (busy); delete it"));
        // Never opened: the Save dialog's placeholder, still empty.
        assert!(message(false, false, busy())
            .ends_with("notes.txt was left empty and could not be removed (busy); delete it"));
        // Checked empty, so empty however the copy went.
        assert!(message(true, false, busy())
            .ends_with("notes.txt was left empty and could not be removed (busy); delete it"));
        let unchecked = || Discard::Unchecked("no access".into());
        assert!(message(true, true, unchecked())
            .ends_with("notes.txt was left empty and could not be removed (no access); delete it"));
        assert!(message(true, false, unchecked()).ends_with(
            "notes.txt may be incomplete and could not be removed (no access); delete it"
        ));
        // Never opened and never checked: perhaps the user's own file.
        assert!(message(false, false, unchecked())
            .ends_with("nothing was written to notes.txt; if it is empty, delete it (no access)"));
        assert!(message(true, false, Discard::HoldsData)
            .ends_with("notes.txt may be incomplete; delete it"));
        // A file the user chose to overwrite, never opened, is not mentioned.
        assert_eq!(
            message(false, false, Discard::HoldsData),
            "could not save the download into notes.txt: disk full"
        );
    }
}
