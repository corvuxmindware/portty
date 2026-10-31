//! Android documents: the `content://` URIs the system file pickers return.
//!
//! Used only through `local_files.rs`. Everything here calls the platform's own
//! classes (`ContentResolver`, `Uri`, `Cursor`, `ParcelFileDescriptor`,
//! `DocumentsContract`) over JNI, on the calling thread - always a background
//! one. Two reasons this is not tauri-plugin-fs's `Fs::open`, although that also
//! yields a `std::fs::File`:
//!
//! - A Tauri mobile-plugin command runs on the Android main thread, and opening a
//!   document can block for as long as its provider likes (a cloud provider may
//!   fetch the whole file first). Here that wait stays off the UI.
//! - No Portty Kotlin is involved, so there is nothing for R8 to rename or strip
//!   in a minified release build, and no plugin library the Gradle build must
//!   include.

#![cfg(target_os = "android")]

use std::os::fd::FromRawFd;

use jni::objects::{JObject, JString, JValue};
use jni::JNIEnv;

use crate::local_files::Discard;

/// `ContentResolver.query(Uri, String[], String, String[], String)`.
const QUERY_SIGNATURE: &str = "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;\
                               [Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;";

/// Open a document: for reading (`"r"`), or for writing from empty (`"wt"`), so
/// a shorter download never keeps the tail of what the file held before.
pub(crate) fn open(uri: &str, write: bool) -> std::io::Result<std::fs::File> {
    let mode = if write { "wt" } else { "r" };
    let fd = with_resolver(|env, resolver| {
        let uri = parse_uri(env, uri)?;
        let mode = env.new_string(mode)?;
        // `openFileDescriptor` refuses a descriptor that covers only part of a
        // file, so what comes back is always the whole document.
        let descriptor = env
            .call_method(
                resolver,
                "openFileDescriptor",
                "(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;",
                &[JValue::from(&uri), JValue::from(&mode)],
            )?
            .l()?;
        if descriptor.is_null() {
            return Ok(-1);
        }
        // From here the Java object no longer closes the descriptor; the `File`
        // below does.
        env.call_method(&descriptor, "detachFd", "()I", &[])?.i()
    })
    .map_err(std::io::Error::other)?;
    if fd < 0 {
        return Err(std::io::Error::other(
            "the document provider returned no file",
        ));
    }
    // SAFETY: `detachFd` handed over sole ownership of this open descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// What the document is called (`OpenableColumns.DISPLAY_NAME`). Best effort:
/// `None` when the provider will not say.
pub(crate) fn display_name(uri: &str) -> Option<String> {
    with_resolver(|env, resolver| {
        let uri = parse_uri(env, uri)?;
        let column = env.new_string("_display_name")?;
        let projection = env.new_object_array(1, "java/lang/String", &column)?;
        let none = JObject::null();
        let cursor = env
            .call_method(
                resolver,
                "query",
                QUERY_SIGNATURE,
                &[
                    JValue::from(&uri),
                    JValue::from(&projection),
                    JValue::from(&none),
                    JValue::from(&none),
                    JValue::from(&none),
                ],
            )?
            .l()?;
        if cursor.is_null() {
            return Ok(None);
        }
        let name = first_string(env, &cursor);
        // Closed whatever the read did; `first_string` has already cleared any
        // exception it caused, so this call is legal.
        if env.call_method(&cursor, "close", "()V", &[]).is_err() {
            let _ = env.exception_clear();
        }
        name
    })
    .ok()
    .flatten()
}

/// Delete a document only while it is still a regular, empty file.
///
/// The emptiness check reads the document's own descriptor. A pipe (some cloud
/// providers) has no size to read, so it is never deleted: only a regular,
/// empty file is known to hold nothing anyone could lose.
///
/// A delete that throws is tried once more after a pause, in case the provider
/// was still busy with the file it has just created (scanning it, say).
///
/// `Removed` is the provider's word, and cannot be checked afterwards: a
/// successful delete revokes this app's access to the document. OnePlus's
/// Downloads provider is known to report success while deleting
/// `<name>.oplusdownload` instead, which is why the frontend asks the host
/// before the Save dialog creates anything (`download_probe.rs`).
pub(crate) fn discard_if_empty(uri: &str) -> Discard {
    let mut failure = String::new();
    for pause in [None, Some(std::time::Duration::from_millis(500))] {
        if let Some(pause) = pause {
            std::thread::sleep(pause);
        }
        let metadata = match open(uri, false).and_then(|file| file.metadata()) {
            Ok(metadata) => metadata,
            // After a failed delete the delete's own error says more.
            Err(_) if !failure.is_empty() => break,
            Err(error) => return Discard::Unchecked(format!("could not open it: {error}")),
        };
        if !metadata.is_file() {
            return Discard::Unchecked("it is not a regular file".into());
        }
        if metadata.len() != 0 {
            return Discard::HoldsData;
        }
        match delete_document(uri) {
            Ok(true) => return Discard::Removed,
            Ok(false) => failure = "its provider declined to delete it".into(),
            Err(error) => failure = error,
        }
    }
    Discard::Failed(failure)
}

/// `DocumentsContract.deleteDocument`. There is no other way in: a document
/// provider's `ContentResolver.delete` is final and always throws.
fn delete_document(uri: &str) -> Result<bool, String> {
    with_resolver(|env, resolver| {
        let uri = parse_uri(env, uri)?;
        env.call_static_method(
            "android/provider/DocumentsContract",
            "deleteDocument",
            "(Landroid/content/ContentResolver;Landroid/net/Uri;)Z",
            &[JValue::from(resolver), JValue::from(&uri)],
        )?
        .z()
    })
}

/// Run `f` with the application's `ContentResolver`, on this thread.
///
/// Errors carry the Java exception's text when there was one. The exception is
/// always cleared before returning: under CheckJNI (every debuggable build) the
/// next JNI call made with one still pending aborts the whole process.
fn with_resolver<T>(
    f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>,
) -> Result<T, String> {
    let android = ndk_context::android_context();
    // SAFETY: tao's Android bootstrap (0.37+, run from WryActivity.onCreate
    // before the Rust mobile entry) stores the process's JavaVM, and a global
    // reference to the application Context that is never deleted, before any
    // Tauri command that reaches here can run.
    let vm =
        unsafe { jni::JavaVM::from_raw(android.vm().cast()) }.map_err(|error| error.to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|error| error.to_string())?;
    // SAFETY: the same never-deleted global reference as above.
    let context = unsafe { JObject::from_raw(android.context().cast()) };
    let result = env.with_local_frame(16, |env| {
        let resolver = env
            .call_method(
                &context,
                "getContentResolver",
                "()Landroid/content/ContentResolver;",
                &[],
            )?
            .l()?;
        f(env, &resolver)
    });
    result.map_err(|error| take_exception(&mut env).unwrap_or_else(|| error.to_string()))
}

fn parse_uri<'local>(env: &mut JNIEnv<'local>, uri: &str) -> jni::errors::Result<JObject<'local>> {
    let text = env.new_string(uri)?;
    env.call_static_method(
        "android/net/Uri",
        "parse",
        "(Ljava/lang/String;)Landroid/net/Uri;",
        &[JValue::from(&text)],
    )?
    .l()
}

/// The first row's first column as a string. Clears any exception it causes.
fn first_string(env: &mut JNIEnv, cursor: &JObject) -> jni::errors::Result<Option<String>> {
    let mut read = || -> jni::errors::Result<Option<String>> {
        if !env.call_method(cursor, "moveToFirst", "()Z", &[])?.z()? {
            return Ok(None);
        }
        let value = env
            .call_method(
                cursor,
                "getString",
                "(I)Ljava/lang/String;",
                &[JValue::Int(0)],
            )?
            .l()?;
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(env.get_string(&JString::from(value))?.into()))
    };
    let result = read();
    if result.is_err() {
        let _ = env.exception_clear();
    }
    result
}

/// Clear the pending Java exception, if any, and return its text.
fn take_exception(env: &mut JNIEnv) -> Option<String> {
    if !env.exception_check().unwrap_or(false) {
        return None;
    }
    let text = env.with_local_frame(4, |env| -> jni::errors::Result<Option<String>> {
        let throwable = env.exception_occurred()?;
        env.exception_clear()?;
        let text = env
            .call_method(&throwable, "toString", "()Ljava/lang/String;", &[])
            .and_then(|value| value.l());
        match text {
            Ok(text) if !text.is_null() => Ok(Some(env.get_string(&JString::from(text))?.into())),
            _ => Ok(None),
        }
    });
    // Whatever happened above, leave nothing pending behind.
    let _ = env.exception_clear();
    text.ok().flatten()
}
