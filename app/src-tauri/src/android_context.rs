//! Android `ndk_context` initialization shim.
//!
//! Lifted from Corvux `src-tauri/src/android_context.rs` (see the
//! `lift-from-corvux` skill). Adapted for Portty: the symbol is bound to
//! `MainActivity` instead of Corvux's `MulticastLockPlugin`, because Portty
//! has no LAN/mDNS discovery and therefore no need for a full Android plugin
//! - it needs only the ndk_context init.
//!
//! ## Why this exists
//!
//! Crates that reach Android system APIs from native code - here, iroh's
//! network monitor, built the first time `build_endpoint` runs (i.e. when the
//! user taps Pair) - read the process-global Android context via
//! [`ndk_context::android_context`]. That global is normally set by tao's
//! `create()` JNI binding, **but Tauri V2's Android flow never runs that
//! path**, so the global stays empty. iroh then reads it and `ndk-context`
//! panics with *"android context was not initialized"*, and under
//! `panic = "abort"` that becomes a `SIGABRT` killing the whole process.
//!
//! Portty wires the init from `MainActivity.onCreate` (Kotlin), which is the
//! earliest hook with the Application `Context` in hand and runs well before
//! any pairing. The Kotlin side calls `System.loadLibrary("portty_app_lib")`
//! first (idempotent) so the `external fun` below always resolves. See
//! tauri-apps/tauri#13267 for why Tauri V2 exposes no public API for this.
//!
//! ## Once per process, not once per call
//!
//! `onCreate` runs once per Activity, and Android can create a second
//! `MainActivity` in the same process (a configuration change the manifest
//! does not absorb, or a launch that clears the task). `ndk_context` asserts
//! that it is initialized exactly once, and a panic inside this
//! `extern "system"` function aborts the process - so a repeat call must be a
//! no-op that reports success. The first call stored the *application*
//! `Context`, which is the same for every Activity, so there is nothing to
//! refresh.

// The JNI entry is Android-only; the once-guard also builds for host unit tests.
#[cfg(target_os = "android")]
use std::ffi::c_void;
use std::sync::{Mutex, PoisonError};

#[cfg(target_os = "android")]
use jni::objects::JObject;
#[cfg(target_os = "android")]
use jni::JNIEnv;

/// Runs `init` until it reports success once; after that, reports success
/// without running it again. A failed attempt is not remembered, so a later
/// call retries it. The lock makes concurrent first calls take turns, so
/// `init` can never succeed twice.
fn init_once(initialized: &Mutex<bool>, init: impl FnOnce() -> bool) -> bool {
    let mut initialized = initialized.lock().unwrap_or_else(PoisonError::into_inner);
    if !*initialized {
        *initialized = init();
    }
    *initialized
}

/// JNI entry: `MainActivity.nativeInitNdkContext(Context)`.
///
/// Called from every `MainActivity.onCreate`; only the first successful call
/// in a process initializes the global `ndk_context` (see [`init_once`]).
/// Returns `false` on failure so Kotlin can stop startup before credential
/// code attempts to use Android Keystore without a valid application context.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_corvuxmindware_portty_MainActivity_nativeInitNdkContext(
    env: JNIEnv,
    _this: JObject,
    context: JObject,
) -> jni::sys::jboolean {
    static NDK_CONTEXT_INITIALIZED: Mutex<bool> = Mutex::new(false);
    if init_once(&NDK_CONTEXT_INITIALIZED, || {
        initialize_ndk_context(&env, &context)
    }) {
        jni::sys::JNI_TRUE
    } else {
        jni::sys::JNI_FALSE
    }
}

/// Initializes the global `ndk_context` with the real `JavaVM` + a global ref
/// to the supplied application `Context`. The global ref is intentionally
/// **leaked** so the `jobject` stays valid for the process lifetime (matching
/// `ndk_context`'s expectation that the stored pointer outlives every reader).
/// Must run at most once per process: `ndk_context` asserts on a second call.
#[cfg(target_os = "android")]
fn initialize_ndk_context(env: &JNIEnv, context: &JObject) -> bool {
    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            eprintln!("portty ndk_context init: get_java_vm failed: {e}");
            return false;
        }
    };
    let ctx_global = match env.new_global_ref(context) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("portty ndk_context init: new_global_ref failed: {e}");
            return false;
        }
    };

    // SAFETY: `get_java_vm_pointer()` returns the process-global JavaVM, valid
    // for the process lifetime. `ctx_global` is a JNI global reference we leak
    // immediately below, so the underlying `jobject` remains valid as long as
    // `ndk_context` holds the raw pointer (i.e. forever, in practice).
    unsafe {
        ndk_context::initialize_android_context(
            vm.get_java_vm_pointer() as *mut c_void,
            ctx_global.as_raw() as *mut c_void,
        );
    }
    std::mem::forget(ctx_global);

    eprintln!("portty ndk_context initialized via MainActivity.onCreate");
    true
}

#[cfg(test)]
mod tests {
    use super::init_once;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// An `init` that counts its runs and reports `result`.
    fn counted(runs: &AtomicUsize, result: bool) -> impl FnOnce() -> bool + '_ {
        move || {
            runs.fetch_add(1, Ordering::SeqCst);
            result
        }
    }

    #[test]
    fn a_repeat_call_reports_success_without_initializing_again() {
        let initialized = Mutex::new(false);
        let runs = AtomicUsize::new(0);

        assert!(init_once(&initialized, counted(&runs, true)));
        // A re-created MainActivity calls in again. Running init a second time
        // is exactly the `assert!(previous.is_none())` abort seen on device.
        assert!(init_once(&initialized, counted(&runs, true)));
        assert!(init_once(&initialized, counted(&runs, true)));

        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_init_is_retried_rather_than_remembered() {
        let initialized = Mutex::new(false);
        let runs = AtomicUsize::new(0);

        // A failure happens before ndk_context is touched, so retrying is safe.
        assert!(!init_once(&initialized, counted(&runs, false)));
        assert!(init_once(&initialized, counted(&runs, true)));
        assert!(init_once(&initialized, counted(&runs, true)));

        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_first_calls_initialize_exactly_once() {
        let initialized = Mutex::new(false);
        let runs = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            let callers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| init_once(&initialized, counted(&runs, true))))
                .collect();
            for caller in callers {
                assert!(caller.join().expect("caller thread panicked"));
            }
        });

        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
