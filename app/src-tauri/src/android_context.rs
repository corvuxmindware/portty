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

#![cfg(target_os = "android")]

use std::ffi::c_void;

use jni::objects::JObject;
use jni::JNIEnv;

/// JNI entry: `MainActivity.nativeInitNdkContext(Context)`.
///
/// Called once from `MainActivity.onCreate`. Initializes the global
/// `ndk_context` with the real `JavaVM` + a global ref to the supplied
/// application `Context`. The global ref is intentionally **leaked** so the
/// `jobject` stays valid for the process lifetime (matching `ndk_context`'s
/// expectation that the stored pointer outlives every reader). Returns `false`
/// on failure so Kotlin can stop startup before credential code attempts to use
/// Android Keystore without a valid application context.
#[no_mangle]
pub extern "system" fn Java_com_corvuxmindware_portty_MainActivity_nativeInitNdkContext(
    env: JNIEnv,
    _this: JObject,
    context: JObject,
) -> jni::sys::jboolean {
    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            eprintln!("portty ndk_context init: get_java_vm failed: {e}");
            return jni::sys::JNI_FALSE;
        }
    };
    let ctx_global = match env.new_global_ref(&context) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("portty ndk_context init: new_global_ref failed: {e}");
            return jni::sys::JNI_FALSE;
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
    jni::sys::JNI_TRUE
}
