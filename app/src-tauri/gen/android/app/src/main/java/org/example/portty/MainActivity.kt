package org.example.portty

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.firebase.FirebaseApp

class MainActivity : TauriActivity() {
  /** The wry WebView, captured in onWebViewCreate; used by the back handler. */
  private var porttyWebView: WebView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    // Block the Recents/app-switcher thumbnail (and screenshots) from capturing
    // the terminal or a pending approval. FLAG_SECURE is the guaranteed Android
    // layer; the webview privacy cover in BiometricGate is best-effort on top.
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE,
    )
    // Rust setup now opens the Keystore-backed Portty credential store, so the
    // application context must exist before Tauri enters the Rust mobile entry.
    initNdkContext()
    super.onCreate(savedInstanceState)
    // Cold start from a push-notification tap: for notification+data FCM
    // messages delivered in the background, Android posts the notification
    // itself and hands the data payload to the launcher intent as extras.
    storeWakeFromIntent(intent)
    requestNotificationPermissionIfPushEnabled()
    registerBackHandler()
  }

  /**
   * Route the Android back gesture (button or swipe) through the web UI. On each
   * back press we ask the web layer to peel ONE layer off the top - an open menu
   * / sheet, or a sub-screen returning to the session list - via
   * `window.__porttyOnBack()`. Only when the web UI reports it consumed nothing
   * (returns false) do we background the app, so the user is never trapped and
   * back never bypasses the lock. Tauri's own webview-history back is disabled
   * (WryActivity.handleBackNavigation is overridden false), so we own this.
   */
  private fun registerBackHandler() {
    onBackPressedDispatcher.addCallback(
      this,
      object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
          val wv = porttyWebView
          if (wv == null) {
            this@MainActivity.moveTaskToBack(true)
            return
          }
          wv.evaluateJavascript(
            "(function(){try{return (window.__porttyOnBack && window.__porttyOnBack()) ? true : false}catch(e){return false}})()",
          ) { result ->
            // evaluateJavascript stringifies the boolean; anything but "true"
            // (false / null on error) means the web UI didn't consume it.
            if (result != "true") this@MainActivity.moveTaskToBack(true)
          }
        }
      },
    )
  }

  /** Wry hands us the WebView here once created; kept so the back handler can
   *  ask the web UI to handle the gesture. */
  override fun onWebViewCreate(webView: WebView) {
    porttyWebView = webView
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    // Warm tap (activity already alive, launchMode=singleTask).
    storeWakeFromIntent(intent)
  }

  /**
   * Android 13+ shows no notifications until the user grants POST_NOTIFICATIONS
   * at runtime - the manifest entry alone is not enough. iOS asks at launch
   * (push_glue.mm `requestAuthorizationWithOptions`); this is the Android twin.
   * Gated on FirebaseApp actually being initialized, so builds without a
   * google-services.json (push dormant, see packaging/PUSH-SETUP.md) never show
   * a pointless prompt.
   */
  private fun requestNotificationPermissionIfPushEnabled() {
    if (Build.VERSION.SDK_INT < 33) return
    try {
      if (FirebaseApp.getApps(this).isEmpty()) return
      val granted =
        ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
          PackageManager.PERMISSION_GRANTED
      if (granted) return
      ActivityCompat.requestPermissions(
        this,
        arrayOf(Manifest.permission.POST_NOTIFICATIONS),
        REQUEST_POST_NOTIFICATIONS,
      )
    } catch (ex: Throwable) {
      // A push nicety must never break launch; the doorbell just stays silent.
      Log.w("PorttyPush", "notification permission request skipped: ${ex.message}")
    }
  }

  /**
   * Bridge the opaque `wake` payload to the Rust core (see push_wake.rs).
   *
   * This activity is `exported="true"` because it is the launcher, so ANY app on
   * the device can start it with a `wake` extra of its choosing. That is not
   * fixable here - Android has no trustworthy caller identity for
   * `startActivity` - so the extra is treated as untrusted input and bounded
   * rather than believed:
   *
   *  - refused unless it is plausible hex, before it touches the filesystem;
   *  - refused past `MAX_WAKE_HEX`, so a caller cannot choose how much we write;
   *  - PREPENDED to a short candidate list rather than overwriting it, so a junk
   *    intent cannot displace a real pending wake (`PorttyWakeStore`);
   *  - removed from the intent once handled, so a replayed delivery (a
   *    configuration change re-running onCreate) does not store it twice.
   *
   * The blob itself is sealed with a key that never leaves this phone, so a
   * spoofed one can never name a host - Rust just fails to open it. The ceiling
   * on abuse is a missed doorbell tap.
   */
  private fun storeWakeFromIntent(intent: Intent?) {
    if (intent == null) return
    val wake = intent.getStringExtra("wake") ?: return
    intent.removeExtra("wake")
    if (!PorttyWakeStore.looksLikeWakeBlob(wake)) {
      Log.w("PorttyPush", "ignoring a wake extra that is not a wake blob")
      return
    }
    if (PorttyWakeStore.prepend(this, wake)) {
      Log.i("PorttyPush", "wake blob stored from notification tap")
    }
  }

  /**
   * Initialize the global `ndk_context` (JavaVM + Application context) BEFORE
   * Tauri starts Rust setup. Tauri V2's Android
   * flow never runs tao's `create()` - which would normally set it - so without
   * this, iroh's network monitor panics on the first `build_endpoint` with
   * "android context was not initialized". Implemented in Rust via the JNI symbol
   * `Java_com_corvuxmindware_portty_MainActivity_nativeInitNdkContext`
   * (see `src/android_context.rs`). `System.loadLibrary` is idempotent, so calling
   * it here guarantees the symbol resolves regardless of when wry first loads it.
   * A failure is logged here; secure-store setup then fails closed instead of
   * silently returning to plaintext credential files.
   */
  private fun initNdkContext() {
    try {
      System.loadLibrary("portty_app_lib")
      check(nativeInitNdkContext(applicationContext)) {
        "native ndk_context initialization returned failure"
      }
      Log.i("Portty", "ndk_context initialized at MainActivity.onCreate")
    } catch (ex: Throwable) {
      Log.e("Portty", "ndk_context init failed: ${ex.message}", ex)
      throw ex
    }
  }

  private external fun nativeInitNdkContext(context: Context): Boolean

  private companion object {
    const val REQUEST_POST_NOTIFICATIONS = 4201
  }
}
