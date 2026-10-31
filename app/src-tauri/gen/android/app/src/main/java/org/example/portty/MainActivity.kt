package org.example.portty

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.view.WindowManager
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.firebase.FirebaseApp
import kotlin.system.exitProcess

class MainActivity : TauriActivity() {
  /** The wry WebView, captured in onWebViewCreate; used by the back handler. */
  private var porttyWebView: WebView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    // Portty's UI is always black, so the status- and navigation-bar icons must
    // stay light whatever the phone's system theme. The default styles follow
    // the system theme: in light mode they draw dark icons that vanish on the
    // black UI, and add a light scrim behind 3-button navigation. dark() keeps
    // the icons light and the scrim off.
    enableEdgeToEdge(
      statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
      navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
    )
    // Block the Recents/app-switcher thumbnail (and screenshots) from capturing
    // the terminal or a pending approval. FLAG_SECURE is the guaranteed Android
    // layer; the webview privacy cover in BiometricGate is best-effort on top.
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE,
    )
    // Tauri's runtime starts once per process and stays bound to the first
    // MainActivity. A second one in the same process cannot work (see
    // restartProcess), so start the app over instead of running half-broken.
    if (tauriStartedInProcess) {
      // The restart drops this launch's intent; keep a doorbell tap it carried.
      storeWakeFromIntent(intent)
      restartProcess() // ends this process; never returns
    }
    tauriStartedInProcess = true
    // tao (since 0.37, shipped with Tauri 2.12) initializes the global
    // ndk_context itself during WryActivity.onCreate, before the Rust mobile
    // entry runs - so the initNdkContext() shim this app used with tao 0.35 is
    // gone. Initializing here as well would abort the process: ndk-context
    // asserts it is initialized exactly once, and a panic inside the JNI
    // boundary cannot unwind.
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

  /**
   * fontScale is in the manifest's configChanges, so a system font-size change
   * no longer re-creates this Activity - and a live WebView reads the font scale
   * only when it is created (Chromium's AwSettings sets text zoom to
   * fontScale x 100). Apply a changed scale the same way so the new size shows
   * at once. Only on a real change: setTextZoom also stops WebView from
   * tracking the scale by itself.
   */
  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    val settings = porttyWebView?.settings ?: return
    val textZoom = (newConfig.fontScale * 100).toInt()
    if (settings.textZoom != textZoom) settings.textZoom = textZoom
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
   * Replace this process with a fresh one. Used when a MainActivity is created
   * in a process whose Tauri runtime already belongs to an earlier MainActivity:
   * a configuration change the manifest does not list, or a launch that clears
   * the task (`am start --activity-clear-task`, some launchers and automation
   * apps). Tauri 2.11.5 cannot move its runtime to a new Activity:
   *
   *  - PluginManager and every native plugin keep the FIRST Activity forever
   *    (an upstream TODO), so biometric unlock, file pickers and permission
   *    prompts all fail - the app lock could never be passed;
   *  - an Activity with a new id gets no WebView at all (a blank screen), and
   *    once the old Activity is destroyed Tauri closes its only window and
   *    exits the process anyway.
   *
   * The restart intent reopens the app when the user is looking at it. From the
   * background Android 10+ blocks it, and the task is simply rebuilt in a new
   * process the next time the app is opened.
   */
  private fun restartProcess(): Nothing {
    Log.w("Portty", "MainActivity re-created in a running process; restarting the app")
    try {
      startActivity(Intent.makeRestartActivityTask(ComponentName(this, MainActivity::class.java)))
    } catch (ex: Throwable) {
      Log.e("Portty", "could not schedule the app restart: ${ex.message}", ex)
    }
    // SIGKILL, as Android's own crash handler does, so no exit hooks run while
    // Rust and WebView threads are live. The activity started above survives:
    // Android launches a not-yet-run activity in a new process if its old one dies.
    Process.killProcess(Process.myPid())
    exitProcess(10)
  }

  private companion object {
    const val REQUEST_POST_NOTIFICATIONS = 4201

    /**
     * Whether a MainActivity already started Tauri in this process. Only used
     * on the main thread; a new process starts with it false.
     */
    var tauriStartedInProcess = false
  }
}
