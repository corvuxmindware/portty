package org.example.portty

import android.util.Log
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import java.io.File

/**
 * FCM half of the push doorbell (active only when the build shipped a
 * google-services.json - see app/build.gradle.kts).
 *
 * Mirrors the iOS glue (gen/apple/Sources/portty-app/push_glue.mm): everything
 * is bridged to the Rust core through two small files under `filesDir/push/`,
 * which the core scans on connect/resume (see src-tauri/src/push_wake.rs -
 * `filesDir` is Tauri's app-data dir on Android; the Rust side scans the
 * candidate set to stay robust to mapping changes):
 *
 *  - native_token.json  {"provider":"fcm","token":"…"} - written on every
 *    token (re)issue; the Rust core forwards it to the connected host.
 *  - wake_blob.txt - the opaque `wake` payload of the last push; the Rust
 *    core decrypts it (phone-local key) to learn WHICH host rang.
 *
 * The relay sends notification+data messages: in background Android posts the
 * notification itself and the tap intent carries the data extras (handled in
 * MainActivity); in foreground `onMessageReceived` fires here. Neither path
 * reads anything beyond the opaque `wake` string.
 */
class PorttyMessagingService : FirebaseMessagingService() {
  override fun onNewToken(token: String) {
    try {
      writeBridgeFile("native_token.json", "{\"provider\":\"fcm\",\"token\":\"$token\"}")
      Log.i("PorttyPush", "FCM token stored")
    } catch (ex: Throwable) {
      Log.e("PorttyPush", "could not store FCM token: ${ex.message}", ex)
    }
  }

  override fun onMessageReceived(message: RemoteMessage) {
    val wake = message.data["wake"] ?: return
    // Only the FCM service can reach this callback, so the payload is not
    // attacker-chosen here. It still goes through PorttyWakeStore: the file is a
    // candidate list because the notification-TAP path (MainActivity, exported)
    // is open, and both writers have to agree on the format.
    if (!PorttyWakeStore.looksLikeWakeBlob(wake)) {
      Log.w("PorttyPush", "ignoring an FCM wake payload that is not a wake blob")
      return
    }
    PorttyWakeStore.prepend(this, wake)
  }

  private fun writeBridgeFile(name: String, content: String) {
    val dir = File(filesDir, "push").apply { mkdirs() }
    val tmp = File(dir, "$name.tmp")
    tmp.writeText(content)
    tmp.renameTo(File(dir, name))
  }
}
