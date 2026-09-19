package org.example.portty

import android.content.Context
import android.util.Log
import java.io.File

/**
 * The Android half of the push wake bridge file (`filesDir/push/wake_blob.txt`),
 * shared by the two paths that can produce a wake:
 *
 *  - [PorttyMessagingService.onMessageReceived] - a foreground FCM data message,
 *    which only the FCM service can deliver;
 *  - [MainActivity.storeWakeFromIntent] - a notification tap, which arrives as an
 *    Intent extra on an **exported** launcher activity, so any app on the device
 *    can produce one.
 *
 * Because the second path is open, the file is treated as a short candidate LIST
 * rather than a single value. Overwriting meant a junk intent silently displaced a
 * genuine pending wake and the doorbell was lost; prepending means a spoofed blob
 * takes a slot instead of the whole file.
 *
 * Nothing here authenticates anything, and it does not need to. The blob is
 * XChaCha20-Poly1305 ciphertext under a key that never leaves the phone, and the
 * Rust core decides which candidate is real by trying to open each one (see
 * `push_wake.rs::consume_wake_blobs`). These bounds only stop a caller from
 * choosing how much we write, or from evicting a real wake with a fake one.
 */
internal object PorttyWakeStore {
  /** Keep in step with `MAX_WAKE_CANDIDATES` in `push_wake.rs`. */
  private const val MAX_CANDIDATES = 4

  /**
   * A real blob is hex of `nonce(24) || ciphertext(32)` - 112 characters. The cap
   * is deliberately loose so envelope changes do not need a matching edit here,
   * but it is still a cap: without one the caller picks the write size.
   */
  private const val MAX_WAKE_HEX = 1024

  /** Cheap shape check. Hex only, even length, bounded, non-empty. */
  fun looksLikeWakeBlob(value: String): Boolean {
    val trimmed = value.trim()
    return trimmed.isNotEmpty() &&
      trimmed.length <= MAX_WAKE_HEX &&
      trimmed.length % 2 == 0 &&
      trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
  }

  /**
   * Put `wake` at the front of the candidate list, keeping at most
   * [MAX_CANDIDATES]. Returns whether it was stored.
   *
   * Written to a temp file and renamed, so a reader never observes a half-written
   * list - and so a crash mid-write cannot destroy the previous candidates.
   */
  fun prepend(context: Context, wake: String): Boolean {
    val trimmed = wake.trim()
    return try {
      val dir = File(context.filesDir, "push").apply { mkdirs() }
      val target = File(dir, "wake_blob.txt")
      val existing =
        try {
          if (target.length() <= MAX_WAKE_HEX.toLong() * MAX_CANDIDATES) {
            target.readLines().map { it.trim() }.filter { looksLikeWakeBlob(it) }
          } else {
            // Too large to have come from us; start over rather than parse it.
            emptyList()
          }
        } catch (ex: Throwable) {
          emptyList()
        }
      // Distinct so a repeated delivery of the same wake cannot push the rest out.
      val candidates = (listOf(trimmed) + existing).distinct().take(MAX_CANDIDATES)
      val tmp = File(dir, "wake_blob.txt.tmp")
      tmp.writeText(candidates.joinToString("\n"))
      tmp.renameTo(target)
      true
    } catch (ex: Throwable) {
      Log.e("PorttyPush", "could not store wake blob: ${ex.message}", ex)
      false
    }
  }
}
