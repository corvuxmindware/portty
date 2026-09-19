// Local OS notifications for pending agent approvals.
//
// This is the NEAR half of the doorbell, and it is worth being precise about
// which half, because the two are easy to conflate:
//
//   - FAR half (crates/push-relay): the phone is suspended, so nothing of ours
//     is running. Only APNs can wake it, which needs an Apple key and a
//     deployed relay. That path is `spawn_doorbell` host-side.
//   - NEAR half (this file): the app is still alive and the host has already
//     delivered the request over the iroh pipe. We can post straight to the OS
//     with no server, no credentials, and no relay.
//
// Without this, a permission request that arrives while the app is merely
// backgrounded shows nothing at all: the card sits waiting behind a dark screen
// and the agent stays blocked until the user happens to look.
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";

export type NotificationPermission = "granted" | "denied" | "unsupported";

/* Cached for the session. Asking is cheap but PROMPTING is not: iOS and Android
   both show the system dialog only once, and re-entering an agent shouldn't look
   like a retry. */
let permissionChecked = false;
let permissionGranted = false;

/**
 * Ask for notification permission, at a moment the user is actually looking.
 *
 * Call this from a FOREGROUND action - Portty calls it when an agent session is
 * opened, which is exactly when approvals become possible. Do NOT call it from
 * the notification path itself: that fires when the app is off screen, and
 * neither iOS nor Android will show a permission dialog to a backgrounded app,
 * so the prompt would silently never appear and every notification would be
 * dropped. Corvux hit precisely this on Android 13+ (its own audit note records
 * alarms being "silently dropped because the permission was never requested"),
 * and this is that lesson applied.
 *
 * On Android this also sidesteps a Portty-specific trap: `MainActivity.kt`'s
 * runtime POST_NOTIFICATIONS prompt is gated on `FirebaseApp.getApps` being
 * non-empty, so a build without `google-services.json` never asks. The plugin
 * declares its own POST_NOTIFICATIONS and asks independently of that gate, so
 * local notifications work whether or not push is provisioned.
 *
 * Never throws. `"unsupported"` means the plugin isn't registered - the browser
 * workbench (`pnpm design`) and vitest, where every call rejects. That result is
 * deliberately NOT cached, so a real device still gets its chance to answer.
 */
export async function ensureNotificationPermission(): Promise<NotificationPermission> {
  if (permissionChecked) return permissionGranted ? "granted" : "denied";
  try {
    let granted = await isPermissionGranted();
    if (!granted) granted = (await requestPermission()) === "granted";
    permissionChecked = true;
    permissionGranted = granted;
    return granted ? "granted" : "denied";
  } catch {
    return "unsupported";
  }
}

/**
 * Should a pending approval raise an OS notification?
 *
 * Pure so the rule is testable without a device. Two conditions:
 *
 *  1. Something is actually waiting. Policy runs BEFORE this (see
 *     `maybeAutoApprove` in App.tsx) - an auto-approved request needs no human,
 *     so it must not buzz a pocket.
 *  2. The app is not on screen. When it is visible the arrival handler already
 *     calls `attachAgent` and puts the card in front of the user, so a banner
 *     over the top of it is pure noise.
 */
export function shouldNotifyPendingApproval(input: {
  appVisible: boolean;
  pendingCount: number;
}): boolean {
  if (input.pendingCount < 1) return false;
  return !input.appVisible;
}

/**
 * Notification copy. Deliberately generic.
 *
 * A notification renders on the LOCK SCREEN, where anyone holding the phone can
 * read it - so this says that a decision is waiting and nothing else. No tool
 * name, no command, no path, no host. That matches what the relay already
 * forwards for the far half (a static "pending approval" alert with the detail
 * sealed), so the wording a user sees does not depend on which path delivered
 * it. The exact action still has to be read on the card, behind the app lock.
 */
export function pendingApprovalMessage(pendingCount: number): {
  title: string;
  body: string;
} {
  const plural = pendingCount === 1 ? "" : "s";
  return {
    title: "Portty",
    body: `${pendingCount} approval${plural} waiting`,
  };
}

/**
 * Post the notification, if the rule allows and permission is already held.
 *
 * Checks permission but never REQUESTS it - see
 * [`ensureNotificationPermission`] for why prompting here cannot work. If the
 * grant is missing we simply stay quiet.
 *
 * Never throws. A missing notification must not be able to break answering an
 * approval, which is the actual job.
 */
export async function notifyPendingApproval(input: {
  appVisible: boolean;
  pendingCount: number;
}): Promise<boolean> {
  if (!shouldNotifyPendingApproval(input)) return false;
  try {
    if (!(await isPermissionGranted())) return false;
    const { title, body } = pendingApprovalMessage(input.pendingCount);
    sendNotification({ title, body });
    return true;
  } catch {
    return false;
  }
}

/** `document.visibilityState`, guarded for non-browser test environments. */
export function appIsVisible(): boolean {
  return typeof document === "undefined" ? true : document.visibilityState === "visible";
}
