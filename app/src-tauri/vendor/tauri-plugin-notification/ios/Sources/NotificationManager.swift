// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

import Foundation
import UserNotifications

@objc public protocol NotificationHandlerProtocol {
  func willPresent(notification: UNNotification) -> UNNotificationPresentationOptions
  func didReceive(response: UNNotificationResponse)
}

@objc public class NotificationManager: NSObject, UNUserNotificationCenterDelegate {
  public weak var notificationHandler: NotificationHandlerProtocol?

  override init() {
    super.init()
    // PORTTY PATCH: upstream does `UNUserNotificationCenter.current().delegate =
    // self` here. There is only ONE such delegate, and Portty already installs
    // its own in push_glue.mm - so whichever object initialises last silently
    // evicts the other:
    //
    //   - plugin wins  -> `PorttyNotificationDelegate` never fires, so a tapped
    //     PUSH notification never calls porttyStoreWake and the doorbell's
    //     tap -> wake-blob -> reconnect-to-that-host flow breaks.
    //   - push_glue wins -> the plugin's handlers never fire anyway.
    //
    // Portty only ever POSTS through this plugin (`sendNotification`,
    // `isPermissionGranted`, `requestPermission`) and consumes none of its
    // notification events, and posting does not require being the delegate. So
    // leave the delegate to push_glue, which needs it. A local-notification tap
    // lands in `porttyStoreWake`, which ignores any payload without a valid
    // wake blob, so the app simply opens.
    //
    // Side effect worth knowing: this also makes the tap path through
    // `toActiveNotification` unreachable, so the force-unwrap patched in
    // NotificationHandler.swift can no longer be hit at all. That patch stays as
    // defence in depth in case a future change re-claims the delegate.
  }

  public func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    willPresent notification: UNNotification,
    withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
  ) {
    var presentationOptions: UNNotificationPresentationOptions? = nil

    if notification.request.trigger?.isKind(of: UNPushNotificationTrigger.self) != true {
      presentationOptions = notificationHandler?.willPresent(notification: notification)
    }

    completionHandler(presentationOptions ?? [])
  }

  public func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    didReceive response: UNNotificationResponse,
    withCompletionHandler completionHandler: @escaping () -> Void
  ) {
    if response.notification.request.trigger?.isKind(of: UNPushNotificationTrigger.self) != true {
      notificationHandler?.didReceive(response: response)
    }

    completionHandler()
  }
}
