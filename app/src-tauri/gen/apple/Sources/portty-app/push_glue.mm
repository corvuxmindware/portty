// Push doorbell glue for the Tauri iOS app.
//
// Tauri's runtime (tao) owns the UIApplicationDelegate in Rust, so there is no
// AppDelegate.swift to extend. Instead this file attaches the two remote-
// notification delegate methods onto tao's delegate class AT RUNTIME (after
// UIApplicationDidFinishLaunchingNotification, when the delegate exists), and
// installs a UNUserNotificationCenter delegate for taps.
//
// Data flow (bridge files, read by the Rust core - see src/push_wake.rs):
//   Application Support/<bundle-id>/push/native_token.json
//       {"provider":"apns","token":"<hex>"} - written on every APNs
//       registration; the Rust core forwards it to the connected host, which
//       registers with the push relay.
//   Application Support/<bundle-id>/push/wake_blob.txt
//       newline-separated hex `wake` payloads, newest first, at most
//       kPorttyMaxWakeCandidates of them; the Rust core decrypts each in turn
//       (phone-local key) and takes the first that opens, to learn WHICH host
//       rang and auto-reconnect there.
//
// Nothing here talks to the network and nothing reads notification content
// beyond the opaque `wake` string.
//
// The `wake` string is remote input. It arrives from APNs, having been forwarded
// by a relay that may not be ours, so its shape and size are not ours to assume:
// it is hex-checked and length-capped before it decides the contents of a file we
// write. It is also PREPENDED rather than written over, so two hosts ringing
// within a few seconds of each other do not cost the user the earlier doorbell.
// Kotlin does the same thing for the same file (PorttyWakeStore.kt) - one format,
// one reader contract in push_wake.rs.

#import <UIKit/UIKit.h>
#import <UserNotifications/UserNotifications.h>
#import <objc/runtime.h>

static NSString *porttyPushDir(void) {
  NSString *support = NSSearchPathForDirectoriesInDomains(
                          NSApplicationSupportDirectory, NSUserDomainMask, YES)
                          .firstObject;
  NSString *bundleId = NSBundle.mainBundle.bundleIdentifier ?: @"portty";
  NSString *dir =
      [[support stringByAppendingPathComponent:bundleId] stringByAppendingPathComponent:@"push"];
  [NSFileManager.defaultManager createDirectoryAtPath:dir
                          withIntermediateDirectories:YES
                                           attributes:nil
                                                error:nil];
  return dir;
}

static void porttyWrite(NSString *name, NSString *content) {
  NSString *path = [porttyPushDir() stringByAppendingPathComponent:name];
  [content writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

// Keep in step with MAX_WAKE_CANDIDATES in src/push_wake.rs and PorttyWakeStore.kt.
static const NSUInteger kPorttyMaxWakeCandidates = 4;
// A real blob is hex of nonce(24) || ciphertext(32) - 112 characters. The cap is
// deliberately loose so an envelope change needs no edit here, but it is still a
// cap: without one the sender picks how much we write.
static const NSUInteger kPorttyMaxWakeHex = 1024;

static BOOL porttyLooksLikeWakeBlob(NSString *value) {
  if (value.length == 0 || value.length > kPorttyMaxWakeHex || value.length % 2 != 0) {
    return NO;
  }
  static NSCharacterSet *nonHex;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    nonHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"]
        invertedSet];
  });
  return [value rangeOfCharacterFromSet:nonHex].location == NSNotFound;
}

// Put `wake` at the front of the candidate list, keeping at most
// kPorttyMaxWakeCandidates. Malformed or duplicate existing entries are dropped on
// the way through, so the file cannot accumulate junk.
static void porttyPrependWake(NSString *wake) {
  NSString *path = [porttyPushDir() stringByAppendingPathComponent:@"wake_blob.txt"];
  NSMutableArray<NSString *> *candidates = [NSMutableArray arrayWithObject:wake];
  // nil (no file yet) has length 0 and separates into nil, so both paths below are
  // no-ops on a fresh install.
  NSString *existing = [NSString stringWithContentsOfFile:path
                                                encoding:NSUTF8StringEncoding
                                                   error:nil];
  if (existing.length <= kPorttyMaxWakeHex * kPorttyMaxWakeCandidates) {
    for (NSString *line in [existing componentsSeparatedByString:@"\n"]) {
      if (candidates.count >= kPorttyMaxWakeCandidates) break;
      NSString *trimmed =
          [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
      if (porttyLooksLikeWakeBlob(trimmed) && ![candidates containsObject:trimmed]) {
        [candidates addObject:trimmed];
      }
    }
  }
  porttyWrite(@"wake_blob.txt", [candidates componentsJoinedByString:@"\n"]);
}

static void porttyStoreWake(NSDictionary *userInfo) {
  id wake = userInfo[@"wake"];
  if (![wake isKindOfClass:NSString.class]) return;
  NSString *trimmed = [(NSString *)wake
      stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
  if (!porttyLooksLikeWakeBlob(trimmed)) {
    NSLog(@"[portty-push] ignoring a wake payload that is not a wake blob");
    return;
  }
  porttyPrependWake(trimmed);
}

// ── privacy cover for the app-switcher snapshot ──────────────────────────
// iOS snapshots the UI for the app switcher when the app resigns active. The
// webview privacy cover (BiometricGate) is best-effort and may not paint before
// that snapshot, so we add a native black cover to the key window synchronously
// on willResignActive and remove it on didBecomeActive. Nothing here reads app
// content - it just hides the terminal / a pending approval from the thumbnail.
static UIView *porttyPrivacyCover;

static void porttyShowPrivacyCover(void) {
  if (porttyPrivacyCover) return;
  UIWindow *key = nil;
  for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
    if ([scene isKindOfClass:UIWindowScene.class]) {
      for (UIWindow *w in ((UIWindowScene *)scene).windows) {
        if (w.isKeyWindow) {
          key = w;
          break;
        }
      }
    }
    if (key) break;
  }
  if (!key) return;
  UIView *cover = [[UIView alloc] initWithFrame:key.bounds];
  cover.backgroundColor = UIColor.blackColor;
  cover.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
  [key addSubview:cover];
  [key bringSubviewToFront:cover];
  porttyPrivacyCover = cover;
}

static void porttyHidePrivacyCover(void) {
  [porttyPrivacyCover removeFromSuperview];
  porttyPrivacyCover = nil;
}

// ── methods attached onto tao's application delegate ─────────────────────

static void portty_didRegisterForRemoteNotifications(id self, SEL _cmd, UIApplication *app,
                                                     NSData *deviceToken) {
  NSMutableString *hex = [NSMutableString stringWithCapacity:deviceToken.length * 2];
  const unsigned char *bytes = (const unsigned char *)deviceToken.bytes;
  for (NSUInteger i = 0; i < deviceToken.length; i++) {
    [hex appendFormat:@"%02x", bytes[i]];
  }
  porttyWrite(@"native_token.json",
              [NSString stringWithFormat:@"{\"provider\":\"apns\",\"token\":\"%@\"}", hex]);
  NSLog(@"[portty-push] APNs token stored (%lu bytes)", (unsigned long)deviceToken.length);
}

static void portty_didFailToRegister(id self, SEL _cmd, UIApplication *app, NSError *error) {
  NSLog(@"[portty-push] APNs registration failed: %@", error);
}

// ── notification-center delegate (taps + foreground presentation) ────────

@interface PorttyNotificationDelegate : NSObject <UNUserNotificationCenterDelegate>
@end

@implementation PorttyNotificationDelegate
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
    didReceiveNotificationResponse:(UNNotificationResponse *)response
             withCompletionHandler:(void (^)(void))completionHandler {
  // Tap → remember which host rang; the app (already launching/resuming)
  // consumes the blob and reconnects there.
  porttyStoreWake(response.notification.request.content.userInfo);
  completionHandler();
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
       willPresentNotification:(UNNotification *)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler {
  // Foregrounded app: the host replays the approval card over the live link
  // anyway, so present nothing and stay out of the way.
  porttyStoreWake(notification.request.content.userInfo);
  completionHandler(UNNotificationPresentationOptionNone);
}
@end

static PorttyNotificationDelegate *porttyNotificationDelegate;

__attribute__((constructor)) static void portty_install_push_glue(void) {
  // Runs at binary load, before UIApplicationMain: only registers observers.
  [NSNotificationCenter.defaultCenter
      addObserverForName:UIApplicationDidFinishLaunchingNotification
                  object:nil
                   queue:NSOperationQueue.mainQueue
              usingBlock:^(NSNotification *note) {
                UIApplication *app = UIApplication.sharedApplication;
                Class delegateClass = object_getClass(app.delegate);
                if (delegateClass) {
                  // Attach the APNs callbacks tao's delegate doesn't implement.
                  // If a future tao DOES implement them, addMethod fails and we
                  // leave its implementation alone (logged for diagnosis).
                  BOOL added = class_addMethod(
                      delegateClass,
                      @selector(application:didRegisterForRemoteNotificationsWithDeviceToken:),
                      (IMP)portty_didRegisterForRemoteNotifications, "v@:@@");
                  class_addMethod(
                      delegateClass,
                      @selector(application:didFailToRegisterForRemoteNotificationsWithError:),
                      (IMP)portty_didFailToRegister, "v@:@@");
                  if (!added) {
                    NSLog(@"[portty-push] delegate already implements APNs callbacks; "
                          @"leaving them in place");
                  }
                }
                porttyNotificationDelegate = [PorttyNotificationDelegate new];
                UNUserNotificationCenter *center = UNUserNotificationCenter.currentNotificationCenter;
                center.delegate = porttyNotificationDelegate;
                [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert |
                                                         UNAuthorizationOptionSound |
                                                         UNAuthorizationOptionBadge)
                                      completionHandler:^(BOOL granted, NSError *error) {
                                        if (granted) {
                                          dispatch_async(dispatch_get_main_queue(), ^{
                                            [UIApplication.sharedApplication
                                                registerForRemoteNotifications];
                                          });
                                        } else {
                                          NSLog(@"[portty-push] notification permission denied%@",
                                                error ? [NSString stringWithFormat:@": %@", error]
                                                      : @"");
                                        }
                                      }];
                // Cold start from a notification tap: the payload rides
                // launchOptions (didReceiveNotificationResponse also fires,
                // this is belt + braces).
                NSDictionary *launch = note.userInfo
                    ? note.userInfo[UIApplicationLaunchOptionsRemoteNotificationKey]
                    : nil;
                if ([launch isKindOfClass:NSDictionary.class]) {
                  porttyStoreWake(launch);
                }
              }];
  [NSNotificationCenter.defaultCenter
      addObserverForName:UIApplicationWillResignActiveNotification
                  object:nil
                   queue:NSOperationQueue.mainQueue
              usingBlock:^(NSNotification *note) {
                // Cover the UI before iOS snapshots it for the app switcher.
                porttyShowPrivacyCover();
              }];
  [NSNotificationCenter.defaultCenter
      addObserverForName:UIApplicationDidBecomeActiveNotification
                  object:nil
                   queue:NSOperationQueue.mainQueue
              usingBlock:^(NSNotification *note) {
                // Back in the foreground: drop the privacy cover…
                porttyHidePrivacyCover();
                // …and clear the badge - it means "pending approval", and
                // opening the app is how you handle it.
                UIApplication.sharedApplication.applicationIconBadgeNumber = 0;
              }];
}
