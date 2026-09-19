# Push doorbell setup runbook

Portty's async push ("phone locked in a pocket, agent hits a permission gate →
notification within seconds") has four moving parts. All the code ships in this
repo; this runbook is the operator/provisioning work that CANNOT ship in code:
Apple/Google credentials and one on-device validation pass.

Do not guess a missing value. Each section says where the value comes from.

## Architecture recap (what talks to what)

```
agent (ACP) ──stdio── portty-host ──HTTPS──> push-relay ──h2──> APNs / FCM ──> phone OS
                         │  ▲                                                  │
                         │  └── Frame::PushRegister (token, sealed blob) ──────┤
                         └──── iroh QUIC (sealed pipe) ── Portty app ◄── tap ──┘
```

- The host queues the approval (source of truth) and rings the relay
  (`/v1/wake`, pseudonym only). The relay forwards a static "pending
  approval" alert + the phone-sealed wake blob. The tap opens the app, the
  app decrypts the blob → knows which host rang → reconnects → the host
  replays the pending approval card. Content never touches the relay.
- Registration is automatic: the native layer writes the device token to a
  bridge file; the Rust core forwards it to the host on every connect
  (`Frame::PushRegister`); the host persists it and registers with the relay
  (re-registering at boot and on any 404 - a relay restart heals itself).

Metadata boundary: the relay process or its TLS reverse proxy can observe the
host's source IP, a stable random host pseudonym, the provider/device token at
registration, and wake/revoke timing. APNs/FCM necessarily receives its device
token, the generic notification text, and the opaque sealed selector. Terminal
bytes, agent prompts, tool names, decisions, pairing keys, and the plaintext
host identity are never sent through this path. Review/limit reverse-proxy
access-log retention for a hosted deployment; self-hosting keeps this metadata
under the user's control.

## 1. Relay deployment

```sh
PORTTY_PUSH_OPEN_REGISTRATION=1 \
PORTTY_PUSH_ADDR='0.0.0.0:9877' \
PORTTY_APNS_KEY_PATH='/run/secrets/AuthKey_KEYID.p8' \
PORTTY_APNS_KEY_ID='<Apple key id>' \
PORTTY_APNS_TEAM_ID='<Apple team id>' \
PORTTY_APNS_TOPIC='org.example.portty' \
PORTTY_FCM_SERVICE_ACCOUNT='/run/secrets/firebase-service-account.json' \
portty-push-relay
```

Put TLS in front (caddy/nginx). See `crates/push-relay/README.md` for the
full env reference and the admin-token (gated) registration mode.

> **Open-registration abuse & the device-token residual (#10).** Both `register`
> and `wake` require proof of the host secret (the bearer must hash to the
> pseudonym), so an attacker cannot touch a pseudonym they don't hold. But in
> open mode nothing binds a registered `device_token` to the registrant, so a
> reachable attacker can mint their OWN pseudonym pointing at a VICTIM's token and
> wake it - spamming pushes / burning your APNs/FCM quota. Mitigations in place,
> and note the first two are properties of the TARGET, so they hold however the
> sender spreads itself across addresses and pseudonyms:
> **(1)** one `device_token` may be registered under at most
> `MAX_PSEUDONYMS_PER_TOKEN` (8) distinct pseudonyms - a real phone is paired with
> a handful of machines, while the attack needs a fresh pseudonym per attempt to
> dodge the per-pseudonym throttle; re-registering the SAME pseudonym is never
> capped, so a reconnecting phone is unaffected;
> **(2)** a per-`device_token` wake budget (`WAKE_BUDGET_MAX`, 60 per 5 min) caps
> what any one device can be made to receive;
> **(3)** a **per-source-IP rate limit** (60 write requests/min, `RATE_LIMIT_MAX`)
> bounds a single abuser, and `MAX_DEVICES*` bound the table. Deployment guidance:
> **(a)** prefer gated `PORTTY_PUSH_ADMIN_TOKEN` mode for anything multi-tenant;
> **(b)** if self-hosting open mode, firewall the relay to networks you trust -
> the per-IP limit is **weakened behind a reverse proxy** (it sees the proxy IP),
> so also cap request rate at the proxy. None of (1)-(3) PROVES possession - they
> bound how much a token-holder can do with what they took. The full fix (a
> relay-issued challenge round-tripped through the push channel to prove token
> possession before a token is wakeable) is still a deferred protocol change.

> **The relay sees the raw host secret (#28) - so it must stay on TLS (#29).**
> `register`/`wake`/`revoke` authenticate by sending the host secret itself as the
> bearer (the relay recomputes `SHA256(context, secret)` and checks it equals the
> registered pseudonym), so the relay process - or anything terminating its TLS -
> learns the secret and could forge wake/revoke for that host. Two things bound
> this: the host now **refuses a non-`https://` relay URL** unless it is loopback
> or `PORTTY_PUSH_ALLOW_INSECURE=1` is set (#29), so the secret is never put on a
> plaintext wire; and the metadata boundary above already treats the relay as
> semi-trusted. That flag needs an explicit `1`/`true`/`yes` - `0`, `false`, and an
> empty value all leave the refusal in place, so a half-unset variable cannot arm
> it. A permitted plaintext (loopback) relay is also called with proxies DISABLED,
> since an `HTTP_PROXY` in the environment would carry the bearer off-box in the
> clear - the exact thing the loopback exemption assumes cannot happen. The real fix - the relay storing a verification key and the host
> **signing** each request so the secret never leaves the host - is the same
> signature/challenge redesign deferred for #10.

- **APNs JWT**: create an APNs Auth Key (`.p8`) in the Apple Developer portal
  (Keys → Apple Push Notifications service). The relay signs ES256 JWTs with
  the configured key/team ids and refreshes its cached token every 50 minutes;
  no cron or relay restart is needed. Sandbox vs production: TestFlight/App
  Store builds use PRODUCTION APNs (the default `PORTTY_APNS_URL`); Xcode debug installs use
  `PORTTY_APNS_URL=https://api.sandbox.push.apple.com/3/device`.
- **FCM OAuth token**: supply a service-account JSON with the
  `firebasemessaging.messages.create` permission. The relay requests the
  Firebase Messaging scope, caches the short-lived OAuth token, and refreshes
  it one minute before expiry. `GOOGLE_APPLICATION_CREDENTIALS` is accepted as
  an alternative to `PORTTY_FCM_SERVICE_ACCOUNT`; the Firebase project id is
  read from the JSON unless `PORTTY_FCM_PROJECT` overrides it.

Pre-minted `PORTTY_APNS_BEARER` / `PORTTY_FCM_BEARER` values remain available
for emergency compatibility, but they are static and must be replaced by the
operator when they expire. Do not combine them with automatic key sources.

### Endpoints are allowlisted

Both sandbox and production APNs hosts are accepted, so the override above needs
nothing extra. Anything else is refused at startup:

- the URL must be `https` (loopback may use `http`, with the opt-out below);
- the host must be an official APNs / FCM / Google OAuth host;
- a URL embedding credentials (`https://user:pass@host/`) is never accepted;
- the same rules apply to `token_uri` inside the service-account JSON, which is
  where the signed RSA assertion is sent.

The reason is that these are not merely destinations. An APNs provider JWT and an
FCM OAuth assertion are bearer credentials for your push identity — whoever
receives one can send notifications as you until it expires. A mistyped or planted
endpoint used to redirect them silently.

If you genuinely terminate push through your own proxy, set
`PORTTY_PUSH_ALLOW_CUSTOM_ENDPOINTS=1`. It loosens the host allowlist only, logs a
warning naming the host on every start, and still enforces TLS and the no-embedded-
credentials rule.

## 2. Host configuration

```sh
export PORTTY_PUSH_RELAY_URL='https://push.example.com'
# Optional deterministic deployment identity; by default the host generates a
# random owner-only secret and derives the stable public handle from it:
# export PORTTY_PUSH_HOST_SECRET='<64 hex>'
portty-host
```

The random secret persists as `<identity dir>/push_relay_secret_v2.bin` and
registrations as `<identity dir>/push_registrations.json` (both owner-only).
Legacy `PORTTY_PUSH_HOST_PSEUDONYM` is ignored because a caller-chosen public
handle cannot authenticate wake/revoke calls.

## 3. iOS provisioning

Code already in the repo: `aps-environment` entitlement,
`UserNotifications.framework` dependency, and the runtime glue
(`app/src-tauri/gen/apple/Sources/portty-app/push_glue.mm`) that registers for
remote notifications, stores the token/wake bridge files, and clears the badge.

Operator steps:
1. Apple Developer portal → the app id `org.example.portty` must have
   the **Push Notifications** capability enabled (automatic signing then
   regenerates the profile).
2. Create the APNs Auth Key (once per team; shared across apps) → feeds the
   relay JWT above.
3. Build/upload per `MAC_IOS_BUILD_RUNBOOK.md`. Debug uses
   `portty-app_iOS.entitlements` (`aps-environment=development`); the RELEASE
   build config points `CODE_SIGN_ENTITLEMENTS` at
   `portty-app_iOS.release.entitlements` (`aps-environment=production`) - do NOT
   rely on signing to rewrite it (it does not). After archiving, VERIFY the
   built `.ipa` embeds `aps-environment=production`
   (`codesign -d --entitlements - Portty.app`), or every distributed build
   silently registers a sandbox token and the wake never fires. The
   `push_entitlement_is_production_for_release_and_development_for_debug` test
   guards the committed config; the archive check confirms the result. Note
   re-running `tauri ios init` regenerates `gen/apple` - reapply this wiring.

## 4. Android provisioning

Code already in the repo: FCM service, manifest wiring, gradle wiring -
all dormant until a Firebase config exists.

Operator steps:
1. Firebase console → create/reuse a project → add Android app with package
   `org.example.portty` → download **google-services.json** into
   `app/src-tauri/gen/android/app/` (the gradle plugin applies itself only
   when the file exists - do not commit the file).
2. Use the same Firebase project id + service account for the relay's
   `PORTTY_FCM_SERVICE_ACCOUNT` (or `GOOGLE_APPLICATION_CREDENTIALS`).
3. Rebuild and reinstall (`packaging/ANDROID_BUILD_RUNBOOK.md`). On Android
   13+ the first launch now asks for notification permission automatically
   (MainActivity gates the prompt on Firebase being configured, mirroring
   iOS's launch-time `requestAuthorizationWithOptions`).

## 5. On-device validation checklist (must pass before calling this DONE)

Code paths that cannot be exercised on a dev laptop - run once on real
hardware per platform:

- [ ] Fresh install → notification permission prompt appears → accept →
      `push/native_token.json` appears in the app container.
- [ ] Pair with a host (relay configured) → host log shows the registration
      forward; relay answers 204.
- [ ] Lock the phone. Trigger an agent permission (e.g. `portty agent` prompt
      that runs a tool). Notification arrives within seconds.
- [ ] Tap it → app opens → reconnects to the RIGHT host (multi-host phones:
      pair two hosts and ring from the second) → the approval card is on
      screen → approve → agent resumes on the laptop.
- [ ] Same flow with the app fully killed (cold start).
- [ ] Same flow while the phone is connected but idle >8 s (locked-phone
      grace path: the wake must still fire).
- [ ] iOS badge shows on push, clears on open. Android 13+: notification
      permission prompt honored.
- [ ] Relay restart mid-day → next wake 404s → host re-registers → subsequent
      pushes deliver (no operator action).

### Protocol v5 (this release - see `RELEASE-NOTES.md`)

- [ ] **Flag-day gate:** an OLD (v4) phone build cannot connect to the v5 host -
      it shows "This phone is running an older Portty version than the laptop.
      Update Portty from the App Store, then reconnect." (and the laptop shows
      the mirror when it is the older side). Confirms both the version gate and
      the directional message (#13).
- [ ] **Resolved-elsewhere detail (#49):** with a phone AND a laptop `portty
      agent` chat on one session, answer the card on the laptop → the phone's
      card is replaced by an "Approved/Rejected on the laptop" notice and the
      Decision log row shows the outcome + resolver - not a bare "answered
      elsewhere". Repeat answering on a second phone (shows "on another device").

## 6. Native changes that need a device build to verify (not push-specific)

These privacy/security fixes are code-correct and follow the existing idioms in
their files, but they cannot be compiled or exercised on a dev laptop - confirm
them in the actual platform builds before shipping a release:

- [ ] **iOS release entitlement** (see §3.3): the archived `.ipa` embeds
      `aps-environment=production`, not `development`.
- [ ] **Android app-switcher privacy** (`MainActivity.kt` `FLAG_SECURE`): after a
      gradle build, background the app → the Recents/overview thumbnail shows a
      blank/secured frame, not the terminal; screenshots of the app are blocked.
- [ ] **iOS app-switcher privacy** (`push_glue.mm`, `willResignActive` cover):
      after an Xcode build, background the app → the switcher card shows the
      black cover, not the terminal or a pending approval; foregrounding clears
      it.

Known platform notes:
- The Rust core scans `app_data_dir`, `app_local_data_dir` and
  `app_config_dir` for the `push/` bridge dir, so the exact Tauri↔native dir
  mapping is not load-bearing; if a token never shows up, log the paths on
  both sides first (`push_wake.rs::bridge_dirs`).
- The iOS glue attaches APNs delegate methods at runtime because tao owns the
  app delegate; if a Tauri upgrade starts implementing
  `didRegisterForRemoteNotificationsWithDeviceToken` itself, the glue logs
  "delegate already implements APNs callbacks" and yields.
