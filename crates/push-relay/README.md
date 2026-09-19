# Portty push relay

This optional service is a wake-only doorbell. It cannot receive terminal
bytes, agent prompts, tool names, approval choices, or pairing keys. It can
observe the connecting host's source IP (directly or in the TLS reverse proxy),
a stable random host pseudonym, the provider/device token supplied during
registration, and wake/revoke timing. The wake payload is supplied already
sealed by the phone and is stored/forwarded as an opaque hex string. Operators
of a hosted relay should treat proxy access logs and this metadata as sensitive;
self-hosting keeps that visibility with the user.

## Run (self-host)

```sh
PORTTY_PUSH_OPEN_REGISTRATION=1 \
PORTTY_PUSH_ADDR='127.0.0.1:9877' \
cargo run -p portty-push-relay
```

Open registration requires each host to prove knowledge of a random 256-bit
secret whose one-way SHA-256 handle is being registered. The public handle is
never accepted as a bearer. For a hosted/multi-tenant deployment, gate initial
registration behind an operator secret instead: set
`PORTTY_PUSH_ADMIN_TOKEN='<secret>'` on both relay and host (and don't set the
open flag; the relay refuses to start with both or neither). Wake and revoke
calls still use the host-specific secret.

Provider configuration supports automatic short-lived credential rotation:

- APNs (preferred): `PORTTY_APNS_KEY_PATH` (the `.p8` key),
  `PORTTY_APNS_KEY_ID`, `PORTTY_APNS_TEAM_ID`, and `PORTTY_APNS_TOPIC`. The
  relay signs ES256 provider JWTs and refreshes its cached token every 50
  minutes. `PORTTY_APNS_URL` defaults to production; use
  `https://api.sandbox.push.apple.com/3/device` for Xcode debug installs.
  APNs is HTTP/2-only; the relay's client is built with h2.
- FCM (preferred): set `PORTTY_FCM_SERVICE_ACCOUNT` or the standard
  `GOOGLE_APPLICATION_CREDENTIALS` to a service-account JSON file. The relay
  exchanges signed assertions for OAuth tokens and refreshes them one minute
  before expiry. `PORTTY_FCM_PROJECT` overrides the JSON `project_id`.
- Compatibility: `PORTTY_APNS_BEARER` and `PORTTY_FCM_BEARER` still accept
  pre-minted tokens, but those static values do not rotate. Do not configure a
  static bearer and its signing/service-account source together.

## Registration is automatic

The phone sends its push token to the **host** over the sealed pipe
(`Frame::PushRegister`); the host persists it (`push_registrations.json` in
its identity dir) and forwards it here, authenticated by its private relay
secret. Each phone gets an opaque registration id, so several paired phones do
not overwrite each other and revoke can delete only its target. The host
re-registers every stored device at boot and whenever a wake answers 404
(relay restarted), so the memory-only table heals itself. Manual `curl`
registration is no longer part of the flow.

Configure the host:

```sh
export PORTTY_PUSH_RELAY_URL='https://push.example.com'
# optional deterministic deployment secret; normally Portty generates and
# stores this owner-only in the host identity directory:
# export PORTTY_PUSH_HOST_SECRET='<64 hex>'
```

When an approval arrives with no authenticated phone attached - or a phone is
attached but hasn't answered within a short grace window (locked phone whose
connection hasn't idle-timed-out yet) - the host calls `/v1/wake`. The actual
approval remains in the host's in-memory ACP queue (24h default, configurable
with `PORTTY_APPROVAL_TTL_SECS`). Tapping the OS notification launches
Portty; the app auto-reconnects and the host's replay opens the pending
approval card.

When the laptop revokes a phone, the durable local tombstone is committed
first. `/v1/revoke` then deletes only that phone's relay registration and sends
a generic pair-ended notification carrying the same phone-sealed host selector.
The notification is never authorization: the app deletes its credential only
after an authenticated reconnect reports `Revoked` (or a live sealed control
frame does). A compromised or delayed push service therefore cannot unpair a
device or revive an old pair.

## Abuse bounds

- Wake/revoke: the random host secret must derive the requested public handle;
  unknown handles are rejected **before** rate-limit state is written.
- Register: bounded table (10k registrations, 32 per host; existing entries may
  always refresh), hex-validated blob (≤4 KiB), constant-time token checks.
- All provider calls carry a 10 s timeout.

Production deployments should put TLS in front of this process.

## Real-device release checklist

CI exercises the full register → wake → targeted revoke router flow with a
recording provider and separately validates the exact APNs/FCM URLs, auth
headers, generic notification text, and opaque wake blob. Provider delivery and
OS background launch still require credentials and physical devices; run this
checklist for every mobile release candidate:

1. Deploy the reviewed relay behind TLS and confirm `/health` returns `ok`.
2. Install the signed candidate on a physical iPhone/Android device, grant
   notifications, pair it, and verify the relay receives its registration.
3. Put the app in the background, then force-close it for a second pass. With
   no authenticated phone attached, create a pending agent approval on the host.
4. Confirm one generic notification arrives without a command, tool title,
   laptop name, or host id visible in the provider payload or notification UI.
5. Tap the notification. Confirm Portty opens, selects the sealed host, performs
   an authenticated reconnect, and shows the still-pending approval card.
6. Resolve the approval and wait past the grace window; confirm no duplicate
   notification is emitted for the resolved card.
7. Revoke that phone from the laptop. Confirm the generic pair-ended
   notification arrives, the relay deletes only that registration, and the app
   removes credentials only after authenticated revocation confirmation.
8. Repeat with APNs sandbox for an Xcode debug install, APNs production for the
   signed distribution build, and FCM for the Android release build. Review
   relay logs to ensure no bearer, push token, sealed blob, or pairing secret was
   logged.
