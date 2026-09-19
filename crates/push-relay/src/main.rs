//! Portty's optional blind push doorbell.
//!
//! It never accepts terminal bytes, prompts, tool names, or decisions. A host
//! presents an opaque pseudonym; the relay forwards a pre-sealed wake blob to
//! the device token registered for that pseudonym. What the relay can observe:
//! source IP (or the fronting proxy can), stable random host pseudonym, device
//! push token, and wake/revoke timing. Content and the host identity remain
//! hidden behind the phone-sealed blob.
//!
//! Registration modes (exactly one must be configured at startup):
//!   - `PORTTY_PUSH_OPEN_REGISTRATION=1` - self-host default: a host registers
//!     the handle derived from its private random bearer, bounded by caps.
//!   - `PORTTY_PUSH_ADMIN_TOKEN=<secret>` - gated: registrations require the
//!     operator token (hosted/multi-tenant deployments).
//!
//! The device table is deliberately memory-only: hosts persist their own
//! registrations and re-register on boot or when a wake answers 404, so a
//! relay restart heals itself and there is nothing user-linked to leak at rest.

mod provider_auth;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};

use provider_auth::ProviderConfig;

/// Hex-encoded sealed blob cap (2 KiB of ciphertext is far above what the
/// phone seals - a device id plus envelope overhead).
const MAX_BLOB_BYTES: usize = 4096;
const MIN_WAKE_INTERVAL: Duration = Duration::from_secs(3);
const HOST_HANDLE_CONTEXT: &[u8] = b"portty-push-host-handle-v2";
/// Registration table cap. Registrations are tiny, so this is a
/// memory-abuse valve, not a scaling knob; at the cap NEW pseudonyms are
/// refused (503) while existing ones may still refresh their token.
const MAX_DEVICES: usize = 10_000;
const MAX_DEVICES_PER_HOST: usize = 32;
/// A registration this old is assumed dead. A live host re-registers on every
/// connect and every push-token rotation, so anything untouched for a month has
/// stopped using this relay - and its slot should not be held against a real one.
const REGISTRATION_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// How much of the table to reclaim when it fills. Open registration only asks
/// for proof of a secret the registrant generated themselves, so an attacker can
/// mint unlimited pseudonyms; without eviction a filled table stayed full until
/// the operator restarted the process and every NEW host got a 503 forever.
/// Dropping the oldest tenth keeps that a slowdown instead of an outage.
const RECLAIM_FRACTION: usize = 10;
/// Outbound provider calls are bounded so a black-holed APNs/FCM endpoint
/// can't pile up in-flight wakes.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);

/// Global ceiling on outbound provider calls in flight at once, across every
/// request handler.
///
/// `PROVIDER_TIMEOUT` bounds how long ONE call may hang; it does nothing about
/// how MANY hang at once. A slow or black-holed APNs/FCM endpoint plus a burst
/// of wakes meant up to `PROVIDER_TIMEOUT` worth of arrivals sitting in flight
/// together - each holding a socket, a TLS session and a task - which is how a
/// provider outage turns into a relay outage.
///
/// Load is SHED, not queued: a wake that cannot get a slot is dropped with a
/// warning rather than made to wait. Queueing would rebuild the same pile-up one
/// level up, and a wake is a doorbell - the phone picks the approval up on its
/// next connect regardless. A permit is never held for longer than
/// `PROVIDER_TIMEOUT`, so slots always come back.
const PROVIDER_CONCURRENCY: usize = 32;

/// Per-source-IP write-endpoint budget: 60 requests / minute. Generous for a
/// real host (register once + a handful of wakes) but caps a spam flood.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX: u32 = 60;

/// How many distinct host pseudonyms one `device_token` may be registered under.
///
/// Nothing proves a registrant owns the token it registers, so the abuse shape is
/// "register a victim's token under a pseudonym you control, then wake it". A real
/// phone is paired with a handful of machines; an attacker needs a fresh
/// pseudonym per attempt, because the per-pseudonym throttle bounds each one. So
/// capping pseudonyms-per-token attacks the manoeuvre directly rather than the
/// source address, which rotates freely.
///
/// This does NOT prove possession - the deferred fix still stands. It bounds how
/// much a token-holder can do with what they took.
const MAX_PSEUDONYMS_PER_TOKEN: usize = 8;

/// Wake budget per `device_token`, independent of who asked or from where.
///
/// The per-IP cap misses an attacker with several addresses and the per-pseudonym
/// throttle misses one who rotates pseudonyms. Both are properties of the
/// SENDER; this is a property of the TARGET, which is what the victim actually
/// experiences - so it holds however the sender is distributed.
///
/// Deliberately generous: a busy agent session behind the existing 3s
/// per-pseudonym throttle could legitimately ring a few dozen times in five
/// minutes, and a doorbell that silently stops arriving is worse than one that
/// arrives too often.
const WAKE_BUDGET_WINDOW: Duration = Duration::from_secs(300);
const WAKE_BUDGET_MAX: u32 = 60;

/// Fixed-window per-IP rate limiter for the write endpoints. Open-registration
/// authenticates by proof-of-secret, but nothing binds a registered
/// `device_token` to the registrant - so a reachable attacker could register a
/// victim's token and wake it to burn the operator's push quota, and the
/// per-pseudonym 3s throttle is trivially dodged by rotating pseudonyms. A
/// per-IP cap bounds a single abuser (#10 / #32). Caveat: behind a reverse
/// proxy the observed IP is the proxy's - see PUSH-SETUP for the deployment
/// note and the deferred proof-of-token-possession fix.
struct PerIpLimiter {
    window: Duration,
    max: u32,
    hits: std::sync::Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl PerIpLimiter {
    fn new(window: Duration, max: u32) -> Self {
        Self {
            window,
            max,
            hits: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// True if `ip` is within budget (records the hit); false once it exceeds
    /// `max` in the current window.
    fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let mut hits = self.hits.lock().unwrap();
        // Evict expired windows every call - bounds the map to IPs seen within
        // one window (a self-host relay sees a handful).
        hits.retain(|_, (start, _)| now.saturating_duration_since(*start) < self.window);
        match hits.get_mut(&ip) {
            Some((start, count)) if now.saturating_duration_since(*start) < self.window => {
                if *count >= self.max {
                    return false;
                }
                *count += 1;
                true
            }
            _ => {
                hits.insert(ip, (now, 1));
                true
            }
        }
    }
}

/// Fixed-window budget keyed on the push token being woken.
///
/// Reuses the shape of [`PerIpLimiter`] rather than sharing it: the key type and
/// the eviction bound are different (tokens live as long as a registration, IPs
/// for one window), and folding them into one generic obscured which of the two
/// caps a given call was subject to.
struct PerTokenLimiter {
    window: Duration,
    max: u32,
    hits: std::sync::Mutex<HashMap<String, (Instant, u32)>>,
}

impl PerTokenLimiter {
    fn new(window: Duration, max: u32) -> Self {
        Self {
            window,
            max,
            hits: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// True if this token is within budget (records the hit). Expired windows are
    /// evicted every call, so the map is bounded by tokens woken within one
    /// window rather than by every token ever seen.
    fn allow(&self, token: &str, now: Instant) -> bool {
        let mut hits = self.hits.lock().unwrap();
        hits.retain(|_, (start, _)| now.saturating_duration_since(*start) < self.window);
        match hits.get_mut(token) {
            Some((start, count)) if now.saturating_duration_since(*start) < self.window => {
                if *count >= self.max {
                    return false;
                }
                *count += 1;
                true
            }
            _ => {
                hits.insert(token.to_string(), (now, 1));
                true
            }
        }
    }
}

#[derive(Clone)]
struct AppState {
    devices: Arc<Mutex<HashMap<(String, String), Device>>>,
    last_wake: Arc<Mutex<HashMap<String, Instant>>>,
    registration: RegistrationAuth,
    sender: Arc<dyn PushSender>,
    ip_limiter: Arc<PerIpLimiter>,
    /// Per-`device_token` wake budget. Keyed on the TARGET, so it survives an
    /// attacker rotating source addresses and pseudonyms - see `WAKE_BUDGET_MAX`.
    token_limiter: Arc<PerTokenLimiter>,
    /// Slots for in-flight outbound provider calls - see `PROVIDER_CONCURRENCY`.
    provider_slots: Arc<Semaphore>,
}

#[derive(Clone)]
enum RegistrationAuth {
    /// bearer must equal the operator's admin token (constant-time compare).
    Admin(Arc<str>),
    /// bearer must derive the handle being registered (self-host default).
    Open,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Provider {
    Apns,
    Fcm,
}

#[derive(Clone, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct Device {
    #[zeroize(skip)]
    provider: Provider,
    device_token: String,
    /// Ciphertext generated on the phone (hex). The relay stores and forwards
    /// it but cannot derive the host identity or pending approval from it.
    sealed_wake_blob: String,
    /// When this registration was last written or woken. Drives TTL expiry and
    /// least-recently-used eviction (see `reclaim_registrations`). Never comes off
    /// the wire - a registrant must not be able to backdate or refresh its own
    /// entry, so it is always stamped here.
    #[zeroize(skip)]
    #[serde(skip, default = "Instant::now")]
    refreshed: Instant,
}

#[derive(Deserialize)]
struct RegisterRequest {
    host_pseudonym: String,
    registration_id: String,
    provider: Provider,
    device_token: String,
    sealed_wake_blob: String,
}

#[derive(Deserialize)]
struct WakeRequest {
    host_pseudonym: String,
}

#[derive(Deserialize)]
struct RevokeRequest {
    host_pseudonym: String,
    registration_id: String,
}

fn valid_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_registration_id(value: &str) -> bool {
    valid_id(value)
}

fn valid_blob(value: &str) -> bool {
    value.len() <= MAX_BLOB_BYTES && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn host_secret_matches(presented: &str, host_pseudonym: &str) -> bool {
    use sha2::{Digest, Sha256};
    let Ok(secret) = hex::decode(presented) else {
        return false;
    };
    if secret.len() != 32 || !valid_id(host_pseudonym) {
        return false;
    }
    let mut digest = Sha256::new();
    digest.update(HOST_HANDLE_CONTEXT);
    digest.update(secret);
    let expected = hex::encode(digest.finalize());
    expected.as_bytes().ct_eq(host_pseudonym.as_bytes()).into()
}

fn host_bearer_matches(headers: &HeaderMap, host_pseudonym: &str) -> bool {
    bearer(headers).is_some_and(|secret| host_secret_matches(secret, host_pseudonym))
}

fn host_registration_proof_matches(headers: &HeaderMap, host_pseudonym: &str) -> bool {
    headers
        .get("x-portty-host-authorization")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|secret| host_secret_matches(secret, host_pseudonym))
}

async fn health() -> &'static str {
    "ok"
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<RegisterRequest>,
) -> StatusCode {
    if !state.ip_limiter.allow(peer.ip(), Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let authorized = match (&state.registration, bearer(&headers)) {
        // Admin token: attacker-supplied string - compare constant-time.
        (RegistrationAuth::Admin(token), Some(presented)) => {
            bool::from(presented.as_bytes().ct_eq(token.as_bytes()))
                && host_registration_proof_matches(&headers, &request.host_pseudonym)
        }
        // Open mode: prove knowledge of the random host secret whose one-way
        // handle is being registered. The public handle is not a bearer.
        (RegistrationAuth::Open, Some(_)) => host_bearer_matches(&headers, &request.host_pseudonym),
        (_, None) => false,
    };
    if !authorized {
        return StatusCode::UNAUTHORIZED;
    }
    if !valid_id(&request.host_pseudonym)
        || !valid_registration_id(&request.registration_id)
        || request.device_token.is_empty()
        || request.device_token.len() > 4096
        || !valid_blob(&request.sealed_wake_blob)
    {
        return StatusCode::BAD_REQUEST;
    }
    let now = Instant::now();
    let mut devices = state.devices.lock().await;
    let key = (
        request.host_pseudonym.clone(),
        request.registration_id.clone(),
    );
    let is_new = !devices.contains_key(&key);
    if is_new {
        reclaim_registrations(&mut devices, now);
    }
    let host_count = devices
        .keys()
        .filter(|(host, _)| host == &request.host_pseudonym)
        .count();
    // The per-host cap is a real limit on one host and stays hard. The global cap
    // is only reachable after reclamation could not free anything.
    if is_new && (devices.len() >= MAX_DEVICES || host_count >= MAX_DEVICES_PER_HOST) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    // How many OTHER pseudonyms already point at this exact token. Counted on the
    // token, not the registration id, because the token is the thing that
    // identifies the victim's device.
    let pseudonyms_for_token = devices
        .iter()
        .filter(|((host, _), device)| {
            device.device_token == request.device_token && host != &request.host_pseudonym
        })
        .map(|((host, _), _)| host.clone())
        .collect::<std::collections::HashSet<_>>()
        .len();
    if pseudonyms_for_token >= MAX_PSEUDONYMS_PER_TOKEN {
        // 403, not 503: this is a refusal about this token, not relay capacity,
        // and a legitimate phone will never see it.
        return StatusCode::FORBIDDEN;
    }
    devices.insert(
        key,
        Device {
            provider: request.provider,
            device_token: request.device_token,
            sealed_wake_blob: request.sealed_wake_blob,
            refreshed: now,
        },
    );
    StatusCode::NO_CONTENT
}

/// Make room in a full registration table: drop everything past its TTL, and if
/// that is not enough, the least recently refreshed tenth.
///
/// Registrations are authenticated but not *scarce* - in open mode the credential
/// is a secret the registrant generates, so anyone can mint pseudonyms and fill
/// the table. Without this the cap turned a slow flood into a permanent outage
/// for every host that had not registered yet, recoverable only by a restart.
/// Eviction is not free for the victim, but a re-register is one request that
/// every host already makes on connect.
fn reclaim_registrations(devices: &mut HashMap<(String, String), Device>, now: Instant) {
    devices.retain(|_, device| now.duration_since(device.refreshed) < REGISTRATION_TTL);
    if devices.len() < MAX_DEVICES {
        return;
    }
    let mut ages: Vec<((String, String), Instant)> = devices
        .iter()
        .map(|(key, device)| (key.clone(), device.refreshed))
        .collect();
    // Oldest first; `sort_by_key` is stable so equal timestamps keep a fixed
    // relative order rather than evicting arbitrarily between calls.
    ages.sort_by_key(|(_, refreshed)| *refreshed);
    let drop_count = (MAX_DEVICES / RECLAIM_FRACTION).max(1);
    for (key, _) in ages.into_iter().take(drop_count) {
        devices.remove(&key);
    }
    tracing::warn!(
        evicted = drop_count,
        "push registration table was full; evicted the least recently refreshed entries"
    );
}

async fn wake(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<WakeRequest>,
) -> StatusCode {
    if !state.ip_limiter.allow(peer.ip(), Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    if !host_bearer_matches(&headers, &request.host_pseudonym) {
        return StatusCode::UNAUTHORIZED;
    }
    // Look up FIRST: an unregistered pseudonym must not insert rate-limit
    // state (that was an unauthenticated memory-growth hole). 404 also tells
    // a legitimate host that the relay restarted → it re-registers + retries.
    // Waking is proof the registration is live, so stamp it: eviction sorts by
    // last refresh, and a host that only ever wakes (never re-registers) must not
    // age out from under itself.
    let devices: Vec<Device> = {
        let now = Instant::now();
        let mut table = state.devices.lock().await;
        table
            .iter_mut()
            .filter(|((host, _), _)| host == &request.host_pseudonym)
            .map(|(_, device)| {
                device.refreshed = now;
                device.clone()
            })
            .collect()
    };
    if devices.is_empty() {
        return StatusCode::NOT_FOUND;
    }
    {
        let mut wakes = state.last_wake.lock().await;
        if wakes
            .get(&request.host_pseudonym)
            .is_some_and(|last| last.elapsed() < MIN_WAKE_INTERVAL)
        {
            return StatusCode::TOO_MANY_REQUESTS;
        }
        // Bounded: only registered pseudonyms reach this insert, so the map
        // can never outgrow the device table.
        wakes.insert(request.host_pseudonym.clone(), Instant::now());
    }
    let mut delivered = false;
    let now = Instant::now();
    for device in devices {
        // Checked per TARGET, inside the loop: one pseudonym can hold several
        // registrations, and a token over budget must be skipped without
        // suppressing the others.
        if !state.token_limiter.allow(&device.device_token, now) {
            tracing::warn!("wake budget exhausted for a device token; skipping it");
            continue;
        }
        // Shed rather than queue - see `PROVIDER_CONCURRENCY`. `continue`, not
        // `break`: the other targets of this wake may still have slots, and one
        // saturated moment should not silently truncate the fan-out.
        let Ok(_slot) = state.provider_slots.clone().try_acquire_owned() else {
            tracing::warn!("provider concurrency ceiling reached; shedding this wake");
            continue;
        };
        match state.sender.send(device, NotificationKind::Wake).await {
            Ok(()) => delivered = true,
            Err(error) => tracing::warn!(%error, "push provider rejected wake-up"),
        }
    }
    if delivered {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::BAD_GATEWAY
    }
}

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeRequest>,
) -> StatusCode {
    if !host_bearer_matches(&headers, &request.host_pseudonym)
        || !valid_registration_id(&request.registration_id)
    {
        return StatusCode::UNAUTHORIZED;
    }
    let key = (request.host_pseudonym.clone(), request.registration_id);
    let Some(device) = state.devices.lock().await.remove(&key) else {
        return StatusCode::NOT_FOUND;
    };
    // Forget rate-limit state once the final registration disappears.
    if !state
        .devices
        .lock()
        .await
        .keys()
        .any(|(host, _)| host == &request.host_pseudonym)
    {
        state.last_wake.lock().await.remove(&request.host_pseudonym);
    }
    // The registration is already gone, so this notification is a courtesy. It
    // takes a slot on the same ceiling as a wake and is shed the same way.
    let Ok(_slot) = state.provider_slots.clone().try_acquire_owned() else {
        tracing::warn!("provider concurrency ceiling reached; shedding a pair-revoked notice");
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match state.sender.send(device, NotificationKind::Revoked).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(error) => {
            tracing::warn!(%error, "push provider rejected pair-revoked wake");
            StatusCode::BAD_GATEWAY
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotificationKind {
    Wake,
    Revoked,
}

#[async_trait::async_trait]
trait PushSender: Send + Sync {
    async fn send(&self, device: Device, kind: NotificationKind) -> Result<(), String>;
}

struct ProviderSender {
    client: reqwest::Client,
    providers: ProviderConfig,
}

#[async_trait::async_trait]
impl PushSender for ProviderSender {
    async fn send(&self, device: Device, kind: NotificationKind) -> Result<(), String> {
        let request = build_provider_request(&self.client, &self.providers, &device, kind).await?;
        let response = self
            .client
            .execute(request)
            .await
            .map_err(|error| error.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("provider returned {}", response.status()))
        }
    }
}

/// Build the exact APNs/FCM request separately from transport. This makes the
/// privacy contract (opaque blob, generic text, correct token/topic/auth) fully
/// testable without binding sockets or contacting a real provider in CI.
async fn build_provider_request(
    client: &reqwest::Client,
    providers: &ProviderConfig,
    device: &Device,
    kind: NotificationKind,
) -> Result<reqwest::Request, String> {
    let (alert, title, body) = match kind {
        NotificationKind::Wake => (
            "Portty has a pending approval",
            "Portty",
            "Pending approval",
        ),
        NotificationKind::Revoked => (
            "This Portty pair was ended on the laptop",
            "Portty pair ended",
            "Open Portty to synchronize securely",
        ),
    };
    let request = match device.provider {
        Provider::Apns => {
            let bearer = providers.apns_bearer()?;
            let topic = providers.apns_topic()?;
            client
                .post(format!(
                    "{}/{}",
                    providers.apns_url().trim_end_matches('/'),
                    device.device_token
                ))
                .bearer_auth(&bearer)
                .header("apns-topic", topic)
                .header("apns-push-type", "alert")
                .header("apns-priority", "10")
                .json(&serde_json::json!({
                    "aps": {
                        "alert": alert,
                        "sound": "default",
                        "badge": 1,
                    },
                    "wake": device.sealed_wake_blob,
                }))
                .build()
                .map_err(|error| error.to_string())?
        }
        Provider::Fcm => {
            let url = providers.fcm_send_url()?;
            let bearer = providers.fcm_bearer(client).await?;
            client
                .post(url)
                .bearer_auth(&bearer)
                .json(&serde_json::json!({
                    "message": {
                        "token": device.device_token,
                        "notification": { "title": title, "body": body },
                        "data": { "wake": device.sealed_wake_blob }
                    }
                }))
                .build()
                .map_err(|error| error.to_string())?
        }
    };
    Ok(request)
}

/// Install the process-wide Rustls crypto provider before any TLS client is
/// built. reqwest is built with `rustls-no-provider` so the relay keeps one
/// crypto stack (ring) instead of also pulling aws-lc-rs, and the cost of that
/// choice is that nothing installs a default provider for us - building a client
/// would fail with "no process-level CryptoProvider available", which for this
/// binary means every APNs/FCM send dies at startup. Mirrors the phone app's
/// `install_rustls_crypto_provider`.
fn install_rustls_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn build_state(registration: RegistrationAuth) -> AppState {
    install_rustls_crypto_provider();
    // No redirects. Provider calls carry an OAuth bearer (FCM) or a JWT (APNs) in
    // an Authorization header, and the endpoints are operator-configured - a
    // redirect from a mistyped or hostile host would hand that credential on.
    // APNs and FCM never legitimately redirect these POSTs.
    let client = reqwest::Client::builder()
        .timeout(PROVIDER_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");
    let sender = ProviderSender {
        client,
        providers: ProviderConfig::from_env().unwrap_or_else(|error| panic!("{error}")),
    };
    build_state_with_sender(registration, Arc::new(sender))
}

fn build_state_with_sender(
    registration: RegistrationAuth,
    sender: Arc<dyn PushSender>,
) -> AppState {
    AppState {
        devices: Arc::new(Mutex::new(HashMap::new())),
        last_wake: Arc::new(Mutex::new(HashMap::new())),
        registration,
        sender,
        ip_limiter: Arc::new(PerIpLimiter::new(RATE_LIMIT_WINDOW, RATE_LIMIT_MAX)),
        token_limiter: Arc::new(PerTokenLimiter::new(WAKE_BUDGET_WINDOW, WAKE_BUDGET_MAX)),
        provider_slots: Arc::new(Semaphore::new(PROVIDER_CONCURRENCY)),
    }
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/register", post(register))
        .route("/v1/wake", post(wake))
        .route("/v1/revoke", post(revoke))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "portty_push_relay=info".into()),
        )
        .init();
    let registration = match (
        std::env::var("PORTTY_PUSH_ADMIN_TOKEN").ok(),
        std::env::var("PORTTY_PUSH_OPEN_REGISTRATION").is_ok_and(|v| v == "1"),
    ) {
        (Some(token), false) => RegistrationAuth::Admin(token.into()),
        (None, true) => RegistrationAuth::Open,
        (Some(_), true) => {
            panic!("set PORTTY_PUSH_ADMIN_TOKEN or PORTTY_PUSH_OPEN_REGISTRATION=1, not both")
        }
        (None, false) => panic!(
            "configure registration: PORTTY_PUSH_OPEN_REGISTRATION=1 (self-host) \
             or PORTTY_PUSH_ADMIN_TOKEN=<secret> (gated)"
        ),
    };
    let addr: SocketAddr = std::env::var("PORTTY_PUSH_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9877".into())
        .parse()
        .expect("PORTTY_PUSH_ADDR must be host:port");
    let app = build_router(build_state(registration));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind relay");
    tracing::info!(%addr, "wake-only relay listening");
    // `into_make_service_with_connect_info` supplies the peer `SocketAddr` so the
    // per-IP limiter (#10) sees the source address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve relay");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// Keyed on the TARGET, so it holds however the sender is distributed - which
    /// is the property the per-IP and per-pseudonym caps do not have.
    #[test]
    fn per_token_limiter_caps_wakes_at_one_device_then_recovers() {
        let lim = PerTokenLimiter::new(Duration::from_secs(300), 3);
        let start = Instant::now();
        for i in 0..3 {
            assert!(lim.allow("tok-a", start), "wake {i} should be in budget");
        }
        assert!(!lim.allow("tok-a", start), "the 4th wake is over budget");
        // A different device is unaffected: one victim's budget must not become
        // everyone's outage.
        assert!(lim.allow("tok-b", start));
        // And the window rolls.
        assert!(lim.allow("tok-a", start + Duration::from_secs(301)));
    }

    #[test]
    fn per_ip_limiter_caps_a_flood_then_recovers() {
        let lim = PerIpLimiter::new(Duration::from_secs(60), 3);
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let t0 = Instant::now();
        assert!(lim.allow(ip, t0));
        assert!(lim.allow(ip, t0 + Duration::from_secs(1)));
        assert!(lim.allow(ip, t0 + Duration::from_secs(2)));
        assert!(
            !lim.allow(ip, t0 + Duration::from_secs(3)),
            "the 4th request within the window is throttled"
        );
        // A different source IP has its own budget.
        let other: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(lim.allow(other, t0 + Duration::from_secs(3)));
        // Once the window rolls over, the original IP is allowed again.
        assert!(lim.allow(ip, t0 + Duration::from_secs(61)));
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RecordedDelivery {
        provider: &'static str,
        token: String,
        blob: String,
        kind: NotificationKind,
    }

    #[derive(Default)]
    struct RecordingSender {
        deliveries: Mutex<Vec<RecordedDelivery>>,
    }

    #[async_trait::async_trait]
    impl PushSender for RecordingSender {
        async fn send(&self, device: Device, kind: NotificationKind) -> Result<(), String> {
            self.deliveries.lock().await.push(RecordedDelivery {
                provider: match device.provider {
                    Provider::Apns => "apns",
                    Provider::Fcm => "fcm",
                },
                token: device.device_token.clone(),
                blob: device.sealed_wake_blob.clone(),
                kind,
            });
            Ok(())
        }
    }

    #[test]
    fn host_pseudonym_is_full_entropy_hex() {
        assert!(valid_id(&"ab".repeat(32)));
        assert!(!valid_id("host-name"));
        assert!(!valid_id(&"ab".repeat(31)));
    }

    fn host_secret() -> String {
        "11".repeat(32)
    }

    fn pseudonym_for(secret: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(HOST_HANDLE_CONTEXT);
        digest.update(hex::decode(secret).unwrap());
        hex::encode(digest.finalize())
    }

    fn pseudonym() -> String {
        pseudonym_for(&host_secret())
    }

    fn registration_id() -> String {
        "22".repeat(32)
    }

    fn register_body(pseudonym: &str) -> String {
        serde_json::json!({
            "host_pseudonym": pseudonym,
            "registration_id": registration_id(),
            "provider": "apns",
            "device_token": "device-token-1",
            "sealed_wake_blob": "deadbeef",
        })
        .to_string()
    }

    fn post_json(uri: &str, bearer: &str, body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"))
            .header("x-portty-host-authorization", host_secret())
            // The handlers require ConnectInfo (the per-IP limiter, #10); oneshot
            // has no socket, so supply a fixed loopback peer. 60/min is never hit.
            .extension(ConnectInfo("127.0.0.1:9999".parse::<SocketAddr>().unwrap()))
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn open_mode_lets_a_host_register_only_its_own_pseudonym() {
        let app = build_router(build_state(RegistrationAuth::Open));
        let p = pseudonym();
        // Wrong host secret → 401.
        let other = "33".repeat(32);
        let res = app
            .clone()
            .oneshot(post_json("/v1/register", &other, register_body(&p)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        // Self-registration → 204.
        let res = app
            .clone()
            .oneshot(post_json("/v1/register", &host_secret(), register_body(&p)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn admin_mode_requires_the_admin_token() {
        let app = build_router(build_state(RegistrationAuth::Admin("sekrit".into())));
        let p = pseudonym();
        let res = app
            .clone()
            .oneshot(post_json("/v1/register", &p, register_body(&p)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let res = app
            .clone()
            .oneshot(post_json("/v1/register", "sekrit", register_body(&p)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    /// The abuse shape this cap exists for: nothing proves a registrant owns the
    /// token it registers, so an attacker points pseudonym after pseudonym at a
    /// victim's device token and wakes each one. Every pseudonym is individually
    /// legitimate - it proves knowledge of its OWN secret - so the only thing that
    /// distinguishes the attack is how many of them name the same token.
    #[tokio::test]
    async fn register_refuses_too_many_pseudonyms_for_one_device_token() {
        let app = build_router(build_state(RegistrationAuth::Open));

        // Each attempt is a fresh, self-consistent host: its own secret, its own
        // derived pseudonym, all aimed at ONE device token.
        let attempt = |index: usize| {
            let secret = format!("{:02x}", index + 0x40).repeat(32);
            let pseudonym = pseudonym_for(&secret);
            let body = serde_json::json!({
                "host_pseudonym": pseudonym,
                "registration_id": registration_id(),
                "provider": "apns",
                "device_token": "device-token-1",
                "sealed_wake_blob": "deadbeef",
            })
            .to_string();
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {secret}"))
                .header("x-portty-host-authorization", &secret)
                .extension(ConnectInfo("127.0.0.1:9999".parse::<SocketAddr>().unwrap()))
                .body(Body::from(body))
                .unwrap()
        };

        for index in 0..MAX_PSEUDONYMS_PER_TOKEN {
            let res = app.clone().oneshot(attempt(index)).await.unwrap();
            assert_eq!(
                res.status(),
                StatusCode::NO_CONTENT,
                "pseudonym {index} is under the cap"
            );
        }
        let res = app
            .clone()
            .oneshot(attempt(MAX_PSEUDONYMS_PER_TOKEN))
            .await
            .unwrap();
        // FORBIDDEN, not SERVICE_UNAVAILABLE: this is about this token, not relay
        // capacity, and the distinction is what a legitimate host needs to see.
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// The cap must not stop a phone re-registering with the SAME pseudonym, which
    /// happens on every reconnect. Counting distinct pseudonyms rather than rows
    /// is what makes that hold.
    #[tokio::test]
    async fn re_registering_the_same_pseudonym_is_never_capped() {
        let app = build_router(build_state(RegistrationAuth::Open));
        let p = pseudonym();
        for round in 0..(MAX_PSEUDONYMS_PER_TOKEN * 3) {
            let res = app
                .clone()
                .oneshot(post_json("/v1/register", &host_secret(), register_body(&p)))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NO_CONTENT, "round {round}");
        }
    }

    #[tokio::test]
    async fn register_rejects_malformed_input() {
        let app = build_router(build_state(RegistrationAuth::Open));
        // Non-hex pseudonym.
        let res = app
            .clone()
            .oneshot(post_json(
                "/v1/register",
                "not-hex",
                register_body("not-hex"),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "malformed handles must fail before request-shape details are exposed"
        );
        // Non-hex blob.
        let p = pseudonym();
        let body = serde_json::json!({
            "host_pseudonym": p,
            "registration_id": registration_id(),
            "provider": "apns",
            "device_token": "t",
            "sealed_wake_blob": "zzzz",
        })
        .to_string();
        let res = app
            .clone()
            .oneshot(post_json("/v1/register", &host_secret(), body))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wake_for_unknown_pseudonym_is_404_and_inserts_no_state() {
        let state = build_state(RegistrationAuth::Open);
        let app = build_router(state.clone());
        let p = pseudonym();
        let body = serde_json::json!({ "host_pseudonym": p }).to_string();
        let res = app
            .clone()
            .oneshot(post_json("/v1/wake", &host_secret(), body))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        // The unauthenticated-memory-growth hole: an invented pseudonym must
        // leave NO trace in the rate-limit map.
        assert!(state.last_wake.lock().await.is_empty());
    }

    #[tokio::test]
    async fn wake_requires_secret_matching_public_handle() {
        let app = build_router(build_state(RegistrationAuth::Open));
        let p = pseudonym();
        let body = serde_json::json!({ "host_pseudonym": p }).to_string();
        let res = app
            .clone()
            .oneshot(post_json("/v1/wake", &"cd".repeat(32), body))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn second_wake_inside_the_interval_is_rate_limited() {
        let state = build_state(RegistrationAuth::Open);
        let app = build_router(state.clone());
        let p = pseudonym();
        // Register first so wakes reach the rate limiter.
        let res = app
            .clone()
            .oneshot(post_json("/v1/register", &host_secret(), register_body(&p)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let body = serde_json::json!({ "host_pseudonym": p }).to_string();
        // First wake passes auth + rate limit, then fails at the provider
        // (APNs is unconfigured in tests) → 502 proves it got that far.
        let res = app
            .clone()
            .oneshot(post_json("/v1/wake", &host_secret(), body.clone()))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        // Immediate second wake → 429.
        let res = app
            .clone()
            .oneshot(post_json("/v1/wake", &host_secret(), body))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// `PROVIDER_TIMEOUT` bounds how long ONE provider call may hang. This bounds
    /// how MANY hang at once, which is what turns a provider outage into a relay
    /// outage. With every slot held, the wake is SHED - it returns immediately and
    /// never reaches the provider - rather than queueing behind the stall.
    #[tokio::test]
    async fn a_saturated_provider_ceiling_sheds_the_wake_instead_of_queueing_it() {
        let sender = Arc::new(RecordingSender::default());
        let state = build_state_with_sender(RegistrationAuth::Open, sender.clone());
        let app = build_router(state.clone());
        let p = pseudonym();
        let res = app
            .clone()
            .oneshot(post_json("/v1/register", &host_secret(), register_body(&p)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Stand in for a stalled provider holding every slot.
        let held = state
            .provider_slots
            .clone()
            .acquire_many_owned(PROVIDER_CONCURRENCY as u32)
            .await
            .unwrap();

        let body = serde_json::json!({ "host_pseudonym": p }).to_string();
        let res = app
            .clone()
            .oneshot(post_json("/v1/wake", &host_secret(), body))
            .await
            .unwrap();
        // It answered (this await returning at all is the point) and delivered
        // nothing.
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        assert!(
            sender.deliveries.lock().await.is_empty(),
            "a shed wake must never reach the provider"
        );
        // The shed path must not have leaked a permit on its way out.
        assert_eq!(state.provider_slots.available_permits(), 0);

        // And slots come back when the provider does.
        drop(held);
        assert_eq!(
            state.provider_slots.available_permits(),
            PROVIDER_CONCURRENCY
        );
    }

    #[tokio::test]
    async fn registrations_are_per_phone_and_revoke_is_targeted() {
        let state = build_state(RegistrationAuth::Open);
        let app = build_router(state.clone());
        let host = pseudonym();
        let first = registration_id();
        let second = "44".repeat(32);
        for (id, token) in [(&first, "phone-a"), (&second, "phone-b")] {
            let body = serde_json::json!({
                "host_pseudonym": host,
                "registration_id": id,
                "provider": "apns",
                "device_token": token,
                "sealed_wake_blob": "deadbeef",
            })
            .to_string();
            let response = app
                .clone()
                .oneshot(post_json("/v1/register", &host_secret(), body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        assert_eq!(state.devices.lock().await.len(), 2);

        let revoke_body = serde_json::json!({
            "host_pseudonym": host,
            "registration_id": first,
        })
        .to_string();
        let wrong = app
            .clone()
            .oneshot(post_json(
                "/v1/revoke",
                &"55".repeat(32),
                revoke_body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.devices.lock().await.len(), 2);

        // APNs is deliberately unconfigured in tests, so delivery returns 502;
        // privacy cleanup still removes only the targeted phone registration.
        let revoked = app
            .clone()
            .oneshot(post_json("/v1/revoke", &host_secret(), revoke_body))
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::BAD_GATEWAY);
        let devices = state.devices.lock().await;
        assert!(!devices.contains_key(&(host.clone(), first)));
        assert!(devices.contains_key(&(host, second)));
    }

    #[tokio::test]
    async fn register_wake_and_revoke_flow_reaches_provider_with_only_opaque_data() {
        let sender = Arc::new(RecordingSender::default());
        let state = build_state_with_sender(RegistrationAuth::Open, sender.clone());
        let app = build_router(state.clone());
        let host = pseudonym();

        let registered = app
            .clone()
            .oneshot(post_json(
                "/v1/register",
                &host_secret(),
                register_body(&host),
            ))
            .await
            .unwrap();
        assert_eq!(registered.status(), StatusCode::NO_CONTENT);

        let wake = app
            .clone()
            .oneshot(post_json(
                "/v1/wake",
                &host_secret(),
                serde_json::json!({ "host_pseudonym": host }).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(wake.status(), StatusCode::NO_CONTENT);

        let revoked = app
            .clone()
            .oneshot(post_json(
                "/v1/revoke",
                &host_secret(),
                serde_json::json!({
                    "host_pseudonym": host,
                    "registration_id": registration_id(),
                })
                .to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        assert!(state.devices.lock().await.is_empty());

        assert_eq!(
            *sender.deliveries.lock().await,
            vec![
                RecordedDelivery {
                    provider: "apns",
                    token: "device-token-1".into(),
                    blob: "deadbeef".into(),
                    kind: NotificationKind::Wake,
                },
                RecordedDelivery {
                    provider: "apns",
                    token: "device-token-1".into(),
                    blob: "deadbeef".into(),
                    kind: NotificationKind::Revoked,
                },
            ]
        );
    }

    #[tokio::test]
    async fn provider_requests_have_expected_auth_headers_and_privacy_bounded_payloads() {
        // Not just setup: this test is the only thing that builds a real client
        // in CI, so it is also the guard that `rustls-no-provider` still has a
        // provider installed. Without it `Client::new` panics here rather than
        // in production on the first push.
        install_rustls_crypto_provider();
        let client = reqwest::Client::new();
        let providers = ProviderConfig::test_static();
        let apns = Device {
            provider: Provider::Apns,
            device_token: "apns-token".into(),
            sealed_wake_blob: "aabbccdd".into(),
            refreshed: Instant::now(),
        };
        let request = build_provider_request(&client, &providers, &apns, NotificationKind::Wake)
            .await
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://apns.test.invalid/3/device/apns-token"
        );
        assert_eq!(
            request.headers()["authorization"],
            "Bearer apns-test-bearer"
        );
        assert_eq!(request.headers()["apns-topic"], "com.example.portty");
        assert_eq!(request.headers()["apns-push-type"], "alert");
        let body: serde_json::Value =
            serde_json::from_slice(request.body().and_then(reqwest::Body::as_bytes).unwrap())
                .unwrap();
        assert_eq!(body["wake"], "aabbccdd");
        assert_eq!(body["aps"]["alert"], "Portty has a pending approval");
        assert!(body.get("host_pseudonym").is_none());

        let fcm = Device {
            provider: Provider::Fcm,
            device_token: "fcm-token".into(),
            sealed_wake_blob: "11223344".into(),
            refreshed: Instant::now(),
        };
        let request = build_provider_request(&client, &providers, &fcm, NotificationKind::Revoked)
            .await
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://fcm.test.invalid/v1/projects/portty-test/messages:send"
        );
        assert_eq!(request.headers()["authorization"], "Bearer fcm-test-bearer");
        let body: serde_json::Value =
            serde_json::from_slice(request.body().and_then(reqwest::Body::as_bytes).unwrap())
                .unwrap();
        assert_eq!(body["message"]["token"], "fcm-token");
        assert_eq!(body["message"]["data"]["wake"], "11223344");
        assert_eq!(
            body["message"]["notification"]["title"],
            "Portty pair ended"
        );
        assert!(body["message"].get("host_pseudonym").is_none());
    }

    #[tokio::test]
    async fn device_table_is_bounded() {
        let state = build_state(RegistrationAuth::Open);
        // Simulate a full table cheaply (inserting 10k via HTTP is slow).
        {
            let mut devices = state.devices.lock().await;
            for i in 0..MAX_DEVICES {
                let host = if i == 0 {
                    pseudonym()
                } else {
                    format!("{i:064x}")
                };
                devices.insert(
                    (host, registration_id()),
                    Device {
                        provider: Provider::Apns,
                        device_token: "t".into(),
                        sealed_wake_blob: String::new(),
                        refreshed: Instant::now(),
                    },
                );
            }
        }
        let app = build_router(state.clone());
        let fresh_secret = "ef".repeat(32);
        let fresh = pseudonym_for(&fresh_secret);
        let res = app
            .clone()
            .oneshot(post_json(
                "/v1/register",
                &fresh_secret,
                register_body(&fresh),
            ))
            .await
            .unwrap();
        // A full table now RECLAIMS instead of refusing forever. Open
        // registration lets anyone mint pseudonyms, so a permanent 503 for every
        // new host was a denial of service that only a restart could clear.
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        {
            let devices = state.devices.lock().await;
            let reclaimed = MAX_DEVICES / RECLAIM_FRACTION;
            assert_eq!(devices.len(), MAX_DEVICES - reclaimed + 1);
        }
        // An EXISTING pseudonym may still refresh its token.
        let existing = pseudonym();
        let res = app
            .clone()
            .oneshot(post_json(
                "/v1/register",
                &host_secret(),
                register_body(&existing),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    /// One host still cannot take more than its share, reclamation or not.
    #[tokio::test]
    async fn per_host_cap_still_refuses_beyond_its_share() {
        let state = build_state(RegistrationAuth::Open);
        let host = pseudonym();
        {
            let mut devices = state.devices.lock().await;
            for i in 0..MAX_DEVICES_PER_HOST {
                devices.insert(
                    (host.clone(), format!("{i:064x}")),
                    Device {
                        provider: Provider::Apns,
                        device_token: "t".into(),
                        sealed_wake_blob: String::new(),
                        refreshed: Instant::now(),
                    },
                );
            }
        }
        let app = build_router(state.clone());
        // A registration id this host has not used yet, so the request is new.
        let body = serde_json::json!({
            "host_pseudonym": host,
            "registration_id": "ab".repeat(32),
            "provider": "apns",
            "device_token": "device-token-1",
            "sealed_wake_blob": "deadbeef",
        })
        .to_string();
        let res = app
            .oneshot(post_json("/v1/register", &host_secret(), body))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A synthetic "now" far enough ahead of process start that any age these
    /// tests need can be subtracted from it.
    ///
    /// `Instant` counts from boot, so `Instant::now() - REGISTRATION_TTL` (30
    /// days) underflows on any machine with less than 30 days of uptime. The
    /// previous helper swallowed that as `unwrap_or_else(Instant::now)`, which
    /// silently dated every "old" entry to the present: the expiry test then
    /// asserted a stale entry was dropped when nothing was old enough to drop.
    /// It passed only on a long-uptime workstation, and would have failed on
    /// every freshly-booted CI runner. Ageing DOWN from a future base cannot
    /// underflow, so the fixtures no longer depend on uptime.
    fn clock_base() -> Instant {
        Instant::now() + REGISTRATION_TTL + Duration::from_secs(24 * 60 * 60)
    }

    fn aged(base: Instant, by: Duration) -> Instant {
        base.checked_sub(by)
            .expect("clock_base must sit further ahead than any age under test")
    }

    /// Registrations nobody has touched for longer than the TTL are dead weight:
    /// a live host re-registers on every connect.
    #[test]
    fn expired_registrations_are_dropped_before_anything_is_evicted() {
        let mut devices: HashMap<(String, String), Device> = HashMap::new();
        let device = |refreshed: Instant| Device {
            provider: Provider::Apns,
            device_token: "t".into(),
            sealed_wake_blob: String::new(),
            refreshed,
        };
        let now = clock_base();
        devices.insert(
            ("stale".into(), "a".into()),
            device(aged(now, REGISTRATION_TTL + Duration::from_secs(60))),
        );
        devices.insert(
            ("fresh".into(), "b".into()),
            device(aged(now, Duration::from_secs(60))),
        );

        reclaim_registrations(&mut devices, now);

        assert!(!devices.contains_key(&("stale".to_string(), "a".to_string())));
        assert!(devices.contains_key(&("fresh".to_string(), "b".to_string())));
    }

    /// With nothing expired, a full table gives up its least recently refreshed
    /// entries - and keeps the ones still in use.
    #[test]
    fn a_full_table_evicts_least_recently_refreshed_first() {
        let mut devices: HashMap<(String, String), Device> = HashMap::new();
        let now = clock_base();
        for i in 0..MAX_DEVICES {
            // Older index == older entry, all well inside the TTL.
            let age = Duration::from_secs((MAX_DEVICES - i) as u64);
            devices.insert(
                (format!("{i:064x}"), "r".into()),
                Device {
                    provider: Provider::Apns,
                    device_token: "t".into(),
                    sealed_wake_blob: String::new(),
                    refreshed: aged(now, age),
                },
            );
        }

        reclaim_registrations(&mut devices, now);

        let reclaimed = MAX_DEVICES / RECLAIM_FRACTION;
        assert_eq!(devices.len(), MAX_DEVICES - reclaimed);
        // The oldest went; the newest stayed.
        assert!(!devices.contains_key(&(format!("{:064x}", 0), "r".to_string())));
        assert!(devices.contains_key(&(format!("{:064x}", MAX_DEVICES - 1), "r".to_string())));
    }
}
