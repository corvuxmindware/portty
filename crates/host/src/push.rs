//! Optional wake-only push doorbell + device push registration.
//!
//! Privacy contract (mirrors `crates/push-relay`): the relay or its TLS proxy
//! can observe the connecting host's source IP, a stable random-looking host
//! pseudonym, a device push token, and wake/revoke timing. A wake POST body
//! carries the pseudonym and nothing else - no session, agent, terminal, or
//! approval data. The `sealed_wake_blob` stored at registration is ciphertext
//! the PHONE created with a key that never leaves the phone; the host and relay
//! store and forward it opaquely.
//!
//! The pending `RequestPermission` itself stays queued in `SessionManager` -
//! the host is the source of truth and the push is just a doorbell.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use portty_protocol::PushProvider;
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::session::{ManagerEvent, SessionManager};
use portty_transport::{CredentialStore, DeviceId, Durability, FileCredentialStore};

/// Domain tag binding the public relay handle to the private host secret.
const HOST_HANDLE_CONTEXT: &[u8] = b"portty-push-host-handle-v2";
/// How long a *connected* phone gets to render + answer an approval card
/// before the doorbell rings anyway. Covers the locked-phone window where the
/// QUIC connection hasn't idle-timed-out yet (up to ~30 s) - exactly the case
/// push exists for. An answered card cancels the ring (pending re-check).
const WAKE_GRACE: Duration = Duration::from_secs(8);
/// Host-side debounce, mirroring the relay's own per-pseudonym rate limit.
const LOCAL_DEBOUNCE: Duration = Duration::from_secs(3);
/// Every relay/APNs/FCM call is bounded: a black-holed relay must never wedge
/// the doorbell task (or pile up graced re-check tasks) indefinitely.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// On-disk registration file, sibling of the peer store in the identity dir.
const REGISTRY_FILE: &str = "push_registrations.json";
/// Random relay credential. Unlike the v1 handle, this is not derivable from
/// the host's public DeviceId.
const HOST_SECRET_FILE: &str = "push_relay_secret_v2.bin";

/// Doorbell configuration. Present only when `PORTTY_PUSH_RELAY_URL` is set -
/// without it the host makes zero outbound HTTP calls (no relay, no cloud).
#[derive(Clone)]
pub struct PushConfig {
    /// Relay base URL, no trailing slash.
    pub relay_url: String,
    /// 64-hex host handle the relay keys everything by.
    pub pseudonym: String,
    /// Random 256-bit bearer used for wake/revoke requests. The public handle
    /// is a one-way derivation of this value, never the credential itself.
    auth_secret: Arc<Zeroizing<String>>,
    /// Hosted relays may require an operator token for registration. Normal
    /// self-hosted relays use the per-host secret here too.
    registration_bearer: Arc<Zeroizing<String>>,
}

/// Names of the push env vars that are BEARER CREDENTIALS for the relay.
/// Everything else about push config is non-secret.
pub const PUSH_SECRET_ENV_VARS: [&str; 2] = ["PORTTY_PUSH_HOST_SECRET", "PORTTY_PUSH_ADMIN_TOKEN"];

/// The push secrets, read exactly once and then REMOVED from this process's
/// environment.
///
/// Every child the daemon starts inherits its environment: a phone-created
/// shell, an ACP adapter (`agent-client-protocol` spawns it with the parent
/// environment plus its own additions), an agent-requested terminal, and
/// anything those start in turn. Leaving the relay credentials there published
/// them to `env` in any phone terminal and into agent transcripts and model
/// context. Taking them out of the environment on first read means no descendant
/// can see them, whatever it spawns.
///
/// Snapshotted rather than re-read because `configured()` runs more than once and
/// each call must produce the SAME credential - re-reading after the removal
/// would silently fall back to the on-disk secret and orphan registrations.
///
/// Not covered: an operator who exports these in their shell PROFILE. A login
/// shell re-reads the profile, so the value comes back in that child. Prefer the
/// service-manager environment (launchd/systemd unit) over a profile export.
type PushSecretEnv = (Option<Zeroizing<String>>, Option<Zeroizing<String>>);

fn push_secret_env() -> &'static PushSecretEnv {
    static SNAPSHOT: std::sync::OnceLock<PushSecretEnv> = std::sync::OnceLock::new();
    SNAPSHOT.get_or_init(|| {
        let take = |key: &str| {
            let value = std::env::var(key).ok();
            if value.is_some() {
                // Called from `main` before any mode runs, so no child exists yet.
                std::env::remove_var(key);
            }
            // Zeroizing: this snapshot outlives every use, so the process should
            // not also keep a plain copy of the bearer for its whole lifetime.
            value.map(Zeroizing::new)
        };
        let host_secret = take(PUSH_SECRET_ENV_VARS[0]);
        let admin_token = take(PUSH_SECRET_ENV_VARS[1]);
        (host_secret, admin_token)
    })
}

/// Take the push bearer secrets out of the environment NOW.
///
/// Called once from `main` before any mode runs. Idempotent, and safe to call
/// even when push is not configured - the point is that no child process, in any
/// mode, ever inherits these. See [`push_secret_env`].
pub fn take_secret_env() {
    let _ = push_secret_env();
}

/// Put the snapshotted secrets back, on a child this process is deliberately
/// re-launching as ITSELF. Returns the variable names it set.
///
/// Only `launch_windows_daemon` needs this, and only because Windows has no
/// `fork`. On Unix the daemon IS this process after forking, so it still holds
/// the snapshot in memory. On Windows the daemon is a brand-new process, and
/// scrubbing the environment before spawning it meant the real daemon came up
/// with no fixed host secret and no operator token - push registration then
/// failed with nothing to explain why.
///
/// This is not a hole in the scrub. The child re-runs `take_secret_env()` as its
/// own first statement, before it can spawn a shell or an adapter, so the values
/// sit in its environment for the same brief window they sat in this process's,
/// visible to the same thing: another process of the same user.
///
/// Deliberately NOT `#[cfg(windows)]`, and takes the `Command` rather than
/// returning pairs for the caller to apply. `std::process::Command` is the same
/// type everywhere, so this way the logic is compiled and unit-tested on every
/// platform and the Windows-only part is one call - the previous version of this
/// fix left the loop itself inside a `cfg` block that no CI job type-checks.
// Unused off Windows by design: it is compiled and tested on every platform so
// that a change here cannot break the Windows daemon silently, which is exactly
// how it broke the first time. CI runs with `-D warnings`, hence the allow.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn restore_secret_env_for_relaunch(command: &mut std::process::Command) -> Vec<&'static str> {
    restore_from_snapshot(command, push_secret_env())
}

/// The mapping itself, over an explicit snapshot so a test can supply one - the
/// process-wide `OnceLock` is empty in a test binary, which would make a test of
/// the public wrapper pass for the wrong reason.
#[cfg_attr(not(windows), allow(dead_code))]
fn restore_from_snapshot(
    command: &mut std::process::Command,
    snapshot: &PushSecretEnv,
) -> Vec<&'static str> {
    let (host_secret, admin_token) = snapshot;
    let mut restored = Vec::new();
    for (name, value) in PUSH_SECRET_ENV_VARS
        .into_iter()
        .zip([host_secret, admin_token])
    {
        if let Some(value) = value {
            command.env(name, value.as_str());
            restored.push(name);
        }
    }
    restored
}

impl PushConfig {
    /// `PORTTY_PUSH_RELAY_URL` enables push. A private random credential is
    /// generated once and stored owner-only; its derived handle is what the
    /// relay indexes. Corrupt credential state fails closed instead of silently
    /// changing identity and orphaning registrations.
    pub fn from_env(identity_dir: &Path) -> std::io::Result<Option<Self>> {
        // Take the secrets out of the environment even when push is disabled -
        // otherwise a relay URL that is set later (or not at all) still leaves
        // the credentials visible to every spawned shell and adapter.
        let (host_secret, admin_token) = push_secret_env();
        let Ok(relay_url) = std::env::var("PORTTY_PUSH_RELAY_URL") else {
            return Ok(None);
        };
        let relay_url = validate_relay_url(&relay_url)?;
        let mut secret = match host_secret {
            Some(encoded) => decode_secret(encoded)?,
            None => load_or_create_host_secret(identity_dir)?,
        };
        let admin_token = admin_token.as_ref().map(|token| token.to_string());
        let pseudonym = derive_host_handle(&secret);
        let auth_secret = hex::encode(secret);
        secret.zeroize();
        if std::env::var_os("PORTTY_PUSH_HOST_PSEUDONYM").is_some() {
            warn!("PORTTY_PUSH_HOST_PSEUDONYM is ignored; v2 derives an unforgeable handle from PORTTY_PUSH_HOST_SECRET");
        }
        let registration_bearer = admin_token.clone().unwrap_or_else(|| auth_secret.clone());
        Ok(Some(Self {
            relay_url,
            pseudonym,
            auth_secret: Arc::new(Zeroizing::new(auth_secret)),
            registration_bearer: Arc::new(Zeroizing::new(registration_bearer)),
        }))
    }
}

/// Parse and vet the relay URL, returning the normalized base to build request
/// paths from.
///
/// The wake/register/revoke bearer is the raw host secret (see #28 /
/// PUSH-SETUP), so the URL MUST carry it over TLS. A plaintext `http://` relay
/// is refused unless it is loopback (never leaves the machine) or the operator
/// explicitly opts out with `PORTTY_PUSH_ALLOW_INSECURE` (e.g. TLS terminated by
/// a trusted local tunnel). Closes #29: a mis-set `http://` URL used to silently
/// leak the secret to any on-path observer.
///
/// This used to hand-split the string, which was bypassable: in
/// `http://localhost:80@attacker.example` everything before the `@` is USERINFO,
/// so splitting on `:` read the host as "localhost", took the loopback
/// exemption, and shipped the secret in plaintext to attacker.example. Parse
/// with a real URL parser and reject the shapes that made that work - userinfo
/// (never meaningful for the relay, and the classic way to make a hostile host
/// read as a trusted one), plus a query or fragment, which would silently
/// corrupt the `/v1/...` paths appended to this base.
/// HTTP client for relay calls.
///
/// No redirects (see `PushCtx::new`), and for a PLAINTEXT relay also no proxy: a
/// loopback `http://` URL is permitted precisely because the bearer never leaves
/// the machine, but an `HTTP_PROXY` in the environment would send it to that proxy
/// instead - off-box, unencrypted. HTTPS relays keep proxy support, where the
/// bearer stays inside TLS.
fn relay_client(relay_url: &str) -> reqwest::Client {
    install_rustls_crypto_provider();
    let mut builder = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if relay_url.starts_with("http://") {
        builder = builder.no_proxy();
    }
    builder.build().expect("reqwest client")
}

/// Install the process-wide Rustls crypto provider before any TLS client is
/// built. reqwest is built with `rustls-no-provider` so Portty keeps one crypto
/// stack (ring, which iroh already uses) instead of also pulling aws-lc-rs, and
/// the cost of that choice is that nothing installs a default provider for us -
/// `Client::builder().build()` would fail with "no process-level CryptoProvider
/// available". Called from `relay_client` rather than `main` so it holds for
/// every entry point, including tests. Mirrors the phone app's
/// `install_rustls_crypto_provider`.
fn install_rustls_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Strict opt-in flag: only an explicit affirmative counts.
///
/// `var_os(..).is_some()` treated `PORTTY_PUSH_ALLOW_INSECURE=0`, `=false`, and
/// even an empty value as "yes, send my relay bearer over plaintext HTTP" -
/// exactly backwards for a security escape hatch, and easy to trip by unsetting a
/// variable the wrong way in a unit file.
fn env_flag_is_true(key: &str) -> bool {
    std::env::var(key).is_ok_and(|value| {
        let value = value.trim();
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
}

fn validate_relay_url(raw: &str) -> std::io::Result<String> {
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg);
    let url = reqwest::Url::parse(raw.trim()).map_err(|error| {
        invalid(format!(
            "PORTTY_PUSH_RELAY_URL is not a valid URL ({error}); expected https://host[:port][/base]"
        ))
    })?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(invalid(format!(
            "PORTTY_PUSH_RELAY_URL must use https:// (or http://localhost for testing), not {}://",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(
            "PORTTY_PUSH_RELAY_URL must not contain a username or password - \
             userinfo before the `@` hides the real host and the relay never uses it"
                .into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(
            "PORTTY_PUSH_RELAY_URL must not contain a query or fragment - \
             request paths are appended to it"
                .into(),
        ));
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| invalid("PORTTY_PUSH_RELAY_URL has no host".into()))?;
    if url.scheme() == "http" {
        // `host_str` keeps the brackets on an IPv6 literal; strip them before
        // parsing. The parser has already lowercased the host for http(s).
        let literal = host.trim_start_matches('[').trim_end_matches(']');
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
            || literal
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            if env_flag_is_true("PORTTY_PUSH_ALLOW_INSECURE") {
                warn!("PORTTY_PUSH_RELAY_URL is http:// with PORTTY_PUSH_ALLOW_INSECURE set - the host secret bearer is sent WITHOUT TLS; only safe behind a trusted local tunnel");
            } else {
                return Err(invalid(
                    "PORTTY_PUSH_RELAY_URL must use https:// - the host secret is sent as a bearer \
                     and would leak over plaintext http. Use https, point at localhost for testing, \
                     or set PORTTY_PUSH_ALLOW_INSECURE=1 if TLS is terminated by a trusted local tunnel."
                        .into(),
                ));
            }
        }
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn decode_secret(encoded: &str) -> std::io::Result<[u8; 32]> {
    let decoded = hex::decode(encoded).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PORTTY_PUSH_HOST_SECRET must be exactly 64 hexadecimal characters",
        )
    })?;
    decoded.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PORTTY_PUSH_HOST_SECRET must be exactly 64 hexadecimal characters",
        )
    })
}

fn load_or_create_host_secret(identity_dir: &Path) -> std::io::Result<[u8; 32]> {
    let store = FileCredentialStore::new(identity_dir);
    if let Some(mut bytes) = store.read(HOST_SECRET_FILE)? {
        let decoded = bytes.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "push relay credential has an invalid length",
            )
        });
        bytes.zeroize();
        return decoded;
    }
    let mut secret = [0u8; 32];
    // The bearer this mints is the host's only credential at the relay, so a
    // failed entropy draw must abort rather than persist a weak secret.
    SysRng.try_fill_bytes(&mut secret).map_err(|_| {
        std::io::Error::other("the operating system random number generator failed")
    })?;
    // The relay bearer is generated once and reused; regenerating it orphans
    // every existing registration, so this one is worth confirming.
    store.write(HOST_SECRET_FILE, &secret, Durability::Required)?;
    Ok(secret)
}

/// Public relay handle derived from a secret known only to this host. The relay
/// can verify a bearer by recomputing this value without storing that bearer.
pub fn derive_host_handle(secret: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(HOST_HANDLE_CONTEXT);
    h.update(secret);
    hex::encode(h.finalize())
}

fn random_registration_id() -> String {
    let mut id = [0u8; 32];
    // Infallible by signature - this is a `#[serde(default)]` target, so it
    // cannot return a Result. rand 0.8 panicked on this same event.
    SysRng
        .try_fill_bytes(&mut id)
        .expect("OS entropy source unavailable");
    hex::encode(id)
}

/// One phone's push registration, exactly as forwarded to the relay.
#[derive(Clone, Serialize, Deserialize, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PushRegistration {
    /// Opaque, per-phone relay key. It prevents one phone registration from
    /// overwriting another and permits targeted deletion on revoke.
    #[serde(default = "random_registration_id")]
    pub registration_id: String,
    /// "apns" | "fcm" (string in the file for forward compatibility).
    pub provider: String,
    pub token: String,
    /// Phone-sealed ciphertext, stored/forwarded opaquely (hex on the wire).
    pub sealed_wake_blob: Vec<u8>,
}

impl std::fmt::Debug for PushRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRegistration")
            .field("registration_id", &self.registration_id)
            .field("provider", &self.provider)
            .field("token", &"<redacted>")
            .field("sealed_wake_blob_len", &self.sealed_wake_blob.len())
            .finish()
    }
}

impl PushRegistration {
    pub fn new(provider: String, token: String, sealed_wake_blob: Vec<u8>) -> Self {
        Self {
            registration_id: random_registration_id(),
            provider,
            token,
            sealed_wake_blob,
        }
    }
}

pub fn provider_name(p: PushProvider) -> &'static str {
    match p {
        PushProvider::Apns => "apns",
        PushProvider::Fcm => "fcm",
    }
}

/// Persisted registrations keyed by phone DeviceId hex, so a host restart can
/// re-register every device with the (memory-only) relay.
pub struct PushRegistry {
    store: FileCredentialStore,
    entries: HashMap<String, PushRegistration>,
}

impl PushRegistry {
    /// Missing file → empty. Corrupt or insecure registration state fails
    /// closed so the host does not accidentally retain or mis-target tokens.
    pub fn load(identity_dir: &Path) -> std::io::Result<Self> {
        let store = FileCredentialStore::new(identity_dir);
        let entries = match store.read(REGISTRY_FILE)? {
            Some(mut bytes) => {
                let parsed = serde_json::from_slice(&bytes)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
                bytes.zeroize();
                parsed?
            }
            None => HashMap::new(),
        };
        Ok(Self { store, entries })
    }

    /// Insert/replace one phone's registration and persist atomically
    /// (tmp + rename, 0600 - the push token is worth protecting).
    pub fn upsert(
        &mut self,
        device: &DeviceId,
        mut reg: PushRegistration,
    ) -> std::io::Result<PushRegistration> {
        let key = device.as_hex();
        if let Some(existing) = self.entries.get(&key) {
            reg.registration_id.clone_from(&existing.registration_id);
        }
        let previous = self.entries.insert(key.clone(), reg.clone());
        // BestEffort: the phone re-sends its registration on every connect, so a
        // lost write really does heal itself. Contrast `remove`.
        if let Err(error) = self.persist(Durability::BestEffort) {
            if let Some(previous) = previous {
                self.entries.insert(key, previous);
            } else {
                self.entries.remove(&key);
            }
            return Err(error);
        }
        Ok(reg)
    }

    pub fn all(&self) -> Vec<PushRegistration> {
        self.entries.values().cloned().collect()
    }

    /// Remove a revoked phone locally. Relay-side unregister is handled by the
    /// targeted-registration path; deleting the persisted token immediately
    /// prevents it from being re-registered after a host restart.
    pub fn remove(&mut self, device: &DeviceId) -> std::io::Result<Option<PushRegistration>> {
        let key = device.as_hex();
        let Some(removed) = self.entries.remove(&key) else {
            return Ok(None);
        };
        // Required, unlike an ordinary registration update. "A lost write heals
        // itself" is true only for ADDING a registration, because the phone
        // re-sends it on every connect. Nothing re-sends a removal: if this one is
        // lost to a crash, startup reloads the revoked phone and re-registers it,
        // and it starts receiving doorbells again.
        if let Err(error) = self.persist(Durability::Required) {
            self.entries.insert(key, removed);
            return Err(error);
        }
        Ok(Some(removed))
    }

    /// Drop every registration whose device is no longer a live pairing.
    ///
    /// Belt to `remove`'s braces, and the part that does not depend on a write
    /// having survived: the peer store's tombstones are the authority on who is
    /// revoked, so a registration that outlived its pairing by any route - lost
    /// removal, a store restored from backup, a revoke that happened while this
    /// host was down - is discarded here rather than re-registered. Returns the
    /// number dropped; persistence is the caller's, since startup can defer it.
    pub fn retain_live_peers(&mut self, live: &[DeviceId]) -> usize {
        let live: std::collections::HashSet<String> =
            live.iter().map(|device| device.as_hex()).collect();
        let before = self.entries.len();
        self.entries.retain(|key, _| live.contains(key));
        before - self.entries.len()
    }

    fn persist(&self, durability: Durability) -> std::io::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(&self.entries)?;
        let result = self.store.write(REGISTRY_FILE, &bytes, durability);
        bytes.zeroize();
        result
    }
}

/// Everything the doorbell + registration handlers share.
#[derive(Clone)]
pub struct PushCtx {
    pub cfg: PushConfig,
    pub registry: Arc<AsyncMutex<PushRegistry>>,
    pub client: reqwest::Client,
    /// Kept so `register_all` can re-read the peer store, which is the authority
    /// on who is still paired. Re-read rather than cached: a `portty-host revoke`
    /// can run at any time, and this path is rare (boot, or a relay restart).
    identity_dir: std::path::PathBuf,
    last_fire: Arc<StdMutex<Option<Instant>>>,
}

impl PushCtx {
    pub fn new(cfg: PushConfig, identity_dir: &Path) -> std::io::Result<Self> {
        Ok(Self {
            client: relay_client(&cfg.relay_url),
            cfg,
            registry: Arc::new(AsyncMutex::new(PushRegistry::load(identity_dir)?)),
            identity_dir: identity_dir.to_path_buf(),
            // Follow NO redirects. Every relay call carries the raw host secret
            // in `x-portty-host-authorization`; reqwest strips `Authorization`
            // on a cross-host redirect but keeps custom headers, so a relay that
            // answered 302 could hand the secret to any host it named. The relay
            // API is a fixed set of local paths - a redirect is always wrong.
            last_fire: Arc::new(StdMutex::new(None)),
        })
    }

    /// Forward one registration to the relay. The relay authenticates either
    /// the derived host secret (open mode) or the configured operator token.
    pub async fn register_with_relay(&self, reg: &PushRegistration) -> Result<(), String> {
        let resp = self
            .client
            .post(format!("{}/v1/register", self.cfg.relay_url))
            .bearer_auth(self.cfg.registration_bearer.as_ref().as_str())
            .header(
                "x-portty-host-authorization",
                self.cfg.auth_secret.as_ref().as_str(),
            )
            .json(&serde_json::json!({
                "host_pseudonym": self.cfg.pseudonym,
                "registration_id": reg.registration_id,
                "provider": reg.provider,
                "device_token": reg.token,
                "sealed_wake_blob": hex::encode(&reg.sealed_wake_blob),
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("relay returned {}", resp.status()))
        }
    }

    /// Re-register every persisted device (host boot, or a relay that lost its
    /// memory-only table - see the 404 retry in `fire`).
    ///
    /// Registrations for devices that are no longer paired are dropped instead of
    /// re-registered. This is the one path that re-arms a stale registration, so
    /// it is where the peer store's tombstones get consulted rather than trusting
    /// that every `remove` write landed.
    ///
    /// A peer store we cannot read means we cannot tell who was revoked, so
    /// nothing is registered at all. That costs doorbells until the next connect -
    /// where the phone re-registers anyway - and is the right direction.
    pub async fn register_all(&self) {
        let live = match portty_transport::PeerStore::load(&self.identity_dir) {
            Ok(store) => store.known_devices(),
            Err(error) => {
                warn!(%error, "skipping push (re)registration: cannot read peer store to check for revoked devices");
                return;
            }
        };
        let live = &live;
        let regs = {
            let mut registry = self.registry.lock().await;
            let dropped = registry.retain_live_peers(live);
            if dropped > 0 {
                warn!(
                    dropped,
                    "discarding push registrations for devices that are no longer paired"
                );
                if let Err(error) = registry.persist(Durability::Required) {
                    // In memory they are already gone, so this run will not
                    // re-register them; the next boot retries the cleanup.
                    warn!(%error, "could not persist push registry cleanup");
                }
            }
            registry.all()
        };
        for reg in regs {
            if let Err(error) = self.register_with_relay(&reg).await {
                warn!(%error, "could not (re)register push device with relay");
            }
        }
    }

    /// Ring the doorbell: POST a wake that carries only the pseudonym. A 404
    /// means the (stateless) relay doesn't know us - e.g. it restarted - so
    /// re-register from the persisted registry and retry once.
    async fn fire(&self) {
        {
            let mut last = self.last_fire.lock().unwrap();
            if let Some(prev) = *last {
                if prev.elapsed() < LOCAL_DEBOUNCE {
                    return;
                }
            }
            *last = Some(Instant::now());
        }
        match self.post_wake().await {
            Ok(status) if status.as_u16() == 404 => {
                info!("relay lost our registrations (restart?); re-registering");
                self.register_all().await;
                if let Err(error) = self.post_wake().await {
                    warn!(%error, "could not fire push doorbell after re-register");
                }
            }
            Ok(status) if !status.is_success() => {
                warn!(%status, "push relay refused wake");
            }
            Ok(_) => {}
            Err(error) => warn!(%error, "could not fire push doorbell"),
        }
    }

    async fn post_wake(&self) -> Result<reqwest::StatusCode, reqwest::Error> {
        self.client
            .post(format!("{}/v1/wake", self.cfg.relay_url))
            .bearer_auth(self.cfg.auth_secret.as_ref().as_str())
            .json(&serde_json::json!({ "host_pseudonym": self.cfg.pseudonym }))
            .send()
            .await
            .map(|r| r.status())
    }

    /// Delete one phone's relay registration and ask the provider to wake it
    /// with a generic "pair ended" notification. The payload is only the
    /// phone-sealed host selector; the app still requires an authenticated
    /// reconnect failure before deleting credentials.
    pub async fn notify_revoked(&self, device: DeviceId) {
        let registration = match self.registry.lock().await.remove(&device) {
            Ok(Some(registration)) => registration,
            Ok(None) => return,
            Err(error) => {
                warn!(peer = %device, %error, "revoked pair but could not durably remove push registration");
                return;
            }
        };
        let response = self
            .client
            .post(format!("{}/v1/revoke", self.cfg.relay_url))
            .bearer_auth(self.cfg.auth_secret.as_ref().as_str())
            .json(&serde_json::json!({
                "host_pseudonym": self.cfg.pseudonym,
                "registration_id": registration.registration_id,
            }))
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                warn!(peer = %device, status = %response.status(), "relay could not deliver pair-revoked wake")
            }
            Err(error) => warn!(peer = %device, %error, "relay pair-revoked wake failed"),
        }
    }
}

/// Build the optional push context once so the live connection path and the
/// same-user revoke IPC share one registry/credential view.
pub fn configured(identity_dir: &Path) -> Option<PushCtx> {
    match PushConfig::from_env(identity_dir) {
        Ok(Some(config)) => match PushCtx::new(config, identity_dir) {
            Ok(ctx) => Some(ctx),
            Err(error) => {
                warn!(%error, "push registry unavailable; disabling optional push synchronization");
                None
            }
        },
        Ok(None) => None,
        Err(error) => {
            warn!(%error, "push credential unavailable; disabling optional push synchronization");
            None
        }
    }
}

/// Watch approval events and ring the relay doorbell. Never dies on broadcast
/// lag: dropped events are tolerated because every NEW `AgentPermission` rings
/// again, and the graced pending re-check path is idempotent.
pub fn spawn_doorbell(
    mgr: SessionManager,
    ctx: PushCtx,
    connected_phones: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    let mut events = mgr.subscribe_events();
    tokio::spawn(async move {
        // Boot-time re-register: the relay's device table is memory-only.
        ctx.register_all().await;
        loop {
            use tokio::sync::broadcast::error::RecvError;
            let event = match events.recv().await {
                Ok(ev) => ev,
                // A busy timeline burst can evict events from the broadcast
                // buffer - and one of them may have been the `AgentPermission`
                // the agent is now BLOCKED on, so no further event will arrive
                // to re-trigger us. The old code just `continue`d and the phone
                // was never woken. Reconcile against the source of truth: if any
                // card is still pending, ring (debounced + graced as usual).
                Err(RecvError::Lagged(_)) => {
                    if mgr.any_agent_permission_pending().await {
                        if connected_phones.load(Ordering::Relaxed) == 0 {
                            ctx.fire().await;
                        } else {
                            let mgr = mgr.clone();
                            let ctx = ctx.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(WAKE_GRACE).await;
                                if mgr.any_agent_permission_pending().await {
                                    ctx.fire().await;
                                }
                            });
                        }
                    }
                    continue;
                }
                Err(RecvError::Closed) => break,
            };
            let ManagerEvent::AgentPermission { id, tool_call, .. } = event else {
                continue;
            };
            if connected_phones.load(Ordering::Relaxed) == 0 {
                ctx.fire().await;
            } else {
                // "Connected" may be a locked phone whose QUIC connection
                // hasn't idle-timed-out. Give a live viewer a beat to answer,
                // then ring iff the card is still pending.
                let mgr = mgr.clone();
                let ctx = ctx.clone();
                let tool_call_id = tool_call.tool_call_id;
                tokio::spawn(async move {
                    tokio::time::sleep(WAKE_GRACE).await;
                    if mgr.agent_permission_pending(id, &tool_call_id).await {
                        ctx.fire().await;
                    }
                });
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_handle_is_stable_64_hex_and_secret_bound() {
        let secret = [7u8; 32];
        let p = derive_host_handle(&secret);
        assert_eq!(p.len(), 64);
        assert_eq!(p, derive_host_handle(&secret));
        assert!(!p.contains(&hex::encode(secret)));
        assert_ne!(derive_host_handle(&[8u8; 32]), p);
    }

    /// Windows has no `fork`, so the detached daemon is a fresh process that
    /// cannot inherit the in-memory snapshot `main` took. These cover the mapping
    /// that hands the secrets over - the bug it replaces was a daemon coming up
    /// with no fixed host secret and no operator token.
    #[test]
    fn a_relaunched_child_is_given_back_the_secrets_main_took() {
        let snapshot: PushSecretEnv = (
            Some(Zeroizing::new("a".repeat(64))),
            Some(Zeroizing::new("operator-token".into())),
        );
        let mut command = std::process::Command::new("does-not-run");
        let restored = restore_from_snapshot(&mut command, &snapshot);
        assert_eq!(restored, PUSH_SECRET_ENV_VARS);

        let env: Vec<_> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(env.contains(&("PORTTY_PUSH_HOST_SECRET".into(), Some("a".repeat(64)))));
        assert!(env.contains(&(
            "PORTTY_PUSH_ADMIN_TOKEN".into(),
            Some("operator-token".into())
        )));
    }

    #[test]
    fn a_relaunched_child_is_given_nothing_that_was_not_configured() {
        // Push not configured, or only one of the two set: pass exactly what
        // existed, so an unset variable stays unset rather than becoming empty.
        let mut command = std::process::Command::new("does-not-run");
        assert!(restore_from_snapshot(&mut command, &(None, None)).is_empty());
        assert_eq!(command.get_envs().count(), 0);

        let partial: PushSecretEnv = (None, Some(Zeroizing::new("operator-token".into())));
        let mut command = std::process::Command::new("does-not-run");
        assert_eq!(
            restore_from_snapshot(&mut command, &partial),
            ["PORTTY_PUSH_ADMIN_TOKEN"]
        );
        assert_eq!(command.get_envs().count(), 1);
    }

    #[test]
    fn relay_scheme_requires_tls_except_loopback() {
        // https is always fine.
        assert!(validate_relay_url("https://push.example.com").is_ok());
        assert!(validate_relay_url("https://push.example.com:8443/base").is_ok());
        // Plaintext http to a real host is refused - the raw-secret bearer would leak.
        assert!(validate_relay_url("http://push.example.com").is_err());
        assert!(validate_relay_url("http://push.example.com:9877/wake").is_err());
        // Loopback never leaves the machine, so http is allowed for local testing.
        assert!(validate_relay_url("http://localhost:9877").is_ok());
        assert!(validate_relay_url("http://127.0.0.1:9877").is_ok());
        assert!(validate_relay_url("http://[::1]:9877").is_ok());
        // A scheme-less or non-http(s) URL is rejected outright.
        assert!(validate_relay_url("push.example.com").is_err());
        assert!(validate_relay_url("ftp://push.example.com").is_err());
        assert!(validate_relay_url("https://").is_err());
    }

    /// The bypass this parser replaced: everything before `@` is userinfo, so
    /// the real host is attacker.example, not localhost. Splitting the string by
    /// hand read "localhost", took the loopback exemption, and would have sent
    /// the raw host secret to the attacker in plaintext.
    #[test]
    fn userinfo_cannot_smuggle_a_hostile_host_past_the_loopback_exemption() {
        for url in [
            "http://localhost:80@attacker.example",
            "http://localhost@attacker.example/v1",
            "http://127.0.0.1:80@attacker.example",
            "https://user:pass@push.example.com",
        ] {
            let error = validate_relay_url(url)
                .expect_err(&format!("{url} must be rejected"))
                .to_string();
            assert!(error.contains("username or password"), "{url}: {error}");
        }
    }

    /// A security escape hatch must not be armed by "0", "false", or an empty
    /// value - which is what `var_os(..).is_some()` did.
    #[test]
    fn insecure_push_needs_an_explicit_affirmative() {
        let key = "PORTTY_TEST_PUSH_FLAG";
        for off in ["", "0", "false", "no", "off", " ", "2"] {
            std::env::set_var(key, off);
            assert!(!env_flag_is_true(key), "{off:?} must not arm the flag");
        }
        for on in ["1", "true", "TRUE", "yes", " 1 "] {
            std::env::set_var(key, on);
            assert!(env_flag_is_true(key), "{on:?} must arm the flag");
        }
        std::env::remove_var(key);
        assert!(!env_flag_is_true(key));
    }

    /// A plaintext relay is allowed only because the bearer stays on the machine;
    /// a proxy would carry it off-box in the clear, so plaintext clients get none.
    #[test]
    fn plaintext_relay_clients_do_not_use_a_proxy() {
        // Smoke: both shapes build. The no_proxy distinction is asserted by
        // construction (reqwest exposes no getter), so this guards the builder
        // from panicking and documents the intent next to the code.
        let _ = relay_client("http://127.0.0.1:9877");
        let _ = relay_client("https://push.example.com");
    }

    /// A query or fragment would silently corrupt every `/v1/...` path built
    /// from this base, so it is refused rather than half-honoured.
    #[test]
    fn relay_url_rejects_query_and_fragment() {
        assert!(validate_relay_url("https://push.example.com/?a=b").is_err());
        assert!(validate_relay_url("https://push.example.com/#frag").is_err());
    }

    /// The stored base must have no trailing slash, since callers append
    /// `/v1/register` and friends to it.
    #[test]
    fn relay_url_is_normalized_without_a_trailing_slash() {
        assert_eq!(
            validate_relay_url("https://push.example.com/").unwrap(),
            "https://push.example.com"
        );
        assert_eq!(
            validate_relay_url("  https://push.example.com/base/  ").unwrap(),
            "https://push.example.com/base"
        );
    }

    #[test]
    fn registry_round_trips_and_replaces_per_device() {
        let dir = tempfile::tempdir().unwrap();
        let did = DeviceId([1u8; 16]);
        let mut reg = PushRegistry::load(dir.path()).unwrap();
        assert!(reg.all().is_empty());
        reg.upsert(
            &did,
            PushRegistration::new("apns".into(), "tok-a".into(), vec![1, 2, 3]),
        )
        .unwrap();
        let first_id = reg.all()[0].registration_id.clone();
        // Same device re-registering (token rotation) replaces, not appends.
        reg.upsert(
            &did,
            PushRegistration::new("apns".into(), "tok-b".into(), vec![4, 5]),
        )
        .unwrap();
        let reloaded = PushRegistry::load(dir.path()).unwrap();
        let all = reloaded.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].registration_id, first_id);
        assert_eq!(all[0].token, "tok-b");
        assert_eq!(all[0].sealed_wake_blob, vec![4, 5]);
        let debug = format!("{:?}", all[0]);
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("tok-b"));
    }

    /// The re-register path is the only thing that re-arms a stale registration,
    /// so it checks the peer store instead of assuming every `remove` write
    /// survived. Nothing re-sends a removal the way the phone re-sends a
    /// registration, which is why a lost one does not heal itself.
    #[test]
    fn a_registration_without_a_live_pairing_is_dropped_not_re_registered() {
        let dir = tempfile::tempdir().unwrap();
        let revoked = DeviceId([9u8; 16]);
        let live = DeviceId([10u8; 16]);
        let mut registry = PushRegistry::load(dir.path()).unwrap();
        for device in [&revoked, &live] {
            registry
                .upsert(
                    device,
                    PushRegistration::new("apns".into(), "tok".into(), vec![1]),
                )
                .unwrap();
        }
        assert_eq!(registry.all().len(), 2);

        assert_eq!(registry.retain_live_peers(&[live]), 1);
        registry.persist(Durability::Required).unwrap();

        // Gone from disk too, so the next boot does not resurrect it either.
        let reloaded = PushRegistry::load(dir.path()).unwrap();
        assert_eq!(reloaded.all().len(), 1);
    }

    #[test]
    fn retaining_live_peers_drops_nothing_when_every_pairing_is_current() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([11u8; 16]);
        let mut registry = PushRegistry::load(dir.path()).unwrap();
        registry
            .upsert(
                &device,
                PushRegistration::new("fcm".into(), "tok".into(), vec![2]),
            )
            .unwrap();
        assert_eq!(registry.retain_live_peers(&[device]), 0);
        assert_eq!(registry.all().len(), 1);
    }

    #[test]
    fn relay_secret_is_random_stable_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_host_secret(dir.path()).unwrap();
        let second = load_or_create_host_secret(dir.path()).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, [0u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(HOST_SECRET_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn corrupt_registry_fails_closed_and_remove_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileCredentialStore::new(dir.path());
        store
            .write(REGISTRY_FILE, b"not json", Durability::Required)
            .unwrap();
        assert!(PushRegistry::load(dir.path()).is_err());

        store.remove(REGISTRY_FILE).unwrap();
        let device = DeviceId([3u8; 16]);
        let mut registry = PushRegistry::load(dir.path()).unwrap();
        registry
            .upsert(
                &device,
                PushRegistration::new("fcm".into(), "token".into(), vec![9]),
            )
            .unwrap();
        let removed = registry.remove(&device).unwrap().unwrap();
        assert_eq!(removed.token, "token");
        assert!(PushRegistry::load(dir.path()).unwrap().all().is_empty());
    }
}
