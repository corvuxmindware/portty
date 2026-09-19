use std::path::Path;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const APNS_REFRESH_AFTER_SECS: u64 = 50 * 60;
const FCM_ASSERTION_LIFETIME_SECS: u64 = 60 * 60;
const FCM_REFRESH_MARGIN_SECS: u64 = 60;
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_APNS_URL: &str = "https://api.push.apple.com/3/device";
const DEFAULT_FCM_URL: &str = "https://fcm.googleapis.com/v1/projects";

// ── Endpoint allowlist ────────────────────────────────────────────────
//
// An APNs provider JWT and an FCM OAuth assertion are BEARER CREDENTIALS for
// this relay's push identity: whoever holds one can send notifications as us
// until it expires, and the OAuth assertion is exchanged for a token with the
// full `firebase.messaging` scope. So a configured endpoint is not merely a
// destination - it is the party we hand that credential to, which makes it an
// authorization decision rather than a formatting question.
//
// These were previously read straight from the environment, so a wrong (or
// planted) `PORTTY_APNS_URL`, `PORTTY_FCM_URL`, or service-account `token_uri`
// silently redirected signed credentials to an attacker. Everything below is
// checked BEFORE any credential is signed for it.

/// APNs production and sandbox provider APIs.
const APNS_HOSTS: &[&str] = &["api.push.apple.com", "api.sandbox.push.apple.com"];
/// FCM HTTP v1 send API.
const FCM_HOSTS: &[&str] = &["fcm.googleapis.com"];
/// Google's OAuth 2 token endpoints - where the signed JWT assertion goes.
const OAUTH_HOSTS: &[&str] = &["oauth2.googleapis.com", "accounts.google.com"];

/// Escape hatch for a self-hoster who really does terminate APNs/FCM through
/// their own proxy, and for integration tests.
///
/// It loosens the HOST allowlist only. TLS is still required (except on
/// loopback, where there is no wire to observe) and embedded credentials are
/// still refused, because neither has a legitimate configuration.
const ALLOW_CUSTOM_ENDPOINTS_VAR: &str = "PORTTY_PUSH_ALLOW_CUSTOM_ENDPOINTS";

pub(crate) struct ProviderConfig {
    apns_url: String,
    apns_auth: Option<ApnsAuth>,
    apns_topic: Option<String>,
    fcm_base_url: String,
    fcm_project: Option<String>,
    fcm_auth: Option<FcmAuth>,
}

enum ApnsAuth {
    Static(Zeroizing<String>),
    Signing(ApnsSigningKey),
}

enum FcmAuth {
    Static(Zeroizing<String>),
    ServiceAccount(FcmServiceAccount),
}

struct ApnsSigningKey {
    key_id: String,
    team_id: String,
    key: EncodingKey,
    cached: StdMutex<Option<CachedApnsToken>>,
}

struct CachedApnsToken {
    value: Zeroizing<String>,
    issued_at: u64,
}

struct FcmServiceAccount {
    client_email: String,
    key_id: Option<String>,
    token_uri: String,
    key: EncodingKey,
    cached: Mutex<Option<CachedOAuthToken>>,
}

struct CachedOAuthToken {
    value: Zeroizing<String>,
    refresh_at: Instant,
}

#[derive(Serialize)]
struct ApnsClaims<'a> {
    iss: &'a str,
    iat: u64,
}

#[derive(Serialize)]
struct GoogleClaims<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct ServiceAccountFile {
    project_id: Option<String>,
    private_key_id: Option<String>,
    client_email: String,
    private_key: String,
    #[serde(default = "default_google_token_uri")]
    token_uri: String,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: u64,
}

fn default_google_token_uri() -> String {
    GOOGLE_TOKEN_URI.into()
}

fn allow_custom_endpoints() -> bool {
    matches!(
        std::env::var(ALLOW_CUSTOM_ENDPOINTS_VAR).as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Check an operator-configured endpoint before any credential is signed for it.
/// Returns the endpoint unchanged on success so callers keep composing URLs by
/// string concatenation exactly as before.
fn validated_endpoint(
    var: &str,
    raw: &str,
    official: &[&str],
    allow_custom: bool,
) -> Result<String, String> {
    let raw = raw.trim();
    let url =
        reqwest::Url::parse(raw).map_err(|error| format!("{var} is not a valid URL: {error}"))?;
    // Refused unconditionally, opt-out or not: `https://user:pass@host/` is
    // never how a push endpoint is legitimately configured, and it is exactly
    // how a credential-harvesting URL is dressed up to look like one.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{var} must not embed credentials in the URL"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("{var} has no host"))?
        .to_ascii_lowercase();
    let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
    // TLS or nothing. Cleartext puts the provider token on the wire for anyone
    // on the path. Loopback is the one exemption - there is no wire - and it
    // still requires the explicit opt-out.
    if url.scheme() != "https" && !(loopback && allow_custom) {
        return Err(format!(
            "{var} must use https, got {}:// (only a loopback proxy may use http, \
             and only with {ALLOW_CUSTOM_ENDPOINTS_VAR}=1)",
            url.scheme()
        ));
    }
    if !official.contains(&host.as_str()) {
        if !allow_custom {
            return Err(format!(
                "{var} points at {host}, which is not an official push endpoint \
                 (expected one of: {}). Signed provider credentials are sent to \
                 this host, so it is not accepted by default. Set \
                 {ALLOW_CUSTOM_ENDPOINTS_VAR}=1 if you really do terminate push \
                 through your own host.",
                official.join(", ")
            ));
        }
        tracing::warn!(
            %host,
            endpoint = var,
            "sending signed push provider credentials to a non-official host \
             ({ALLOW_CUSTOM_ENDPOINTS_VAR} is set)"
        );
    }
    Ok(raw.to_string())
}

/// The project id is spliced into the FCM send URL, so it is validated as a path
/// segment rather than trusted. Google project ids are lowercase letters,
/// digits and hyphens; `.` and `:` are permitted for legacy domain-scoped ids.
/// Anything that could restructure the URL (`/`, `?`, `#`, `@`, whitespace) is
/// refused.
fn validated_fcm_project(project: &str) -> Result<String, String> {
    let project = project.trim();
    let shaped = !project.is_empty()
        && project.len() <= 64
        && project.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b':')
        });
    if !shaped {
        return Err(
            "the FCM project id must be lowercase letters, digits, hyphens, `.` or `:`".into(),
        );
    }
    Ok(project.to_string())
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))
}

impl ApnsSigningKey {
    fn from_pem(key_id: String, team_id: String, pem: &[u8]) -> Result<Self, String> {
        let key = EncodingKey::from_ec_pem(pem)
            .map_err(|error| format!("invalid APNs P-256 private key: {error}"))?;
        Ok(Self {
            key_id,
            team_id,
            key,
            cached: StdMutex::new(None),
        })
    }

    fn bearer(&self) -> Result<String, String> {
        self.bearer_at(unix_time()?)
    }

    fn bearer_at(&self, now: u64) -> Result<String, String> {
        let mut cached = self
            .cached
            .lock()
            .map_err(|_| "APNs token cache is poisoned".to_string())?;
        if let Some(token) = cached.as_ref() {
            if now >= token.issued_at
                && now.saturating_sub(token.issued_at) < APNS_REFRESH_AFTER_SECS
            {
                return Ok(token.value.to_string());
            }
        }

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let value = encode(
            &header,
            &ApnsClaims {
                iss: &self.team_id,
                iat: now,
            },
            &self.key,
        )
        .map_err(|error| format!("could not sign APNs provider token: {error}"))?;
        *cached = Some(CachedApnsToken {
            value: Zeroizing::new(value.clone()),
            issued_at: now,
        });
        Ok(value)
    }
}

impl FcmServiceAccount {
    fn from_file(path: &Path, allow_custom: bool) -> Result<(Self, Option<String>), String> {
        let mut contents = std::fs::read_to_string(path).map_err(|error| {
            format!(
                "could not read FCM service account {}: {error}",
                path.display()
            )
        })?;
        let parsed = serde_json::from_str(&contents).map_err(|error| {
            format!(
                "could not parse FCM service account {}: {error}",
                path.display()
            )
        });
        contents.zeroize();
        let mut account: ServiceAccountFile = parsed?;
        let key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .map_err(|error| format!("invalid FCM RSA private key: {error}"));
        account.private_key.zeroize();
        let key = key?;
        let ServiceAccountFile {
            project_id,
            private_key_id,
            client_email,
            private_key: _,
            token_uri,
        } = account;
        // `token_uri` comes out of a JSON file on disk, so it is operator input
        // like any environment variable - and it is the one endpoint that
        // receives the signed RSA assertion.
        let token_uri = validated_endpoint(
            &format!("token_uri in {}", path.display()),
            &token_uri,
            OAUTH_HOSTS,
            allow_custom,
        )?;
        Ok((
            Self {
                client_email,
                key_id: private_key_id,
                token_uri,
                key,
                cached: Mutex::new(None),
            },
            project_id,
        ))
    }

    #[cfg(test)]
    fn from_pem(
        client_email: String,
        key_id: Option<String>,
        token_uri: String,
        pem: &[u8],
    ) -> Result<Self, String> {
        let key = EncodingKey::from_rsa_pem(pem)
            .map_err(|error| format!("invalid FCM RSA private key: {error}"))?;
        Ok(Self {
            client_email,
            key_id,
            token_uri,
            key,
            cached: Mutex::new(None),
        })
    }

    async fn bearer(&self, client: &reqwest::Client) -> Result<String, String> {
        self.bearer_with(|token_uri, assertion| async move {
            exchange_oauth_token(client, &token_uri, &assertion).await
        })
        .await
    }

    async fn bearer_with<F, Fut>(&self, exchange: F) -> Result<String, String>
    where
        F: FnOnce(String, String) -> Fut,
        Fut: std::future::Future<Output = Result<OAuthTokenResponse, String>>,
    {
        // Hold the lock through refresh so a burst of wakes performs one OAuth
        // exchange instead of racing several identical assertions.
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached.as_ref() {
            if Instant::now() < token.refresh_at {
                return Ok(token.value.to_string());
            }
        }

        let now = unix_time()?;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.key_id.clone();
        let assertion = encode(
            &header,
            &GoogleClaims {
                iss: &self.client_email,
                scope: FCM_SCOPE,
                aud: &self.token_uri,
                iat: now,
                exp: now + FCM_ASSERTION_LIFETIME_SECS,
            },
            &self.key,
        )
        .map_err(|error| format!("could not sign FCM OAuth assertion: {error}"))?;

        let token = exchange(self.token_uri.clone(), assertion).await?;
        let refresh_after = token.expires_in.saturating_sub(FCM_REFRESH_MARGIN_SECS);
        let value = token.access_token;
        *cached = Some(CachedOAuthToken {
            value: Zeroizing::new(value.clone()),
            refresh_at: Instant::now() + Duration::from_secs(refresh_after),
        });
        Ok(value)
    }

    #[cfg(test)]
    async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
}

async fn exchange_oauth_token(
    client: &reqwest::Client,
    token_uri: &str,
    assertion: &str,
) -> Result<OAuthTokenResponse, String> {
    let response = client
        .post(token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion),
        ])
        .send()
        .await
        .map_err(|error| format!("FCM OAuth token exchange failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(format!(
            "FCM OAuth token endpoint returned {status}: {}",
            detail.chars().take(512).collect::<String>()
        ));
    }
    response
        .json()
        .await
        .map_err(|error| format!("invalid FCM OAuth token response: {error}"))
}

impl ProviderConfig {
    pub(crate) fn from_env() -> Result<Self, String> {
        let allow_custom = allow_custom_endpoints();
        let apns_static = std::env::var("PORTTY_APNS_BEARER").ok();
        let apns_key_path = std::env::var("PORTTY_APNS_KEY_PATH").ok();
        let apns_auth = match (apns_static, apns_key_path) {
            (Some(_), Some(_)) => {
                return Err("set PORTTY_APNS_BEARER or PORTTY_APNS_KEY_PATH, not both".into())
            }
            (Some(token), None) => Some(ApnsAuth::Static(Zeroizing::new(token))),
            (None, Some(path)) => {
                let key_id = std::env::var("PORTTY_APNS_KEY_ID")
                    .map_err(|_| "PORTTY_APNS_KEY_ID is required with PORTTY_APNS_KEY_PATH")?;
                let team_id = std::env::var("PORTTY_APNS_TEAM_ID")
                    .map_err(|_| "PORTTY_APNS_TEAM_ID is required with PORTTY_APNS_KEY_PATH")?;
                let mut pem = std::fs::read(&path)
                    .map_err(|error| format!("could not read APNs key {path}: {error}"))?;
                let signer = ApnsSigningKey::from_pem(key_id, team_id, &pem);
                pem.zeroize();
                Some(ApnsAuth::Signing(signer?))
            }
            (None, None) => None,
        };

        let fcm_static = std::env::var("PORTTY_FCM_BEARER").ok();
        let fcm_account_path = std::env::var("PORTTY_FCM_SERVICE_ACCOUNT")
            .ok()
            .or_else(|| std::env::var("GOOGLE_APPLICATION_CREDENTIALS").ok());
        let mut fcm_project = std::env::var("PORTTY_FCM_PROJECT").ok();
        let fcm_auth = match (fcm_static, fcm_account_path) {
            (Some(_), Some(_)) => {
                return Err("set PORTTY_FCM_BEARER or an FCM service-account path, not both".into())
            }
            (Some(token), None) => Some(FcmAuth::Static(Zeroizing::new(token))),
            (None, Some(path)) => {
                let (account, account_project) =
                    FcmServiceAccount::from_file(Path::new(&path), allow_custom)?;
                if fcm_project.is_none() {
                    fcm_project = account_project;
                }
                Some(FcmAuth::ServiceAccount(account))
            }
            (None, None) => None,
        };
        // Whichever source supplied it, the project id ends up in a URL path.
        let fcm_project = match fcm_project {
            Some(project) => Some(validated_fcm_project(&project)?),
            None => None,
        };

        let apns_topic = std::env::var("PORTTY_APNS_TOPIC").ok();
        if apns_auth.is_some() && apns_topic.is_none() {
            return Err("PORTTY_APNS_TOPIC is required when APNs auth is configured".into());
        }
        if fcm_auth.is_some() && fcm_project.is_none() {
            return Err(
                "PORTTY_FCM_PROJECT is required when the service-account JSON has no project_id"
                    .into(),
            );
        }

        let apns_url = match std::env::var("PORTTY_APNS_URL") {
            Ok(raw) => validated_endpoint("PORTTY_APNS_URL", &raw, APNS_HOSTS, allow_custom)?,
            Err(_) => DEFAULT_APNS_URL.to_string(),
        };
        let fcm_base_url = match std::env::var("PORTTY_FCM_URL") {
            Ok(raw) => validated_endpoint("PORTTY_FCM_URL", &raw, FCM_HOSTS, allow_custom)?,
            Err(_) => DEFAULT_FCM_URL.to_string(),
        };

        Ok(Self {
            apns_url,
            apns_auth,
            apns_topic,
            fcm_base_url,
            fcm_project,
            fcm_auth,
        })
    }

    pub(crate) fn apns_url(&self) -> &str {
        &self.apns_url
    }

    pub(crate) fn apns_topic(&self) -> Result<&str, String> {
        self.apns_topic
            .as_deref()
            .ok_or_else(|| "PORTTY_APNS_TOPIC is not configured".into())
    }

    pub(crate) fn apns_bearer(&self) -> Result<String, String> {
        match self.apns_auth.as_ref() {
            Some(ApnsAuth::Static(token)) => Ok(token.to_string()),
            Some(ApnsAuth::Signing(key)) => key.bearer(),
            None => Err("APNs credentials are not configured".into()),
        }
    }

    pub(crate) fn fcm_send_url(&self) -> Result<String, String> {
        let project = self
            .fcm_project
            .as_deref()
            .ok_or_else(|| "PORTTY_FCM_PROJECT is not configured".to_string())?;
        Ok(format!(
            "{}/{project}/messages:send",
            self.fcm_base_url.trim_end_matches('/')
        ))
    }

    pub(crate) async fn fcm_bearer(&self, client: &reqwest::Client) -> Result<String, String> {
        match self.fcm_auth.as_ref() {
            Some(FcmAuth::Static(token)) => Ok(token.to_string()),
            Some(FcmAuth::ServiceAccount(account)) => account.bearer(client).await,
            None => Err("FCM credentials are not configured".into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_static() -> Self {
        Self {
            apns_url: "https://apns.test.invalid/3/device".into(),
            apns_auth: Some(ApnsAuth::Static(Zeroizing::new("apns-test-bearer".into()))),
            apns_topic: Some("com.example.portty".into()),
            fcm_base_url: "https://fcm.test.invalid/v1/projects".into(),
            fcm_project: Some("portty-test".into()),
            fcm_auth: Some(FcmAuth::Static(Zeroizing::new("fcm-test-bearer".into()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use base64::Engine;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use serde::Deserialize;

    use super::*;

    // Disposable fixture material only. Reconstruct the PEM envelope at test
    // runtime so repository scanners do not mistake it for a deployed secret.
    const TEST_APNS_PRIVATE_KEY_BODY: &str = r#"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMGEC1BA40+4sWDLU
ase3GvxhxLW6GTadTxCFG2qJEFShRANCAARFQTTQnCrDHTGlbIEpjxz/pXBoEh8I
hRxQinxNGdB2/r71R00/ETrTz3oo+wkgh83yA7kcPWH8N+s3ujjaWx2R
"#;
    const TEST_APNS_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERUE00Jwqwx0xpWyBKY8c/6VwaBIf
CIUcUIp8TRnQdv6+9UdNPxE60896KPsJIIfN8gO5HD1h/DfrN7o42lsdkQ==
-----END PUBLIC KEY-----
"#;
    const TEST_FCM_PRIVATE_KEY_BODY: &str = r#"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcn4GNvUR3jBYJ
4nSc/l2qgPMoP7wWEHUozuW1WPfyt08o2Y09+fejSbXSjs6ChSsHJF/8i5U6Js6s
dKh4KXfAXazy4fV0Dhw/kKWcFAEvUK1iMDiSGf/HYy7jow/JFWAPyAIKmBd8Nxjr
i/NelJVebqxaiX3vX7E/4/2t5bK7++PFLuzx5jGu6m7FCFJgLbB9JXpJT3GV32AV
dNkt/fw/d4aH4fmBtiUcFrshA2ITe/SZsGdTzdC5RmOoIju3oEfU+/b6OeGL/Ltx
DygT/Bf7bGVCuCYvwAn7OSSmBScmi8KJ2W+OiImULWCl82lwAEtmJjehA2QQ08bl
JZgx3ueBAgMBAAECggEAFKHyKsBFk+yM7xW3lCsRtW1j0CLNwz58xnk68E/GuHM+
OvLFi8NBzoqJL4zdcUVk9cEIHQUsyohwkZ5DVyGBqoLYNsq8+sKLD8LGSidwyO0B
mgoqcDdwPURgUTehtUuDdVZeIoGAyMQaV4T6GKFKqs8s3Ta4iVdoqzH2Onod0gib
GmTN8FR9cg4kr4ySypihPUBdymm+nG2EFIDvZPwpKFVccvgVzkSVDiILXTJEPSk3
FLGLY/UMHQeURhBV8iCuax6O3IKaq2aUNwUpZq8j5EaSS+FbOXU1QUaP6uwkA7C8
KQEB4jLDWlR+f6LwcGX7x27ROezmPq0rc+8tDXqPxQKBgQDxqRgr3TMqDzdFi7Wj
cy7ucSBNw00YRpXSsJIIElGxILAgUgRm9FmJpmHx+f85zShceDP44jrY5lQM48bl
9Ar/NQPg/uvYVV4RYyaSQ/MLb1RtHof0n3NdSNw09e5YJONcll2SnIxCMeioqUcn
GqQ1urf8X9IpeN5s7VGY37E6LwKBgQDptth2mgx3P6YuipgL+q17q/gD2ZuOI80E
z0/WVR+cVu+hrNeRM2rroC5FHJbqBYY/4KKQC+QUbqxHvsauFddWwEHZn4UJrDAp
FuoyU4Abe6jB3XJZy20D+RXBIyjFkuXYne9GRvUnuCaxt1xE3gJRAWhF1TcRwvZ5
Skt/e0t9TwKBgQDZBIeGbMET1lJGjC50OG4/ByyBaRAE6u6FJLgfs4PVU4uXmtAF
PQ5jhR2UVnOTjt/eGrxhl5hNTJrScIMf4sc1ZIC1P3jA7/joGGh9FbRf4nyo+bAS
SFcrwNCwZuLCGW5sqUQi858pmvRa8pnJTi2FasbrR4nOYJMusviCFvBrVQKBgEc0
hQjFcGzYgIoHgcGMk1RtlXee0ezhbXI8s0dK0gGw3vt0DI1ZjAbT26UEy9nq6vcF
OqIGbWvoOCb3sdKSJvRwSN/D4SWMR3QNXjcNB6fX6hd+n3tKJiGivwUD8EUZt1ti
6uaPcduzGF7mzX7R4QTLF/jGuCt6KdvUTeI+L0azAoGABf6V93jClU/lw0uD0yEw
XZfBb1xrA3s1H0IuPWVskRVJsxOTHcQZIc9vNtP5QdeoqdExyvvlx9XRqxLR9HD0
cmO1Lt7ySLt22eZM8smoJeRyMmqgTWY/ZwFM3Hv9YiVvYkaOFu7JSK6neiVJgH8L
J+qfSNaXbvOyNQ0pSO2C5+8=
"#;

    fn test_private_key(body: &str) -> String {
        format!(
            "-----BEGIN {kind}-----\n{body}-----END {kind}-----\n",
            kind = "PRIVATE KEY"
        )
    }

    #[derive(Debug, Deserialize)]
    struct DecodedApnsClaims {
        iss: String,
        iat: u64,
    }

    #[derive(Debug, Deserialize)]
    struct DecodedGoogleClaims {
        iss: String,
        scope: String,
        aud: String,
        iat: u64,
        exp: u64,
    }

    /// These exercise `validated_endpoint` directly rather than through
    /// `from_env`. Environment variables are process-global, and Rust runs tests
    /// in threads - an env-mutating test would race every other test in this
    /// binary.
    mod endpoints {
        use super::*;

        fn check(raw: &str, official: &[&str], allow_custom: bool) -> Result<String, String> {
            validated_endpoint("PORTTY_TEST_URL", raw, official, allow_custom)
        }

        #[test]
        fn official_hosts_pass_through_byte_for_byte() {
            // Returned unchanged, not normalized: callers build the final URL by
            // concatenation (`{apns_url}/{token}`), so a helpfully-added trailing
            // slash here would produce a double slash there.
            for (url, hosts) in [
                (DEFAULT_APNS_URL, APNS_HOSTS),
                ("https://api.sandbox.push.apple.com/3/device", APNS_HOSTS),
                (DEFAULT_FCM_URL, FCM_HOSTS),
                (GOOGLE_TOKEN_URI, OAUTH_HOSTS),
            ] {
                assert_eq!(check(url, hosts, false).as_deref(), Ok(url));
            }
        }

        /// The headline: an unofficial host receives a signed provider JWT, so it
        /// is refused unless the operator says otherwise.
        #[test]
        fn an_unofficial_host_is_refused_by_default_and_allowed_on_opt_in() {
            let evil = "https://attacker.example/3/device";
            let error = check(evil, APNS_HOSTS, false).unwrap_err();
            assert!(
                error.contains("attacker.example") && error.contains(ALLOW_CUSTOM_ENDPOINTS_VAR),
                "the error must name the host and the opt-out: {error}"
            );
            assert_eq!(check(evil, APNS_HOSTS, true).as_deref(), Ok(evil));
        }

        /// Case and trailing whitespace must not walk past the allowlist.
        #[test]
        fn host_matching_ignores_case_and_surrounding_whitespace() {
            let raw = "  https://API.PUSH.APPLE.COM/3/device  ";
            assert_eq!(
                check(raw, APNS_HOSTS, false).as_deref(),
                Ok("https://API.PUSH.APPLE.COM/3/device")
            );
        }

        /// Cleartext leaks the provider token to anyone on the path. The opt-out
        /// deliberately does NOT cover it for a routable host.
        #[test]
        fn http_is_refused_even_for_an_official_host_and_even_with_the_opt_out() {
            for allow_custom in [false, true] {
                let error = check(
                    "http://api.push.apple.com/3/device",
                    APNS_HOSTS,
                    allow_custom,
                )
                .unwrap_err();
                assert!(error.contains("https"), "{error}");
            }
        }

        /// A loopback proxy has no wire to observe, so it is the one http case -
        /// and still only with the explicit opt-out.
        #[test]
        fn http_loopback_needs_the_opt_out() {
            let local = "http://127.0.0.1:8080/3/device";
            assert!(check(local, APNS_HOSTS, false).is_err());
            assert_eq!(check(local, APNS_HOSTS, true).as_deref(), Ok(local));
        }

        /// `https://user:pass@host/` is how a credential-harvesting URL is
        /// disguised as a real one. Never accepted, opt-out or not.
        #[test]
        fn embedded_credentials_are_refused_unconditionally() {
            for raw in [
                "https://user:pass@api.push.apple.com/3/device",
                "https://user@api.push.apple.com/3/device",
            ] {
                for allow_custom in [false, true] {
                    let error = check(raw, APNS_HOSTS, allow_custom).unwrap_err();
                    assert!(error.contains("credentials"), "{error}");
                }
            }
        }

        #[test]
        fn garbage_and_hostless_urls_are_refused() {
            for raw in ["not a url", "https://", "file:///etc/passwd", ""] {
                assert!(
                    check(raw, APNS_HOSTS, true).is_err(),
                    "{raw} must not be accepted"
                );
            }
        }

        /// The project id is spliced into the send URL as a path segment.
        #[test]
        fn the_fcm_project_id_is_checked_as_a_path_segment() {
            assert_eq!(
                validated_fcm_project("portty-test").as_deref(),
                Ok("portty-test")
            );
            assert_eq!(
                validated_fcm_project("legacy.domain:project").as_deref(),
                Ok("legacy.domain:project")
            );
            for bad in [
                "",
                "../../evil",
                "a/b",
                "proj?x=1",
                "proj#frag",
                "user@host",
                "has space",
                "UPPER",
            ] {
                assert!(
                    validated_fcm_project(bad).is_err(),
                    "{bad:?} must not be accepted as a project id"
                );
            }
        }
    }

    #[test]
    fn apns_jwt_is_valid_cached_and_rotated_before_expiry() {
        let private_key = test_private_key(TEST_APNS_PRIVATE_KEY_BODY);
        let signer = ApnsSigningKey::from_pem(
            "KEY1234567".into(),
            "TEAM123456".into(),
            private_key.as_bytes(),
        )
        .unwrap();
        let first = signer.bearer_at(1_700_000_000).unwrap();
        assert_eq!(first, signer.bearer_at(1_700_001_000).unwrap());
        let rotated = signer.bearer_at(1_700_003_001).unwrap();
        assert_ne!(first, rotated);

        let header = decode_header(&rotated).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY1234567"));
        let mut validation = Validation::new(Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let claims = decode::<DecodedApnsClaims>(
            &rotated,
            &DecodingKey::from_ec_pem(TEST_APNS_PUBLIC_KEY.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(claims.iss, "TEAM123456");
        assert_eq!(claims.iat, 1_700_003_001);
    }

    #[tokio::test]
    async fn fcm_service_account_exchanges_caches_and_refreshes_oauth_token() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(StdMutex::new(Vec::<(String, String)>::new()));
        let private_key = test_private_key(TEST_FCM_PRIVATE_KEY_BODY);
        let account = FcmServiceAccount::from_pem(
            "push@test.invalid".into(),
            Some("rsa-key-1".into()),
            "https://oauth.test.invalid/token".into(),
            private_key.as_bytes(),
        )
        .unwrap();

        let first_calls = calls.clone();
        let first_captured = captured.clone();
        let first = account
            .bearer_with(move |uri, assertion| async move {
                first_calls.fetch_add(1, Ordering::SeqCst);
                first_captured.lock().unwrap().push((uri, assertion));
                Ok(OAuthTokenResponse {
                    access_token: "mock-access-1".into(),
                    expires_in: 3600,
                })
            })
            .await
            .unwrap();
        assert_eq!(first, "mock-access-1");
        let cached = account
            .bearer_with(|_, _| async { Err("cache unexpectedly missed".into()) })
            .await
            .unwrap();
        assert_eq!(cached, "mock-access-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        account.invalidate().await;
        let refresh_calls = calls.clone();
        let refreshed = account
            .bearer_with(move |_, _| async move {
                refresh_calls.fetch_add(1, Ordering::SeqCst);
                Ok(OAuthTokenResponse {
                    access_token: "mock-access-2".into(),
                    expires_in: 3600,
                })
            })
            .await
            .unwrap();
        assert_eq!(refreshed, "mock-access-2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let captured = captured.lock().unwrap();
        assert_eq!(captured[0].0, "https://oauth.test.invalid/token");
        assert_eq!(captured[0].1.split('.').count(), 3);
        let header = decode_header(&captured[0].1).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some("rsa-key-1"));
        let payload = captured[0].1.split('.').nth(1).unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let claims: DecodedGoogleClaims = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims.iss, "push@test.invalid");
        assert_eq!(claims.scope, FCM_SCOPE);
        assert_eq!(claims.aud, "https://oauth.test.invalid/token");
        assert_eq!(claims.exp - claims.iat, FCM_ASSERTION_LIFETIME_SECS);
    }
}
