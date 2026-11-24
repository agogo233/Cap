use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

use crate::store::{self, DEFAULT_SERVER_URL};

pub const PRICING_URL: &str = "https://cap.so/pricing?ref=desktop";

#[derive(Debug)]
pub enum AuthApiError {
    InvalidAuthentication,
    UpgradeRequired,
    Timeout,
    Status(reqwest::StatusCode, String),
    Other(String),
}

impl AuthApiError {
    pub fn message(&self) -> String {
        match self {
            Self::InvalidAuthentication => {
                "User is not authenticated or credentials have expired!".into()
            }
            Self::UpgradeRequired => {
                "User needs to upgrade their account to use this feature!".into()
            }
            Self::Timeout => "The request has timed out".into(),
            Self::Status(_, message) | Self::Other(message) => message.clone(),
        }
    }
}

impl std::fmt::Display for AuthApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

pub fn submit_deep_link(_url: &str) {
    // Sign-in is disabled in this build: token-bearing URLs are dropped.
}

pub fn sign_out() -> bool {
    store::set_auth(None)
}

pub fn apply_desktop_headers(mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    request = request
        .header("X-Cap-Desktop-Version", env!("CARGO_PKG_VERSION"))
        .header("X-Cap-Desktop-Features", "googleDriveUpload,gpui");
    if let Ok(secret) = std::env::var("VITE_VERCEL_AUTOMATION_BYPASS_SECRET")
        && !secret.is_empty()
    {
        request = request.header("x-vercel-protection-bypass", secret);
    }
    request
}

pub fn server_url() -> String {
    normalize_server_url(&store::GeneralSettings::load().server_url)
}

fn normalize_server_url(url: &str) -> String {
    if url.trim().is_empty() {
        DEFAULT_SERVER_URL.to_string()
    } else {
        url.trim_end_matches('/').to_string()
    }
}

pub fn is_server_url_custom() -> bool {
    !has_same_origin(&server_url(), DEFAULT_SERVER_URL)
}

#[derive(Clone)]
pub(crate) struct UploadRequestContext {
    server_url: String,
    owner_id: String,
}

tokio::task_local! {
    static UPLOAD_REQUEST: UploadRequestContext;
}

impl UploadRequestContext {
    pub(crate) fn for_upload(
        server_url: &str,
        owner_id: Option<&str>,
    ) -> Result<Self, AuthApiError> {
        let context = Self {
            server_url: server_url.to_string(),
            owner_id: owner_id
                .filter(|id| !id.is_empty())
                .ok_or(AuthApiError::InvalidAuthentication)?
                .to_string(),
        };
        context.credentials()?;
        Ok(context)
    }

    fn credentials_from(
        &self,
        current_server: &str,
        current_auth: &serde_json::Map<String, Value>,
    ) -> Result<String, AuthApiError> {
        if !has_same_origin(current_server, &self.server_url)
            || current_auth.get("user_id").and_then(Value::as_str) != Some(self.owner_id.as_str())
        {
            return Err(AuthApiError::InvalidAuthentication);
        }
        current_auth
            .get("secret")
            .and_then(Value::as_object)
            .and_then(|secret| secret.get("api_key").or_else(|| secret.get("token")))
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .ok_or(AuthApiError::InvalidAuthentication)
    }

    fn credentials(&self) -> Result<String, AuthApiError> {
        self.credentials_from(&server_url(), &store::store_section("auth"))
    }

    pub(crate) async fn run<F: std::future::Future>(self, future: F) -> F::Output {
        UPLOAD_REQUEST.scope(self, future).await
    }
}

/// Idle API connections are dropped after 4 s, before the 5 s keep-alive
/// timeout of a self-hosted Node server, so a request is never sent on a
/// connection the server is closing.
pub(crate) const API_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(4);
/// The shared API client is rebuilt this often, so system proxy changes still
/// apply. It is wall clock time, which counts a sleep where the pool's idle
/// clock does not, so calls after a longer sleep start on new connections.
const API_CLIENT_MAX_AGE: Duration = Duration::from_secs(30);

fn api_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
}

/// Multipart uploads hold their own client and drop it when the upload ends,
/// so a later upload never starts on a pooled connection from an earlier
/// network (#2522).
pub fn api_client() -> Result<reqwest::Client, AuthApiError> {
    api_client_builder()
        .build()
        .map_err(|error| AuthApiError::Other(error.to_string()))
}

static SHARED_API_CLIENT: Mutex<Option<(std::time::SystemTime, reqwest::Client)>> =
    Mutex::new(None);

/// Held by every test that resets the shared client or counts its
/// connections, so a reset on one thread cannot land in another's count.
#[cfg(test)]
pub(crate) static SHARED_API_CLIENT_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

/// Drops the shared client, as quitting the app does, for tests that model a
/// relaunch.
#[cfg(test)]
pub(crate) fn reset_shared_api_client() {
    *SHARED_API_CLIENT
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
}

/// The client `authed_request` uses. Calls close together, like Instant
/// presigns about once a second or the requests after a recording stops,
/// reuse its open connections instead of each paying a TCP and TLS handshake.
fn shared_api_client() -> Result<reqwest::Client, AuthApiError> {
    let mut shared = SHARED_API_CLIENT
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some((built, client)) = shared.as_ref()
        && built.elapsed().is_ok_and(|age| age < API_CLIENT_MAX_AGE)
    {
        return Ok(client.clone());
    }
    let client = api_client_builder()
        .pool_idle_timeout(API_POOL_IDLE_TIMEOUT)
        .build()
        .map_err(|error| AuthApiError::Other(error.to_string()))?;
    *shared = Some((std::time::SystemTime::now(), client.clone()));
    Ok(client)
}

pub async fn authed_request(
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<reqwest::Response, AuthApiError> {
    authed_request_with(&shared_api_client()?, method, path, body).await
}

pub async fn authed_request_with(
    client: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<reqwest::Response, AuthApiError> {
    let (server, token) = if let Ok(context) = UPLOAD_REQUEST.try_with(Clone::clone) {
        let token = context.credentials()?;
        (context.server_url, token)
    } else {
        let auth = store::auth_snapshot();
        (
            normalize_server_url(&auth.server_url),
            auth.token.ok_or(AuthApiError::InvalidAuthentication)?,
        )
    };
    let url = format!("{server}{path}");
    let mut request = client.request(method, url);
    request = apply_desktop_headers(request).bearer_auth(token);
    if let Some(body) = body {
        request = request
            .header("Content-Type", "application/json")
            .json(&body);
    }
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            AuthApiError::Timeout
        } else {
            AuthApiError::Other(error.to_string())
        }
    })?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(AuthApiError::InvalidAuthentication);
    }
    Ok(response)
}

pub async fn update_auth_plan() -> Result<(), AuthApiError> {
    let snapshot = store::auth_snapshot();
    if !snapshot.signed_in() {
        return Err(AuthApiError::InvalidAuthentication);
    }
    let account = auth_identity(&store::store_section("auth"));

    let mut plan = None;
    if !snapshot.plan_manual {
        match authed_request(reqwest::Method::GET, "/api/desktop/plan", None).await {
            Ok(response) if response.status().is_success() => {
                if let Ok(body) = response.json::<Value>().await
                    && let Some(upgraded) = body.get("upgraded").and_then(Value::as_bool)
                {
                    plan = Some(json!({
                        "upgraded": upgraded,
                        "manual": false,
                        "last_checked": chrono::Utc::now().timestamp() as i32,
                    }));
                }
            }
            Ok(response) => tracing::warn!("Plan fetch returned {}", response.status()),
            Err(error) => tracing::warn!("Failed to fetch plan: {error}"),
        }
    }

    let mut organizations = None;
    let mut organizations_failed = false;
    match authed_request(reqwest::Method::GET, "/api/desktop/organizations", None).await {
        Ok(response) if response.status().is_success() => {
            if let Ok(orgs) = response.json::<Value>().await {
                organizations = Some(orgs);
            }
        }
        Ok(response) => tracing::warn!("Organizations fetch returned {}", response.status()),
        Err(error) => {
            tracing::warn!("Failed to fetch organizations: {error}");
            organizations_failed = true;
        }
    }

    // Merged into the auth section as it is on disk now, and only if it still
    // belongs to the account these responses are for: a sign-out or account
    // switch during the requests must not be overwritten by the old session.
    let mut stale = false;
    let persisted = store::update_store_section("auth", |auth| {
        if account.is_none() || auth_identity(auth) != account {
            stale = true;
            return false;
        }
        if let Some(plan) = plan {
            auth.insert("plan".into(), plan);
        }
        let now = json!(chrono::Utc::now().timestamp() as i32);
        if let Some(orgs) = organizations {
            auth.insert("organizations".into(), orgs);
            auth.insert("organizations_updated_at".into(), now);
        } else if organizations_failed
            && auth
                .get("organizations")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            auth.insert("organizations_updated_at".into(), now);
        }
        true
    });
    if stale {
        return Err(AuthApiError::InvalidAuthentication);
    }
    if !persisted {
        return Err(AuthApiError::Other("Failed to persist auth plan".into()));
    }
    Ok(())
}

fn auth_identity(auth: &serde_json::Map<String, Value>) -> Option<(Value, Value)> {
    Some((auth.get("user_id")?.clone(), auth.get("secret")?.clone()))
}

pub fn has_same_origin(left: &str, right: &str) -> bool {
    match (origin_of(left), origin_of(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn origin_of(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    Some(url.origin().ascii_serialization())
}

#[cfg(test)]
mod server_change_tests;

#[cfg(test)]
mod upload_context_tests {
    use super::*;

    #[test]
    fn upload_credentials_refresh_only_for_the_same_account_and_server() {
        let context = UploadRequestContext {
            server_url: "https://original.invalid".into(),
            owner_id: "owner".into(),
        };
        let original = json!({"user_id":"owner","secret":{"api_key":"original-credential"}})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            context
                .credentials_from("https://original.invalid", &original)
                .unwrap(),
            "original-credential"
        );
        let refreshed = json!({"user_id":"owner","secret":{"api_key":"refreshed-credential"}})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            context
                .credentials_from("https://original.invalid", &refreshed)
                .unwrap(),
            "refreshed-credential"
        );
        assert_eq!(
            context
                .credentials_from("https://original.invalid:443", &refreshed)
                .unwrap(),
            "refreshed-credential"
        );
        assert!(
            context
                .credentials_from("https://changed.invalid", &refreshed)
                .is_err()
        );
        let different_owner =
            json!({"user_id":"another-owner","secret":{"api_key":"different-credential"}})
                .as_object()
                .unwrap()
                .clone();
        assert!(
            context
                .credentials_from("https://original.invalid", &different_owner)
                .is_err()
        );
        assert!(
            context
                .credentials_from("https://original.invalid", &serde_json::Map::new())
                .is_err()
        );
    }
}
