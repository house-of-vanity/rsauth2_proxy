use crate::crypto::CookieCrypto;
use crate::oidc::{ClientCredentialsError, OidcClient};
use crate::routes::SharedRoutes;
use crate::session::{now_timestamp, Session};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

pub struct AppState {
    pub config: crate::config::Config,
    pub oidc: OidcClient,
    pub routes: SharedRoutes,
    pub crypto: CookieCrypto,
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    pub machine_cache: RwLock<HashMap<[u8; 32], Instant>>,
}

#[derive(Serialize, Deserialize)]
struct AuthStatePayload {
    original_url: String,
    pkce_verifier: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct RefreshStatePayload {
    original_url: String,
}

const COOKIE_NAME: &str = "_auth_proxy_session";
const MAX_SESSION_DURATION: i64 = 86400; // 24h

// --- / ---

pub async fn root() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        concat!(
            "rsauth2-proxy is running.\n",
            "\n",
            "This is a Traefik ForwardAuth backend. It has no UI.\n",
            "Users interact with it transparently through protected applications.\n",
            "\n",
            "Endpoints:\n",
            "  GET /auth       ForwardAuth (called by Traefik)\n",
            "  GET /callback   OIDC callback\n",
            "  GET /refresh    Token refresh\n",
            "  GET /sign_out   Logout\n",
            "  GET /health     Health check\n",
        ),
    )
        .into_response()
}

// --- /health ---

pub async fn health() -> StatusCode {
    StatusCode::OK
}

// --- /metrics ---

pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    let body = state.metrics_handle.render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

// --- /auth ---

pub async fn auth(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let start = std::time::Instant::now();
    let resp = auth_inner(&state, &headers).await;
    let status = resp.status().as_u16().to_string();
    metrics::counter!("auth_requests_total", "status" => status).increment(1);
    metrics::histogram!("auth_request_duration_seconds").record(start.elapsed().as_secs_f64());
    resp
}

async fn auth_inner(state: &AppState, headers: &HeaderMap) -> Response {
    let host = get_header(headers, "x-forwarded-host");
    let uri = get_header(headers, "x-forwarded-uri");
    let proto = get_header(headers, "x-forwarded-proto");

    let host = match host {
        Some(h) => h,
        None => {
            tracing::warn!("missing X-Forwarded-Host header");
            return (StatusCode::BAD_REQUEST, "missing X-Forwarded-Host").into_response();
        }
    };

    let proto = proto.unwrap_or("https");
    let uri = uri.unwrap_or("/");
    let original_url = format!("{}://{}{}", proto, host, uri);

    let (browser_access, machine_access) = state
        .routes
        .read()
        .await
        .get(host)
        .map(|route| (Some(route.browser_access), route.machine_access.is_some()))
        .unwrap_or((None, false));
    if machine_access {
        if let Some(authorization) = headers.get(header::AUTHORIZATION) {
            return authorize_machine(state, headers, host, uri, authorization).await;
        }
    }
    if browser_access == Some(false) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let session = extract_session_from_headers(headers, &state.crypto);

    match session {
        Some(session) if !session.is_access_expired() => {
            authorize_request(state, &session, host).await
        }
        Some(session) if session.refresh_token.is_some() => {
            redirect_to_refresh(state, &original_url)
        }
        _ => redirect_to_login(state, &original_url),
    }
}

async fn authorize_machine(
    state: &AppState,
    headers: &HeaderMap,
    host: &str,
    uri: &str,
    authorization: &axum::http::HeaderValue,
) -> Response {
    let Some(encoded) = authorization
        .to_str()
        .ok()
        .and_then(|s| s.strip_prefix("Basic "))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some((client_id, client_secret)) = STANDARD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|credentials| {
            credentials
                .split_once(':')
                .map(|(id, secret)| (id.to_owned(), secret.to_owned()))
        })
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if client_id.is_empty() || client_secret.is_empty() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let method = get_header(headers, "x-forwarded-method").unwrap_or("");
    let path = uri.split('?').next().unwrap_or("");
    let allowed = state
        .routes
        .read()
        .await
        .get(host)
        .and_then(|route| route.machine_access.as_ref())
        .is_some_and(|machine| {
            machine.client_ids.iter().any(|id| id == &client_id)
                && machine.method == method
                && machine.path == path
        });
    if !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }

    let cache_key: [u8; 32] = Sha256::digest(authorization.as_bytes()).into();
    if state
        .machine_cache
        .read()
        .await
        .get(&cache_key)
        .is_some_and(|expiry| *expiry > Instant::now())
    {
        return StatusCode::OK.into_response();
    }

    match state
        .oidc
        .check_client_credentials(&client_id, &client_secret)
        .await
    {
        Ok(expires_in) => {
            // Never cache longer than Keycloak's token lifetime; keep revocation
            // delay bounded even when the client has a long token lifetime.
            let ttl = expires_in.saturating_sub(30).min(300);
            let mut cache = state.machine_cache.write().await;
            cache.retain(|_, expiry| *expiry > Instant::now());
            if ttl > 0 {
                cache.insert(cache_key, Instant::now() + Duration::from_secs(ttl));
            }
            StatusCode::OK.into_response()
        }
        Err(ClientCredentialsError::Invalid) => StatusCode::UNAUTHORIZED.into_response(),
        Err(ClientCredentialsError::Unavailable(error)) => {
            tracing::warn!(error = %error, "Keycloak client credentials check unavailable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

// --- /callback ---

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackParams>,
) -> Response {
    // Handle OIDC error responses (e.g. authentication_expired, access_denied)
    if let Some(error) = &params.error {
        let desc = params.error_description.as_deref().unwrap_or("");
        tracing::warn!(error, description = desc, "OIDC provider returned error");
        metrics::counter!("callback_requests_total", "result" => "error").increment(1);

        // If we have state, try to redirect back to the original URL to retry
        if let Some(state_str) = &params.state {
            if let Ok(auth_state) = decrypt_state::<AuthStatePayload>(&state.crypto, state_str) {
                return redirect_to_login(&state, &auth_state.original_url);
            }
        }

        return (
            StatusCode::BAD_GATEWAY,
            format!("Authentication failed: {} {}", error, desc),
        )
            .into_response();
    }

    let code = match &params.code {
        Some(c) => c.as_str(),
        None => {
            metrics::counter!("callback_requests_total", "result" => "error").increment(1);
            return (StatusCode::BAD_REQUEST, "missing code parameter").into_response();
        }
    };

    let state_str = match &params.state {
        Some(s) => s.as_str(),
        None => {
            metrics::counter!("callback_requests_total", "result" => "error").increment(1);
            return (StatusCode::BAD_REQUEST, "missing state parameter").into_response();
        }
    };

    let auth_state = match decrypt_state::<AuthStatePayload>(&state.crypto, state_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "invalid callback state");
            metrics::counter!("callback_requests_total", "result" => "error").increment(1);
            return (StatusCode::BAD_REQUEST, "invalid state").into_response();
        }
    };

    let token_response = match state
        .oidc
        .exchange_code(code, &auth_state.pkce_verifier)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "token exchange failed");
            metrics::counter!("callback_requests_total", "result" => "error").increment(1);
            return (StatusCode::BAD_GATEWAY, "token exchange failed").into_response();
        }
    };

    let id_token_str = match &token_response.id_token {
        Some(t) => t,
        None => {
            tracing::error!("no id_token in token response");
            metrics::counter!("callback_requests_total", "result" => "error").increment(1);
            return (StatusCode::BAD_GATEWAY, "missing id_token").into_response();
        }
    };

    let claims = match state
        .oidc
        .validate_id_token(id_token_str, Some(&auth_state.nonce))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "id_token validation failed");
            metrics::counter!("callback_requests_total", "result" => "error").increment(1);
            return (StatusCode::BAD_GATEWAY, "invalid id_token").into_response();
        }
    };

    let now = now_timestamp();
    let exp = claims.exp.min(now + MAX_SESSION_DURATION);

    let session = Session {
        sub: claims.sub,
        username: claims.preferred_username.unwrap_or_default(),
        email: claims.email.unwrap_or_default(),
        groups: claims.groups.unwrap_or_default(),
        exp,
        iat: now,
        refresh_token: token_response.refresh_token,
    };

    let cookie_value = match session.encrypt(&state.crypto) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to encrypt session");
            metrics::counter!("callback_requests_total", "result" => "error").increment(1);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let cookie_header = format_set_cookie(&state.config.cookie_domain, &cookie_value, exp - now);

    metrics::counter!("callback_requests_total", "result" => "success").increment(1);

    (
        StatusCode::FOUND,
        [
            (header::SET_COOKIE, cookie_header),
            (header::LOCATION, auth_state.original_url),
        ],
    )
        .into_response()
}

// --- /refresh ---

#[derive(Deserialize)]
pub struct RefreshParams {
    pub state: String,
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<RefreshParams>,
) -> Response {
    let refresh_state = match decrypt_state::<RefreshStatePayload>(&state.crypto, &params.state) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "invalid refresh state");
            return (StatusCode::BAD_REQUEST, "invalid state").into_response();
        }
    };

    let old_session = match extract_session_from_headers(&headers, &state.crypto) {
        Some(s) => s,
        None => {
            metrics::counter!("refresh_requests_total", "result" => "login").increment(1);
            return redirect_to_login(&state, &refresh_state.original_url);
        }
    };

    let refresh_tok = match &old_session.refresh_token {
        Some(t) => t.clone(),
        None => {
            metrics::counter!("refresh_requests_total", "result" => "login").increment(1);
            return redirect_to_login(&state, &refresh_state.original_url);
        }
    };

    let token_response = match state.oidc.refresh_token(&refresh_tok).await {
        Ok(t) => t,
        Err(e) => {
            tracing::info!(error = %e, "refresh token failed, redirecting to login");
            metrics::counter!("refresh_requests_total", "result" => "login").increment(1);
            return redirect_to_login(&state, &refresh_state.original_url);
        }
    };

    // Validate new ID token (no nonce check on refresh)
    let id_token_str = match &token_response.id_token {
        Some(t) => t,
        None => {
            tracing::error!("no id_token in refresh response");
            metrics::counter!("refresh_requests_total", "result" => "login").increment(1);
            return redirect_to_login(&state, &refresh_state.original_url);
        }
    };

    let claims = match state.oidc.validate_id_token(id_token_str, None).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "refreshed id_token validation failed");
            metrics::counter!("refresh_requests_total", "result" => "login").increment(1);
            return redirect_to_login(&state, &refresh_state.original_url);
        }
    };

    let now = now_timestamp();
    let exp = claims.exp.min(now + MAX_SESSION_DURATION);

    let new_session = Session {
        sub: claims.sub,
        username: claims.preferred_username.unwrap_or_default(),
        email: claims.email.unwrap_or_default(),
        groups: claims.groups.unwrap_or_default(),
        exp,
        iat: now,
        refresh_token: token_response.refresh_token.or(Some(refresh_tok)),
    };

    let cookie_value = match new_session.encrypt(&state.crypto) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to encrypt session");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let cookie_header = format_set_cookie(&state.config.cookie_domain, &cookie_value, exp - now);

    metrics::counter!("refresh_requests_total", "result" => "success").increment(1);

    (
        StatusCode::FOUND,
        [
            (header::SET_COOKIE, cookie_header),
            (header::LOCATION, refresh_state.original_url),
        ],
    )
        .into_response()
}

// --- /sign_out ---

pub async fn sign_out(State(state): State<Arc<AppState>>) -> Response {
    let expired_cookie = format!(
        "{}=; Domain={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        COOKIE_NAME, state.config.cookie_domain
    );

    let redirect_target = state
        .oidc
        .end_session_url()
        .unwrap_or(state.config.base_url());

    (
        StatusCode::FOUND,
        [
            (header::SET_COOKIE, expired_cookie),
            (header::LOCATION, redirect_target.to_string()),
        ],
    )
        .into_response()
}

// --- helpers ---

fn get_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn extract_session_from_headers(headers: &HeaderMap, crypto: &CookieCrypto) -> Option<Session> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    let value = cookie_header
        .split(';')
        .map(|s| s.trim())
        .find(|s| s.starts_with(COOKIE_NAME))?
        .strip_prefix(COOKIE_NAME)?
        .strip_prefix('=')?;
    Session::decrypt(crypto, value).ok()
}

async fn authorize_request(state: &AppState, session: &Session, host: &str) -> Response {
    let routes = state.routes.read().await;

    let route = match routes.get(host) {
        Some(r) => r,
        None => {
            tracing::debug!(host, "host not found in routes, denying");
            return forbidden_page(host, &session.username, "This service is not registered.");
        }
    };

    if !route.allowed_groups.is_empty() {
        let has_access = session
            .groups
            .iter()
            .any(|g| route.allowed_groups.contains(g));
        if !has_access {
            tracing::debug!(host, user = session.username, "user not in allowed groups");
            return forbidden_page(
                host,
                &session.username,
                &format!(
                    "You need to be a member of one of these groups: {}",
                    route.allowed_groups.join(", ")
                ),
            );
        }
    }

    let groups_csv = session.groups.join(",");

    (
        StatusCode::OK,
        [
            ("X-Auth-Request-User", session.username.as_str()),
            ("X-Auth-Request-Email", session.email.as_str()),
            ("X-Auth-Request-Groups", groups_csv.as_str()),
        ],
    )
        .into_response()
}

fn forbidden_page(host: &str, username: &str, reason: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>403 - Access Denied</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    background: #0f0f0f;
    color: #e0e0e0;
  }}
  .box {{
    text-align: center;
    padding: 3rem 2rem;
    max-width: 480px;
  }}
  .lock {{
    font-size: 5rem;
    line-height: 1;
    margin-bottom: 1rem;
  }}
  h1 {{
    font-size: 1.8rem;
    color: #ff6b6b;
    margin-bottom: 0.5rem;
  }}
  .host {{
    font-size: 0.95rem;
    color: #888;
    margin-bottom: 1.5rem;
    word-break: break-all;
  }}
  .reason {{
    font-size: 1rem;
    color: #aaa;
    margin-bottom: 2rem;
    line-height: 1.5;
  }}
  .user {{
    display: inline-block;
    background: #1a1a2e;
    border: 1px solid #333;
    border-radius: 6px;
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
    color: #7c7cf0;
  }}
  .hint {{
    margin-top: 1.5rem;
    font-size: 0.8rem;
    color: #555;
  }}
</style>
</head>
<body>
<div class="box">
  <div class="lock">&#x1f6ab;</div>
  <h1>Access Denied</h1>
  <div class="host">{host}</div>
  <div class="reason">{reason}</div>
  <div class="user">Logged in as <strong>{username}</strong></div>
  <div class="hint">Contact your administrator if you think this is a mistake.</div>
</div>
</body>
</html>"#,
        host = host,
        reason = reason,
        username = username,
    );

    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

fn redirect_to_login(state: &AppState, original_url: &str) -> Response {
    let (pkce_verifier, pkce_challenge) = generate_pkce();

    let nonce = generate_random_string();

    let auth_state = AuthStatePayload {
        original_url: original_url.to_string(),
        pkce_verifier,
        nonce: nonce.clone(),
    };

    let encrypted_state = match encrypt_state(&state.crypto, &auth_state) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to encrypt auth state");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let auth_url = state
        .oidc
        .auth_url(&encrypted_state, &pkce_challenge, &nonce);

    (StatusCode::FOUND, [(header::LOCATION, auth_url)]).into_response()
}

fn redirect_to_refresh(state: &AppState, original_url: &str) -> Response {
    let payload = RefreshStatePayload {
        original_url: original_url.to_string(),
    };

    let encrypted = match encrypt_state(&state.crypto, &payload) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to encrypt refresh state");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut url =
        url::Url::parse(&format!("{}/refresh", state.config.base_url())).expect("valid base_url");
    url.query_pairs_mut().append_pair("state", &encrypted);

    (StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response()
}

fn generate_pkce() -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut verifier_bytes);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    (verifier, challenge)
}

fn generate_random_string() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn encrypt_state<T: Serialize>(crypto: &CookieCrypto, payload: &T) -> anyhow::Result<String> {
    let json = serde_json::to_vec(payload)?;
    crypto.encrypt(&json)
}

fn decrypt_state<T: for<'de> Deserialize<'de>>(
    crypto: &CookieCrypto,
    encoded: &str,
) -> anyhow::Result<T> {
    let plaintext = crypto.decrypt(encoded)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn format_set_cookie(domain: &str, value: &str, max_age_secs: i64) -> String {
    format!(
        "{}={}; Domain={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        COOKIE_NAME, value, domain, max_age_secs
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::crypto::CookieCrypto;
    use crate::oidc::OidcClient;
    use crate::routes::{MachineAccess, RouteConfig};
    use crate::session::{now_timestamp, Session};
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use std::collections::HashMap;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    const TEST_KEY: [u8; 32] = [0x42; 32];
    const MOCK_NONCE: &str = "test-nonce-123";

    // --- RSA key generation for mock JWT signing ---

    struct TestKeys {
        encoding_key: jsonwebtoken::EncodingKey,
        n: String,
        e: String,
        kid: String,
    }

    fn generate_test_keys() -> TestKeys {
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPrivateKey;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();

        TestKeys {
            encoding_key,
            n,
            e,
            kid: "test-key-1".into(),
        }
    }

    // --- Mock Keycloak server ---

    #[derive(Clone)]
    struct MockKeycloakState {
        encoding_key: jsonwebtoken::EncodingKey,
        jwks_n: String,
        jwks_e: String,
        kid: String,
        issuer: String,
    }

    async fn mock_discovery(
        State(st): State<Arc<MockKeycloakState>>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "issuer": st.issuer,
            "authorization_endpoint": format!("{}/authorize", st.issuer),
            "token_endpoint": format!("{}/token", st.issuer),
            "jwks_uri": format!("{}/jwks", st.issuer),
            "end_session_endpoint": format!("{}/end-session", st.issuer),
        }))
    }

    async fn mock_jwks(State(st): State<Arc<MockKeycloakState>>) -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "keys": [{
                "kid": st.kid,
                "kty": "RSA",
                "alg": "RS256",
                "n": st.jwks_n,
                "e": st.jwks_e,
            }]
        }))
    }

    async fn mock_token(State(st): State<Arc<MockKeycloakState>>, headers: HeaderMap) -> Response {
        if let Some(value) = headers.get(header::AUTHORIZATION) {
            let expected = format!("Basic {}", STANDARD.encode("vector:test-machine-secret"));
            if value.to_str().ok() != Some(expected.as_str()) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
        let now = now_timestamp();
        let claims = serde_json::json!({
            "iss": st.issuer,
            "sub": "test-user-id",
            "aud": "test-client",
            "exp": now + 3600,
            "iat": now,
            "preferred_username": "testuser",
            "email": "test@example.com",
            "groups": ["admins", "developers"],
            "nonce": MOCK_NONCE,
        });

        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(st.kid.clone()),
            ..Default::default()
        };
        let id_token = jsonwebtoken::encode(&header, &claims, &st.encoding_key).unwrap();

        axum::Json(serde_json::json!({
            "id_token": id_token,
            "access_token": "mock-access-token",
            "refresh_token": "mock-new-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_expires_in": 86400,
        }))
        .into_response()
    }

    async fn start_mock_keycloak(keys: &TestKeys) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());

        let mock_state = Arc::new(MockKeycloakState {
            encoding_key: keys.encoding_key.clone(),
            jwks_n: keys.n.clone(),
            jwks_e: keys.e.clone(),
            kid: keys.kid.clone(),
            issuer: issuer.clone(),
        });

        let mock_app = Router::new()
            .route("/.well-known/openid-configuration", get(mock_discovery))
            .route("/jwks", get(mock_jwks))
            .route("/token", post(mock_token))
            .with_state(mock_state);

        tokio::spawn(async move {
            axum::serve(listener, mock_app).await.unwrap();
        });

        issuer
    }

    // --- Test environment ---

    async fn setup() -> (Router, Arc<AppState>) {
        let keys = generate_test_keys();
        let issuer = start_mock_keycloak(&keys).await;

        let config = Config {
            listen: "127.0.0.1:0".into(),
            oidc_issuer: issuer.clone(),
            client_id: "test-client".into(),
            client_secret: "test-secret".into(),
            cookie_secret: TEST_KEY,
            cookie_domain: ".example.com".into(),
            routes_file: "/dev/null".into(),
            callback_url: "http://auth.example.com/callback".into(),
            log_level: "debug".into(),
        };

        let oidc = OidcClient::discover(
            &config.oidc_issuer,
            config.client_id.clone(),
            config.client_secret.clone(),
            config.callback_url.clone(),
        )
        .await
        .unwrap();

        let mut routes = HashMap::new();
        routes.insert(
            "grafana.example.com".into(),
            RouteConfig {
                allowed_groups: vec!["admins".into(), "developers".into()],
                browser_access: true,
                machine_access: None,
            },
        );
        routes.insert(
            "wiki.example.com".into(),
            RouteConfig {
                allowed_groups: vec![],
                browser_access: true,
                machine_access: None,
            },
        );
        routes.insert(
            "loki.example.com".into(),
            RouteConfig {
                allowed_groups: vec![],
                browser_access: false,
                machine_access: Some(MachineAccess {
                    client_ids: vec!["vector".into()],
                    method: "POST".into(),
                    path: "/loki/api/v1/push".into(),
                }),
            },
        );

        let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .unwrap_or_else(|_| {
                // Recorder already installed by another test — get a dummy handle
                metrics_exporter_prometheus::PrometheusBuilder::new()
                    .build_recorder()
                    .handle()
            });

        let state = Arc::new(AppState {
            config,
            oidc,
            routes: Arc::new(RwLock::new(routes)),
            crypto: CookieCrypto::new(&TEST_KEY),
            metrics_handle,
            machine_cache: RwLock::new(HashMap::new()),
        });

        let app = Router::new()
            .route("/auth", get(auth))
            .route("/callback", get(callback))
            .route("/refresh", get(refresh))
            .route("/sign_out", get(sign_out))
            .route("/health", get(health))
            .route("/metrics", get(metrics_handler))
            .with_state(state.clone());

        (app, state)
    }

    fn make_cookie(crypto: &CookieCrypto, session: &Session) -> String {
        let encrypted = session.encrypt(crypto).unwrap();
        format!("{}={}", COOKIE_NAME, encrypted)
    }

    fn active_session() -> Session {
        Session {
            sub: "test-user-id".into(),
            username: "testuser".into(),
            email: "test@example.com".into(),
            groups: vec!["admins".into(), "developers".into()],
            exp: now_timestamp() + 3600,
            iat: now_timestamp(),
            refresh_token: Some("mock-refresh-token".into()),
        }
    }

    // --- Unit tests ---

    #[test]
    fn pkce_challenge_matches_verifier() {
        let (verifier, challenge) = generate_pkce();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        assert_eq!(verifier.len(), 43); // 32 bytes → 43 base64url chars
    }

    #[test]
    fn state_encrypt_decrypt_roundtrip() {
        let crypto = CookieCrypto::new(&TEST_KEY);
        let original = AuthStatePayload {
            original_url: "https://example.com/path?q=1".into(),
            pkce_verifier: "verifier123".into(),
            nonce: "nonce456".into(),
        };
        let encrypted = encrypt_state(&crypto, &original).unwrap();
        let restored: AuthStatePayload = decrypt_state(&crypto, &encrypted).unwrap();
        assert_eq!(restored.original_url, original.original_url);
        assert_eq!(restored.pkce_verifier, original.pkce_verifier);
        assert_eq!(restored.nonce, original.nonce);
    }

    #[test]
    fn cookie_parsing() {
        let crypto = CookieCrypto::new(&TEST_KEY);
        let session = active_session();
        let cookie_val = make_cookie(&crypto, &session);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("other=abc; {}", cookie_val).parse().unwrap(),
        );

        let restored = extract_session_from_headers(&headers, &crypto).unwrap();
        assert_eq!(restored.sub, "test-user-id");
        assert_eq!(restored.username, "testuser");
    }

    #[test]
    fn cookie_parsing_missing_cookie() {
        let crypto = CookieCrypto::new(&TEST_KEY);
        let headers = HeaderMap::new();
        assert!(extract_session_from_headers(&headers, &crypto).is_none());
    }

    #[test]
    fn cookie_parsing_wrong_key() {
        let crypto1 = CookieCrypto::new(&[0x42; 32]);
        let crypto2 = CookieCrypto::new(&[0x99; 32]);
        let cookie_val = make_cookie(&crypto1, &active_session());

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie_val.parse().unwrap());

        assert!(extract_session_from_headers(&headers, &crypto2).is_none());
    }

    // --- Integration tests ---

    #[tokio::test]
    async fn health_returns_200() {
        let (app, _) = setup().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_no_session_redirects_to_keycloak() {
        let (app, _) = setup().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "grafana.example.com")
                    .header("x-forwarded-uri", "/d/dashboard")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.contains("/authorize"),
            "should redirect to OIDC authorize"
        );
        assert!(location.contains("client_id=test-client"));
        assert!(location.contains("code_challenge="));
        assert!(location.contains("code_challenge_method=S256"));
        assert!(location.contains("nonce="));
        assert!(location.contains("state="));
    }

    #[tokio::test]
    async fn auth_valid_session_returns_200_with_headers() {
        let (app, state) = setup().await;
        let cookie = make_cookie(&state.crypto, &active_session());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "grafana.example.com")
                    .header("x-forwarded-uri", "/")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-auth-request-user").unwrap(),
            "testuser"
        );
        assert_eq!(
            resp.headers().get("x-auth-request-email").unwrap(),
            "test@example.com"
        );
        let groups = resp
            .headers()
            .get("x-auth-request-groups")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(groups.contains("admins"));
        assert!(groups.contains("developers"));
    }

    #[tokio::test]
    async fn auth_any_authenticated_user_for_empty_groups() {
        let (app, state) = setup().await;
        let mut session = active_session();
        session.groups = vec!["random-group".into()];
        let cookie = make_cookie(&state.crypto, &session);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "wiki.example.com")
                    .header("x-forwarded-uri", "/")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_host_not_in_routes_returns_403() {
        let (app, state) = setup().await;
        let cookie = make_cookie(&state.crypto, &active_session());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "unknown.example.com")
                    .header("x-forwarded-uri", "/")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn auth_wrong_group_returns_403() {
        let (app, state) = setup().await;
        let mut session = active_session();
        session.groups = vec!["viewers".into()];
        let cookie = make_cookie(&state.crypto, &session);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "grafana.example.com")
                    .header("x-forwarded-uri", "/")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn auth_expired_with_refresh_redirects_to_refresh_endpoint() {
        let (app, state) = setup().await;
        let mut session = active_session();
        session.exp = now_timestamp() - 10;
        let cookie = make_cookie(&state.crypto, &session);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "grafana.example.com")
                    .header("x-forwarded-uri", "/dashboard")
                    .header("x-forwarded-proto", "https")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.contains("/refresh"),
            "should redirect to /refresh, got: {}",
            location
        );
    }

    #[tokio::test]
    async fn auth_expired_without_refresh_redirects_to_keycloak() {
        let (app, state) = setup().await;
        let mut session = active_session();
        session.exp = now_timestamp() - 10;
        session.refresh_token = None;
        let cookie = make_cookie(&state.crypto, &session);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "grafana.example.com")
                    .header("x-forwarded-uri", "/")
                    .header("x-forwarded-proto", "https")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.contains("/authorize"),
            "should redirect to Keycloak, got: {}",
            location
        );
    }

    #[tokio::test]
    async fn auth_missing_forwarded_host_returns_400() {
        let (app, _) = setup().await;
        let resp = app
            .oneshot(Request::builder().uri("/auth").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    async fn machine_request(
        app: Router,
        host: &str,
        method: &str,
        path: &str,
        secret: &str,
    ) -> StatusCode {
        let credentials = STANDARD.encode(format!("vector:{secret}"));
        app.oneshot(
            Request::builder()
                .uri("/auth")
                .header("x-forwarded-host", host)
                .header("x-forwarded-method", method)
                .header("x-forwarded-uri", path)
                .header(header::AUTHORIZATION, format!("Basic {credentials}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[tokio::test]
    async fn machine_credentials_are_limited_to_route_and_method() {
        let (app, _) = setup().await;
        assert_eq!(
            machine_request(
                app.clone(),
                "loki.example.com",
                "POST",
                "/loki/api/v1/push",
                "test-machine-secret"
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            machine_request(
                app.clone(),
                "loki.example.com",
                "POST",
                "/loki/api/v1/push",
                "wrong"
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            machine_request(
                app.clone(),
                "loki.example.com",
                "GET",
                "/loki/api/v1/push",
                "test-machine-secret"
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            machine_request(
                app.clone(),
                "loki.example.com",
                "POST",
                "/loki/api/v1/query",
                "test-machine-secret"
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            machine_request(
                app.clone(),
                "grafana.example.com",
                "POST",
                "/loki/api/v1/push",
                "test-machine-secret"
            )
            .await,
            StatusCode::FOUND
        );

        let no_credentials = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header("x-forwarded-host", "loki.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_credentials.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn callback_exchanges_code_and_sets_cookie() {
        let (app, state) = setup().await;

        let auth_state = AuthStatePayload {
            original_url: "https://grafana.example.com/dashboard".into(),
            pkce_verifier: "test-verifier-01234567890123456789012".into(),
            nonce: MOCK_NONCE.into(),
        };
        let encrypted_state = encrypt_state(&state.crypto, &auth_state).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!(
                        "/callback?code=mock-auth-code&state={}",
                        encrypted_state
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "https://grafana.example.com/dashboard"
        );

        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.starts_with("_auth_proxy_session="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Domain=.example.com"));

        // Verify the cookie contains a valid session
        let cookie_value = set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("_auth_proxy_session=")
            .unwrap();
        let session = Session::decrypt(&state.crypto, cookie_value).unwrap();
        assert_eq!(session.sub, "test-user-id");
        assert_eq!(session.username, "testuser");
        assert_eq!(session.email, "test@example.com");
        assert_eq!(session.groups, vec!["admins", "developers"]);
        assert!(session.refresh_token.is_some());
    }

    #[tokio::test]
    async fn callback_invalid_state_returns_400() {
        let (app, _) = setup().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/callback?code=abc&state=garbage-data")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn refresh_updates_session_and_redirects() {
        let (app, state) = setup().await;

        let mut session = active_session();
        session.exp = now_timestamp() - 10;
        let cookie = make_cookie(&state.crypto, &session);

        let refresh_state = RefreshStatePayload {
            original_url: "https://grafana.example.com/dashboard".into(),
        };
        let encrypted_state = encrypt_state(&state.crypto, &refresh_state).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/refresh?state={}", encrypted_state))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "https://grafana.example.com/dashboard"
        );

        // New cookie should be set
        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        let cookie_value = set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("_auth_proxy_session=")
            .unwrap();
        let new_session = Session::decrypt(&state.crypto, cookie_value).unwrap();
        assert!(!new_session.is_access_expired());
        assert!(new_session.refresh_token.is_some());
    }

    #[tokio::test]
    async fn refresh_without_cookie_redirects_to_login() {
        let (app, state) = setup().await;

        let refresh_state = RefreshStatePayload {
            original_url: "https://grafana.example.com/".into(),
        };
        let encrypted_state = encrypt_state(&state.crypto, &refresh_state).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/refresh?state={}", encrypted_state))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("/authorize"));
    }

    #[tokio::test]
    async fn sign_out_clears_cookie_and_redirects() {
        let (app, _) = setup().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/sign_out")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);

        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("Max-Age=0"), "cookie should be expired");

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.contains("/end-session"),
            "should redirect to OIDC end_session"
        );
    }
}
