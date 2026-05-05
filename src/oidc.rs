use anyhow::{Context, Result};
use jsonwebtoken::{decode, decode_header, DecodingKey, TokenData, Validation};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: Option<String>,
}

#[derive(Deserialize, Clone)]
#[allow(dead_code)]
pub struct JwkKey {
    pub kid: Option<String>,
    pub kty: String,
    pub n: Option<String>,
    pub e: Option<String>,
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub refresh_expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct IdTokenClaims {
    pub sub: String,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub groups: Option<Vec<String>>,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
}

pub struct OidcClient {
    http: Client,
    pub discovery: OidcDiscovery,
    jwks: Arc<RwLock<Vec<JwkKey>>>,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

impl OidcClient {
    pub async fn discover(
        issuer: &str,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Result<Self> {
        let http = Client::new();
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscovery = http
            .get(&discovery_url)
            .send()
            .await?
            .error_for_status()
            .context("OIDC discovery request failed")?
            .json()
            .await
            .context("failed to parse OIDC discovery")?;

        let jwks: JwksResponse = http
            .get(&discovery.jwks_uri)
            .send()
            .await?
            .error_for_status()
            .context("JWKS request failed")?
            .json()
            .await
            .context("failed to parse JWKS")?;

        tracing::info!(
            keys = jwks.keys.len(),
            "OIDC discovery complete"
        );

        Ok(Self {
            http,
            discovery,
            jwks: Arc::new(RwLock::new(jwks.keys)),
            client_id,
            client_secret,
            redirect_uri,
        })
    }

    pub fn auth_url(&self, state: &str, pkce_challenge: &str, nonce: &str) -> String {
        let mut url = url::Url::parse(&self.discovery.authorization_endpoint)
            .expect("valid authorization_endpoint URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email")
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        url.to_string()
    }

    pub async fn exchange_code(&self, code: &str, pkce_verifier: &str) -> Result<TokenResponse> {
        let resp = self
            .http
            .post(&self.discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("token exchange failed ({}): {}", status, body);
        }

        Ok(resp.json().await?)
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let resp = self
            .http
            .post(&self.discovery.token_endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("token refresh failed ({}): {}", status, body);
        }

        Ok(resp.json().await?)
    }

    pub async fn validate_id_token(
        &self,
        token: &str,
        expected_nonce: Option<&str>,
    ) -> Result<IdTokenClaims> {
        let header = decode_header(token)?;
        let kid = header.kid.as_deref();

        let jwks = self.jwks.read().await;
        let key = if let Some(kid) = kid {
            jwks.iter().find(|k| k.kid.as_deref() == Some(kid))
        } else {
            jwks.first()
        }
        .context("no matching JWK found")?;

        let decoding_key = DecodingKey::from_rsa_components(
            key.n.as_deref().context("missing 'n' in JWK")?,
            key.e.as_deref().context("missing 'e' in JWK")?,
        )?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.discovery.issuer]);
        validation.set_audience(&[&self.client_id]);

        let token_data: TokenData<IdTokenClaims> = decode(token, &decoding_key, &validation)?;

        if let Some(expected) = expected_nonce {
            if token_data.claims.nonce.as_deref() != Some(expected) {
                anyhow::bail!("nonce mismatch");
            }
        }

        Ok(token_data.claims)
    }

    pub async fn refresh_jwks(&self) -> Result<()> {
        let jwks: JwksResponse = self
            .http
            .get(&self.discovery.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let count = jwks.keys.len();
        *self.jwks.write().await = jwks.keys;
        tracing::debug!(keys = count, "JWKS refreshed");
        Ok(())
    }

    pub fn end_session_url(&self) -> Option<&str> {
        self.discovery.end_session_endpoint.as_deref()
    }
}
