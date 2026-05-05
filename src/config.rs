use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub oidc_issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub cookie_secret: [u8; 32],
    pub cookie_domain: String,
    pub routes_file: String,
    pub callback_url: String,
    pub log_level: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let cookie_secret_b64 =
            std::env::var("AUTH_PROXY_COOKIE_SECRET").context("AUTH_PROXY_COOKIE_SECRET required")?;
        let decoded = STANDARD
            .decode(&cookie_secret_b64)
            .context("invalid base64 in AUTH_PROXY_COOKIE_SECRET")?;
        let cookie_secret: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("cookie secret must be 32 bytes, got {}", v.len()))?;

        Ok(Self {
            listen: std::env::var("AUTH_PROXY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            oidc_issuer: std::env::var("AUTH_PROXY_OIDC_ISSUER")
                .context("AUTH_PROXY_OIDC_ISSUER required")?,
            client_id: std::env::var("AUTH_PROXY_CLIENT_ID")
                .context("AUTH_PROXY_CLIENT_ID required")?,
            client_secret: std::env::var("AUTH_PROXY_CLIENT_SECRET")
                .context("AUTH_PROXY_CLIENT_SECRET required")?,
            cookie_secret,
            cookie_domain: std::env::var("AUTH_PROXY_COOKIE_DOMAIN")
                .context("AUTH_PROXY_COOKIE_DOMAIN required")?,
            routes_file: std::env::var("AUTH_PROXY_ROUTES_FILE")
                .unwrap_or_else(|_| "/config/routes.yaml".into()),
            callback_url: std::env::var("AUTH_PROXY_CALLBACK_URL")
                .context("AUTH_PROXY_CALLBACK_URL required")?,
            log_level: std::env::var("AUTH_PROXY_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        })
    }

    pub fn base_url(&self) -> &str {
        self.callback_url
            .strip_suffix("/callback")
            .unwrap_or(&self.callback_url)
    }
}
