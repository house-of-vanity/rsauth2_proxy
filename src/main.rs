mod config;
mod crypto;
mod handlers;
mod oidc;
mod routes;
mod session;

use crate::config::Config;
use crate::crypto::CookieCrypto;
use crate::handlers::AppState;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tokio::sync::RwLock;

const HELP: &str = "\
rsauth2-proxy — Auth proxy for Traefik ForwardAuth with Keycloak OIDC

USAGE:
    rsauth2-proxy              Start the proxy (configured via environment variables)
    rsauth2-proxy --help       Show this help
    rsauth2-proxy --version    Show version

ENVIRONMENT VARIABLES:
    AUTH_PROXY_OIDC_ISSUER      (required)  OIDC issuer URL
                                            Example: https://auth.example.com/realms/main
    AUTH_PROXY_CLIENT_ID        (required)  Keycloak client ID
    AUTH_PROXY_CLIENT_SECRET    (required)  Keycloak client secret
    AUTH_PROXY_COOKIE_SECRET    (required)  AES-256 encryption key, 32 bytes, base64-encoded
                                            Generate with: openssl rand -base64 32
    AUTH_PROXY_COOKIE_DOMAIN    (required)  Cookie domain, must cover all protected hosts
                                            Example: .example.com
    AUTH_PROXY_CALLBACK_URL     (required)  Full public URL for the OIDC callback endpoint
                                            Example: https://auth-proxy.example.com/callback
    AUTH_PROXY_LISTEN           (optional)  Listen address [default: 0.0.0.0:8080]
    AUTH_PROXY_ROUTES_FILE      (optional)  Path to routes config [default: /config/routes.yaml]
    AUTH_PROXY_LOG_LEVEL        (optional)  Log level: debug, info, warn, error [default: info]

ENDPOINTS:
    GET /auth       ForwardAuth endpoint (called by Traefik for every request)
    GET /callback   OIDC callback (receives authorization code from Keycloak)
    GET /refresh    Token refresh (transparent redirect when access token expires)
    GET /sign_out   Logout (clears cookie, redirects to Keycloak end_session)
    GET /health     Health check (returns 200 OK)
    GET /metrics    Prometheus metrics (text exposition format)

ROUTES FILE (routes.yaml):
    routes:
      grafana.example.com:
        allowed_groups: [\"admins\", \"developers\"]   # user must be in at least one group
      wiki.example.com:
        allowed_groups: []                            # any authenticated user
      # Hosts not listed are denied (403)

    The file is polled every 5 seconds and reloaded on change.
    Works with Kubernetes ConfigMap volume mounts (symlink-based updates).

RESPONSE HEADERS (forwarded to upstream on 200):
    X-Auth-Request-User      preferred_username from the ID token
    X-Auth-Request-Email     email from the ID token
    X-Auth-Request-Groups    comma-separated list of groups

KEYCLOAK SETUP:
    Groups must be included in the ID token via a \"Group Membership\" protocol mapper
    with claim name \"groups\" and full path disabled.

TRAEFIK MIDDLEWARE:
    apiVersion: traefik.io/v1alpha1
    kind: Middleware
    metadata:
      name: auth-proxy
    spec:
      forwardAuth:
        address: http://auth-proxy.auth-proxy.svc:80/auth
        trustForwardHeader: true
        authResponseHeaders:
          - X-Auth-Request-User
          - X-Auth-Request-Email
          - X-Auth-Request-Groups

SECURITY:
    - Sessions encrypted with AES-256-GCM (not just signed)
    - PKCE S256 on all authorization flows
    - JWT validated against Keycloak JWKS (keys refreshed hourly)
    - No open redirects (redirect URL encrypted in state parameter)
    - Deny by default (unlisted hosts get 403)
    - Fully stateless (all state in encrypted cookies), supports multiple replicas
    - Graceful shutdown on SIGTERM/SIGINT

SOURCE: https://github.com/ab/rsauth2-proxy";

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", HELP);
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("rsauth2-proxy {}", VERSION);
        return Ok(());
    }

    let config = Config::from_env()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&config.log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install prometheus recorder");

    metrics::describe_counter!("auth_requests_total", "Total auth check requests");
    metrics::describe_histogram!(
        "auth_request_duration_seconds",
        "Auth check request duration in seconds"
    );
    metrics::describe_counter!("callback_requests_total", "Total OIDC callback requests");
    metrics::describe_counter!("refresh_requests_total", "Total token refresh requests");
    metrics::describe_gauge!("routes_loaded_total", "Number of loaded routes");

    tracing::info!(listen = %config.listen, "starting rsauth2-proxy");

    let oidc = oidc::OidcClient::discover(
        &config.oidc_issuer,
        config.client_id.clone(),
        config.client_secret.clone(),
        config.callback_url.clone(),
    )
    .await?;

    let initial_routes = routes::load_routes(&config.routes_file)?;
    let shared_routes: routes::SharedRoutes = Arc::new(RwLock::new(initial_routes));

    let crypto = CookieCrypto::new(&config.cookie_secret);

    let state = Arc::new(AppState {
        config: config.clone(),
        oidc,
        routes: shared_routes.clone(),
        crypto,
        metrics_handle,
        machine_cache: RwLock::new(std::collections::HashMap::new()),
    });

    // Background: watch routes file for changes
    let routes_path = config.routes_file.clone();
    let routes_ref = shared_routes.clone();
    tokio::spawn(async move {
        routes::watch_routes(routes_path, routes_ref).await;
    });

    // Background: periodically refresh JWKS keys
    let oidc_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = oidc_state.oidc.refresh_jwks().await {
                tracing::warn!(error = %e, "failed to refresh JWKS");
            }
        }
    });

    let app = Router::new()
        .route("/", get(handlers::root))
        .route("/auth", get(handlers::auth))
        .route("/callback", get(handlers::callback))
        .route("/refresh", get(handlers::refresh))
        .route("/sign_out", get(handlers::sign_out))
        .route("/health", get(handlers::health))
        .route("/metrics", get(handlers::metrics_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    tracing::info!(addr = %config.listen, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm.recv() => {},
    }
    tracing::info!("shutdown signal received");
}
