use crate::config::Tls;
use crate::error::{Error, Result};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Once;

const INSECURE_HTTP_ENV: &str = "AUTHZ_INSECURE_HTTP";
const DEV_CORS_ENV: &str = "AUTHZ_DEV_CORS";

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Interprets a dev-mode toggle value: `1`, `true`, `yes`, and `on` (case-insensitive,
/// whitespace-trimmed) enable it; anything else — including unset — leaves it off.
pub fn env_flag_enabled(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// True when `AUTHZ_INSECURE_HTTP` asks servers to skip TLS and serve plaintext HTTP.
/// Local-dev escape hatch only — never set this in production.
pub fn insecure_http_enabled() -> bool {
    env_flag_enabled(std::env::var(INSECURE_HTTP_ENV).ok().as_deref())
}

/// True when `AUTHZ_DEV_CORS` asks servers to layer a wide-open CORS policy so browser
/// SPAs on other origins can call them. Local-dev escape hatch only.
pub fn dev_cors_enabled() -> bool {
    env_flag_enabled(std::env::var(DEV_CORS_ENV).ok().as_deref())
}

/// Serves `app` over plaintext HTTP. `serve_tls` delegates here when
/// `AUTHZ_INSECURE_HTTP` is set; public so the plaintext path stays testable.
pub async fn serve_plain_http(name: &str, address: &str, port: u16, app: Router) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", address, port).parse()?;

    tracing::warn!(
        "Starting {name} server WITHOUT TLS on {addr} ({INSECURE_HTTP_ENV} is set — dev only)"
    );
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::Server(format!("Failed to start {name} server: {e}")))?;

    Ok(())
}

pub async fn serve_tls(name: &str, address: &str, port: u16, tls: &Tls, app: Router) -> Result<()> {
    if insecure_http_enabled() {
        return serve_plain_http(name, address, port, app).await;
    }

    ensure_rustls_provider();

    let addr: SocketAddr = format!("{}:{}", address, port).parse()?;
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
            .await
            .map_err(|e| Error::Server(format!("Failed to load TLS config for {name}: {e}")))?;

    tracing::info!("Starting {name} server with TLS on {}", addr);
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::Server(format!("Failed to start {name} server: {e}")))?;

    Ok(())
}
