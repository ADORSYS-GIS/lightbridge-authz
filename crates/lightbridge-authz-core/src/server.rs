use crate::config::Tls;
use crate::error::{Error, Result};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::net::SocketAddr;
use std::sync::{Arc, Once};

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
    let rustls_config = match &tls.client_ca_bundle_path {
        Some(client_ca_bundle_path) => build_mtls_config(name, tls, client_ca_bundle_path)?,
        None => RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
            .await
            .map_err(|e| Error::Server(format!("Failed to load TLS config for {name}: {e}")))?,
    };

    tracing::info!("Starting {name} server with TLS on {}", addr);
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::Server(format!("Failed to start {name} server: {e}")))?;

    Ok(())
}

/// Builds a `rustls::ServerConfig` that requires and verifies a client certificate against
/// `client_ca_bundle_path` (mTLS, #347), then wraps it for `axum-server`. Every failure here —
/// an unreadable file, a bundle with no parseable PEM certificates, or a verifier/config that
/// fails to build — is a hard startup error naming the offending path: per this codebase's
/// fail-closed rule, a misconfigured trust anchor must refuse to start, never silently fall back
/// to `with_no_client_auth`.
///
/// `WebPkiClientVerifier::builder` without `allow_unauthenticated()` is fail-closed by
/// construction: a connection presenting no certificate, an expired one, or one not signed by a
/// CA in `client_ca_bundle_path` is rejected at the TLS handshake, before any application code
/// (including this router's own auth middleware) ever runs.
fn build_mtls_config(name: &str, tls: &Tls, client_ca_bundle_path: &str) -> Result<RustlsConfig> {
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&tls.cert_path)
        .map_err(|e| {
            Error::Server(format!(
                "Failed to read TLS cert for {name} at '{}': {e}",
                tls.cert_path
            ))
        })?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| {
            Error::Server(format!(
                "Failed to parse TLS cert for {name} at '{}': {e}",
                tls.cert_path
            ))
        })?;
    let key = PrivateKeyDer::from_pem_file(&tls.key_path).map_err(|e| {
        Error::Server(format!(
            "Failed to read/parse TLS key for {name} at '{}': {e}",
            tls.key_path
        ))
    })?;

    let ca_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(client_ca_bundle_path)
            .map_err(|e| {
                Error::Server(format!(
                    "Failed to read client-CA bundle for {name} at '{client_ca_bundle_path}': {e}"
                ))
            })?
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| {
                Error::Server(format!(
                    "Failed to parse client-CA bundle for {name} at '{client_ca_bundle_path}': {e}"
                ))
            })?;
    if ca_certs.is_empty() {
        return Err(Error::Server(format!(
            "client-CA bundle for {name} at '{client_ca_bundle_path}' contains no PEM certificates"
        )));
    }

    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert).map_err(|e| {
            Error::Server(format!(
                "Failed to add client-CA cert for {name} from '{client_ca_bundle_path}' to trust store: {e}"
            ))
        })?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| {
            Error::Server(format!(
                "Failed to build client-cert verifier for {name} from '{client_ca_bundle_path}': {e}"
            ))
        })?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| {
            Error::Server(format!(
                "Failed to build mTLS server config for {name}: {e}"
            ))
        })?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}
