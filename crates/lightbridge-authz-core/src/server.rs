use crate::config::Tls;
use crate::error::{Error, Result};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Once;

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn serve_tls(name: &str, address: &str, port: u16, tls: &Tls, app: Router) -> Result<()> {
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
