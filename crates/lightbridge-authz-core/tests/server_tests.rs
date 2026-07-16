#![cfg(feature = "axum")]

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use lightbridge_authz_core::config::Tls;
use lightbridge_authz_core::server::{
    dev_cors_enabled, env_flag_enabled, insecure_http_enabled, serve_plain_http, serve_tls,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use tokio::sync::Mutex;

static ENV_VAR_GUARD: Mutex<()> = Mutex::const_new(());

#[test]
fn env_flag_enabled_accepts_truthy_values() {
    for value in ["1", "true", "TRUE", " yes ", "on", "On"] {
        assert!(
            env_flag_enabled(Some(value)),
            "{value:?} should enable the flag"
        );
    }
}

#[test]
fn env_flag_enabled_rejects_falsy_and_unset_values() {
    for value in [Some("0"), Some("false"), Some(""), Some("off"), None] {
        assert!(
            !env_flag_enabled(value),
            "{value:?} should not enable the flag"
        );
    }
}

fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port should be reservable")
        .local_addr()
        .expect("listener should report its address")
        .port()
}

fn fetch_healthz_plaintext(port: u16) -> String {
    let mut last_error = None;
    for _ in 0..100 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout should be settable");
                stream
                    .write_all(
                        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .expect("request should be writable");
                let mut response = String::new();
                stream
                    .read_to_string(&mut response)
                    .expect("response should be readable");
                return response;
            }
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    panic!("server never accepted a connection: {last_error:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_plain_http_serves_requests_without_tls() {
    let port = reserve_port();
    let app = Router::new().route("/healthz", get(|| async { StatusCode::OK }));
    let server =
        tokio::spawn(async move { serve_plain_http("TEST", "127.0.0.1", port, app).await });

    let response = tokio::task::spawn_blocking(move || fetch_healthz_plaintext(port))
        .await
        .expect("plaintext fetch should not panic");

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected a plaintext 200 response, got: {response}"
    );
    server.abort();
}

#[tokio::test]
async fn insecure_http_enabled_reflects_env_var() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }
    assert!(!insecure_http_enabled());

    unsafe {
        std::env::set_var("AUTHZ_INSECURE_HTTP", "1");
    }
    assert!(insecure_http_enabled());

    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }
}

#[tokio::test]
async fn dev_cors_enabled_reflects_env_var() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_DEV_CORS");
    }
    assert!(!dev_cors_enabled());

    unsafe {
        std::env::set_var("AUTHZ_DEV_CORS", "true");
    }
    assert!(dev_cors_enabled());

    unsafe {
        std::env::remove_var("AUTHZ_DEV_CORS");
    }
}

#[tokio::test]
async fn serve_plain_http_reports_bind_failure_as_server_error() {
    let port = reserve_port();
    let _busy_listener =
        TcpListener::bind(("127.0.0.1", port)).expect("port should be reservable for the test");

    let app = Router::new();
    let result = serve_plain_http("TEST", "127.0.0.1", port, app).await;

    let err = result.expect_err("binding an already-occupied port should fail");
    assert!(
        err.to_string().contains("Failed to start TEST server"),
        "unexpected error message: {err}"
    );
}

#[tokio::test]
async fn serve_tls_delegates_to_plain_http_when_insecure_http_is_enabled() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::set_var("AUTHZ_INSECURE_HTTP", "1");
    }

    let port = reserve_port();
    let app = Router::new().route("/healthz", get(|| async { StatusCode::OK }));
    let tls = Tls {
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
    };
    let server = tokio::spawn(async move { serve_tls("TEST", "127.0.0.1", port, &tls, app).await });

    let response = tokio::task::spawn_blocking(move || fetch_healthz_plaintext(port))
        .await
        .expect("plaintext fetch should not panic");

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected a plaintext 200 response, got: {response}"
    );
    server.abort();

    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }
}

#[tokio::test]
async fn serve_tls_reports_missing_cert_files_as_server_error() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }

    let port = reserve_port();
    let app = Router::new();
    let tls = Tls {
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
    };

    let result = serve_tls("TEST", "127.0.0.1", port, &tls, app).await;

    let err = result.expect_err("missing TLS cert/key files should fail to load");
    assert!(
        err.to_string().contains("Failed to load TLS config"),
        "unexpected error message: {err}"
    );
}

fn generate_self_signed_cert(
    dir: &std::path::Path,
) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let output = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path.to_str().expect("path should be valid utf-8"),
            "-out",
            cert_path.to_str().expect("path should be valid utf-8"),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .output();

    match output {
        Ok(output) if output.status.success() => Some((cert_path, key_path)),
        _ => None,
    }
}

#[tokio::test]
async fn serve_tls_starts_listening_with_a_valid_certificate() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }

    let dir = std::env::temp_dir().join(format!(
        "lightbridge-authz-core-tls-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be creatable");

    let Some((cert_path, key_path)) = generate_self_signed_cert(&dir) else {
        eprintln!(
            "skipping serve_tls_starts_listening_with_a_valid_certificate: openssl CLI unavailable"
        );
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };

    let port = reserve_port();
    let app = Router::new().route("/healthz", get(|| async { StatusCode::OK }));
    let tls = Tls {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
    };
    let server = tokio::spawn(async move { serve_tls("TEST", "127.0.0.1", port, &tls, app).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server.is_finished(),
        "a valid TLS listener should stay up serving connections"
    );
    server.abort();

    let _ = std::fs::remove_dir_all(&dir);
}
