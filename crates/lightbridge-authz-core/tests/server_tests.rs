#![cfg(feature = "axum")]

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use lightbridge_authz_core::server::{env_flag_enabled, serve_plain_http};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

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
