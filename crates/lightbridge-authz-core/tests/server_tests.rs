#![cfg(feature = "axum")]

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use lightbridge_authz_core::config::Tls;
use lightbridge_authz_core::server::{
    dev_cors_enabled, env_flag_enabled, insecure_http_enabled, serve_plain_http, serve_tls,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::Once;
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
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
        client_ca_bundle_path: None,
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
        client_ca_bundle_path: None,
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
        client_ca_bundle_path: None,
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

// mTLS (#347) -- `serve_tls`'s `Tls::client_ca_bundle_path` branch, exercised against a real
// TLS handshake via `reqwest` (never a mock), the same client-cert code path
// `UsageServiceSpendReader` uses in production against this exact server. Every CA/leaf keypair
// is generated fresh at test-run time with `rcgen`, never committed to the repo -- see
// `crates/lightbridge-authz-budget/tests/usage_service_ca_bundle_tests.rs`'s module doc comment
// for why (this repo's Gitleaks CI gate flags a committed private-key PEM regardless of it being
// a throwaway test key).

fn ensure_rustls_provider_for_test() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Returns the `Issuer` alongside the `Certificate` (rcgen 0.14's `signed_by` takes an
/// `&Issuer`, built from `CertificateParams` + signing key, not a bare `&Certificate`/`&KeyPair`
/// pair -- a `Certificate` alone does not expose the params needed to reconstruct one).
fn gen_ca(common_name: &str) -> (Certificate, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("ECDSA P-256 key generation must succeed");
    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is always valid");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params
        .self_signed(&key)
        .expect("self-signing a CA cert must succeed");
    let issuer = Issuer::new(params, key);
    (cert, issuer)
}

/// A `localhost`/`127.0.0.1` server leaf, `serverAuth` EKU, signed by `issuer`.
fn gen_server_leaf(issuer: &Issuer<'static, KeyPair>) -> (Certificate, KeyPair) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("ECDSA P-256 key generation must succeed");
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("a single DNS SAN is always valid");
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(31);
    let cert = params
        .signed_by(&key, issuer)
        .expect("signing a leaf cert with its issuer must succeed");
    (cert, key)
}

/// A client-identity leaf, `clientAuth` EKU, signed by `issuer` -- matches the
/// deployed `authz-tls` cert's actual shape (confirmed against the live cluster: `kubectl -n
/// converse get certificate authz-tls -o yaml` shows `usages: [server auth, client auth]` on one
/// shared cert), modeled here as its own leaf for test clarity.
fn gen_client_leaf(issuer: &Issuer<'static, KeyPair>) -> (Certificate, KeyPair) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("ECDSA P-256 key generation must succeed");
    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is always valid");
    params
        .distinguished_name
        .push(DnType::CommonName, "authz-api-test-client");
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(31);
    let cert = params
        .signed_by(&key, issuer)
        .expect("signing a leaf cert with its issuer must succeed");
    (cert, key)
}

fn write_temp_pem(pem: &str, label: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "lightbridge-authz-core-mtls-test-{label}-{}-{unique}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).expect("must write temp PEM file");
    path
}

/// Starts a real `serve_tls` listener requiring client certs signed by `ca_cert`/`ca_issuer`.
/// Returns the bound port and the background task's handle -- callers should `handle.abort()`.
async fn spawn_mtls_serve_tls(
    ca_cert: &Certificate,
    ca_issuer: &Issuer<'static, KeyPair>,
) -> (
    u16,
    tokio::task::JoinHandle<Result<(), lightbridge_authz_core::Error>>,
) {
    ensure_rustls_provider_for_test();

    let (server_leaf_cert, server_leaf_key) = gen_server_leaf(ca_issuer);
    let cert_path = write_temp_pem(&server_leaf_cert.pem(), "server-leaf-cert");
    let key_path = write_temp_pem(&server_leaf_key.serialize_pem(), "server-leaf-key");
    let ca_bundle_path = write_temp_pem(&ca_cert.pem(), "client-ca");

    let port = reserve_port();
    let app = Router::new().route("/healthz", get(|| async { StatusCode::OK }));
    let tls = Tls {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
        client_ca_bundle_path: Some(ca_bundle_path.to_string_lossy().to_string()),
    };
    let handle = tokio::spawn(async move {
        let result = serve_tls("TEST-MTLS", "127.0.0.1", port, &tls, app).await;
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&ca_bundle_path);
        result
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (port, handle)
}

/// Test (mandated by #347's acceptance criteria): a request presenting no client certificate is
/// rejected at the TLS layer once `client_ca_bundle_path` is set -- never reaches the router.
#[tokio::test]
async fn serve_tls_with_client_ca_bundle_rejects_a_connection_with_no_client_certificate() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }

    let (ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (port, server) = spawn_mtls_serve_tls(&ca_cert, &ca_issuer).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client without an identity must still build");

    let result = client
        .get(format!("https://127.0.0.1:{port}/healthz"))
        .send()
        .await;

    server.abort();
    assert!(
        result.is_err(),
        "a request with no client certificate must be rejected at the TLS handshake, not reach \
         the router"
    );
}

/// Test (mandated by #347's acceptance criteria): a client certificate signed by the configured
/// CA is accepted and the request reaches the router.
#[tokio::test]
async fn serve_tls_with_client_ca_bundle_accepts_a_certificate_signed_by_the_trusted_ca() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }

    let (ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (port, server) = spawn_mtls_serve_tls(&ca_cert, &ca_issuer).await;

    let (client_leaf_cert, client_leaf_key) = gen_client_leaf(&ca_issuer);
    let mut identity_pem = client_leaf_cert.pem().into_bytes();
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(client_leaf_key.serialize_pem().as_bytes());
    let identity =
        reqwest::Identity::from_pem(&identity_pem).expect("generated client identity must parse");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .build()
        .expect("client with a valid identity must build");

    let response = client
        .get(format!("https://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .expect("a CA-trusted client certificate must be accepted at the TLS handshake");

    server.abort();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the request must reach the router and succeed once the TLS handshake is accepted"
    );
}

/// Test (mandated by #347's acceptance criteria): a client certificate signed by an unrelated CA
/// is rejected, not silently accepted -- proves verification is real, not merely "any cert".
#[tokio::test]
async fn serve_tls_with_client_ca_bundle_rejects_a_certificate_from_an_untrusted_ca() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }

    let (ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (_other_ca_cert, other_ca_issuer) = gen_ca("unrelated-test-ca");
    let (port, server) = spawn_mtls_serve_tls(&ca_cert, &ca_issuer).await;

    let (client_leaf_cert, client_leaf_key) = gen_client_leaf(&other_ca_issuer);
    let mut identity_pem = client_leaf_cert.pem().into_bytes();
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(client_leaf_key.serialize_pem().as_bytes());
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .expect("generated client identity must parse even though its CA is untrusted");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .build()
        .expect("client with an identity must build");

    let result = client
        .get(format!("https://127.0.0.1:{port}/healthz"))
        .send()
        .await;

    server.abort();
    assert!(
        result.is_err(),
        "a client certificate signed by an unrelated CA must be rejected, never silently accepted"
    );
}

/// Regression: with `client_ca_bundle_path` unset (every server today except `authz-usage` once
/// #347 lands), a request presenting no client certificate still succeeds -- proves the mTLS
/// branch above did not change default behavior for every other listener.
#[tokio::test]
async fn serve_tls_without_client_ca_bundle_accepts_a_connection_with_no_client_certificate() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }
    ensure_rustls_provider_for_test();

    let dir = std::env::temp_dir().join(format!(
        "lightbridge-authz-core-no-mtls-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be creatable");
    let Some((cert_path, key_path)) = generate_self_signed_cert(&dir) else {
        eprintln!(
            "skipping serve_tls_without_client_ca_bundle_accepts_a_connection_with_no_client_certificate: openssl CLI unavailable"
        );
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };

    let port = reserve_port();
    let app = Router::new().route("/healthz", get(|| async { StatusCode::OK }));
    let tls = Tls {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
        client_ca_bundle_path: None,
    };
    let server = tokio::spawn(async move { serve_tls("TEST", "127.0.0.1", port, &tls, app).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client without an identity must build");

    let response = client
        .get(format!("https://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .expect("no client certificate is required when client_ca_bundle_path is unset");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(response.status(), StatusCode::OK);
}

/// Test (fail-closed construction, mirrors `UsageServiceClient::ca_bundle_path`'s client-side
/// convention): an unreadable `client_ca_bundle_path` is a hard startup error naming the path,
/// never a silent fallback to `with_no_client_auth`.
#[tokio::test]
async fn serve_tls_reports_unreadable_client_ca_bundle_as_server_error() {
    let _guard = ENV_VAR_GUARD.lock().await;
    unsafe {
        std::env::remove_var("AUTHZ_INSECURE_HTTP");
    }
    ensure_rustls_provider_for_test();

    let (_ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (server_leaf_cert, server_leaf_key) = gen_server_leaf(&ca_issuer);
    let cert_path = write_temp_pem(&server_leaf_cert.pem(), "server-leaf-cert");
    let key_path = write_temp_pem(&server_leaf_key.serialize_pem(), "server-leaf-key");

    let port = reserve_port();
    let app = Router::new();
    let tls = Tls {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
        client_ca_bundle_path: Some("/nonexistent/path/does-not-exist/ca.crt".to_string()),
    };

    let result = serve_tls("TEST", "127.0.0.1", port, &tls, app).await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let err = result.expect_err("an unreadable client-CA bundle must fail startup, not degrade");
    assert!(
        err.to_string()
            .contains("/nonexistent/path/does-not-exist/ca.crt"),
        "error must name the offending path, got: {err}"
    );
}
