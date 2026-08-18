//! Exercises `UsageServiceSpendReader::new`'s `client_cert_path`/`client_key_path` arguments
//! (#347, mTLS) against a *real* TLS handshake where the server requires and verifies a client
//! certificate -- `usage_service_ca_bundle_tests.rs` proves the client verifies the *server*'s
//! certificate; this file proves the reverse direction, the one #347 actually adds. The server
//! side here builds its own `rustls::ServerConfig` with a `WebPkiClientVerifier`, the same
//! mechanism `lightbridge_authz_core::server::serve_tls`'s `build_mtls_config` uses in
//! production, so this proves the client half of the exact TLS stack the real deployment runs.
//!
//! Every CA/leaf keypair is generated fresh at test-run time with `rcgen`, never committed to the
//! repo -- see `usage_service_ca_bundle_tests.rs`'s module doc comment for why (this repo's
//! Gitleaks CI gate flags a committed private-key PEM regardless of it being a throwaway test
//! key).

use axum::routing::post;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use lightbridge_authz_budget::{Period, Spend, SpendReader, UsageServiceSpendReader};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::server::WebPkiClientVerifier;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Once};
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn period() -> Period {
    Period::parse("2026-08").expect("valid period")
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
        "lightbridge-authz-budget-client-identity-{label}-{}-{unique}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).expect("must write temp PEM file");
    path
}

async fn spend_query_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "total_cost": 3.75 }))
}

/// Starts a real HTTPS server on an ephemeral loopback port that REQUIRES and verifies a client
/// certificate signed by `client_ca_cert`, presenting a `localhost`/`127.0.0.1`
/// leaf signed by `server_ca_issuer` for its own identity (kept independent from
/// the client-verification CA so a bug that conflated the two directions would be visible).
/// Returns the bound address and the background task's handle -- callers should `handle.abort()`.
async fn spawn_mtls_https_server(
    server_ca_issuer: &Issuer<'static, KeyPair>,
    client_ca_cert: &Certificate,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    ensure_rustls_provider();

    let (server_leaf_cert, server_leaf_key) = gen_server_leaf(server_ca_issuer);

    let mut roots = RootCertStore::empty();
    roots
        .add(
            rustls::pki_types::CertificateDer::pem_slice_iter(client_ca_cert.pem().as_bytes())
                .next()
                .expect("client CA PEM must contain a certificate")
                .expect("client CA PEM must parse"),
        )
        .expect("client CA must add to trust store");
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier must build");

    let cert_der: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(server_leaf_cert.pem().as_bytes())
            .collect::<Result<_, _>>()
            .expect("server leaf cert must parse");
    let key_der = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        server_leaf_key.serialize_pem().as_bytes(),
    )
    .expect("server leaf key must parse");

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_der, key_der)
        .expect("server config must build");

    let listener = TcpListener::bind("127.0.0.1:0").expect("must bind an ephemeral port");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local addr");
    listener
        .set_nonblocking(true)
        .expect("listener must support non-blocking mode");

    let config = RustlsConfig::from_config(Arc::new(server_config));
    let app = Router::new().route("/usage/v1/spend/query", post(spend_query_handler));

    let handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, config)
            .expect("must wrap the bound listener with the rustls acceptor")
            .serve(app.into_make_service())
            .await
            .expect("test mTLS server must not fail to serve");
    });

    (addr, handle)
}

/// Test (mandated by #347's acceptance criteria): a reader with no configured client identity is
/// rejected by a server that requires one, and that rejection resolves to `Spend::Unavailable`,
/// never `Err` and never `Spend::Known` -- the fail-closed contract this reader documents.
#[tokio::test]
async fn reader_with_no_client_identity_is_rejected_by_a_server_requiring_mtls() {
    let (_server_ca_cert, server_ca_issuer) = gen_ca("lightbridge-test-server-ca");
    let (client_ca_cert, _client_ca_issuer) = gen_ca("lightbridge-test-client-ca");
    let (addr, server) = spawn_mtls_https_server(&server_ca_issuer, &client_ca_cert).await;
    let base_url = format!("https://{addr}");

    let reader =
        UsageServiceSpendReader::new(base_url, true, None, None, None, Duration::from_secs(5))
            .expect("reader construction without a client identity must succeed");

    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("a TLS handshake failure must not surface as Err -- fail-closed contract");

    server.abort();
    assert_eq!(
        spend,
        Spend::Unavailable,
        "a server requiring a client certificate must reject a reader presenting none"
    );
}

/// Test (mandated by #347's acceptance criteria): a reader presenting a client certificate signed
/// by the CA the server trusts succeeds.
#[tokio::test]
async fn reader_with_a_certificate_signed_by_the_trusted_ca_succeeds() {
    let (_server_ca_cert, server_ca_issuer) = gen_ca("lightbridge-test-server-ca");
    let (client_ca_cert, client_ca_issuer) = gen_ca("lightbridge-test-client-ca");
    let (addr, server) = spawn_mtls_https_server(&server_ca_issuer, &client_ca_cert).await;
    let base_url = format!("https://{addr}");

    let (client_leaf_cert, client_leaf_key) = gen_client_leaf(&client_ca_issuer);
    let cert_path = write_temp_pem(&client_leaf_cert.pem(), "client-cert");
    let key_path = write_temp_pem(&client_leaf_key.serialize_pem(), "client-key");

    let reader = UsageServiceSpendReader::new(
        base_url,
        true,
        None,
        Some(cert_path.to_str().expect("temp path is valid UTF-8")),
        Some(key_path.to_str().expect("temp path is valid UTF-8")),
        Duration::from_secs(5),
    )
    .expect("reader construction with a valid client identity must succeed");

    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    server.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    assert_eq!(
        spend,
        Spend::Known(3_750_000),
        "a client certificate signed by the trusted CA must let the request through"
    );
}

/// Test (mandated by #347's acceptance criteria): a reader presenting a client certificate signed
/// by an UNRELATED CA is rejected, not silently accepted -- proves verification is real.
#[tokio::test]
async fn reader_with_a_certificate_from_an_untrusted_ca_is_rejected() {
    let (_server_ca_cert, server_ca_issuer) = gen_ca("lightbridge-test-server-ca");
    let (client_ca_cert, _client_ca_issuer) = gen_ca("lightbridge-test-client-ca");
    let (_other_ca_cert, other_ca_issuer) = gen_ca("unrelated-test-ca");
    let (addr, server) = spawn_mtls_https_server(&server_ca_issuer, &client_ca_cert).await;
    let base_url = format!("https://{addr}");

    let (client_leaf_cert, client_leaf_key) = gen_client_leaf(&other_ca_issuer);
    let cert_path = write_temp_pem(&client_leaf_cert.pem(), "wrong-ca-client-cert");
    let key_path = write_temp_pem(&client_leaf_key.serialize_pem(), "wrong-ca-client-key");

    let reader = UsageServiceSpendReader::new(
        base_url,
        true,
        None,
        Some(cert_path.to_str().expect("temp path is valid UTF-8")),
        Some(key_path.to_str().expect("temp path is valid UTF-8")),
        Duration::from_secs(5),
    )
    .expect("reader construction with a validly-formed (if wrong-CA) identity must succeed");

    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("a TLS verification failure must not surface as Err -- fail-closed contract");

    server.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    assert_eq!(
        spend,
        Spend::Unavailable,
        "a client certificate signed by an unrelated CA must be rejected, never silently accepted"
    );
}

/// Test: setting `client_cert_path` without `client_key_path` is a hard construction error naming
/// which one is missing, never a silent "connect without an identity" fallback.
#[tokio::test]
async fn client_cert_path_without_client_key_path_is_a_hard_construction_error() {
    let err = UsageServiceSpendReader::new(
        "https://authz-usage:3002",
        false,
        None,
        Some("/some/cert.pem"),
        None,
        Duration::from_secs(1),
    )
    .expect_err("a half-configured client identity must fail construction, not degrade silently");

    let message = err.to_string();
    assert!(
        message.contains("client_key_path"),
        "error must name the missing field, got: {message}"
    );
}

/// Test: the mirror image -- `client_key_path` without `client_cert_path`.
#[tokio::test]
async fn client_key_path_without_client_cert_path_is_a_hard_construction_error() {
    let err = UsageServiceSpendReader::new(
        "https://authz-usage:3002",
        false,
        None,
        None,
        Some("/some/key.pem"),
        Duration::from_secs(1),
    )
    .expect_err("a half-configured client identity must fail construction, not degrade silently");

    let message = err.to_string();
    assert!(
        message.contains("client_cert_path"),
        "error must name the missing field, got: {message}"
    );
}

/// Test: an unreadable `client_cert_path` is a hard construction error naming the path.
#[tokio::test]
async fn unreadable_client_cert_path_is_a_hard_construction_error() {
    let path = "/nonexistent/path/does-not-exist/client.crt";
    let err = UsageServiceSpendReader::new(
        "https://authz-usage:3002",
        false,
        None,
        Some(path),
        Some("/some/key.pem"),
        Duration::from_secs(1),
    )
    .expect_err("an unreadable client cert path must fail construction, not degrade silently");

    let message = err.to_string();
    assert!(
        message.contains(path),
        "error must name the offending path, got: {message}"
    );
}

/// Test: an unreadable `client_key_path` is a hard construction error naming the path.
#[tokio::test]
async fn unreadable_client_key_path_is_a_hard_construction_error() {
    let (_ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (client_leaf_cert, _client_leaf_key) = gen_client_leaf(&ca_issuer);
    let cert_path = write_temp_pem(&client_leaf_cert.pem(), "readable-client-cert");
    let key_path = "/nonexistent/path/does-not-exist/client.key";

    let err = UsageServiceSpendReader::new(
        "https://authz-usage:3002",
        false,
        None,
        Some(cert_path.to_str().expect("temp path is valid UTF-8")),
        Some(key_path),
        Duration::from_secs(1),
    )
    .expect_err("an unreadable client key path must fail construction, not degrade silently");

    let _ = std::fs::remove_file(&cert_path);
    let message = err.to_string();
    assert!(
        message.contains(key_path),
        "error must name the offending path, got: {message}"
    );
}

/// Test: a client cert/key pair that exists but does not parse as a valid identity (garbage PEM)
/// is also a hard construction error, not a silent "connect without an identity" fallback.
#[tokio::test]
async fn malformed_client_identity_is_a_hard_construction_error() {
    let cert_path = write_temp_pem("this is not a PEM certificate", "malformed-client-cert");
    let key_path = write_temp_pem("this is not a PEM key either", "malformed-client-key");

    let err = UsageServiceSpendReader::new(
        "https://authz-usage:3002",
        false,
        None,
        Some(cert_path.to_str().expect("temp path is valid UTF-8")),
        Some(key_path.to_str().expect("temp path is valid UTF-8")),
        Duration::from_secs(1),
    )
    .expect_err("a malformed client identity must fail construction, not degrade silently");

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    let message = err.to_string();
    assert!(
        message.contains("client identity"),
        "error must describe the client-identity parse failure, got: {message}"
    );
}
