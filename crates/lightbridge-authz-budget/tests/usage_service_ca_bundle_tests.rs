//! Exercises `UsageServiceSpendReader::new`'s `ca_bundle_path` argument against a *real* TLS
//! handshake, not a mock -- this is the piece `usage_service_spend_reader_tests.rs` cannot cover,
//! because `httpmock`'s plain (non-TLS) mock server never exercises certificate verification at
//! all. The server side here uses `axum_server::tls_rustls`, the exact TLS-serving mechanism
//! `lightbridge_authz_core::server::serve_tls` uses in production (see
//! `crates/lightbridge-authz-core/src/server.rs`), so this test proves the client half of the
//! same TLS stack the real deployment runs.
//!
//! Every CA/leaf keypair here is generated fresh at test-run time with `rcgen`, never committed
//! to the repo: a checked-in private-key PEM fixture is flagged by this repo's Gitleaks CI gate
//! (`private-key` rule) regardless of it being a throwaway test key, so generating on the fly is
//! both simpler and avoids a guaranteed CI failure. `gen_ca`/`gen_leaf` below produce certificates
//! with the extensions (`basicConstraints`, `keyUsage`, `extendedKeyUsage`, an `authorityKeyIdentifier`
//! on the leaf) and an ATS-compliant (<=825 day) leaf validity window that real-world TLS stacks
//! -- including macOS's `rustls-platform-verifier`, which this workspace's `reqwest` build uses --
//! actually require; a bare self-signed pair without these was rejected outright during
//! development (`"localhost" certificate is not standards compliant`).

use axum::routing::post;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use lightbridge_authz_budget::{Period, Spend, SpendReader, UsageServiceSpendReader};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Once;
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

/// A self-signed CA certificate, proper `basicConstraints`/`keyUsage` CA extensions included.
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

/// A leaf certificate for `localhost`/`127.0.0.1`, signed by `issuer`, with the
/// `serverAuth` EKU and an `authorityKeyIdentifier` extension real TLS stacks expect, and a
/// 31-day validity window (well under Apple's 825-day ATS ceiling for leaf certificates).
fn gen_leaf(issuer: &Issuer<'static, KeyPair>) -> (Certificate, KeyPair) {
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

/// Writes `pem` to a fresh temp file and returns its path; used only for the CA bundle a reader
/// under test loads via `ca_bundle_path` (a real file path is the actual API contract).
fn write_temp_pem(pem: &str, label: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "lightbridge-authz-budget-{label}-{}-{unique}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).expect("must write temp CA bundle file");
    path
}

/// `total_cost` is already micro-USD on the wire (#488) -- this fixture uses a whole
/// micro-USD figure so the `Spend::Known(3_750_000)` assertions below need no scaling.
async fn spend_query_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "total_cost": 3_750_000.0 }))
}

/// Starts a real HTTPS server on an ephemeral loopback port, presenting a freshly generated
/// `localhost`/`127.0.0.1` leaf certificate signed by `ca_issuer`, serving
/// `POST /usage/v1/spend/query`. Returns the bound address and the background task's handle --
/// callers should `handle.abort()` once done.
async fn spawn_https_server(
    ca_issuer: &Issuer<'static, KeyPair>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    ensure_rustls_provider();

    let (leaf_cert, leaf_key) = gen_leaf(ca_issuer);

    let listener = TcpListener::bind("127.0.0.1:0").expect("must bind an ephemeral port");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local addr");
    listener
        .set_nonblocking(true)
        .expect("listener must support non-blocking mode");

    let config = RustlsConfig::from_pem(
        leaf_cert.pem().into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("generated leaf cert/key must load into a rustls config");

    let app = Router::new().route("/usage/v1/spend/query", post(spend_query_handler));

    let handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, config)
            .expect("must wrap the bound listener with the rustls acceptor")
            .serve(app.into_make_service())
            .await
            .expect("test TLS server must not fail to serve");
    });

    (addr, handle)
}

/// Test 1 (mandated test list): a valid CA bundle is loaded and the client verifies successfully
/// against a server presenting a cert issued by that CA.
#[tokio::test]
async fn valid_ca_bundle_verifies_the_server_certificate() {
    let (ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (addr, server) = spawn_https_server(&ca_issuer).await;
    let base_url = format!("https://{addr}");
    let ca_bundle_path = write_temp_pem(&ca_cert.pem(), "valid-ca");

    let reader = UsageServiceSpendReader::new(
        base_url,
        false,
        Some(ca_bundle_path.to_str().expect("temp path is valid UTF-8")),
        None,
        None,
        Duration::from_secs(5),
    )
    .expect("reader construction with a valid CA bundle must succeed");

    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    server.abort();
    let _ = std::fs::remove_file(&ca_bundle_path);
    assert_eq!(
        spend,
        Spend::Known(3_750_000),
        "a trusted CA bundle must let the request through and read the response"
    );
}

/// Test 2 (mandated test list) -- the one that actually proves verification is real: a server
/// certificate NOT signed by the configured CA is rejected, not silently accepted. Prove-fail-first
/// context: before `ca_bundle_path` existed, this reader had no way to express "trust only this
/// CA" at all -- every call either verified against the ambient system trust store (which trusts
/// neither test CA here) or skipped verification entirely (`insecure_skip_verify`), so a
/// wrong-CA scenario like this one could never even be constructed as a positive/negative pair.
#[tokio::test]
async fn server_certificate_not_signed_by_the_configured_ca_is_rejected() {
    let (_ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (other_ca_cert, _other_ca_issuer) = gen_ca("unrelated-test-ca");
    let (addr, server) = spawn_https_server(&ca_issuer).await;
    let base_url = format!("https://{addr}");
    let wrong_ca_bundle_path = write_temp_pem(&other_ca_cert.pem(), "wrong-ca");

    let reader = UsageServiceSpendReader::new(
        base_url,
        false,
        Some(
            wrong_ca_bundle_path
                .to_str()
                .expect("temp path is valid UTF-8"),
        ),
        None,
        None,
        Duration::from_secs(5),
    )
    .expect("reader construction with a valid (if wrong) CA bundle must succeed");

    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("a TLS verification failure must not surface as Err -- fail-closed contract");

    server.abort();
    let _ = std::fs::remove_file(&wrong_ca_bundle_path);
    assert_eq!(
        spend,
        Spend::Unavailable,
        "a certificate signed by an unrelated CA must be rejected, never silently accepted"
    );
}

/// Test 3a (mandated test list): an unreadable CA bundle path is a hard startup/construction
/// error naming the path, not a silent fallback to skip-verify or the system trust store.
#[tokio::test]
async fn unreadable_ca_bundle_path_is_a_hard_construction_error() {
    let path = "/nonexistent/path/does-not-exist/ca.crt";
    let err = UsageServiceSpendReader::new(
        "https://authz-usage:3002",
        false,
        Some(path),
        None,
        None,
        Duration::from_secs(1),
    )
    .expect_err("an unreadable CA bundle path must fail construction, not degrade silently");

    let message = err.to_string();
    assert!(
        message.contains(path),
        "error must name the offending path, got: {message}"
    );
}

/// Test 3b (mandated test list): a CA bundle that exists but does not parse as PEM is also a hard
/// construction error naming the path.
#[tokio::test]
async fn malformed_ca_bundle_is_a_hard_construction_error() {
    let path = write_temp_pem("this is not a PEM certificate", "malformed");
    let path_str = path.to_str().expect("temp path must be valid UTF-8");

    let err = UsageServiceSpendReader::new(
        "https://authz-usage:3002",
        false,
        Some(path_str),
        None,
        None,
        Duration::from_secs(1),
    )
    .expect_err("a malformed PEM CA bundle must fail construction, not degrade silently");

    let message = err.to_string();
    assert!(
        message.contains(path_str),
        "error must name the offending path, got: {message}"
    );

    let _ = std::fs::remove_file(&path);
}

/// Test 4 (mandated test list): with `ca_bundle_path` unset and `insecure_skip_verify: true`,
/// existing local-Compose behavior is unchanged -- the client still reaches a server presenting a
/// certificate no configured CA vouches for, exactly as it did before `ca_bundle_path` existed.
#[tokio::test]
async fn insecure_skip_verify_without_a_ca_bundle_still_connects_like_local_compose() {
    let (_ca_cert, ca_issuer) = gen_ca("lightbridge-test-ca");
    let (addr, server) = spawn_https_server(&ca_issuer).await;
    let base_url = format!("https://{addr}");

    let reader =
        UsageServiceSpendReader::new(base_url, true, None, None, None, Duration::from_secs(5))
            .expect("reader construction must succeed");

    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    server.abort();
    assert_eq!(
        spend,
        Spend::Known(3_750_000),
        "insecure_skip_verify must still let local-Compose-style setups reach the server"
    );
}
