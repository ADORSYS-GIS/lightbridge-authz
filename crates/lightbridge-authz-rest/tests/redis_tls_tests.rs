//! Exercises `redis_tls::build_redis_client` (lightbridge-authz#363) against real TLS
//! handshakes, not mocks -- mirroring `lightbridge-authz-budget`'s
//! `usage_service_ca_bundle_tests.rs`, the established pattern in this repo for proving a
//! `ca_bundle_path` argument is real certificate verification and not just a plumbed-through
//! string. The server side here is a raw `tokio-rustls` TCP acceptor -- not
//! `axum_server::tls_rustls`, which only serves HTTP framing, and `redis`'s wire protocol is not
//! HTTP. It only completes the TLS handshake and then holds the connection open; that alone is
//! enough to prove certificate verification, since `redis::Client::get_multiplexed_async_connection`
//! will not return `Ok` until the underlying TLS transport is up.
//!
//! Every CA/leaf keypair is generated fresh at test-run time with `rcgen`, never committed (a
//! checked-in private-key PEM fixture trips this repo's Gitleaks CI gate regardless of being a
//! throwaway test key).

use lightbridge_authz_rest::redis_tls::build_redis_client;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Once;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A self-signed CA certificate, proper `basicConstraints`/`keyUsage` CA extensions included --
/// same shape as `usage_service_ca_bundle_tests.rs::gen_ca`. Returns the `Issuer` alongside the
/// `Certificate` (rcgen 0.14's `signed_by` takes an `&Issuer`, built from `CertificateParams` +
/// signing key, not a bare `&Certificate`/`&KeyPair` pair -- a `Certificate` alone does not
/// expose the params needed to reconstruct one).
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

/// A leaf certificate for `127.0.0.1`, signed by `issuer` -- same shape as
/// `usage_service_ca_bundle_tests.rs::gen_leaf`, minus the `localhost` DNS SAN (redis-rs's TLS
/// connector is handed a bare IP host, not a DNS name).
fn gen_leaf(issuer: &Issuer<'static, KeyPair>) -> (Certificate, KeyPair) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("ECDSA P-256 key generation must succeed");
    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is always valid");
    params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
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

fn write_temp_pem(pem: &str, label: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "lightbridge-authz-rest-redis-tls-{label}-{}-{unique}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).expect("must write temp CA bundle file");
    path
}

/// Starts a raw TLS TCP server on an ephemeral loopback port, presenting a freshly generated
/// `127.0.0.1` leaf certificate signed by `ca_issuer`. After completing the TLS
/// handshake it just holds the connection open (replying `+PONG\r\n` to anything it reads, so it
/// never blocks a client that does send something) -- proving the handshake succeeded is the
/// whole point; this deliberately does not implement enough of RESP2 to serve a real client.
async fn spawn_tls_redis_stub(
    ca_issuer: &Issuer<'static, KeyPair>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    ensure_rustls_provider();

    let (leaf_cert, leaf_key) = gen_leaf(ca_issuer);
    let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert.der().clone()], key_der.into())
        .expect("leaf cert/key must build a valid rustls ServerConfig");
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("must bind an ephemeral port");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local addr");

    let handle = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls_stream) = acceptor.accept(stream).await else {
            // Expected for the wrong-CA test: the client aborts the handshake before it
            // completes, so `accept` never returns Ok here. Nothing to serve.
            return;
        };
        let mut buf = [0u8; 1024];
        loop {
            match tls_stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    // redis-rs may pipeline more than one RESP2 command per write (protocol
                    // setup traffic ahead of anything we send explicitly). Each top-level RESP2
                    // command is a multi-bulk array starting with `*`, so counting those bytes
                    // (instead of assuming exactly one command per read) answers every pipelined
                    // command with its own `+PONG\r\n`, keeping the client from blocking on a
                    // reply this stub never sent.
                    let replies = buf[..n].iter().filter(|&&b| b == b'*').count().max(1);
                    for _ in 0..replies {
                        if tls_stream.write_all(b"+PONG\r\n").await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });

    (addr, handle)
}

/// Establishes a connection via `get_multiplexed_async_connection` -- doing so fully drives the
/// TLS handshake (certificate verification included), since redis-rs will not hand back a
/// connection until the underlying transport (here: TCP + TLS) is up. This intentionally does
/// not go on to run a real `PING` round-trip: `get_multiplexed_async_connection` may pipeline
/// its own setup traffic (protocol negotiation, `CLIENT SETINFO`, ...) ahead of any command we'd
/// issue, which our intentionally-minimal RESP2 stub server does not attempt to emulate -- the
/// TLS/CA layer this module exists to test is fully exercised by the connect step alone.
async fn try_connect(client: redis::Client) -> Result<(), redis::RedisError> {
    client.get_multiplexed_async_connection().await?;
    Ok(())
}

/// Test 1: a server certificate signed by the configured CA is trusted and the TLS connection
/// (handshake included) is established successfully.
#[tokio::test]
async fn valid_ca_bundle_establishes_the_tls_connection() {
    let (ca_cert, ca_issuer) = gen_ca("lightbridge-redis-test-ca");
    let (addr, server) = spawn_tls_redis_stub(&ca_issuer).await;
    let ca_bundle_path = write_temp_pem(&ca_cert.pem(), "valid-ca");

    let client = build_redis_client(
        &format!("rediss://{addr}/"),
        Some(ca_bundle_path.to_str().expect("temp path is valid UTF-8")),
    )
    .expect("build_redis_client with a valid CA bundle must succeed");

    let result = try_connect(client).await;

    server.abort();
    let _ = std::fs::remove_file(&ca_bundle_path);
    result.expect("a trusted CA bundle must let the TLS connection establish");
}

/// Test 2 -- the one that actually proves verification is real: a server certificate NOT signed
/// by the configured CA is rejected at the TLS layer, not silently accepted. Prove-fail-first
/// context: before `redis.ca_bundle_path` existed, `rediss://` was not even a buildable URL
/// scheme (no TLS feature was compiled in at all), so this positive/negative pair could not
/// previously be constructed.
#[tokio::test]
async fn server_certificate_not_signed_by_the_configured_ca_is_rejected() {
    let (_ca_cert, ca_issuer) = gen_ca("lightbridge-redis-test-ca");
    let (other_ca_cert, _other_ca_issuer) = gen_ca("unrelated-redis-test-ca");
    let (addr, server) = spawn_tls_redis_stub(&ca_issuer).await;
    let wrong_ca_bundle_path = write_temp_pem(&other_ca_cert.pem(), "wrong-ca");

    let client = build_redis_client(
        &format!("rediss://{addr}/"),
        Some(
            wrong_ca_bundle_path
                .to_str()
                .expect("temp path is valid UTF-8"),
        ),
    )
    .expect(
        "build_redis_client with a valid (if wrong) CA bundle must succeed -- the failure \
             happens at the TLS handshake, not client construction",
    );

    let result = try_connect(client).await;

    server.abort();
    let _ = std::fs::remove_file(&wrong_ca_bundle_path);

    let err = result.expect_err(
        "a certificate signed by an unrelated CA must be rejected, never silently accepted",
    );
    let message = err.to_string();
    assert!(
        message.to_ascii_lowercase().contains("certificate"),
        "expected a certificate-verification failure, got: {message}"
    );
}

/// Test 3a: `rediss://` with no `ca_bundle_path` is a hard, eager construction error -- never a
/// silent fallback to the OS/public trust store (which does not trust the cluster's internal CA
/// anyway, so that fallback would just be "never connects", not "connects insecurely" -- but the
/// contract this repo wants is an explicit config error naming the missing key, not a mysterious
/// runtime handshake failure).
#[tokio::test]
async fn rediss_url_without_ca_bundle_path_is_a_hard_construction_error() {
    let err = build_redis_client("rediss://127.0.0.1:1/", None)
        .expect_err("rediss:// with no ca_bundle_path must fail construction, not connect");
    let message = err.to_string();
    assert!(
        message.contains("ca_bundle_path"),
        "error must name the missing config key, got: {message}"
    );
}

/// Test 3b: an unreadable `ca_bundle_path` under `rediss://` is also a hard construction error
/// naming the offending path, matching every other `ca_bundle_path` in this codebase
/// (`UsageServiceSpendReader`, `Tls::client_ca_bundle_path`).
#[tokio::test]
async fn rediss_url_with_unreadable_ca_bundle_path_is_a_hard_construction_error() {
    let path = "/nonexistent/path/does-not-exist/redis-ca.crt";
    let err = build_redis_client("rediss://127.0.0.1:1/", Some(path))
        .expect_err("an unreadable ca_bundle_path must fail construction, not degrade silently");
    let message = err.to_string();
    assert!(
        message.contains(path),
        "error must name the offending path, got: {message}"
    );
}

/// Test 4: plain `redis://` (local Compose) is untouched by any of this -- `ca_bundle_path` is
/// ignored entirely, exactly the pre-#363 behavior, and construction never touches the
/// filesystem or the network (lazy, like `redis::Client::open`).
#[tokio::test]
async fn plain_redis_url_ignores_ca_bundle_path() {
    let client = build_redis_client("redis://127.0.0.1:1/", Some("/nonexistent/path"))
        .expect("redis:// must build regardless of ca_bundle_path, valid or not");
    // Never actually connects (port 1 is unreachable); constructing the client is lazy.
    drop(client);
}

/// Sanity check on test 2's own assertion: confirms the "certificate" substring check actually
/// distinguishes a TLS verification failure from an unrelated connection failure, by checking a
/// connection-refused error (no server at all) does NOT contain "certificate" and IS classified
/// as a connection refusal. Guards against test 2's assertion being vacuously true for any
/// failure rather than specifically a certificate one.
#[tokio::test]
async fn connection_refused_is_distinguishable_from_a_certificate_error() {
    let (ca_cert, _ca_issuer) = gen_ca("lightbridge-redis-test-ca");
    let ca_bundle_path = write_temp_pem(&ca_cert.pem(), "unused-ca");

    // Bind and immediately drop a listener to get a genuinely closed port.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("must bind an ephemeral port");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local addr");
    drop(listener);

    let client = build_redis_client(
        &format!("rediss://{addr}/"),
        Some(ca_bundle_path.to_str().expect("temp path is valid UTF-8")),
    )
    .expect("build_redis_client must still succeed -- construction never dials out");

    let result = try_connect(client).await;
    let _ = std::fs::remove_file(&ca_bundle_path);

    let err = result.expect_err("an unreachable port must fail");
    assert!(
        err.is_connection_refusal(),
        "expected a connection-refusal error, got: {err}"
    );
    assert!(
        !err.to_string().to_ascii_lowercase().contains("certificate"),
        "a connection-refused error must not read as a certificate failure: {err}"
    );
}
