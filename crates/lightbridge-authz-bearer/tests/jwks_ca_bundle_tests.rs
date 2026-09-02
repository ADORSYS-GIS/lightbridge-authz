//! Exercises `trust_ca_bundle` (lightbridge-authz#625) against a *real* TLS handshake, not a
//! mock -- `httpmock`'s plain (non-TLS) server (used by `token_validation_tests.rs`) never
//! exercises certificate verification at all. The server side here uses
//! `axum_server::tls_rustls`, the exact TLS-serving mechanism this workspace's own services use
//! in production (see `lightbridge_authz_core::server::serve_tls`), so this proves the client
//! half of the same TLS stack a real deployment runs -- and it is the seam both production call
//! sites (`BearerTokenService::new` here, `KeycloakRelyingParty::new` in `lightbridge-authz-rest`)
//! now go through. Mirrors `lightbridge-authz-budget`'s `usage_service_ca_bundle_tests.rs` and
//! `lightbridge-authz-rest`'s `redis_tls_tests.rs`, the established pattern in this repo for
//! proving a `ca_bundle_path`-shaped argument is real certificate verification.
//!
//! Every CA/leaf keypair is generated fresh at test-run time with `rcgen`, never committed: a
//! checked-in private-key PEM fixture trips this repo's Gitleaks CI gate regardless of being a
//! throwaway test key.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait};
use lightbridge_authz_core::authz::Rbac;
use lightbridge_authz_core::config::{Federation, Oauth2, Oauth2Type};
use rand_core::OsRng;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use std::collections::HashMap;
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

const TEST_KID: &str = "jwks-ca-bundle-test-key";

/// A real RSA keypair + its JWK representation, so the end-to-end test below can sign a token
/// that the fetched JWKS actually verifies -- not just prove bytes came back over the wire.
struct TestKey {
    encoding_key: EncodingKey,
    jwk: serde_json::Value,
}

fn generate_test_key() -> TestKey {
    let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
    let pem = private
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string();
    let public = RsaPublicKey::from(&private);
    let b64 = |bytes: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": TEST_KID,
        "n": b64(public.n().to_bytes_be()),
        "e": b64(public.e().to_bytes_be()),
    });
    TestKey {
        encoding_key: EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key"),
        jwk,
    }
}

/// A self-signed CA certificate, proper `basicConstraints`/`keyUsage` CA extensions included.
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

/// A leaf certificate for `localhost`/`127.0.0.1`, signed by `issuer`.
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

fn write_temp_pem(pem: &str, label: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "lightbridge-authz-bearer-jwks-ca-{label}-{}-{unique}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).expect("must write temp CA bundle file");
    path
}

async fn jwks_handler(State(jwk): State<serde_json::Value>) -> Json<serde_json::Value> {
    Json(json!({ "keys": [jwk] }))
}

/// Starts a real HTTPS server on an ephemeral loopback port, presenting a freshly generated
/// `localhost`/`127.0.0.1` leaf certificate signed by `ca_issuer`, serving `GET /jwks`.
async fn spawn_https_jwks_server(
    ca_issuer: &Issuer<'static, KeyPair>,
    jwk: serde_json::Value,
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

    let app = Router::new()
        .route("/jwks", get(jwks_handler))
        .with_state(jwk);

    let handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, config)
            .expect("must wrap the bound listener with the rustls acceptor")
            .serve(app.into_make_service())
            .await
            .expect("test TLS server must not fail to serve");
    });

    (addr, handle)
}

fn oauth2_config(jwks_url: String, jwks_ca_bundle_path: Option<String>) -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
        jwks_url,
        jwks_ca_bundle_path,
        oauth2_url: None,
        issuer_url: None,
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        issuance: None,
        audience: None,
        signing: None,
        token_exchange: None,
        relying_party: None,
        rbac: Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::new(),
            default_grants: Vec::new(),
        },
        clients: Vec::new(),
        federation: Some(Federation {
            issuer: "https://keycloak.example.test/realms/dev".to_string(),
            discovery_url: None,
        }),
    }
}

/// Test 1 (mandated test list): a JWKS served over HTTPS by a private-CA cert is fetched
/// successfully when that CA is configured via `jwks_ca_bundle_path`.
#[tokio::test]
async fn valid_ca_bundle_fetches_the_jwks_over_https() {
    let (ca_cert, ca_issuer) = gen_ca("lightbridge-bearer-test-ca");
    let key = generate_test_key();
    let (addr, server) = spawn_https_jwks_server(&ca_issuer, key.jwk.clone()).await;
    let ca_bundle_path = write_temp_pem(&ca_cert.pem(), "valid-ca");

    let client = lightbridge_authz_bearer::trust_ca_bundle(
        reqwest::Client::builder(),
        Some(ca_bundle_path.to_str().expect("temp path is valid UTF-8")),
    )
    .expect("a valid CA bundle must build a client")
    .build()
    .expect("client must build");

    let cache = authkestra_resource::jwt::JwksCache::new(
        format!("https://{addr}/jwks"),
        Duration::from_secs(60),
    )
    .with_client(client);

    let jwks = cache
        .get_jwks()
        .await
        .expect("a trusted CA bundle must let the JWKS fetch succeed over HTTPS");

    server.abort();
    let _ = std::fs::remove_file(&ca_bundle_path);
    assert_eq!(jwks.keys.len(), 1, "expected exactly the one served key");
    assert_eq!(jwks.keys[0].kid.as_deref(), Some(TEST_KID));
}

/// Test 2 (mandated test list): the SAME private-CA-served JWKS endpoint as test 1, but with NO
/// `jwks_ca_bundle_path` configured at all -- the default client (platform trust store only)
/// must fail to verify the private-CA certificate, proving the fetch genuinely depends on the
/// configured CA rather than succeeding regardless.
#[tokio::test]
async fn jwks_ca_bundle_unset_cannot_reach_the_private_ca_endpoint() {
    let (_ca_cert, ca_issuer) = gen_ca("lightbridge-bearer-test-ca");
    let key = generate_test_key();
    let (addr, server) = spawn_https_jwks_server(&ca_issuer, key.jwk.clone()).await;

    let client = lightbridge_authz_bearer::trust_ca_bundle(reqwest::Client::builder(), None)
        .expect("None must always build a client")
        .build()
        .expect("client must build");

    let cache = authkestra_resource::jwt::JwksCache::new(
        format!("https://{addr}/jwks"),
        Duration::from_secs(60),
    )
    .with_client(client);

    let result = cache.get_jwks().await;

    server.abort();
    result.expect_err(
        "with no CA configured, a certificate signed by a private CA must not be trusted",
    );
}

/// Test 2b -- proves verification is real, not merely "any configured path works": a server
/// certificate signed by a DIFFERENT CA than the one configured is rejected.
#[tokio::test]
async fn server_certificate_not_signed_by_the_configured_ca_is_rejected() {
    let (_ca_cert, ca_issuer) = gen_ca("lightbridge-bearer-test-ca");
    let (other_ca_cert, _other_issuer) = gen_ca("unrelated-bearer-test-ca");
    let key = generate_test_key();
    let (addr, server) = spawn_https_jwks_server(&ca_issuer, key.jwk.clone()).await;
    let wrong_ca_bundle_path = write_temp_pem(&other_ca_cert.pem(), "wrong-ca");

    let client = lightbridge_authz_bearer::trust_ca_bundle(
        reqwest::Client::builder(),
        Some(
            wrong_ca_bundle_path
                .to_str()
                .expect("temp path is valid UTF-8"),
        ),
    )
    .expect("a valid (if wrong) CA bundle must still build a client")
    .build()
    .expect("client must build");

    let cache = authkestra_resource::jwt::JwksCache::new(
        format!("https://{addr}/jwks"),
        Duration::from_secs(60),
    )
    .with_client(client);

    let result = cache.get_jwks().await;

    server.abort();
    let _ = std::fs::remove_file(&wrong_ca_bundle_path);
    result.expect_err("a certificate signed by an unrelated CA must be rejected");
}

/// Test 3a (mandated test list): an unreadable CA bundle path is a hard construction-time error,
/// never a silent fallback to the default client. No network involved -- `trust_ca_bundle` fails
/// before any TLS dial.
#[test]
fn unreadable_ca_bundle_path_is_a_hard_construction_error() {
    let path = "/nonexistent/path/does-not-exist/jwks-ca.crt";
    let err = lightbridge_authz_bearer::trust_ca_bundle(reqwest::Client::builder(), Some(path))
        .expect_err("an unreadable ca_bundle_path must fail construction, not degrade silently");

    let message = err.to_string();
    assert!(
        message.contains(path),
        "error must name the offending path, got: {message}"
    );
}

/// Test 3b (mandated test list): a CA bundle that exists but is not valid PEM is also a hard
/// construction error naming the path.
#[test]
fn malformed_ca_bundle_is_a_hard_construction_error() {
    let path = write_temp_pem("this is not a PEM certificate", "malformed");
    let path_str = path.to_str().expect("temp path must be valid UTF-8");

    let err = lightbridge_authz_bearer::trust_ca_bundle(reqwest::Client::builder(), Some(path_str))
        .expect_err("a malformed PEM CA bundle must fail construction, not degrade silently");

    let message = err.to_string();
    assert!(
        message.contains(path_str),
        "error must name the offending path, got: {message}"
    );
    let _ = std::fs::remove_file(&path);
}

/// The end-to-end production seam: `BearerTokenService::new` wires `oauth2.jwks_ca_bundle_path`
/// all the way through to a real token validation against a JWKS served over HTTPS under a
/// private CA -- proving the config field, not just the lower-level `trust_ca_bundle` helper, is
/// actually connected to the seam #625 exists for.
#[tokio::test]
async fn bearer_token_service_validates_a_token_fetched_from_a_private_ca_jwks_endpoint() {
    let (ca_cert, ca_issuer) = gen_ca("lightbridge-bearer-test-ca");
    let key = generate_test_key();
    let (addr, server) = spawn_https_jwks_server(&ca_issuer, key.jwk.clone()).await;
    let ca_bundle_path = write_temp_pem(&ca_cert.pem(), "e2e-valid-ca");

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let far_future_exp = 4_102_444_800_u64;
    let claims = json!({
        "sub": "test-subject",
        "iss": "https://keycloak.example.test/realms/dev",
        "exp": far_future_exp,
    });
    let token = encode(&header, &claims, &key.encoding_key).expect("sign token");

    let jwks_url = format!("https://{addr}/jwks");
    let service = BearerTokenService::new(oauth2_config(
        jwks_url.clone(),
        Some(
            ca_bundle_path
                .to_str()
                .expect("temp path is valid UTF-8")
                .to_string(),
        ),
    ))
    .expect("valid oauth2 config with a valid CA bundle must build a BearerTokenService");

    let info = service
        .validate_bearer_token(&token)
        .await
        .expect("a token verifiable against the private-CA-served JWKS must validate");
    assert_eq!(info.sub, "test-subject");

    // Same JWKS endpoint, no CA configured: the fetch itself must fail closed, not validate the
    // token some other way.
    let unconfigured_service =
        BearerTokenService::new(oauth2_config(jwks_url, None)).expect("None must always build");
    unconfigured_service
        .validate_bearer_token(&token)
        .await
        .expect_err("with no CA configured, the private-CA JWKS endpoint must be unreachable");

    server.abort();
    let _ = std::fs::remove_file(&ca_bundle_path);
}
