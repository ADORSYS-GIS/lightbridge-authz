use std::collections::HashMap;

use base64::Engine;
use httpmock::Method::GET;
use httpmock::MockServer;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::Permission;
use lightbridge_authz_core::authz::Rbac;
use lightbridge_authz_core::config::{Oauth2, Oauth2Type};
use rand_core::OsRng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;

struct TestKey {
    kid: String,
    encoding_key: EncodingKey,
    jwk: serde_json::Value,
}

fn generate_test_key(kid: &str) -> TestKey {
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
        "kid": kid,
        "n": b64(public.n().to_bytes_be()),
        "e": b64(public.e().to_bytes_be()),
    });
    TestKey {
        kid: kid.to_string(),
        encoding_key: EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key"),
        jwk,
    }
}

fn jwks_body(keys: &[&serde_json::Value]) -> String {
    json!({ "keys": keys }).to_string()
}

fn sign(key: &TestKey, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    encode(&header, claims, &key.encoding_key).expect("sign token")
}

fn oauth2_config(jwks_url: String, audience: Option<Vec<String>>, rbac: Rbac) -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
        jwks_url,
        oauth2_url: None,
        issuer_url: None,
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        issuance: None,
        audience,
        signing: None,
        token_exchange: None,
        relying_party: None,
        rbac,
        clients: Vec::new(),
        federation: Some(lightbridge_authz_core::config::Federation {
            issuer: "https://keycloak.example.test/realms/dev".to_string(),
            discovery_url: None,
        }),
    }
}

fn default_rbac() -> Rbac {
    Rbac {
        roles_claim: "roles".to_string(),
        role_permissions: HashMap::new(),
        default_grants: Vec::new(),
    }
}

fn far_future_exp() -> u64 {
    4_102_444_800
}

/// The `iss` claim value used by every fixture in this file that needs one -- matches
/// `oauth2_config`'s own `federation.issuer`, though nothing in this crate enforces `iss` against
/// it today (deliberately -- see [`lightbridge_authz_bearer::TokenInfo::iss`]'s doc comment).
fn test_issuer() -> &'static str {
    "https://keycloak.example.test/realms/dev"
}

#[tokio::test]
async fn empty_token_is_rejected() {
    let service = BearerTokenService::new(oauth2_config(
        "http://unused.invalid/jwks".to_string(),
        None,
        default_rbac(),
    ));

    assert!(service.validate_bearer_token("").await.is_err());
    assert!(service.validate_bearer_token("   ").await.is_err());
}

#[tokio::test]
async fn malformed_token_is_rejected() {
    let service = BearerTokenService::new(oauth2_config(
        "http://unused.invalid/jwks".to_string(),
        None,
        default_rbac(),
    ));

    let err = service
        .validate_bearer_token("not-a-jwt")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn token_without_kid_is_rejected() {
    let service = BearerTokenService::new(oauth2_config(
        "http://unused.invalid/jwks".to_string(),
        None,
        default_rbac(),
    ));

    let header = Header::new(Algorithm::HS256);
    let token = encode(
        &header,
        &json!({"sub": "user-1", "exp": far_future_exp()}),
        &EncodingKey::from_secret(b"unused-secret"),
    )
    .expect("sign hs256 token without kid");

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn unknown_kid_is_rejected() {
    let server = MockServer::start();
    let known = generate_test_key("known-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&known.jwk]));
    });

    let signer = generate_test_key("other-kid");
    let token = sign(&signer, &json!({"sub": "user-1", "exp": far_future_exp()}));

    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, default_rbac()));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn jwks_fetch_failure_is_rejected() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.status(500).body("boom");
    });

    let signer = generate_test_key("some-kid");
    let token = sign(&signer, &json!({"sub": "user-1", "exp": far_future_exp()}));

    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, default_rbac()));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn invalid_signature_is_rejected() {
    let server = MockServer::start();
    let published = generate_test_key("shared-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&published.jwk]));
    });

    let impostor = generate_test_key("shared-kid");
    let token = sign(
        &impostor,
        &json!({"sub": "user-1", "exp": far_future_exp()}),
    );

    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, default_rbac()));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let server = MockServer::start();
    let key = generate_test_key("exp-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(&key, &json!({"sub": "user-1", "exp": 1}));

    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, default_rbac()));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

/// ADR-0025 Stage 2 / Finding 4 (test review): `Claims.iss` is required, not `Option<String>` --
/// a token that carries no `iss` claim at all must be rejected outright, not silently accepted
/// with the field defaulted to empty. This is now load-bearing behavior (the resolver seam
/// downstream trusts `TokenInfo::iss`), so it gets its own dedicated regression test rather than
/// relying on the five other tests' fixtures happening to include the claim. Prove-fail: making
/// `Claims.iss`/`TokenInfo::iss` `Option<String>` (or `#[serde(default)]`) makes this test red,
/// since the token would then deserialize successfully instead of being refused.
#[tokio::test]
async fn missing_iss_is_rejected() {
    let server = MockServer::start();
    let key = generate_test_key("no-iss-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({"sub": "user-no-iss", "exp": far_future_exp()}),
    );

    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, default_rbac()));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn successful_validation_without_audience_config_grants_admin_permissions() {
    let server = MockServer::start();
    let key = generate_test_key("admin-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({
            "sub": "user-admin",
            "iss": test_issuer(),
            "exp": far_future_exp(),
            "roles": ["lightbridge-admin"],
        }),
    );

    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, default_rbac()));

    let info: TokenInfo = service.validate_bearer_token(&token).await.unwrap();
    assert!(info.active);
    assert_eq!(info.sub, "user-admin");
    assert!(info.aud.is_empty());
    assert_eq!(info.roles, vec!["lightbridge-admin".to_string()]);
    assert!(info.has_permission(Permission::AccountCreate));
    assert!(info.require(Permission::ProjectDelete).is_ok());
}

#[tokio::test]
async fn caller_without_matching_role_is_denied_by_require() {
    let server = MockServer::start();
    let key = generate_test_key("norole-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({"sub": "user-norole", "iss": test_issuer(), "exp": far_future_exp()}),
    );

    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, default_rbac()));

    let info = service.validate_bearer_token(&token).await.unwrap();
    assert!(info.roles.is_empty());
    assert!(!info.has_permission(Permission::AccountCreate));
    let err = info.require(Permission::AccountCreate).unwrap_err();
    assert!(err.to_string().contains("missing required permission"));
}

#[tokio::test]
async fn successful_validation_with_single_string_audience() {
    let server = MockServer::start();
    let key = generate_test_key("aud-single-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({
            "sub": "user-aud",
            "iss": test_issuer(),
            "exp": far_future_exp(),
            "aud": "expected-aud",
        }),
    );

    let service = BearerTokenService::new(oauth2_config(
        server.url("/jwks"),
        Some(vec!["expected-aud".to_string()]),
        default_rbac(),
    ));

    let info = service.validate_bearer_token(&token).await.unwrap();
    assert_eq!(info.aud, vec!["expected-aud".to_string()]);
}

#[tokio::test]
async fn successful_validation_with_array_audience() {
    let server = MockServer::start();
    let key = generate_test_key("aud-array-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({
            "sub": "user-aud-array",
            "iss": test_issuer(),
            "exp": far_future_exp(),
            "aud": ["other-aud", "expected-aud"],
        }),
    );

    let service = BearerTokenService::new(oauth2_config(
        server.url("/jwks"),
        Some(vec!["expected-aud".to_string()]),
        default_rbac(),
    ));

    let info = service.validate_bearer_token(&token).await.unwrap();
    assert_eq!(
        info.aud,
        vec!["other-aud".to_string(), "expected-aud".to_string()]
    );
}

#[tokio::test]
async fn audience_configured_but_token_missing_aud_is_rejected() {
    let server = MockServer::start();
    let key = generate_test_key("aud-missing-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(&key, &json!({"sub": "user-noaud", "exp": far_future_exp()}));

    let service = BearerTokenService::new(oauth2_config(
        server.url("/jwks"),
        Some(vec!["expected-aud".to_string()]),
        default_rbac(),
    ));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn audience_mismatch_is_rejected() {
    let server = MockServer::start();
    let key = generate_test_key("aud-mismatch-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({
            "sub": "user-wrongaud",
            "exp": far_future_exp(),
            "aud": "someone-else",
        }),
    );

    let service = BearerTokenService::new(oauth2_config(
        server.url("/jwks"),
        Some(vec!["expected-aud".to_string()]),
        default_rbac(),
    ));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn empty_audience_list_skips_jsonwebtoken_aud_check_but_still_rejects_on_no_match() {
    let server = MockServer::start();
    let key = generate_test_key("aud-empty-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({"sub": "user-empty-aud", "exp": far_future_exp()}),
    );

    let service = BearerTokenService::new(oauth2_config(
        server.url("/jwks"),
        Some(vec![]),
        default_rbac(),
    ));

    let err = service.validate_bearer_token(&token).await.unwrap_err();
    assert_eq!(err.to_string(), "unauthorized");
}

#[tokio::test]
async fn custom_roles_claim_is_honored() {
    let server = MockServer::start();
    let key = generate_test_key("custom-roles-kid");
    server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.header("content-type", "application/json")
            .status(200)
            .body(jwks_body(&[&key.jwk]));
    });

    let token = sign(
        &key,
        &json!({
            "sub": "user-custom",
            "iss": test_issuer(),
            "exp": far_future_exp(),
            "roles": ["lightbridge-admin"],
            "lightbridge_api_roles": "lightbridge-viewer",
        }),
    );

    let rbac = Rbac {
        roles_claim: "lightbridge_api_roles".to_string(),
        role_permissions: HashMap::new(),
        default_grants: Vec::new(),
    };
    let service = BearerTokenService::new(oauth2_config(server.url("/jwks"), None, rbac));

    let info = service.validate_bearer_token(&token).await.unwrap();
    assert_eq!(info.roles, vec!["lightbridge-viewer".to_string()]);
    assert!(info.has_permission(Permission::AccountRead));
    assert!(!info.has_permission(Permission::AccountDelete));
}

#[tokio::test]
async fn service_debug_output_exposes_jwks_url_and_roles_claim_only() {
    let service = BearerTokenService::new(oauth2_config(
        "http://unused.invalid/jwks".to_string(),
        None,
        default_rbac(),
    ));

    let rendered = format!("{service:?}");
    assert!(rendered.contains("unused.invalid"));
    assert!(rendered.contains("roles_claim"));
}
