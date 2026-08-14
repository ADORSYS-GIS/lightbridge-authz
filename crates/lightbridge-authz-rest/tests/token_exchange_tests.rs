// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{JwtSigning, Oauth2TokenExchange};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{CreateAccount, CreateProject};
use lightbridge_authz_rest::signing::{ApiKeyJwtSigner, bootstrap_signing_key};
use lightbridge_authz_rest::token_exchange::{TokenExchangeState, token_exchange_router};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

const ISSUER: &str = "https://authz.example.test";
const SUBJECT: &str = "kc-user-123";
// `create_account` always sets the account's id to the creating subject (ADR-0006: an account IS
// its owner) -- there is no independent account-id parameter to seed a different value with, so
// this must alias `SUBJECT` rather than an arbitrary string. Using a distinct literal here was a
// pre-ADR-0006 leftover that made every test seeding through `seed()` fail with `NotFound` on
// `create_project` (it authorizes on `subject == account_id`), since `ACCOUNT_ID` never matched
// any account that actually existed.
const ACCOUNT_ID: &str = SUBJECT;
const PROJECT_ID: &str = "proj_xchg";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug, Deserialize)]
struct AccessClaims {
    sub: String,
    api_key_id: String,
    project_id: String,
    account_id: String,
    allowed_models: Option<Vec<String>>,
    email: Option<String>,
}

struct MockBearer {
    active: bool,
}

#[async_trait]
impl BearerTokenServiceTrait for MockBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        Ok(TokenInfo {
            active: self.active,
            sub: SUBJECT.to_string(),
            exp: 0,
            aud: vec![],
            roles: vec![],
            permissions: Default::default(),
            caller_kind: None,
            access_token: String::new(),
        })
    }
}

struct ErrBearer;

#[async_trait]
impl BearerTokenServiceTrait for ErrBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        Err(anyhow::anyhow!("upstream jwks unreachable"))
    }
}

fn lazy_repo() -> Arc<StoreRepo> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(pool))
}

fn signing_cfg() -> JwtSigning {
    JwtSigning {
        issuer: ISSUER.to_string(),
        audience: Some("lightbridge-api-key".to_string()),
        ttl_seconds: 7_776_000,
        max_key_age_days: 30,
    }
}

fn exchange_cfg() -> Oauth2TokenExchange {
    Oauth2TokenExchange {
        enabled: true,
        access_ttl_seconds: 900,
        refresh_ttl_seconds: 2_592_000,
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
        ],
    }
}

fn repo(pool: PgPool) -> Arc<StoreRepo> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(pool))
}

async fn seed(repo: &StoreRepo) {
    repo.create_account(
        SUBJECT,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("seed account");
    repo.create_project(
        SUBJECT,
        ACCOUNT_ID,
        CreateProject {
            name: "exchange-project".to_string(),
            allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: format!("bill-{}", cuid2()),
            project_quota: None,
        },
        PROJECT_ID.to_string(),
    )
    .await
    .expect("seed project");
}

fn state(repo: Arc<StoreRepo>, active: bool) -> TokenExchangeState {
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(), repo.clone()).unwrap();
    TokenExchangeState {
        repo,
        signer,
        bearer: Arc::new(MockBearer { active }),
        cfg: exchange_cfg(),
    }
}

async fn post_token(state: TokenExchangeState, body: &str) -> (StatusCode, Value) {
    let response = token_exchange_router::<()>(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn verify_access_token(repo: &StoreRepo, token: &str) -> AccessClaims {
    let jwks = repo.list_verification_jwks().await.unwrap();
    let jwk = jwks.first().expect("an active signing key");
    let decoding =
        DecodingKey::from_rsa_components(jwk["n"].as_str().unwrap(), jwk["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["lightbridge-api-key"]);
    validation.set_issuer(&[ISSUER]);
    decode::<AccessClaims>(token, &decoding, &validation)
        .expect("access token verifies against the active jwk")
        .claims
}

/// Decodes an `id_token`'s full, untyped claim set (verifying its signature), so tests can assert
/// on claims (`auth_time`, `nonce`, `at_hash`, `identity`) that have no fixed home in a typed
/// struct.
async fn verify_id_token(repo: &StoreRepo, token: &str) -> Value {
    let jwks = repo.list_verification_jwks().await.unwrap();
    let jwk = jwks.first().expect("an active signing key");
    let decoding =
        DecodingKey::from_rsa_components(jwk["n"].as_str().unwrap(), jwk["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["lightbridge-api-key"]);
    validation.set_issuer(&[ISSUER]);
    decode::<Value>(token, &decoding, &validation)
        .expect("id token verifies against the active jwk")
        .claims
}

/// Builds a fake `subject_token` (unverified by the `MockBearer` used throughout this file) whose
/// payload segment carries exactly `claims`, so `decode_email`/`decode_auth_time_and_nonce` in
/// `token_exchange.rs` have something real to snapshot from.
fn subject_token_with_claims(claims: &Value) -> String {
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("h.{payload}.s")
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_mints_project_scoped_jwt_with_refresh(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token=upstream-kc-token&project_id=proj_xchg&scope=openid+offline_access",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["issued_token_type"], ACCESS_TOKEN_TYPE);
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    let refresh = body["refresh_token"]
        .as_str()
        .expect("offline_access must yield a refresh token");
    assert!(refresh.starts_with("lgbr_rt_"));

    let claims = verify_access_token(&repo, body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims.sub, SUBJECT);
    assert_eq!(claims.project_id, PROJECT_ID);
    assert_eq!(claims.account_id, ACCOUNT_ID);
    assert_eq!(
        claims.allowed_models,
        Some(vec!["gpt-4.1-mini".to_string()])
    );
    assert!(!claims.api_key_id.is_empty());
    assert_eq!(claims.email, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_without_offline_scope_has_no_refresh_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("refresh_token").is_none(),
        "no offline_access scope => no refresh token"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_with_absent_scope_grants_no_refresh_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    // No `scope` param at all: the default-scope grant must exclude offline_access (OIDC Core
    // §5.4), so no refresh token is minted unless the client explicitly asks for it.
    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("refresh_token").is_none(),
        "absent scope must not silently grant offline_access / a refresh token"
    );
    let scope = body["scope"].as_str().unwrap_or("");
    assert!(
        !scope.split_whitespace().any(|s| s == "offline_access"),
        "granted scope must not include offline_access on an absent request: {scope}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_for_non_member_project_is_denied(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_does_not_exist"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error"], "access_denied");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_with_inactive_subject_token_is_unauthorized(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), false),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_token");
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_project_id_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_rotates_and_rejects_replay(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first_refresh = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&refresh_token={first_refresh}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second_refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(first_refresh, second_refresh, "refresh token must rotate");
    let claims = verify_access_token(&repo, body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims.project_id, PROJECT_ID);
    assert_eq!(claims.account_id, ACCOUNT_ID);

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&refresh_token={first_refresh}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replayed refresh must fail: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

#[sqlx::test(migrations = "../../migrations")]
async fn unsupported_grant_type_is_rejected(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();

    let (status, body) = post_token(
        state(repo.clone(), true),
        "grant_type=client_credentials&client_id=x",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn missing_subject_token_is_invalid_request() {
    let (status, body) = post_token(
        state(lazy_repo(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&project_id=proj_xchg"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "subject_token is required");
}

#[tokio::test]
async fn unsupported_subject_token_type_is_invalid_request() {
    let (status, body) = post_token(
        state(lazy_repo(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&subject_token_type=urn:ietf:params:oauth:token-type:saml2&project_id=proj_xchg"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "subject_token_type must be urn:ietf:params:oauth:token-type:access_token"
    );
}

#[tokio::test]
async fn bearer_validation_error_is_unauthorized() {
    let mut state = state(lazy_repo(), true);
    state.bearer = Arc::new(ErrBearer);

    let (status, body) = post_token(
        state,
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(body["error_description"], "subject_token validation failed");
}

#[tokio::test]
async fn context_resolution_failure_is_server_error() {
    let (status, body) = post_token(
        state(lazy_repo(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg"),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "context resolution failed");
}

#[tokio::test]
async fn missing_refresh_token_is_invalid_request() {
    let (status, body) = post_token(state(lazy_repo(), true), "grant_type=refresh_token").await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "refresh_token is required");
}

#[tokio::test]
async fn refresh_rotation_failure_is_server_error() {
    let (status, body) = post_token(
        state(lazy_repo(), true),
        "grant_type=refresh_token&refresh_token=lgbr_rt_unreachable",
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "refresh token rotation failed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_fails_when_no_signing_key_is_bootstrapped(pool: PgPool) {
    let repo = repo(pool);
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg"),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "access token signing failed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_with_unrecognized_scope_omits_scope_from_response(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg&scope=totally_unrecognized_scope"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("scope").is_none(),
        "an unrecognized scope must not be echoed back: {body}"
    );
    assert!(body.get("refresh_token").is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_snapshots_email_claims_from_subject_token(pool: PgPool) {
    use base64::Engine;

    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"email":"owner@example.test","email_verified":true}"#);
    let subject_token = format!("h.{payload}.s");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token={subject_token}&subject_token_type={ACCESS_TOKEN_TYPE}&project_id=proj_xchg"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_access_token(&repo, body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims.email.as_deref(), Some("owner@example.test"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_tolerates_a_subject_token_with_an_unparsable_payload_segment(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=h.not-valid-base64!!!.s&project_id=proj_xchg"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_access_token(&repo, body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims.email, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_tolerates_a_subject_token_with_a_non_json_payload_segment(pool: PgPool) {
    use base64::Engine;

    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
    let subject_token = format!("h.{payload}.s");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token={subject_token}&project_id=proj_xchg"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_access_token(&repo, body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims.email, None);
}

// ADR-0011: the token-exchange grant returns a full OIDC token object -- `id_token` present iff
// `openid` was granted, `auth_time`/`nonce` propagated from the upstream subject_token when
// present and omitted (never fabricated) when absent, and the refresh grant re-mints
// symmetrically with the exchange grant instead of the old, thinner `mint_from_refresh` path.

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_issues_id_token_when_openid_granted(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let id_token = body["id_token"]
        .as_str()
        .expect("openid scope must yield an id_token");
    let claims = verify_id_token(&repo, id_token).await;
    assert_eq!(claims["sub"], SUBJECT);
    assert_eq!(claims["azp"], "lightbridge-api-key");
    let access_token = body["access_token"].as_str().unwrap();
    assert_eq!(
        claims["at_hash"],
        lightbridge_authz_rest::signing::compute_at_hash(access_token),
        "at_hash must bind the id_token to the access token minted in the same response"
    );
    // ADR-0011, Decision 7: tenant context stays access-token-only.
    for tenant_claim in ["api_key_id", "project_id", "account_id"] {
        assert!(
            claims.get(tenant_claim).is_none(),
            "id_token must not carry {tenant_claim}: {claims}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_omits_id_token_when_openid_not_granted(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg&scope=profile"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("id_token").is_none(),
        "no openid scope => no id_token: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_id_token_propagates_auth_time_and_nonce_when_present(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let subject_token = subject_token_with_claims(&serde_json::json!({
        "auth_time": 1_700_000_000,
        "nonce": "nonce-from-upstream",
    }));

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token={subject_token}&project_id=proj_xchg&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_id_token(&repo, body["id_token"].as_str().unwrap()).await;
    assert_eq!(claims["auth_time"], 1_700_000_000);
    assert_eq!(claims["nonce"], "nonce-from-upstream");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_id_token_omits_auth_time_and_nonce_when_absent(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=x&project_id=proj_xchg&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_id_token(&repo, body["id_token"].as_str().unwrap()).await;
    assert!(
        claims.get("auth_time").is_none(),
        "auth_time must be omitted (never fabricated) when the upstream token carried none: {claims}"
    );
    assert!(
        claims.get("nonce").is_none(),
        "nonce must be omitted (never fabricated) when the upstream token carried none: {claims}"
    );
}

/// ADR-0011, Decision 1: the refresh grant re-mints symmetrically with the original exchange
/// grant. This is the regression test for the `mint_from_refresh` email-dropping bug the ADR
/// names explicitly -- before the fix, `mint_from_refresh` hardcoded
/// `KeyOwner { email: None, email_verified: None, .. }` regardless of what the original exchange
/// snapshotted, so every refreshed access token (and now id_token) was strictly thinner than the
/// one it replaced. Verified to actually catch that bug (not just pass after the fact): reverting
/// `mint_from_refresh`'s `owner` construction back to the old hardcoded `None`s makes this test
/// fail on the `email`/`email_verified` assertions below, for exactly this reason -- see the PR
/// description for the transcript.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_reissues_id_token_and_preserves_email(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let subject_token = subject_token_with_claims(&serde_json::json!({
        "email": "owner@example.test",
        "email_verified": true,
        "auth_time": 1_700_000_000,
        "nonce": "nonce-from-original-exchange",
    }));

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token={subject_token}&project_id=proj_xchg&scope=openid+offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&refresh_token={refresh_token}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let access_claims = verify_access_token(&repo, body["access_token"].as_str().unwrap()).await;
    assert_eq!(
        access_claims.email.as_deref(),
        Some("owner@example.test"),
        "refreshed access token must preserve email, not drop it"
    );

    let id_token = body["id_token"]
        .as_str()
        .expect("scope carried openid across the refresh, so an id_token must be reissued");
    let id_claims = verify_id_token(&repo, id_token).await;
    assert_eq!(id_claims["email"], "owner@example.test");
    assert_eq!(id_claims["email_verified"], true);
    assert_eq!(
        id_claims["auth_time"], 1_700_000_000,
        "auth_time describes the original authentication and must survive a refresh"
    );
    assert!(
        id_claims.get("nonce").is_none(),
        "a refresh presents no authorization request, so the reissued id_token must never carry \
         the original exchange's nonce: {id_claims}"
    );
}
