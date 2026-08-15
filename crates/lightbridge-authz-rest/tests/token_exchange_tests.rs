// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! ADR-0011 phase 2: `POST /oauth2/token` now dispatches through
//! `authkestra_op::handlers::token::handle_token` against a real, config-defined client registry
//! (`oauth2_op::client_store::ConfigClientStore`) instead of the phase-1 hand-rolled match. Every
//! request in this file therefore names a `client_id` (or, for confidential clients, presents a
//! `client_assertion`) -- an unregistered/unauthenticated client is rejected before the grant is
//! ever dispatched, which the phase-1 tests this file replaces had no way to exercise.
//!
//! Confidential-client tests need a real, reachable Redis (`ClientAssertionStore` replay
//! tracking) -- `just it-tests` brings one up; `AUTHZ_REDIS_URL` overrides the default
//! `redis://127.0.0.1:6379`, mirroring `rpc_it_tests.rs`'s own convention.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{
    JwtSigning, Oauth2TokenExchange, OauthClient, OauthClientType,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{CreateAccount, CreateProject};
use lightbridge_authz_rest::oauth2_op::client_assertion_store::RedisClientAssertionStore;
use lightbridge_authz_rest::oauth2_op::client_store::ConfigClientStore;
use lightbridge_authz_rest::oauth2_op::store::TokenExchangeOpStore;
use lightbridge_authz_rest::signing::{ApiKeyJwtSigner, bootstrap_signing_key, generate_rs256_key};
use lightbridge_authz_rest::token_exchange::{TokenExchangeState, token_exchange_router};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

const ISSUER: &str = "https://authz.example.test";
const SUBJECT: &str = "kc-user-123";
// `create_account` always sets the account's id to the creating subject (ADR-0006: an account IS
// its owner) -- there is no independent account-id parameter to seed a different value with, so
// this must alias `SUBJECT` rather than an arbitrary string.
const ACCOUNT_ID: &str = SUBJECT;
const PROJECT_ID: &str = "proj_xchg";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const PUBLIC_CLIENT_ID: &str = "lightbridge-ss";
const CONFIDENTIAL_CLIENT_ID: &str = "lightbridge-mcp";

#[derive(Debug, Deserialize)]
struct AccessClaims {
    sub: String,
    api_key_id: String,
    project_id: String,
    account_id: String,
    allowed_models: Option<Vec<String>>,
    email: Option<String>,
}

/// Configurable mock of the upstream Keycloak validator: `active` gates whether the subject_token
/// is accepted at all, `aud` is what the audience-binding check
/// (`TokenExchangeOpStore::handle_token_exchange`) reads off the (would-be) validated token.
struct MockBearer {
    active: bool,
    aud: Vec<String>,
}

impl MockBearer {
    fn new(active: bool, aud: Vec<String>) -> Self {
        Self { active, aud }
    }
}

#[async_trait]
impl BearerTokenServiceTrait for MockBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        Ok(TokenInfo {
            active: self.active,
            sub: SUBJECT.to_string(),
            exp: 0,
            aud: self.aud.clone(),
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
        audience: None,
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

fn client_scopes() -> Vec<String> {
    exchange_cfg().allowed_scopes
}

fn client_grant_types() -> Vec<String> {
    vec![
        TOKEN_EXCHANGE_GRANT.to_string(),
        "refresh_token".to_string(),
    ]
}

fn public_client(client_id: &str) -> OauthClient {
    OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Public,
        scopes: client_scopes(),
        grant_types: client_grant_types(),
        allowed_audiences: vec![client_id.to_string()],
        jwks: None,
    }
}

/// A confidential client plus the private key material (PEM) and `kid` needed to sign
/// `private_key_jwt` assertions on its behalf -- the public half is what
/// `OauthClient.jwks`/`ClientRegistration.jwks` carries.
struct ConfidentialClientFixture {
    client: OauthClient,
    private_key_pem: String,
    kid: String,
}

fn confidential_client(client_id: &str) -> ConfidentialClientFixture {
    let key = generate_rs256_key().expect("rsa keypair generation");
    let jwks = serde_json::json!({ "keys": [key.public_jwk] });
    let client = OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Confidential,
        scopes: client_scopes(),
        grant_types: client_grant_types(),
        allowed_audiences: vec![client_id.to_string()],
        jwks: Some(jwks),
    };
    ConfidentialClientFixture {
        client,
        private_key_pem: key.private_key_pem,
        kid: key.kid,
    }
}

/// Signs an RFC 7523 §3 `private_key_jwt` client assertion. `aud` is `ISSUER` -- one of the two
/// values `authkestra_op::client_assertion::verify_client_assertion` accepts (`config.issuer` or
/// `config.token_endpoint()`).
fn sign_client_assertion(
    private_key_pem: &str,
    kid: &str,
    client_id: &str,
    jti: &str,
    exp_seconds_from_now: i64,
) -> String {
    let encoding_key =
        EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).expect("valid rsa pem");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": ISSUER,
        "jti": jti,
        "exp": (chrono::Utc::now().timestamp() + exp_seconds_from_now),
    });
    encode(&header, &claims, &encoding_key).expect("assertion signs")
}

fn redis_url() -> String {
    std::env::var("AUTHZ_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

const UNREACHABLE_REDIS_URL: &str = "redis://127.0.0.1:1";

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

/// Builds `TokenExchangeState` for a given client registry, bearer, and Redis URL. Most tests use
/// [`state`] (one public client, real reachable Redis); tests exercising confidential-client auth
/// or Redis failure modes call this directly.
fn state_with(
    repo: Arc<StoreRepo>,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    clients: Vec<OauthClient>,
    redis_url: &str,
) -> TokenExchangeState {
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(), repo.clone()).unwrap();
    let client_store = ConfigClientStore::from_config(&clients);
    let assertions = RedisClientAssertionStore::connect(redis_url, "test:token-exchange-jti:")
        .expect("lazy connection manager always builds");
    let op_store = Arc::new(TokenExchangeOpStore::new(
        client_store,
        assertions,
        repo,
        bearer,
        exchange_cfg(),
    ));
    let op_config = authkestra_op::config::OpConfig {
        issuer: ISSUER.to_string(),
        scopes_supported: exchange_cfg().allowed_scopes,
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: client_grant_types(),
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: 0,
        access_token_ttl_secs: 900,
        device_code_ttl_secs: 0,
        token_exchange_enabled: true,
    };
    TokenExchangeState::new(signer, op_config, op_store)
}

/// One public client (`PUBLIC_CLIENT_ID`), a `MockBearer` whose `aud` already contains it (so the
/// audience-binding check passes by default), and a real, reachable Redis.
fn state(repo: Arc<StoreRepo>, active: bool) -> TokenExchangeState {
    state_with(
        repo,
        Arc::new(MockBearer::new(active, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    )
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

fn decoding_key(jwk: &Value) -> DecodingKey {
    DecodingKey::from_rsa_components(jwk["n"].as_str().unwrap(), jwk["e"].as_str().unwrap())
        .unwrap()
}

async fn verify_access_token(repo: &StoreRepo, token: &str, client_id: &str) -> AccessClaims {
    let jwks = repo.list_verification_jwks().await.unwrap();
    let jwk = jwks.first().expect("an active signing key");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[ISSUER]);
    decode::<AccessClaims>(token, &decoding_key(jwk), &validation)
        .expect("access token verifies against the active jwk")
        .claims
}

/// Decodes an access token's full, untyped claim set -- for assertions the typed `AccessClaims`
/// has no field for (`aud`, absence of `role`/`quota_tier`/`project_quota`).
async fn decode_access_token_claims(repo: &StoreRepo, token: &str, client_id: &str) -> Value {
    let jwks = repo.list_verification_jwks().await.unwrap();
    let jwk = jwks.first().expect("an active signing key");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[ISSUER]);
    decode::<Value>(token, &decoding_key(jwk), &validation)
        .expect("access token verifies against the active jwk")
        .claims
}

/// Decodes an `id_token`'s full, untyped claim set (verifying its signature), so tests can assert
/// on claims (`auth_time`, `nonce`, `at_hash`, `identity`) that have no fixed home in a typed
/// struct.
async fn verify_id_token(repo: &StoreRepo, token: &str, client_id: &str) -> Value {
    let jwks = repo.list_verification_jwks().await.unwrap();
    let jwk = jwks.first().expect("an active signing key");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[ISSUER]);
    decode::<Value>(token, &decoding_key(jwk), &validation)
        .expect("id token verifies against the active jwk")
        .claims
}

/// Builds a fake `subject_token` (unverified by the `MockBearer` used throughout this file) whose
/// payload segment carries exactly `claims`, so `decode_email`/`decode_auth_time_and_nonce` in
/// `oauth2_op` have something real to snapshot from.
fn subject_token_with_claims(claims: &Value) -> String {
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("h.{payload}.s")
}

// ============================================================================================
// Client authentication (ADR-0011, Decisions 5 & 6) -- the core of this phase.
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn public_client_with_no_credential_authenticates(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn unknown_client_id_is_rejected(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id=never-registered&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[sqlx::test(migrations = "../../migrations")]
async fn confidential_client_with_valid_assertion_authenticates(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        CONFIDENTIAL_CLIENT_ID,
        &cuid2(),
        300,
    );
    let bearer = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));
    let state = state_with(repo.clone(), bearer, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}\
             &client_assertion={assertion}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn confidential_client_with_missing_assertion_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    let bearer = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));
    let state = state_with(repo.clone(), bearer, vec![fixture.client], &redis_url());

    // No client_assertion at all -- NoCredential presented against a PrivateKeyJwt-bound client.
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={CONFIDENTIAL_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[sqlx::test(migrations = "../../migrations")]
async fn confidential_client_with_bad_assertion_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    // Signed with a DIFFERENT, unregistered key -- not the client's own.
    let forger = generate_rs256_key().unwrap();
    let bad_assertion = sign_client_assertion(
        &forger.private_key_pem,
        &fixture.kid,
        CONFIDENTIAL_CLIENT_ID,
        &cuid2(),
        300,
    );
    let bearer = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));
    let state = state_with(repo.clone(), bearer, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}\
             &client_assertion={bad_assertion}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

/// The replay polarity test: the SAME assertion presented twice must succeed once and be refused
/// the second time. Proves `record_jti`'s `Ok(false)` branch is actually wired to a rejection, not
/// silently ignored.
#[sqlx::test(migrations = "../../migrations")]
async fn replayed_client_assertion_jti_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    let jti = cuid2();
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        CONFIDENTIAL_CLIENT_ID,
        &jti,
        300,
    );
    let redis = redis_url();

    let bearer1 = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));
    let state1 = state_with(repo.clone(), bearer1, vec![fixture.client.clone()], &redis);
    let body_str = format!(
        "grant_type={TOKEN_EXCHANGE_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}\
         &client_assertion={assertion}&subject_token=x&project_id={PROJECT_ID}"
    );

    let (status, body) = post_token(state1, &body_str).await;
    assert_eq!(status, StatusCode::OK, "first use must succeed: {body}");

    // Fresh state (assertion.jti tracking lives in Redis, not in-process, so a fresh
    // TokenExchangeState still observes the earlier use).
    let bearer2 = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));
    let state2 = state_with(repo.clone(), bearer2, vec![fixture.client], &redis);
    let (status, body) = post_token(state2, &body_str).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed assertion must be refused: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

/// This repo's first review priority: an unavailable dependency must never become the permissive
/// branch. Redis unreachable => confidential-client authentication is REFUSED, not admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn redis_unreachable_refuses_confidential_client_rather_than_admitting(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        CONFIDENTIAL_CLIENT_ID,
        &cuid2(),
        300,
    );
    let bearer = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));
    let state = state_with(
        repo.clone(),
        bearer,
        vec![fixture.client],
        UNREACHABLE_REDIS_URL,
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}\
             &client_assertion={assertion}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "redis-down must refuse, never admit: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

// ============================================================================================
// aud/azp are per-client (ADR-0011, Decision 5).
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn aud_is_the_requesting_client_id_and_varies_between_clients(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let client_a = "client-a";
    let client_b = "client-b";
    let redis = redis_url();

    let state_a = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(true, vec![client_a.to_string()])),
        vec![public_client(client_a)],
        &redis,
    );
    let (status, body) = post_token(
        state_a,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_a}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims_a =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), client_a).await;
    assert_eq!(claims_a["aud"], client_a);

    let state_b = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(true, vec![client_b.to_string()])),
        vec![public_client(client_b)],
        &redis,
    );
    let (status, body) = post_token(
        state_b,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_b}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims_b =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), client_b).await;
    assert_eq!(claims_b["aud"], client_b);

    assert_ne!(claims_a["aud"], claims_b["aud"]);
}

/// Real Keycloak-issued subject tokens carry a multi-valued `aud` (one entry per
/// `oidc-audience-mapper` on the realm, e.g. `["lightbridge-api-key", "converse-frontend"]`) --
/// the requesting client only needs to be ONE member of that array, not its sole value. This is
/// the array-membership semantics `token_info.aud.iter().any(|a| a == &client_id)`
/// (`oauth2_op/store.rs`) already implements; this test pins that behavior so a future edit
/// cannot silently narrow it back to string equality against a single-valued `aud`.
#[sqlx::test(migrations = "../../migrations")]
async fn subject_token_aud_array_containing_client_id_among_others_is_accepted(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let state = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(
            true,
            vec![
                "converse-frontend".to_string(),
                PUBLIC_CLIENT_ID.to_string(),
            ],
        )),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn subject_token_aud_not_naming_the_requesting_client_is_invalid_grant(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    // MockBearer reports the subject_token's aud as some OTHER client -- the requesting client is
    // not a member of it.
    let state = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(true, vec!["someone-else".to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

// ============================================================================================
// Tenant claims / role-quota exclusion (ADR-0011, Decision 7).
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn tenant_claims_on_access_token_role_and_quota_absent_from_both(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}&scope=openid"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let access_claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(access_claims["project_id"], PROJECT_ID);
    assert_eq!(access_claims["account_id"], ACCOUNT_ID);
    for role_claim in ["role", "quota_tier", "project_quota"] {
        assert!(
            access_claims.get(role_claim).is_none(),
            "access token must never carry {role_claim}: {access_claims}"
        );
    }

    let id_claims =
        verify_id_token(&repo, body["id_token"].as_str().unwrap(), PUBLIC_CLIENT_ID).await;
    for tenant_claim in [
        "api_key_id",
        "project_id",
        "account_id",
        "role",
        "quota_tier",
        "project_quota",
    ] {
        assert!(
            id_claims.get(tenant_claim).is_none(),
            "id_token must never carry {tenant_claim}: {id_claims}"
        );
    }
}

// ============================================================================================
// Refresh tokens: client binding (ADR-0011 phase 2 migration) + both client types can obtain one.
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_token_issued_to_client_a_is_rejected_when_presented_by_client_b(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let client_a = "client-a";
    let client_b = "client-b";
    let redis = redis_url();

    let state_a = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(true, vec![client_a.to_string()])),
        vec![public_client(client_a), public_client(client_b)],
        &redis,
    );
    let (status, body) = post_token(
        state_a,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_a}&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // Same underlying client registry, but this state's own client_id on the refresh request is
    // client_b.
    let state_b = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(true, vec![client_b.to_string()])),
        vec![public_client(client_a), public_client(client_b)],
        &redis,
    );
    let (status, body) = post_token(
        state_b,
        &format!("grant_type=refresh_token&client_id={client_b}&refresh_token={refresh_token}"),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a refresh token must be rejected when presented by a different client: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

#[sqlx::test(migrations = "../../migrations")]
async fn both_public_and_confidential_clients_can_obtain_a_refresh_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    // Public.
    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("lgbr_rt_")
    );

    // Confidential.
    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        CONFIDENTIAL_CLIENT_ID,
        &cuid2(),
        300,
    );
    let state = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(
            true,
            vec![CONFIDENTIAL_CLIENT_ID.to_string()],
        )),
        vec![fixture.client],
        &redis_url(),
    );
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}\
             &client_assertion={assertion}&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("lgbr_rt_")
    );
}

// ============================================================================================
// Everything below re-ports phase-1 coverage onto the new dispatch (client_id now required on
// every request).
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_mints_project_scoped_jwt_with_refresh(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}\
             &subject_token=upstream-kc-token&project_id={PROJECT_ID}&scope=openid+offline_access"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(
        body["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    let refresh = body["refresh_token"]
        .as_str()
        .expect("offline_access must yield a refresh token");
    assert!(refresh.starts_with("lgbr_rt_"));

    let claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}&scope=openid"
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

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id=proj_does_not_exist"
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
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_token");
}

/// `seed()` gives `SUBJECT` a single project (`PROJECT_ID`), which the
/// `projects_set_is_default` trigger therefore marks as that account's default -- so an omitted
/// `project_id` must resolve to exactly it (`StoreRepo::find_default_project_id`), and the minted
/// access token's `project_id` claim must reflect that resolution, not just a bare 200.
#[sqlx::test(migrations = "../../migrations")]
async fn missing_project_id_resolves_caller_default_project(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(
        claims["project_id"], PROJECT_ID,
        "an omitted project_id must resolve to the caller's auto-provisioned default project"
    );
}

/// The fallback only ever resolves *the caller's own* default project -- it must never leak or
/// substitute a different account's project, even one `SUBJECT` cannot see. Distinct from
/// `exchange_for_non_member_project_is_denied` below, which covers an explicit, wrong
/// `project_id`; this covers the *default-resolution* path finding nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn missing_project_id_with_no_projects_is_denied(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    // Deliberately account-only: create_account never provisions a project by itself (that is a
    // separate "ensure default project" bootstrap call), so this subject legitimately has zero
    // projects and therefore no default to fall back to.
    repo.create_account(
        SUBJECT,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("seed account");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error"], "access_denied");
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_rotates_and_rejects_replay(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first_refresh = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first_refresh}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second_refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(first_refresh, second_refresh, "refresh token must rotate");
    let claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(claims.project_id, PROJECT_ID);
    assert_eq!(claims.account_id, ACCOUNT_ID);

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first_refresh}"
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replayed refresh must fail: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// A registered client naming a grant type it is not permitted (or that this service never
/// registers any client for, e.g. `client_credentials`) is `unauthorized_client`, distinct from an
/// unknown/unauthenticated client (`invalid_client`, covered above) -- client auth in
/// `handle_token` runs unconditionally before grant dispatch, so this is the shape a truly
/// "wrong grant" failure takes now.
#[sqlx::test(migrations = "../../migrations")]
async fn registered_client_with_unpermitted_grant_type_is_unauthorized_client(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=client_credentials&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "unauthorized_client");
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_subject_token_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "subject_token is required");
}

#[sqlx::test(migrations = "../../migrations")]
async fn unsupported_subject_token_type_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x\
             &subject_token_type=urn:ietf:params:oauth:token-type:saml2&project_id={PROJECT_ID}"
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

#[sqlx::test(migrations = "../../migrations")]
async fn bearer_validation_error_is_unauthorized(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let state = state_with(
        repo.clone(),
        Arc::new(ErrBearer),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(body["error_description"], "subject_token validation failed");
}

/// The axum boundary builds the request's single `TokenManager` (`state.signer.token_manager()`)
/// before ever calling `handle_token` -- unlike the phase-1 hand-rolled dispatch, where signing
/// only happened after subject_token validation and context resolution, so an unreachable DB used
/// to surface *downstream*-specific errors ("context resolution failed", "refresh token rotation
/// failed"). Now any unreachable-DB failure surfaces at that first, shared step regardless of
/// grant type -- see `exchange_fails_when_no_signing_key_is_bootstrapped` for the DB-reachable
/// case (key never bootstrapped) that still distinguishes "signing key unavailable" specifically.
#[tokio::test]
async fn totally_unreachable_repo_fails_the_exchange_grant_closed_as_server_error() {
    let state = state_with(
        lazy_repo(),
        Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["error"], "server_error");
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_refresh_token_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "refresh_token is required");
}

#[tokio::test]
async fn totally_unreachable_repo_fails_the_refresh_grant_closed_as_server_error() {
    let state = state_with(
        lazy_repo(),
        Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    );

    let (status, body) = post_token(
        state,
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token=lgbr_rt_unreachable"),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["error"], "server_error");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_fails_when_no_signing_key_is_bootstrapped(pool: PgPool) {
    let repo = repo(pool);
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "signing key unavailable");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_with_unrecognized_scope_omits_scope_from_response(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x\
             &project_id={PROJECT_ID}&scope=totally_unrecognized_scope"
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token={subject_token}\
             &project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}\
             &subject_token=h.not-valid-base64!!!.s&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token={subject_token}\
             &project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let id_token = body["id_token"]
        .as_str()
        .expect("openid scope must yield an id_token");
    let claims = verify_id_token(&repo, id_token, PUBLIC_CLIENT_ID).await;
    assert_eq!(claims["sub"], SUBJECT);
    assert_eq!(claims["azp"], PUBLIC_CLIENT_ID);
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}&scope=profile"
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token={subject_token}\
             &project_id={PROJECT_ID}&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_id_token(&repo, body["id_token"].as_str().unwrap(), PUBLIC_CLIENT_ID).await;
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x&project_id={PROJECT_ID}&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = verify_id_token(&repo, body["id_token"].as_str().unwrap(), PUBLIC_CLIENT_ID).await;
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
/// one it replaced. The phase-2 refresh grant re-mints through the *same* signing calls the
/// exchange grant uses (`oauth2_op::store::TokenExchangeOpStore::handle_refresh_token`), so there
/// is structurally no second, thinner code path to regress into.
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token={subject_token}\
             &project_id={PROJECT_ID}&scope=openid+offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let access_claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(
        access_claims.email.as_deref(),
        Some("owner@example.test"),
        "refreshed access token must preserve email, not drop it"
    );

    let id_token = body["id_token"]
        .as_str()
        .expect("scope carried openid across the refresh, so an id_token must be reissued");
    let id_claims = verify_id_token(&repo, id_token, PUBLIC_CLIENT_ID).await;
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
