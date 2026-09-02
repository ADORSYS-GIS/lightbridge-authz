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

use std::collections::HashMap;
use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use axum::Form;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use cratestack::CratestackContext;
use cratestack_axum::ratelimit::InMemoryRateLimitStore;
use httpmock::Method::GET;
use httpmock::MockServer;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lightbridge_authz_api::schema;
use lightbridge_authz_api::schema::procedures::ProcedureRegistry;
use lightbridge_authz_api_key::entities::exchange_refresh_token_row::NewExchangeRefreshToken;
use lightbridge_authz_api_key::entities::federated_identity_row::UpsertFederatedIdentity;
use lightbridge_authz_api_key::entities::session_row::NewSession;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_budget::PolicyStore;
use lightbridge_authz_budget::augmentation::AugmentationRepo;
use lightbridge_authz_budget::decision::{Decision, PolicyEngine};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::facts::Facts;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::refill::RefillService;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::review::ReviewService;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::UnavailableSpendReader;
use lightbridge_authz_budget::tier::BudgetTier;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{
    BasicAuth, Billing, BillingPlan, JwtSigning, Oauth2TokenExchange, OauthClient, OauthClientType,
    OidcRelyingParty,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{
    CreateAccount, CreateProject, Permission, ResourceStatus, hash_api_key,
};
use lightbridge_authz_rest::OpaRepoTrait;
use lightbridge_authz_rest::OpaState;
use lightbridge_authz_rest::Procedures;
use lightbridge_authz_rest::auth_provider::{SubjectResolver, build_context};
use lightbridge_authz_rest::authorize::{AuthorizeState, router as authorize_router};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::handlers::introspect::introspect_api_key;
use lightbridge_authz_rest::models::IntrospectRequest;
use lightbridge_authz_rest::oauth2_op::authorization_code_store::DbAuthorizationCodeStore;
use lightbridge_authz_rest::oauth2_op::client_assertion_store::RedisClientAssertionStore;
use lightbridge_authz_rest::oauth2_op::client_store::ConfigClientStore;
use lightbridge_authz_rest::oauth2_op::refresh_signing::bootstrap_idp_signing_keys;
use lightbridge_authz_rest::oauth2_op::store::TokenExchangeOpStore;
use lightbridge_authz_rest::relying_party::KeycloakRelyingParty;
use lightbridge_authz_rest::rpc_authorize::RpcScope;
use lightbridge_authz_rest::signing::{ApiKeyJwtSigner, KeyOwner, generate_rs256_key};
use lightbridge_authz_rest::token_exchange::{TokenExchangeState, token_exchange_router};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

const ISSUER: &str = "https://authz.example.test";
// ADR-0025: the ONE issuer these tests' `oauth2.federation`/`TokenExchangeOpStore` grandfather
// against -- distinct from `ISSUER` above (this service's OWN self-signed-JWT issuer). Every
// `MockBearer`-produced `TokenInfo.iss` in this file uses this value, matching a real Keycloak
// `subject_token`'s issuer, so `resolve_account_for_federated_subject`'s self-healing adoption
// branch fires for these grandfathered (`accounts.id == subject`) fixtures.
const GRANDFATHER_ISSUER: &str = "https://keycloak.example.test/realms/dev";
const SUBJECT: &str = "kc-user-123";

/// A trust-everything [`SubjectResolver`] test double: resolves any `(iss, sub)` to
/// `AccountId::assert_already_resolved(sub)` unconditionally, never touching a database -- this file's own
/// tests either already hold an ADR-0025-resolved value (e.g. a real minted token's `sub`) or
/// exercise `resolve_account_for_federated_subject` directly against `repo` where that matters.
struct TrustEverythingResolver;

#[async_trait]
impl SubjectResolver for TrustEverythingResolver {
    async fn resolve(
        &self,
        _iss: &str,
        sub: &str,
    ) -> lightbridge_authz_core::error::Result<AccountId> {
        Ok(AccountId::assert_already_resolved(sub))
    }
}
// `create_account` always sets the account's id to the creating subject (ADR-0006: an account IS
// its owner) -- there is no independent account-id parameter to seed a different value with, so
// this must alias `SUBJECT` rather than an arbitrary string.
const ACCOUNT_ID: &str = SUBJECT;
const PROJECT_ID: &str = "proj_xchg";
// Refresh-token hardening fixtures (chain_id/chain_expires_at): a second account that owns a
// project SUBJECT is only a roster *member* of, not the owner -- distinct from `seed()`'s
// PROJECT_ID, which SUBJECT owns directly and which `resolve_context`'s ownership branch alone
// would already admit regardless of roster state.
const OWNER_ACCOUNT: &str = "kc-owner-999";
const MEMBER_PROJECT_ID: &str = "proj_member_scope";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const CLIENT_CREDENTIALS_GRANT: &str = "client_credentials";
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
    sub: String,
    iss: String,
}

impl MockBearer {
    fn new(active: bool, aud: Vec<String>) -> Self {
        Self {
            active,
            aud,
            sub: SUBJECT.to_string(),
            iss: GRANDFATHER_ISSUER.to_string(),
        }
    }

    /// ADR-0025: overrides the default (grandfathered) `sub`/`iss` this mock otherwise always
    /// returns -- for tests that need a subject the federation seam must refuse (an untrusted
    /// issuer, or an issuer-matching subject with no `accounts` row).
    fn with_subject(mut self, sub: &str, iss: &str) -> Self {
        self.sub = sub.to_string();
        self.iss = iss.to_string();
        self
    }
}

#[async_trait]
impl BearerTokenServiceTrait for MockBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        Ok(TokenInfo {
            active: self.active,
            sub: self.sub.clone(),
            iss: self.iss.clone(),
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
        claim_mappers: Vec::new(),
    }
}

fn exchange_cfg() -> Oauth2TokenExchange {
    Oauth2TokenExchange {
        enabled: true,
        access_ttl_seconds: 900,
        authorization_code_ttl_seconds: 300,
        refresh_ttl_seconds: 2_592_000,
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
        ],
        refresh_absolute_ttl_seconds: 7_776_000,
        refresh_reuse_grace_seconds: 30,
        device_code_ttl_seconds: 600,
        device_poll_interval_seconds: 5,
        device_verification_uri: "https://authz.example.test/device/verify".to_string(),
        client_credentials_ttl_seconds: 900,
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
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

fn device_client(client_id: &str) -> OauthClient {
    OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Public,
        scopes: vec!["openid".to_string(), "offline_access".to_string()],
        grant_types: vec![
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "refresh_token".to_string(),
        ],
        allowed_audiences: Vec::new(),
        jwks: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

fn browser_client(client_id: &str, redirect_uri: &str) -> OauthClient {
    OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Public,
        scopes: client_scopes(),
        // `refresh_token` alongside `authorization_code`: since #525 this grant issues a rotating
        // refresh token when `offline_access` is granted, and a browser client that cannot then
        // redeem it would be handed a credential it is forbidden to use.
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        allowed_audiences: vec![client_id.to_string()],
        jwks: None,
        redirect_uris: vec![redirect_uri.to_string()],
        post_logout_redirect_uris: Vec::new(),
        require_pkce: true,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

/// A Confidential authorization_code client with `require_pkce: false` -- the exact shape
/// `validate_authorization_code_clients` (`lib.rs`) now refuses at startup (follow-up to PR
/// #466's review finding), used here to prove `/authorize` itself also refuses a codeless-
/// challenge request for this client, independent of both `client_type` and the `require_pkce`
/// flag on the client record. Defense-in-depth: even a client object that somehow reached this
/// endpoint with `require_pkce: false` must not be able to start a non-PKCE authorization_code
/// flow.
fn confidential_browser_client_without_pkce(client_id: &str, redirect_uri: &str) -> OauthClient {
    OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Confidential,
        scopes: client_scopes(),
        grant_types: vec!["authorization_code".to_string()],
        allowed_audiences: vec![client_id.to_string()],
        jwks: None,
        redirect_uris: vec![redirect_uri.to_string()],
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

fn relying_party(repo: Arc<StoreRepo>) -> Arc<KeycloakRelyingParty> {
    relying_party_with_issuer(repo, "https://keycloak.example.test")
}

fn relying_party_with_issuer(repo: Arc<StoreRepo>, issuer: &str) -> Arc<KeycloakRelyingParty> {
    Arc::new(
        KeycloakRelyingParty::new(
            OidcRelyingParty {
                client_id: "authz-idp-rp".to_string(),
                callback_url: "https://authz.example.test/idp/callback".to_string(),
                client_secret: None,
                state_encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                token_encryption_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".to_string(),
                timeout_ms: 500,
                browser_session_ttl_seconds: 28_800,
            },
            issuer.to_string(),
            issuer.to_string(),
            repo,
            Arc::new(InMemoryRateLimitStore::new()),
            None,
        )
        .unwrap(),
    )
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
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    };
    ConfidentialClientFixture {
        client,
        private_key_pem: key.private_key_pem,
        kid: key.kid,
    }
}

/// A `Service` (`client_credentials`/M2M, #534/ADR-0030) client plus its private key, matching
/// [`confidential_client`]'s shape but with `type: service` and `grant_types: [client_credentials]`
/// -- authentication is byte-identical (`private_key_jwt`) between the two, so this exists purely
/// to name the intent at each call site and to default to a realistic `scopes`/`allowed_audiences`
/// pair a machine client would actually be configured with.
fn service_client(
    client_id: &str,
    scopes: Vec<String>,
    allowed_audiences: Vec<String>,
) -> ConfidentialClientFixture {
    let key = generate_rs256_key().expect("rsa keypair generation");
    let jwks = serde_json::json!({ "keys": [key.public_jwk] });
    let client = OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Service,
        scopes,
        grant_types: vec![CLIENT_CREDENTIALS_GRANT.to_string()],
        allowed_audiences,
        jwks: Some(jwks),
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
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
        &AccountId::assert_already_resolved(SUBJECT),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .expect("seed account");
    repo.create_project(
        &AccountId::assert_already_resolved(SUBJECT),
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

/// A second account (`OWNER_ACCOUNT`) owning `MEMBER_PROJECT_ID`, with `SUBJECT` added as a plain
/// roster *member* -- not the owner. Used by refresh-hardening tests that need "subject's standing
/// comes from `project_members`, not `projects.account_id`" (see the `OWNER_ACCOUNT` doc comment),
/// so removing the membership is the only thing that can revoke SUBJECT's access.
async fn seed_member_project(repo: &StoreRepo) {
    repo.create_account(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .expect("seed owner account");
    repo.create_account(
        &AccountId::assert_already_resolved(SUBJECT),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .expect("seed member account");
    repo.create_project(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        OWNER_ACCOUNT,
        CreateProject {
            name: "member-scope-project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: format!("bill-{}", cuid2()),
            project_quota: None,
        },
        MEMBER_PROJECT_ID.to_string(),
    )
    .await
    .expect("seed member project");
    repo.add_project_member(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        MEMBER_PROJECT_ID,
        SUBJECT,
        Some("member"),
    )
    .await
    .expect("add subject as a roster member");
}

/// Builds `TokenExchangeState` for a given client registry, bearer, Redis URL, AND an explicit
/// `Oauth2TokenExchange` -- [`state_with`] is a thin wrapper over this using [`exchange_cfg`];
/// tests that need a non-default `refresh_absolute_ttl_seconds` (the absolute-cap tests) call this
/// directly. Uses a REAL budget repo built off `repo`'s own pool -- see
/// [`state_with_cfg_and_budget_repo`] for tests that need an independently-controlled (e.g. dead)
/// budget-ledger pool while the rest of the stack (`repo`) stays real. `policy_engine` is the
/// ADR-0015 default fixed double ([`default_policy_engine`]) -- tests exercising the fail-closed
/// floor itself call [`state_with_cfg_and_budget_repo`] directly with their own.
fn state_with_cfg(
    repo: Arc<StoreRepo>,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    clients: Vec<OauthClient>,
    redis_url: &str,
    cfg: Oauth2TokenExchange,
) -> TokenExchangeState {
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        repo.pool.clone(),
    ));
    state_with_cfg_and_budget_repo(
        repo.clone(),
        repo,
        budget_repo,
        default_policy_engine(),
        bearer,
        clients,
        redis_url,
        cfg,
    )
}

/// Same as [`state_with_cfg`], but with `quota_repo`/`budget_repo`/`policy_engine` supplied
/// explicitly rather than derived/defaulted -- the ADR-0014/ADR-0015/ADR-0017 fail-closed tests use
/// this to point the budget ledger or the `project_members` lookup at an unreachable pool (and,
/// separately, to control exactly what `fail_closed_floor_micros()` resolves to) while `repo`
/// (subject/context resolution) stays a real, reachable Postgres.
#[allow(clippy::too_many_arguments)]
fn state_with_cfg_and_budget_repo(
    repo: Arc<StoreRepo>,
    quota_repo: Arc<StoreRepo>,
    budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    policy_engine: Arc<dyn PolicyEngine>,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    clients: Vec<OauthClient>,
    redis_url: &str,
    cfg: Oauth2TokenExchange,
) -> TokenExchangeState {
    let device_code_ttl_secs = cfg.device_code_ttl_seconds as u64;
    let device_poll_interval_secs = cfg.device_poll_interval_seconds as u64;
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(), repo.clone()).unwrap();
    let client_store = ConfigClientStore::from_config(&clients, &cfg);
    let assertions =
        RedisClientAssertionStore::connect(redis_url, None, "test:token-exchange-jti:")
            .expect("lazy connection manager always builds");
    let op_config = authkestra_op::config::OpConfig {
        issuer: ISSUER.to_string(),
        scopes_supported: cfg.allowed_scopes.clone(),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            TOKEN_EXCHANGE_GRANT.to_string(),
            "refresh_token".to_string(),
            "authorization_code".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: cfg.authorization_code_ttl_seconds,
        access_token_ttl_secs: 900,
        device_code_ttl_secs,
        token_exchange_enabled: true,
    };
    let op_store = Arc::new(TokenExchangeOpStore::new(
        client_store,
        assertions,
        repo,
        quota_repo,
        budget_repo,
        policy_engine,
        bearer,
        std::sync::Arc::new(Vec::new()),
        cfg,
        GRANDFATHER_ISSUER.to_string(),
    ));
    TokenExchangeState::new(
        signer,
        op_config,
        op_store,
        "https://authz.example.test/device/verify".to_string(),
        device_code_ttl_secs,
        device_poll_interval_secs,
    )
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
    state_with_cfg(repo, bearer, clients, redis_url, exchange_cfg())
}

fn device_state(repo: Arc<StoreRepo>, client_id: &str) -> TokenExchangeState {
    let mut cfg = exchange_cfg();
    cfg.device_poll_interval_seconds = 1;
    state_with_cfg(
        repo,
        Arc::new(MockBearer::new(true, Vec::new())),
        vec![device_client(client_id)],
        &redis_url(),
        cfg,
    )
}

/// Presented-token plaintext -> its `(chain_id, chain_expires_at)` off the real DB row, for tests
/// asserting the rotation-family metadata (not observable from the `TokenResponse` JSON itself).
async fn chain_metadata(
    repo: &StoreRepo,
    plaintext_refresh_token: &str,
) -> (String, chrono::DateTime<chrono::Utc>) {
    let hash = hash_api_key(plaintext_refresh_token);
    let row = repo
        .find_exchange_refresh_token_by_hash(&hash)
        .await
        .unwrap()
        .expect("refresh token row exists");
    (row.chain_id, row.chain_expires_at)
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

/// Same as [`state`], but with `refresh_reuse_grace_seconds: 0` -- the refresh-reuse grace window
/// (2026-08-30 console-401s incident, `Oauth2TokenExchange::refresh_reuse_grace_seconds`'s own doc
/// comment) disabled. Tests that assert an IMMEDIATE replay of a just-rotated token cascades (the
/// pre-incident, strict RFC 6819 §5.2.2.3 behavior) use this instead of [`state`]: `exchange_cfg`'s
/// real default (30s) would otherwise put that immediate replay INSIDE the grace window and turn
/// the cascade this file is asserting into a graced, 200 OK rotation instead.
fn state_no_reuse_grace(repo: Arc<StoreRepo>, active: bool) -> TokenExchangeState {
    state_with_cfg(
        repo,
        Arc::new(MockBearer::new(active, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
        Oauth2TokenExchange {
            refresh_reuse_grace_seconds: 0,
            ..exchange_cfg()
        },
    )
}

/// Wraps a real, Postgres-backed `StoreRepo` as `OpaState` -- the introspection-plane counterpart
/// to [`state`] (the token-exchange-plane state). `api_key_audience: None` since none of these
/// tests mint a self-signed API-key JWT, only token-exchange access tokens.
fn opa_state(repo: Arc<StoreRepo>) -> Arc<OpaState> {
    Arc::new(OpaState {
        repo: repo as Arc<dyn OpaRepoTrait>,
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
        billing: Arc::new(Billing {
            plans: vec![BillingPlan {
                id: "free".to_string(),
                name: "Free".to_string(),
                limits: None,
            }],
        }),
        api_key_audience: None,
        resolver: Arc::new(TrustEverythingResolver),
        federation_issuer: GRANDFATHER_ISSUER.to_string(),
    })
}

/// Calls the real `/v1/authorino/validate/introspect` handler function directly against `state`,
/// returning the decoded status/body -- the introspection-plane counterpart to [`post_token`].
async fn introspect(state: Arc<OpaState>, token: &str) -> (StatusCode, Value) {
    let response = introspect_api_key(
        axum::extract::State(state),
        Form(IntrospectRequest {
            token: token.to_string(),
            token_type_hint: Some("access_token".to_string()),
        }),
    )
    .await
    .expect("introspection handler should return a response, not error, for these tests");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn post_token(state: TokenExchangeState, body: &str) -> (StatusCode, Value) {
    let (status, _, json) = post_token_response(state, body).await;
    (status, json)
}

async fn post_token_response(
    state: TokenExchangeState,
    body: &str,
) -> (StatusCode, HeaderMap, Value) {
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
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, headers, json)
}

async fn post_device_authorization(state: TokenExchangeState, body: &str) -> (StatusCode, Value) {
    let response = token_exchange_router::<()>(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/device_authorization")
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

async fn token_response(
    state: TokenExchangeState,
    method: &str,
    body: &str,
    origin: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri("/oauth2/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    token_exchange_router::<()>(state)
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

fn s256_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn store_browser_code(
    repo: Arc<StoreRepo>,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
) {
    store_browser_code_with_scope(
        repo,
        code,
        client_id,
        redirect_uri,
        verifier,
        "openid profile",
    )
    .await;
}

/// Stores an authorization code carrying an explicit granted scope.
///
/// The scope on the CODE is what the token response must honour (RFC 6749 §4.1.3): an
/// authorization_code token request carries no `scope` parameter at all, so a test that passes one
/// on the token call proves nothing about where the scope actually came from.
async fn store_browser_code_with_scope(
    repo: Arc<StoreRepo>,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
    scope: &str,
) {
    let mut attributes = HashMap::new();
    attributes.insert("account_id".to_string(), ACCOUNT_ID.to_string());
    attributes.insert("project_id".to_string(), PROJECT_ID.to_string());
    DbAuthorizationCodeStore::new(repo)
        .store_code({
            let mut authorization_code = AuthorizationCode::new(
                code.to_string(),
                client_id.to_string(),
                redirect_uri.to_string(),
                scope.to_string(),
                Identity {
                    provider_id: "keycloak".to_string(),
                    external_id: SUBJECT.to_string(),
                    email: Some("user@example.test".to_string()),
                    username: None,
                    attributes,
                },
                chrono::Utc::now() + chrono::Duration::minutes(5),
                false,
            );
            authorization_code.code_challenge = Some(s256_challenge(verifier));
            authorization_code.code_challenge_method = Some("S256".to_string());
            authorization_code.nonce = Some("browser-nonce".to_string());
            authorization_code
        })
        .await
        .unwrap();
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

/// The refresh-token-specific claims `oauth2_op::refresh_token::mint_refresh_jwt` stamps.
/// Re-declared rather than imported (mirroring `AccessClaims` above, for the same reason: this
/// test file verifies the ACTUAL wire shape independently of the minting module's own types).
#[derive(Debug, Deserialize)]
struct RefreshClaims {
    sub: String,
    aud: String,
    jti: String,
    sid: String,
    typ: String,
}

/// Verifies a minted refresh-token JWT against the active signing key -- the same claim
/// shape/audience/typ `BearerTokenService`'s replay guard and `handle_refresh_token`'s own
/// verification check, so a test asserting against this proves the token is genuinely well-formed
/// rather than merely opaque-looking.
/// Verifies a refresh token against the REFRESH key set, and asserts in passing that it does NOT
/// verify against the published access JWKS.
///
/// That second assertion is the security property #629 exists to establish: the refresh signing
/// key is excluded from `/.well-known/jwks.json`, so no resource server holds a key capable of
/// verifying a refresh token, and cross-use is impossible by construction rather than prevented by
/// the `typ` denylist alone. Before #629 this helper verified against `list_verification_jwks`
/// (the published set) and passed -- that it now CANNOT is the change.
async fn verify_refresh_token(repo: &StoreRepo, token: &str) -> RefreshClaims {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["lightbridge-refresh"]);

    for published in repo.list_verification_jwks().await.unwrap() {
        assert!(
            decode::<RefreshClaims>(token, &decoding_key(&published), &validation).is_err(),
            "a refresh token must NOT be verifiable against any key in the published JWKS: {published}"
        );
    }

    let refresh_jwks = repo.list_refresh_verification_jwks().await.unwrap();
    let jwk = refresh_jwks.first().expect("an active refresh signing key");
    decode::<RefreshClaims>(token, &decoding_key(jwk), &validation)
        .expect("refresh token verifies against the refresh jwk")
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
/// payload segment carries exactly `claims`, so `decode_profile_claims`/`decode_auth_time_and_nonce`
/// in `oauth2_op` have something real to snapshot from.
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn authorization_code_token_endpoint_enforces_binding_pkce_and_single_use(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const OTHER_CLIENT: &str = "other-browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const OTHER_REDIRECT_URI: &str = "https://dashboard.example.test/oauth/other";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    let clients = vec![
        browser_client(CLIENT, REDIRECT_URI),
        browser_client(OTHER_CLIENT, OTHER_REDIRECT_URI),
    ];

    store_browser_code(repo.clone(), "success-code", CLIENT, REDIRECT_URI, VERIFIER).await;
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients.clone(),
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=success-code&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["access_token"].is_string(), "body: {body}");
    let id_claims = verify_id_token(&repo, body["id_token"].as_str().unwrap(), CLIENT).await;
    assert_eq!(id_claims["nonce"], "browser-nonce");

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients.clone(),
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=success-code&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    store_browser_code(
        repo.clone(),
        "wrong-verifier",
        CLIENT,
        REDIRECT_URI,
        VERIFIER,
    )
    .await;
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients.clone(),
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=wrong-verifier&redirect_uri={REDIRECT_URI}&code_verifier=wrong-verifier-value"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    store_browser_code(repo.clone(), "wrong-client", CLIENT, REDIRECT_URI, VERIFIER).await;
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients.clone(),
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={OTHER_CLIENT}&code=wrong-client&redirect_uri={OTHER_REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    store_browser_code(
        repo.clone(),
        "wrong-redirect",
        CLIENT,
        REDIRECT_URI,
        VERIFIER,
    )
    .await;
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients,
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=wrong-redirect&redirect_uri={REDIRECT_URI}/&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
}

/// Regresses the authkestra 0.7.0 PKCE hardening (authkestra#273): the token endpoint must
/// refuse a stored authorization code that carries NO `code_challenge`, unconditionally, rather
/// than gating that refusal on `client.require_pkce`. `/authorize` never stores a codeless code
/// (it enforces PKCE S256 unconditionally), so this branch only fires for a code that reached
/// storage by some other path (a legacy pre-#273 code or a downstream `OpStore::store_code`
/// override). Before this fix `mint_from_authorization_code` mirrored authkestra's *old* logic
/// (`else if client.require_pkce`), so a `require_pkce: false` client could redeem a codeless
/// code end to end; upstream 0.7.0 rejects that case unconditionally, and this hand-written copy
/// must faithfully track upstream. The client here is deliberately a PUBLIC `authorization_code`
/// client with `require_pkce: false` (a shape whose require_pkce flag would, before authkestra#273,
/// have allowed a codeless redemption, and which needs no client authentication at the token
/// endpoint) so the refusal is proven independent of the deprecated flag.
#[sqlx::test(migrations = "../../migrations")]
async fn authorization_code_token_endpoint_refuses_stored_code_without_pkce_challenge(
    pool: PgPool,
) {
    const CLIENT: &str = "public-browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    // A Public authorization_code client with require_pkce: false -- the shape that must still be
    // refused at the token endpoint now that PKCE is mandatory regardless of the flag.
    let client = OauthClient {
        client_id: CLIENT.to_string(),
        client_type: OauthClientType::Public,
        scopes: client_scopes(),
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        allowed_audiences: vec![CLIENT.to_string()],
        jwks: None,
        redirect_uris: vec![REDIRECT_URI.to_string()],
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    };
    DbAuthorizationCodeStore::new(repo.clone())
        .store_code({
            let mut attributes = HashMap::new();
            attributes.insert("account_id".to_string(), ACCOUNT_ID.to_string());
            attributes.insert("project_id".to_string(), PROJECT_ID.to_string());
            let authorization_code = AuthorizationCode::new(
                "codeless-code".to_string(),
                CLIENT.to_string(),
                REDIRECT_URI.to_string(),
                "openid".to_string(),
                Identity {
                    provider_id: "keycloak".to_string(),
                    external_id: SUBJECT.to_string(),
                    email: Some("user@example.test".to_string()),
                    username: None,
                    attributes,
                },
                chrono::Utc::now() + chrono::Duration::minutes(5),
                false,
            );
            // Deliberately NO code_challenge / code_challenge_method on purpose.
            authorization_code
        })
        .await
        .unwrap();

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![client],
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=codeless-code&redirect_uri={REDIRECT_URI}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant", "body: {body}");
    assert!(body.get("access_token").is_none(), "body: {body}");
}

/// The defect this whole claim-propagation change exists to fix: unlike the token-exchange grant
/// (`exchange_snapshots_email_claims_from_subject_token`), the browser `authorization_code` grant
/// has no upstream bearer token in hand at redemption time to decode claims from -- the
/// authorization code's own stored `Identity` carries no email either (`store_browser_code`'s
/// fixture above sets one only for a different, unrelated reason -- it is never read by
/// `mint_from_authorization_code`, see that function's own doc comment). Before this fix
/// `mint_from_authorization_code` hardcoded `KeyOwner { email: None, email_verified: None, .. }`
/// unconditionally, so a console login never carried a name/username/email no matter what
/// Keycloak's id-token had. The fix: `TokenExchangeOpStore::load_profile_claims` reads the
/// plaintext snapshot `KeycloakRelyingParty::persist_federated_identity` writes into
/// `federated_identities` at the login that created this session -- seeded here directly via
/// `upsert_federated_identity` rather than driving a real Keycloak-login round trip (that flow is
/// covered end-to-end by `relying_party_tests.rs`; this test isolates the minting half).
#[sqlx::test(migrations = "../../migrations")]
async fn browser_authorization_code_grant_mints_profile_claims_from_federated_identity(
    pool: PgPool,
) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    repo.upsert_federated_identity(
        UpsertFederatedIdentity {
            issuer: GRANDFATHER_ISSUER.to_string(),
            subject: SUBJECT.to_string(),
            token_envelope: None,
            token_sealed_at: None,
            access_expires_at: None,
            refresh_expires_at: None,
            scope: None,
            email: Some("console-user@example.test".to_string()),
            email_verified: Some(true),
            preferred_username: Some("console-handle".to_string()),
            name: Some("Console User".to_string()),
        },
        GRANDFATHER_ISSUER,
    )
    .await
    .expect("seed federated identity");

    store_browser_code(repo.clone(), "profile-code", CLIENT, REDIRECT_URI, VERIFIER).await;
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=profile-code&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let access_claims =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), CLIENT).await;
    assert_eq!(access_claims["email"], "console-user@example.test");
    assert_eq!(access_claims["email_verified"], true);
    assert_eq!(access_claims["preferred_username"], "console-handle");
    assert_eq!(access_claims["name"], "Console User");

    let id_claims = verify_id_token(&repo, body["id_token"].as_str().unwrap(), CLIENT).await;
    assert_eq!(id_claims["email"], "console-user@example.test");
    assert_eq!(id_claims["email_verified"], true);
    assert_eq!(id_claims["preferred_username"], "console-handle");
    assert_eq!(id_claims["name"], "Console User");
}

/// The other half of the same fix's fallback path: a subject with NO `federated_identities` row
/// at all (a session predating this feature, or a self-healed grandfather adoption that never ran
/// a real login) must still mint a token -- just one that omits the profile claims, never one that
/// fails the whole grant over a missing display string.
#[sqlx::test(migrations = "../../migrations")]
async fn browser_authorization_code_grant_omits_profile_claims_with_no_federated_identity_row(
    pool: PgPool,
) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    // Deliberately no `upsert_federated_identity` call -- no federated_identities row exists.

    store_browser_code(
        repo.clone(),
        "no-profile-code",
        CLIENT,
        REDIRECT_URI,
        VERIFIER,
    )
    .await;
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=no-profile-code&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let access_claims =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), CLIENT).await;
    for claim in ["email", "email_verified", "preferred_username", "name"] {
        assert!(
            access_claims.get(claim).is_none(),
            "{claim} must be omitted, not minted as null, with no federated_identities row: \
             {access_claims}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn token_endpoint_cors_is_exact_and_never_wildcarded(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const ORIGIN: &str = "https://dashboard.example.test";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let state = state_with(
        repo,
        Arc::new(MockBearer::new(true, vec![])),
        vec![browser_client(CLIENT, REDIRECT_URI)],
        &redis_url(),
    )
    .with_cors_origins(vec![ORIGIN.to_string()]);

    let response = token_response(state.clone(), "OPTIONS", "", Some(ORIGIN)).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        ORIGIN
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "POST"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "content-type"
    );
    assert_eq!(response.headers()[header::VARY], "Origin");

    let response = token_response(
        state.clone(),
        "POST",
        "grant_type=authorization_code&client_id=unknown",
        Some(ORIGIN),
    )
    .await;
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        ORIGIN
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");

    for origin in ["https://untrusted.example.test", "null"] {
        for (method, body) in [
            ("OPTIONS", ""),
            ("POST", "grant_type=authorization_code&client_id=unknown"),
        ] {
            let response = token_response(state.clone(), method, body, Some(origin)).await;
            assert!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none(),
                "disallowed origin {origin} received ACAO"
            );
            assert_eq!(response.headers()[header::VARY], "Origin");
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn authorize_rejects_unregistered_redirects_and_pkce_before_relying_party(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let router = authorize_router(AuthorizeState::new(
        relying_party(repo.clone()),
        state_with(
            repo,
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
    ));

    for redirect_uri in [
        "https://dashboard.example.test/oauth/callback/",
        "https://dashboard.example.test/oauth/callback?extra=value",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/authorize?client_id={CLIENT}&redirect_uri={redirect_uri}&response_type=code&scope=openid&code_challenge=challenge&code_challenge_method=S256"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    for pkce in ["", "&code_challenge=challenge&code_challenge_method=plain"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid{pkce}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with(REDIRECT_URI));
        assert!(location.contains("error=invalid_request"));
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }
}

/// Runtime proof for the defense-in-depth half of the PKCE fix (follow-up to PR #466): `/authorize`
/// now requires PKCE S256 unconditionally for every `authorization_code` client, never reading
/// `client.require_pkce` at all. Before this change, the endpoint enforced PKCE off that flag
/// alone with no `client_type` check -- so a Confidential client configured (however it got that
/// way -- a bad startup config that predated `validate_authorization_code_clients` covering
/// Confidential clients, or a future regression there) with `require_pkce: false` could start a
/// non-PKCE authorization_code flow. This client fixture is exactly that shape; the request omits
/// `code_challenge` entirely, and must still be refused.
#[sqlx::test(migrations = "../../migrations")]
async fn authorize_requires_pkce_for_confidential_clients_regardless_of_require_pkce_flag(
    pool: PgPool,
) {
    const CLIENT: &str = "confidential-browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let router = authorize_router(AuthorizeState::new(
        relying_party(repo.clone()),
        state_with(
            repo,
            Arc::new(MockBearer::new(true, vec![])),
            vec![confidential_browser_client_without_pkce(
                CLIENT,
                REDIRECT_URI,
            )],
            &redis_url(),
        ),
    ));

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with(REDIRECT_URI));
    assert!(location.contains("error=invalid_request"));
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn active_browser_session_authorizes_without_keycloak(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    let session_id = cuid2();
    repo.create_session(NewSession {
        id: session_id.clone(),
        account_id: ACCOUNT_ID.to_string(),
        project_id: PROJECT_ID.to_string(),
        client_id: None,
        kind: "browser".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        subject: Some(SUBJECT.to_string()),
    })
    .await
    .unwrap();
    let router = authorize_router(AuthorizeState::new(
        relying_party(repo.clone()),
        state_with(
            repo,
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
    ));

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid&state=client-state&code_challenge=challenge&code_challenge_method=S256"
                ))
                .header(header::COOKIE, format!("__Host-authz_session={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location =
        reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        location.origin().ascii_serialization(),
        "https://dashboard.example.test"
    );
    let params: HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert!(params.contains_key("code"));
    assert_eq!(
        params.get("state").map(String::as_str),
        Some("client-state")
    );
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}

/// OIDC Session Management 1.0 §3: a request that carries the `__Host-authz_op_state` cookie
/// (`session_management::OP_BROWSER_STATE_COOKIE`) alongside an active browser session gets
/// `session_state` appended to the authorization redirect (`authorize.rs`'s `issue_code` ->
/// `append_session_state`) -- extends `active_browser_session_authorizes_without_keycloak` above
/// (same session-resumed harness, no Keycloak round trip needed) with that cookie present. The
/// salt rides in cleartext after the `.` in `session_state`, so recomputing the hash with the
/// SAME client_id/origin/opbs/salt this request used -- via `session_management::session_state`,
/// the exact function `issue_code`'s `fresh_session_state` wraps -- proves the value is not just
/// present but the RIGHT one, not merely well-formed.
///
/// Prove-fail-first (recorded verbatim, then reverted): commented out the
/// `session_state = op_browser_state.and_then(...)` computation's use in `authorize.rs`'s
/// `issue_code` (forcing `session_state: None` unconditionally), reran just this test. It failed
/// on `.expect("a request carrying the OP browser-state cookie must get session_state
/// appended")` -- the redirect had no `session_state` query param at all. Restored the line.
#[sqlx::test(migrations = "../../migrations")]
async fn authorize_appends_session_state_when_op_browser_state_cookie_present(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const OPBS: &str = "opbs-test-value-not-a-secret";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    let session_id = cuid2();
    repo.create_session(NewSession {
        id: session_id.clone(),
        account_id: ACCOUNT_ID.to_string(),
        project_id: PROJECT_ID.to_string(),
        client_id: None,
        kind: "browser".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        subject: Some(SUBJECT.to_string()),
    })
    .await
    .unwrap();
    let router = authorize_router(AuthorizeState::new(
        relying_party(repo.clone()),
        state_with(
            repo,
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
    ));

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid&state=client-state&code_challenge=challenge&code_challenge_method=S256"
                ))
                .header(
                    header::COOKIE,
                    format!("__Host-authz_session={session_id}; __Host-authz_op_state={OPBS}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location =
        reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let session_state_param = location
        .query_pairs()
        .find_map(|(key, value)| (key == "session_state").then(|| value.into_owned()))
        .expect("a request carrying the OP browser-state cookie must get session_state appended");
    let salt = session_state_param
        .rsplit('.')
        .next()
        .expect("session_state is salt-suffixed");
    let expected = lightbridge_authz_rest::session_management::session_state(
        CLIENT,
        "https://dashboard.example.test",
        OPBS,
        salt,
    );
    assert_eq!(
        session_state_param, expected,
        "session_state must hash client_id + the redirect_uri's ORIGIN + the OP browser-state \
         cookie's value + its own salt"
    );
}

/// Code-review follow-up to #463/#466/#467 (Finding B): the eventual access token's `sub` claim
/// must be the REAL authenticated subject (`sessions.subject`), never `session.account_id`.
/// `resolve_context` (`crates/lightbridge-authz-api-key/src/repo.rs`) always resolves
/// `account_id` to the project's OWNING account -- here, `OWNER_ACCOUNT` -- even though `SUBJECT`
/// only holds a `project_members` roster row, not ownership (`seed_member_project`). Proof this
/// test catches the regression: reverting `issue_code` in `authorize.rs` to mint
/// `external_id: account_id` (the pre-fix code, before the `subject` parameter was threaded
/// through) makes `claims.sub` come back `OWNER_ACCOUNT` instead of `SUBJECT`, failing this
/// test's first assertion.
#[sqlx::test(migrations = "../../migrations")]
async fn authorize_with_existing_session_mints_the_real_subject_not_the_owner_account(
    pool: PgPool,
) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed_member_project(&repo).await;
    let session_id = cuid2();
    repo.create_session(NewSession {
        id: session_id.clone(),
        account_id: OWNER_ACCOUNT.to_string(),
        project_id: MEMBER_PROJECT_ID.to_string(),
        client_id: None,
        kind: "browser".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        subject: Some(SUBJECT.to_string()),
    })
    .await
    .unwrap();
    let clients = vec![browser_client(CLIENT, REDIRECT_URI)];
    let router = authorize_router(AuthorizeState::new(
        relying_party(repo.clone()),
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients.clone(),
            &redis_url(),
        ),
    ));

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid&state=client-state&code_challenge={}&code_challenge_method=S256",
                    s256_challenge(VERIFIER)
                ))
                .header(header::COOKIE, format!("__Host-authz_session={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location =
        reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let code = location
        .query_pairs()
        .find_map(|(k, v)| (k == "code").then(|| v.into_owned()))
        .expect("authorize issues a code for the active session");

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients,
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code={code}&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // The `authorization_code` grant mints via `TokenManager::issue_user_token` with no `extra`
    // claims (authkestra-op's `handle_authorization_code`), so `account_id`/`project_id` live
    // under the nested `identity.attributes` object `issue_code` populated -- not top-level
    // Decoded loosely rather than through the typed `AccessClaims`. That was originally because
    // an authorization_code token lacked `api_key_id`; since #524 it has one (this grant mints
    // through the same `access_token_extra` as the others), but the loose decode is kept so this
    // test asserts the wire shape directly rather than whatever the struct happens to model.
    let claims =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), CLIENT).await;
    assert_eq!(
        claims["sub"], SUBJECT,
        "sub must be the real authenticated member, not the project owner: {claims}"
    );
    // #524: the browser grant now mints through `mint_human_plane_tokens`, the same path every
    // other grant uses, so tenant context is a TOP-LEVEL claim (`access_token_extra`) rather than
    // nested under `identity.attributes`. The nesting was an artifact of authkestra's default
    // handler passing the authorization code's stored identity through verbatim; it never matched
    // what the exchange or device grants produced, and it is not what authz-api/Authorino read.
    assert_eq!(
        claims["account_id"], OWNER_ACCOUNT,
        "account_id still correctly resolves to the OWNING account, not the acting member: \
         {claims}"
    );
    assert_eq!(claims["project_id"], MEMBER_PROJECT_ID);
}

/// Code-review follow-up to #463/#466/#467 (Finding E, positive path): when a request's
/// `project_id` differs from the project an existing browser session is pinned to, `/authorize`
/// must NOT silently issue a code scoped to the session's own project -- it must re-resolve
/// authorization for the REQUESTED project and issue for that instead. Proof this test catches
/// the regression: reverting `authorize.rs` to always call
/// `issue_code(&state, request, subject, session.account_id, session.project_id)` regardless of
/// the request's `project_id` (the pre-fix behavior) makes the decoded access token's
/// `project_id` come back `PROJECT_ID` instead of `SECOND_PROJECT_ID`, failing this test's
/// assertion.
#[sqlx::test(migrations = "../../migrations")]
async fn authorize_reresolves_context_when_request_project_differs_from_session(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";
    const SECOND_PROJECT_ID: &str = "proj_second";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    repo.create_project(
        &AccountId::assert_already_resolved(SUBJECT),
        ACCOUNT_ID,
        CreateProject {
            name: "second project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: format!("bill-{}", cuid2()),
            project_quota: None,
        },
        SECOND_PROJECT_ID.to_string(),
    )
    .await
    .expect("seed second project owned by the same subject");

    let session_id = cuid2();
    repo.create_session(NewSession {
        id: session_id.clone(),
        account_id: ACCOUNT_ID.to_string(),
        project_id: PROJECT_ID.to_string(),
        client_id: None,
        kind: "browser".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        subject: Some(SUBJECT.to_string()),
    })
    .await
    .unwrap();

    let clients = vec![browser_client(CLIENT, REDIRECT_URI)];
    let router = authorize_router(AuthorizeState::new(
        relying_party(repo.clone()),
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients.clone(),
            &redis_url(),
        ),
    ));

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid&state=client-state&code_challenge={}&code_challenge_method=S256&project_id={SECOND_PROJECT_ID}",
                    s256_challenge(VERIFIER)
                ))
                .header(header::COOKIE, format!("__Host-authz_session={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location =
        reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let code = location
        .query_pairs()
        .find_map(|(k, v)| (k == "code").then(|| v.into_owned()))
        .expect("a code for the requested (second) project, not silently the session's own");

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            clients,
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code={code}&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // #524: tenant context is a top-level claim on every grant now, including this one -- see
    // the sibling test's comment for why the old `identity.attributes` nesting went away.
    let claims =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), CLIENT).await;
    assert_eq!(
        claims["project_id"], SECOND_PROJECT_ID,
        "requesting a different project than the session's must not silently issue for the \
         session's own project: {claims}"
    );
}

/// Code-review follow-up to #463/#466/#467 (Finding E, negative path): a request naming a
/// `project_id` the session's subject is NOT authorized for must be refused outright, not fall
/// back to issuing a code for the session's own project. Proof this test catches the regression:
/// reverting `authorize.rs` to ignore `project_id` once a session exists (the pre-fix behavior)
/// would make this request instead succeed with a `code` scoped to `PROJECT_ID`, failing the
/// `!params.contains_key("code")` assertion below.
#[sqlx::test(migrations = "../../migrations")]
async fn authorize_refuses_when_requested_project_is_not_authorized_for_the_session_subject(
    pool: PgPool,
) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";
    const UNRELATED_ACCOUNT: &str = "unrelated-account-e";
    const UNRELATED_PROJECT: &str = "unrelated-project-e";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    repo.create_account(
        &AccountId::assert_already_resolved(UNRELATED_ACCOUNT),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &AccountId::assert_already_resolved(UNRELATED_ACCOUNT),
        UNRELATED_ACCOUNT,
        CreateProject {
            name: "unrelated project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: format!("bill-{}", cuid2()),
            project_quota: None,
        },
        UNRELATED_PROJECT.to_string(),
    )
    .await
    .unwrap();

    let session_id = cuid2();
    repo.create_session(NewSession {
        id: session_id.clone(),
        account_id: ACCOUNT_ID.to_string(),
        project_id: PROJECT_ID.to_string(),
        client_id: None,
        kind: "browser".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        subject: Some(SUBJECT.to_string()),
    })
    .await
    .unwrap();

    let router = authorize_router(AuthorizeState::new(
        relying_party(repo.clone()),
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
    ));

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid&state=client-state&code_challenge={}&code_challenge_method=S256&project_id={UNRELATED_PROJECT}",
                    s256_challenge(VERIFIER)
                ))
                .header(header::COOKIE, format!("__Host-authz_session={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location =
        reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        location.origin().ascii_serialization(),
        "https://dashboard.example.test"
    );
    let params: HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("error").map(String::as_str),
        Some("access_denied")
    );
    assert!(
        !params.contains_key("code"),
        "must never silently issue a code for a project the subject isn't authorized for"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_browser_session_falls_back_to_relying_party_login(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(serde_json::json!({
                "issuer": keycloak.base_url(),
                "authorization_endpoint": keycloak.url("/authorize"),
                "token_endpoint": keycloak.url("/token"),
                "jwks_uri": keycloak.url("/jwks")
            }));
        })
        .await;
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let router = authorize_router(AuthorizeState::new(
        relying_party_with_issuer(repo.clone(), &keycloak.base_url()),
        state_with(
            repo,
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
    ));

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/authorize?client_id={CLIENT}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid&code_challenge=challenge&code_challenge_method=S256"
                ))
                .header(header::COOKIE, "__Host-authz_session=missing-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .starts_with(&keycloak.url("/authorize"))
    );
    assert!(response.headers().get(header::SET_COOKIE).is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn unknown_client_id_is_rejected(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id=never-registered&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[sqlx::test(migrations = "../../migrations")]
async fn confidential_client_with_valid_assertion_authenticates(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
             &client_assertion={assertion}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn confidential_client_with_missing_assertion_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={CONFIDENTIAL_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[sqlx::test(migrations = "../../migrations")]
async fn confidential_client_with_bad_assertion_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
             &client_assertion={bad_assertion}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
         &client_assertion={assertion}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
             &client_assertion={assertion}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_a}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_b}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims_b =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), client_b).await;
    assert_eq!(claims_b["aud"], client_b);

    assert_ne!(claims_a["aud"], claims_b["aud"]);
}

// ============================================================================================
// #421: `access_token_extra` (`crate::signing`) is shared by `ApiKeyJwtSigner::sign` (real
// self-signed API-key JWTs) and `TokenExchangeOpStore::handle_token_exchange`/
// `handle_refresh_token` (native RFC 8693 human-plane exchange tokens). Both paths stamp
// identical `api_key_id`/`sid`/`lightbridge_caller_kind` shapes -- ADR-0020 Decision 2 / #437's
// own scoped-down interpretation deliberately keeps it that way for now, because
// `ai-helm-values`' Authorino `when` gates trigger introspection on `api_key_id != ""`, and
// emptying/renaming that claim on the exchange path without a coordinated, VERIFIED-DEPLOYED
// gateway change would silently stop introspection from ever running for these tokens -- a
// regression worse than the claim-reuse itself (see `access_token_extra`'s own doc comment).
// This repo's own consumers of "is this really an API key" (`handlers/opa.rs`'s
// `verify_self_issued_token`, and every `ai-helm-values` `when` gate that reads `azp`) do NOT
// use `api_key_id`/`sid`/`lightbridge_caller_kind` to draw that line -- they use `azp`. This test
// pins that as the real, load-bearing discriminant: mints one real API-key JWT and one real
// exchange access token through their actual production signing paths, and proves `azp` reliably
// tells them apart even though every other tenant-ish claim is identical in shape.
// ============================================================================================

/// The one claim that actually, reliably distinguishes a real self-signed API-key JWT from a
/// native-exchange human-plane token today: `azp`. A self-signed API-key JWT's `azp` is always
/// the FIXED `oauth2.signing.audience` config value (`ApiKeyJwtSigner::sign` passes
/// `self.audience.as_deref()`); an exchange token's `azp` is always the requesting OAuth2
/// client's `client_id`, which by deployment convention (`Oauth2TokenExchange::clients`) is never
/// registered under the API-key audience. `api_key_id`/`sid`/`lightbridge_caller_kind` are, by
/// contrast, proven here to be identical in shape on both -- the still-open half of #421's scope,
/// tracked and NOT closed by this test (see this section's own doc comment for why).
#[sqlx::test(migrations = "../../migrations")]
async fn azp_reliably_distinguishes_a_real_api_key_jwt_from_a_real_exchange_session_token(
    pool: PgPool,
) {
    const API_KEY_AUDIENCE: &str = "lightbridge-api-key";
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    // Real self-signed API-key JWT, minted through the actual `ApiKeyJwtSigner::sign` production
    // path -- not a hand-built claim set.
    let api_key_signing_cfg = JwtSigning {
        issuer: ISSUER.to_string(),
        audience: Some(API_KEY_AUDIENCE.to_string()),
        ttl_seconds: 3600,
        max_key_age_days: 30,
        claim_mappers: Vec::new(),
    };
    let signer = ApiKeyJwtSigner::from_config(&api_key_signing_cfg, repo.clone()).unwrap();
    let owner = KeyOwner {
        subject: SUBJECT.to_string(),
        account_id: SUBJECT.to_string(),
        email: None,
        email_verified: None,
        ..Default::default()
    };
    let signed = signer
        .sign(
            &owner,
            "key_1",
            PROJECT_ID,
            ACCOUNT_ID,
            None,
            chrono::Utc::now(),
            None,
        )
        .await
        .unwrap();
    let api_key_claims = decode_access_token_claims(&repo, &signed.token, API_KEY_AUDIENCE).await;

    // Real human-plane exchange access token, minted through the actual RFC 8693
    // `TokenExchangeOpStore::handle_token_exchange` production path, driven over the real HTTP
    // `token_exchange_router` -- not a hand-built claim set either.
    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let exchange_claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;

    // The load-bearing discriminant: `azp` never collides between the two mint paths, by
    // deployment convention (`PUBLIC_CLIENT_ID` is never registered as the API-key audience).
    assert_eq!(api_key_claims["azp"], API_KEY_AUDIENCE);
    assert_eq!(exchange_claims["azp"], PUBLIC_CLIENT_ID);
    assert_ne!(
        api_key_claims["azp"], exchange_claims["azp"],
        "azp must reliably tell a real API-key JWT apart from a real exchange token: \
         api_key={api_key_claims}, exchange={exchange_claims}"
    );

    // The still-open half of #421: every other tenant-shaped claim is identical, by design, for
    // now (ADR-0020 Decision 2 / #437's scoped-down interpretation) -- documented here, not
    // silently assumed, so a future full claim-separation (#421's remaining scope) has a test to
    // update rather than a surprise to discover.
    assert!(
        !api_key_claims["api_key_id"].as_str().unwrap().is_empty(),
        "api_key_id must be present on the API-key path: {api_key_claims}"
    );
    assert!(
        !exchange_claims["api_key_id"].as_str().unwrap().is_empty(),
        "api_key_id is still stamped (with a session id, not a real api_keys.id) on the exchange \
         path -- #421's known, deliberate, not-yet-closed scope: {exchange_claims}"
    );
    assert_eq!(
        api_key_claims["lightbridge_caller_kind"], exchange_claims["lightbridge_caller_kind"],
        "lightbridge_caller_kind is still conflated between the two mint paths -- #421's known, \
         deliberate, not-yet-closed scope (harmless today because #419 deleted the one procedure \
         that read it for a security decision): api_key={api_key_claims}, \
         exchange={exchange_claims}"
    );
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn subject_token_aud_not_naming_the_requesting_client_is_invalid_grant(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// ADR-0025 Stage 2 -- THE security test for this grant, mirroring
/// `federated_subject_resolution_tests.rs`'s `a_second_issuer_presenting_the_same_subject_is_refused_not_merged`
/// at the token-exchange ingress: `SUBJECT` here is a REAL, seeded account id (`seed(&repo)`
/// already created it and gave it `PROJECT_ID`) -- if `handle_token_exchange` skipped
/// `resolve_account_for_federated_subject` and trusted `token_info.sub` directly, this request
/// would succeed outright (SUBJECT genuinely owns PROJECT_ID), which is exactly why this scenario
/// -- an UNTRUSTED issuer presenting an otherwise-valid subject value -- is the one that actually
/// proves resolution happens at THIS seam, not merely that some downstream check happens to
/// reject an accountless subject too (which it also would, redundantly, but that redundancy
/// would mask a skipped resolver call in a weaker test).
#[sqlx::test(migrations = "../../migrations")]
async fn exchange_refuses_when_the_subject_has_no_federated_identity(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let state = state_with(
        repo.clone(),
        Arc::new(
            MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])
                .with_subject(SUBJECT, "https://untrusted-issuer.example"),
        ),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a subject value presented by an untrusted issuer must be refused even though the SAME \
         subject value genuinely owns this project under the trusted issuer: {body}"
    );
    assert_eq!(body["error"], "access_denied");
    assert!(body.get("access_token").is_none());
}

/// THE non-leaking-oracle test for the token-exchange grant, mirroring `opa_tests`'s identically-
/// named-in-spirit `returns_404_not_403_for_an_unfederated_subject`: a resolver refusal (no
/// federated identity) and a genuine "not a member of this project" refusal (a real account with
/// no standing on the requested project) must produce byte-identical error responses -- same
/// status, same body -- so a client can never distinguish "this subject doesn't exist to us" from
/// "this subject exists but isn't authorized here".
#[sqlx::test(migrations = "../../migrations")]
async fn an_unfederated_subject_and_a_non_member_produce_byte_identical_error_responses(
    pool: PgPool,
) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    // A second, unrelated project SUBJECT holds no standing on at all.
    let other_owner = format!("other-owner-{}", cuid2());
    repo.create_account(
        &AccountId::assert_already_resolved(other_owner.clone()),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .unwrap();
    let other_project = format!("other-project-{}", cuid2());
    repo.create_project(
        &AccountId::assert_already_resolved(other_owner.clone()),
        &other_owner,
        CreateProject {
            name: "unrelated".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: format!("bill-{}", cuid2()),
            project_quota: None,
        },
        other_project.clone(),
    )
    .await
    .unwrap();

    let unfederated_state = state_with(
        repo.clone(),
        Arc::new(
            MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])
                .with_subject("kc-sub-with-no-account", GRANDFATHER_ISSUER),
        ),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
    );
    let (unfederated_status, unfederated_body) = post_token(
        unfederated_state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    // SUBJECT is a real, federation-resolvable account -- just not a member of `other_project`.
    let non_member_state = state(repo.clone(), true);
    let (non_member_status, non_member_body) = post_token(
        non_member_state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={other_project}"
        ),
    )
    .await;

    assert_eq!(
        unfederated_status, non_member_status,
        "unfederated: {unfederated_body}, non-member: {non_member_body}"
    );
    assert_eq!(
        unfederated_body, non_member_body,
        "an unfederated subject and a genuine non-member must be indistinguishable on the wire"
    );
}

// ============================================================================================
// Tenant claims / role-quota exclusion (ADR-0011, Decision 7). `quota_tier` is narrower than the
// test name now suggests: as of ADR-0017 it CAN appear on the access token when resolvable (see
// the ADR-0017 test block later in this file) -- what this test actually pins is `seed`'s
// specific fixture, where SUBJECT owns `PROJECT_ID` directly and therefore holds no
// `project_members` row on it, the "resolved, legitimately absent" outcome ADR-0017 calls outcome
// 2. `role`/`project_quota` remain unconditionally excluded from both tokens, unaffected by
// ADR-0017 -- see that ADR's Decision 1 Context for why only `quota_tier` earns the carve-out.
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn tenant_claims_on_access_token_role_and_quota_absent_from_both(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=openid"
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
// #419: `request_budget_refill` used to refuse any caller whose token carried
// `lightbridge_caller_kind: api_key` (#191/#216). `access_token_extra` -- shared by
// `ApiKeyJwtSigner::sign` AND this file's own `handle_token_exchange`/`handle_refresh_token`
// grants -- stamps that claim unconditionally, so it fired on humans too. The tests that shipped
// alongside the original gate never caught this because they built a `CratestackContext` by hand
// rather than minting a token through this real signing path (see #419's own investigation). The
// test below mints one for real, decodes it for real, and proves both halves: the stale signal is
// present, and it no longer changes the outcome.
// ============================================================================================

/// A `schema::Cratestack` lazily wired to an unreachable address -- `Procedures::request_budget_refill`
/// takes `_db: &schema::Cratestack` but never uses it (it delegates entirely to `RefillService`),
/// matching the identical pattern in `budget_refill_procedure_tests.rs::lazy_cratestack_db`.
fn lazy_cratestack_db() -> schema::Cratestack {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy cratestack pool should be constructible");
    schema::Cratestack::builder(pool).build()
}

/// #419's own required regression: mints a genuine human-plane access token through
/// `TokenExchangeOpStore::handle_token_exchange` (the real RFC 8693 exchange
/// `oauth2_op/store.rs` handler backing `POST /oauth2/token`, driven here through the real
/// `token_exchange_router` over HTTP, not called directly) rather than constructing a
/// `CratestackContext` by hand, then feeds that same real token's decoded claims into
/// `request_budget_refill`.
///
/// Two things are asserted:
/// 1. `lightbridge_caller_kind` on the REAL token really is `"api_key"` -- the empirical premise
///    #419 is built on, never previously asserted against a human-plane mint anywhere in this
///    suite (only against `ApiKeyJwtSigner`-minted API-key JWTs, in `signing_tests.rs`).
/// 2. `request_budget_refill`, built from a `CratestackContext` whose `id`/caller-kind extension
///    come from that real token's own decoded claims (not hand-typed), still accepts the call.
///
/// One field is *not* sourced from the real token: `permissions`. This exchanged access token
/// carries no RBAC roles claim at all -- `access_token_extra` never stamps one, on either the
/// exchange or the API-key-signing path -- so there is no real claim to decode `budget:self-refill`
/// out of here. Granting it explicitly is the one deliberate departure from "fully real" in this
/// test; it is orthogonal to the bug #419 fixes (a caller_kind check, not a permission-mapping
/// one) and is the same `Permission` set every other direct-`Procedures`-call test in this crate
/// already grants by hand (see `budget_refill_procedure_tests.rs`'s own `ctx_for`).
#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_accepts_a_real_human_plane_token_that_still_carries_the_stale_api_key_signal(
    pool: PgPool,
) {
    let repo = repo(pool.clone());
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange must succeed: {body}"
    );
    let access_token = body["access_token"]
        .as_str()
        .expect("a successful exchange returns an access_token")
        .to_string();

    let access_claims = decode_access_token_claims(&repo, &access_token, PUBLIC_CLIENT_ID).await;
    let real_sub = access_claims["sub"]
        .as_str()
        .expect("access token carries sub")
        .to_string();
    let real_caller_kind = access_claims
        .get("lightbridge_caller_kind")
        .and_then(Value::as_str)
        .map(str::to_owned);
    assert_eq!(
        real_caller_kind.as_deref(),
        Some(lightbridge_authz_bearer::API_KEY_CALLER_KIND),
        "premise check: a REAL human-plane RFC 8693 exchange token must carry the same \
         `lightbridge_caller_kind: api_key` signal an API-key JWT does -- {access_claims}"
    );

    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    let issuer = Arc::new(AuthzStoreImpl::with_pool(db_pool.clone()));
    let policy_store = Arc::new(
        PolicyStore::load_active_from_db(db_pool.clone(), "budget-refill", 10_000)
            .await
            .expect("migrations seed an active budget-refill revision"),
    );
    let budget_repo = Arc::new(BudgetRepo::new(db_pool.clone()));
    let augmentation_repo = Arc::new(AugmentationRepo::new(db_pool));
    let refill_service = Arc::new(RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_store.engine(),
        Arc::new(UnavailableSpendReader),
    ));
    let review_service = Arc::new(ReviewService::new(budget_repo.clone(), augmentation_repo));
    let procedures = Procedures::new(
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
    );

    // Every field below traces to the real token decoded above, except `permissions` -- see this
    // test's own doc comment for why that one field is granted directly.
    let token_info = TokenInfo {
        active: true,
        sub: real_sub.clone(),
        iss: ISSUER.to_string(),
        exp: 0,
        aud: vec![],
        roles: vec![],
        permissions: [Permission::BudgetSelfRefill].into_iter().collect(),
        caller_kind: real_caller_kind,
        access_token: access_token.clone(),
    };
    let ctx: CratestackContext =
        build_context(&token_info, RpcScope::Budget, &TrustEverythingResolver)
            .await
            .expect("the trust-everything test resolver never refuses");
    let cratestack_db = lazy_cratestack_db();

    let args = schema::procedures::request_budget_refill::Args {
        args: schema::RequestBudgetRefillInput {
            budgetAccountId: real_sub.clone(),
            accountId: real_sub,
            projectId: None,
            period: "2026-08".to_string(),
            idempotencyKey: None,
            requestedAmountMicros: "15000000".to_string(),
        },
    };
    let output = call_request_budget_refill(&procedures, &cratestack_db, &ctx, args)
        .await
        .expect(
            "a human-plane caller holding budget:self-refill must be accepted, regardless of the \
             stale api_key caller-kind signal on their real token",
        );

    assert_eq!(output.status, "auto_approved");
}

/// Mirrors `budget_refill_procedure_tests.rs`'s own `request_refill` helper: cratestack#512's
/// `ProcedureRegistry` methods require an `Authorized` witness only `authorize_with_db`/
/// `invoke_with_db` can produce, so this runs that (trivial, `@allow(auth() != null)`) check
/// before invoking the hand-written procedure body, exactly like the generated RPC dispatch
/// handler does for a real request. Taking `db`/`ctx` by reference (rather than closing over
/// owned locals) is what lets the `async move` closure below capture them as `Copy` references
/// instead of trying to move the caller's only copies into it.
async fn call_request_budget_refill(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::request_budget_refill::Args,
) -> Result<schema::procedures::request_budget_refill::Output, cratestack::CratestackError> {
    let call_args = args.clone();
    schema::procedures::request_budget_refill::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .request_budget_refill(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

// ============================================================================================
// Refresh tokens: client binding (ADR-0011 phase 2 migration) + both client types can obtain one.
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_token_issued_to_client_a_is_rejected_when_presented_by_client_b(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_a}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
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

/// `oauth2_op::refresh_refusal` logs a distinct server-side `reason` per refusal cause, but the
/// WIRE response must be byte-identical regardless -- distinguishing refusal reasons on the wire
/// would be an oracle telling an attacker whether a given presented token ever existed. Compares
/// two genuinely different causes (an unknown/never-issued token vs. a real token presented by
/// the wrong client) end to end through the real `/oauth2/token` handler.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_refusal_reason_never_leaks_onto_the_wire(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let client_a = "wire-client-a";
    let client_b = "wire-client-b";
    let redis = redis_url();
    let clients = || vec![public_client(client_a), public_client(client_b)];

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![client_a.to_string()])),
            clients(),
            &redis,
        ),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_a}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // Reason A: an unknown/garbage token that was never issued at all.
    let (unknown_status, unknown_body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![client_a.to_string()])),
            clients(),
            &redis,
        ),
        &format!(
            "grant_type=refresh_token&client_id={client_a}&refresh_token=lgbr_rt_never_issued"
        ),
    )
    .await;

    // Reason B: a genuinely issued token, but presented by a different client than the one it was
    // bound to.
    let (wrong_client_status, wrong_client_body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![client_b.to_string()])),
            clients(),
            &redis,
        ),
        &format!("grant_type=refresh_token&client_id={client_b}&refresh_token={refresh_token}"),
    )
    .await;

    assert_eq!(
        unknown_status,
        StatusCode::BAD_REQUEST,
        "body: {unknown_body}"
    );
    assert_eq!(
        wrong_client_status,
        StatusCode::BAD_REQUEST,
        "body: {wrong_client_body}"
    );
    assert_eq!(
        unknown_status, wrong_client_status,
        "different server-side refusal reasons must not differ in HTTP status"
    );
    assert_eq!(
        unknown_body, wrong_client_body,
        "different server-side refusal reasons must produce a byte-identical wire response body \
         -- distinguishing them would be an oracle for whether a token ever existed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn both_public_and_confidential_clients_can_obtain_a_refresh_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    // Public.
    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_claims = verify_refresh_token(&repo, body["refresh_token"].as_str().unwrap()).await;
    assert_eq!(refresh_claims.aud, "lightbridge-refresh");
    assert_eq!(refresh_claims.typ, "Refresh");

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
             &client_assertion={assertion}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_claims = verify_refresh_token(&repo, body["refresh_token"].as_str().unwrap()).await;
    assert_eq!(refresh_claims.aud, "lightbridge-refresh");
    assert_eq!(refresh_claims.typ, "Refresh");
}

// ============================================================================================
// Everything below re-ports phase-1 coverage onto the new dispatch (client_id now required on
// every request).
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_mints_project_scoped_jwt_with_refresh(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}\
             &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=upstream-kc-token&project_id={PROJECT_ID}&scope=openid+offline_access"
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
    // The refresh token is now an RS256 JWT (was: an opaque `lgbr_rt_<random>` string) --
    // signed with the same active key the access token above verifies against, carrying the
    // exact claim set `oauth2_op::refresh_token::mint_refresh_jwt` stamps.
    let refresh_claims = verify_refresh_token(&repo, refresh).await;
    assert_eq!(refresh_claims.sub, ACCOUNT_ID);
    assert_eq!(refresh_claims.aud, "lightbridge-refresh");
    assert_eq!(refresh_claims.typ, "Refresh");
    assert!(!refresh_claims.jti.is_empty());
    assert!(!refresh_claims.sid.is_empty());
    // `jti` must be the ACTUAL `exchange_refresh_tokens` row id, not merely non-empty -- this is
    // what lets the DB row and the JWT agree on identity (spec requirement, `refresh_token.rs`'s
    // doc comment).
    let row = repo
        .find_exchange_refresh_token_by_hash(&hash_api_key(refresh))
        .await
        .unwrap()
        .expect("refresh token row exists");
    assert_eq!(refresh_claims.jti, row.id);
    assert_eq!(refresh_claims.sid, row.session_id);

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
async fn token_endpoint_responses_are_never_stored(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, headers, body) = post_token_response(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}\
             &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token\
             &subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");

    let (status, headers, body) = post_token_response(
        state(repo, true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x\
             &project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_without_offline_scope_has_no_refresh_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=openid"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id=proj_does_not_exist"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error"], "access_denied");
}

/// Code-review follow-up to #472 (drive-by finding, now folded into that same PR): unlike
/// `issue_device_tokens` and `handle_refresh_token`, `handle_token_exchange` had NO
/// account/project Active-status check at all -- `resolve_context` alone only checks
/// ownership/membership, not status. This matters more than a symmetric gap: per this repo's
/// docs, `TokenExchangeOpStore` is "the actual token-issuing authority for `authz-idp`'s `POST
/// /oauth2/token`" -- i.e. the RFC 8693 exchange is the PRIMARY human-plane token grant. Proof
/// this test catches the regression: reverting `handle_token_exchange`'s new
/// `require_active_project_and_account` call (and the `Err` branch that follows it) back out
/// makes this request return `200 OK` with a live access token instead of `403 access_denied`.
#[sqlx::test(migrations = "../../migrations")]
async fn exchange_after_project_suspended_is_access_denied(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    repo.set_project_status(
        &AccountId::assert_already_resolved(SUBJECT),
        PROJECT_ID,
        ResourceStatus::Suspended,
    )
    .await
    .expect("owner suspends the project");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a suspended project must not be able to obtain a fresh access token via token exchange: {body}"
    );
    assert_eq!(body["error"], "access_denied");
    assert!(body.get("access_token").is_none());
}

/// Code-review follow-up to #472, account half of the same gap -- see
/// `exchange_after_project_suspended_is_access_denied`'s doc comment for the full rationale.
/// Proof this test catches the regression: same mechanism, reverting the same check makes this
/// request return `200 OK` with a live access token for a SUSPENDED account instead of `403
/// access_denied`.
#[sqlx::test(migrations = "../../migrations")]
async fn exchange_after_account_suspended_is_access_denied(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    repo.set_account_status(
        &AccountId::assert_already_resolved(SUBJECT),
        ACCOUNT_ID,
        ResourceStatus::Suspended,
    )
    .await
    .expect("owner suspends the account");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a suspended account must not be able to obtain a fresh access token via token exchange: {body}"
    );
    assert_eq!(body["error"], "access_denied");
    assert!(body.get("access_token").is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_with_inactive_subject_token_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), false),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "subject_token is invalid");
}

/// `seed()` gives `SUBJECT` a single project (`PROJECT_ID`), which the
/// `projects_set_is_default` trigger therefore marks as that account's default -- so an omitted
/// `project_id` must resolve to exactly it (`StoreRepo::find_default_project_id`), and the minted
/// access token's `project_id` claim must reflect that resolution, not just a bare 200.
#[sqlx::test(migrations = "../../migrations")]
async fn missing_project_id_resolves_caller_default_project(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x"),
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    // Deliberately account-only: create_account never provisions a project by itself (that is a
    // separate "ensure default project" bootstrap call), so this subject legitimately has zero
    // projects and therefore no default to fall back to.
    repo.create_account(
        &AccountId::assert_already_resolved(SUBJECT),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .expect("seed account");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error"], "access_denied");
}

/// Uses [`state_no_reuse_grace`], not [`state`]: the final replay below is presented immediately
/// after rotation, which the real default `refresh_reuse_grace_seconds` (30s) would treat as a
/// graced replay (200 OK, a fresh pair) rather than the strict `invalid_grant` this test asserts
/// -- see `refresh_reuse_grace_within_window_mints_a_fresh_pair_without_cascading` and friends,
/// below, for the grace-window behavior itself.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_rotates_and_rejects_replay(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first_refresh = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first_refresh}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("issued_token_type").is_none(),
        "refresh responses must not claim to be RFC 8693 token-exchange responses: {body}"
    );
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
        state_no_reuse_grace(repo.clone(), true),
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}\
             &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token\
             &project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "subject_token is required");
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_subject_token_type_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token=x\
             &project_id={PROJECT_ID}"
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
async fn unsupported_subject_token_type_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
async fn bearer_validation_error_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "subject_token is invalid");
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["error"], "server_error");
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_refresh_token_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "refresh_token is required");
}

/// `state.signer.token_manager()` (which every grant type dispatches through, `token_exchange.rs`
/// lines 260/425/551 -- built once per request before `handle_refresh_token` or any of this
/// module's JWT verification ever runs) itself hits the unreachable repo first, fetching the
/// active signing key. So this proves fail-closed behavior at that earlier gate, unaffected by
/// the refresh-token JWT change: the presented value below is never even parsed.
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
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x\
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"email":"owner@example.test","email_verified":true}"#);
    let subject_token = format!("h.{payload}.s");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token={subject_token}\
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

/// `preferred_username`/`name`'s own version of `exchange_snapshots_email_claims_from_subject_token`
/// above: the token-exchange grant decodes them straight off the presented `subject_token`
/// (`decode_profile_claims`, `oauth2_op::mod`), same as `email`/`email_verified` already did.
/// Asserted via the untyped claim set (`decode_access_token_claims`) since `AccessClaims` has no
/// field for either -- `signing_tests.rs` already covers the typed shape at the `ApiKeyJwtSigner`
/// layer.
#[sqlx::test(migrations = "../../migrations")]
async fn exchange_snapshots_name_and_preferred_username_claims_from_subject_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let subject_token = subject_token_with_claims(&serde_json::json!({
        "preferred_username": "owner-handle",
        "name": "Owner Name",
    }));

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token={subject_token}\
             &project_id={PROJECT_ID}&scope=openid+profile"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(claims["preferred_username"], "owner-handle");
    assert_eq!(claims["name"], "Owner Name");

    let id_token = body["id_token"]
        .as_str()
        .expect("openid was granted, so an id_token must be issued");
    let id_claims = verify_id_token(&repo, id_token, PUBLIC_CLIENT_ID).await;
    assert_eq!(id_claims["preferred_username"], "owner-handle");
    assert_eq!(id_claims["name"], "Owner Name");
}

#[sqlx::test(migrations = "../../migrations")]
async fn exchange_tolerates_a_subject_token_with_an_unparsable_payload_segment(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}\
             &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=h.not-valid-base64!!!.s&project_id={PROJECT_ID}"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
    let subject_token = format!("h.{payload}.s");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token={subject_token}\
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=openid"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=profile"
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let subject_token = subject_token_with_claims(&serde_json::json!({
        "auth_time": 1_700_000_000,
        "nonce": "nonce-from-upstream",
    }));

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token={subject_token}\
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
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=openid"
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
///
/// `preferred_username`/`name` ride the SAME `exchange_refresh_tokens` row-snapshot mechanism as
/// `email`/`email_verified` (migration
/// `20260830000002_exchange_refresh_tokens_add_profile_claims.sql`) and are asserted here
/// alongside them for exactly that reason: a refresh chain that preserved email but dropped these
/// two would be the identical bug shape one migration later.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_reissues_id_token_and_preserves_email(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let subject_token = subject_token_with_claims(&serde_json::json!({
        "email": "owner@example.test",
        "email_verified": true,
        "preferred_username": "owner-handle",
        "name": "Owner Name",
        "auth_time": 1_700_000_000,
        "nonce": "nonce-from-original-exchange",
    }));

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token={subject_token}\
             &project_id={PROJECT_ID}&scope=openid+profile+offline_access"
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
    let access_claims_untyped = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(
        access_claims_untyped["preferred_username"], "owner-handle",
        "refreshed access token must preserve preferred_username, not drop it"
    );
    assert_eq!(
        access_claims_untyped["name"], "Owner Name",
        "refreshed access token must preserve name, not drop it"
    );

    let id_token = body["id_token"]
        .as_str()
        .expect("scope carried openid across the refresh, so an id_token must be reissued");
    let id_claims = verify_id_token(&repo, id_token, PUBLIC_CLIENT_ID).await;
    assert_eq!(id_claims["email"], "owner@example.test");
    assert_eq!(id_claims["email_verified"], true);
    assert_eq!(id_claims["preferred_username"], "owner-handle");
    assert_eq!(id_claims["name"], "Owner Name");
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

// ============================================================================================
// Refresh-token hardening: absolute cap, re-validation on refresh, and reuse-cascade revocation
// (`chain_id`/`chain_expires_at`, migration `20260815000001_exchange_refresh_tokens_add_chain`).
// See `oauth2_op::store::TokenExchangeOpStore::handle_refresh_token`'s own doc comment for the
// three gaps these close.
// ============================================================================================

/// Regression guard (also exercised, less directly, by `refresh_rotates_and_rejects_replay`
/// above): a normal refresh still succeeds, still rotates, AND the new chain metadata this PR
/// introduces is actually populated -- a freshly exchanged offline-scope token is born into a
/// real, non-empty chain with a future absolute cap.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_succeeds_and_rotates_the_refresh_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"].as_str().unwrap().to_string();
    let (chain_id, chain_expires_at) = chain_metadata(&repo, &first).await;
    assert!(
        !chain_id.is_empty(),
        "a freshly exchanged offline-scope token must be born into a real chain"
    );
    assert!(
        chain_expires_at > chrono::Utc::now(),
        "a freshly born chain's absolute cap must be in the future"
    );

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(first, second, "refresh token must rotate");

    let claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(claims.project_id, PROJECT_ID);
    assert_eq!(claims.account_id, ACCOUNT_ID);

    // The rotated (second) refresh token is itself a well-formed, correctly-claimed JWT, not
    // just "some different string" -- proves the full mint -> present -> verify -> rotate round
    // trip end to end on the new refresh-token format, not only that the CAS/rotation bookkeeping
    // still works.
    let second_claims = verify_refresh_token(&repo, &second).await;
    assert_eq!(second_claims.sub, ACCOUNT_ID);
    assert_eq!(second_claims.aud, "lightbridge-refresh");
    assert_eq!(second_claims.typ, "Refresh");
    assert!(!second_claims.jti.is_empty());
}

/// Gap 2 (absolute cap): a refresh presented after `chain_expires_at` is refused even though the
/// individual token's own `expires_at` (30-day default) is nowhere near expiry -- the two limits
/// are independent, and the chain-level one must win. `refresh_absolute_ttl_seconds: 1` makes the
/// cap trivially reachable with a short, deterministic sleep instead of a mocked clock.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_after_absolute_cap_is_invalid_grant(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let cfg = Oauth2TokenExchange {
        refresh_absolute_ttl_seconds: 1,
        ..exchange_cfg()
    };
    let bearer = || Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()]));

    let (status, body) = post_token(
        state_with_cfg(
            repo.clone(),
            bearer(),
            vec![public_client(PUBLIC_CLIENT_ID)],
            &redis_url(),
            cfg.clone(),
        ),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let (status, body) = post_token(
        state_with_cfg(
            repo.clone(),
            bearer(),
            vec![public_client(PUBLIC_CLIENT_ID)],
            &redis_url(),
            cfg,
        ),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a refresh past the chain's absolute cap must be refused even though the individual \
         token itself has not expired: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Gap 2, continued: `chain_id`/`chain_expires_at` must be INHERITED unchanged across rotations,
/// not regenerated -- otherwise the absolute cap above would never actually bind anything (every
/// rotation would just mint itself a fresh 90-day runway). Asserted across two consecutive
/// rotations (three tokens total) so a bug that only shows up on the second inheritance (e.g.
/// reading the wrong row) cannot hide behind a single-rotation check.
#[sqlx::test(migrations = "../../migrations")]
async fn chain_id_and_absolute_cap_survive_multiple_rotations(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"].as_str().unwrap().to_string();
    let (chain_id_1, chain_expires_at_1) = chain_metadata(&repo, &first).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second = body["refresh_token"].as_str().unwrap().to_string();
    let (chain_id_2, chain_expires_at_2) = chain_metadata(&repo, &second).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={second}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let third = body["refresh_token"].as_str().unwrap().to_string();
    let (chain_id_3, chain_expires_at_3) = chain_metadata(&repo, &third).await;

    assert_eq!(
        chain_id_1, chain_id_2,
        "chain_id must survive the first rotation"
    );
    assert_eq!(
        chain_id_2, chain_id_3,
        "chain_id must survive the second rotation"
    );
    assert_eq!(
        chain_expires_at_1, chain_expires_at_2,
        "the absolute cap must not move on the first rotation"
    );
    assert_eq!(
        chain_expires_at_2, chain_expires_at_3,
        "the absolute cap must not move on the second rotation"
    );
}

/// Gap 1 (re-validation): a subject removed from `project_members` between exchange and refresh
/// must lose the ability to refresh, even though their refresh token itself is still individually
/// valid. Uses `seed_member_project`/`MEMBER_PROJECT_ID`, not `seed`/`PROJECT_ID`, because SUBJECT
/// owning the project directly would make `resolve_context`'s ownership branch admit them
/// regardless of roster state -- this test needs standing that comes ONLY from `project_members`.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_after_member_removed_from_project_is_invalid_grant(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed_member_project(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={MEMBER_PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    repo.remove_project_member(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        MEMBER_PROJECT_ID,
        SUBJECT,
    )
    .await
    .expect("owner removes the member");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a subject removed from the project's roster must not be able to refresh: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Gap 1, continued -- and the fail-open fix specifically: before this change, a refresh whose
/// project could not be resolved fell through to `allowed_models = None`, which this codebase
/// reads as "no restriction," and still minted a token. A deleted project must instead refuse the
/// refresh outright.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_after_project_deleted_is_invalid_grant_not_fail_open(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    repo.delete_project(&AccountId::assert_already_resolved(SUBJECT), PROJECT_ID)
        .await
        .expect("owner deletes the project");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a deleted project must refuse the refresh, not fail open to an unrestricted token: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Gap 1, continued: the same account/project suspension cascade `api_key_validation` enforces for
/// API keys must also gate a refresh -- `resolve_context` alone only checks ownership/membership,
/// not status, so this exercises the extra check `handle_refresh_token` adds on top of it.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_after_project_suspended_is_invalid_grant(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    repo.set_project_status(
        &AccountId::assert_already_resolved(SUBJECT),
        PROJECT_ID,
        ResourceStatus::Suspended,
    )
    .await
    .expect("owner suspends the project");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a suspended project must not be able to refresh: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Gap 1, continued: same as the project-suspension test above, for the account half of the
/// cascade.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_after_account_suspended_is_invalid_grant(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    repo.set_account_status(
        &AccountId::assert_already_resolved(SUBJECT),
        ACCOUNT_ID,
        ResourceStatus::Suspended,
    )
    .await
    .expect("owner suspends the account");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a suspended account must not be able to refresh: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Gap 3 (reuse cascade): replaying a token that was already rotated must revoke the WHOLE chain,
/// not just reject the replay -- the newer, still-live successor must stop working too. This is
/// the RFC 6819 §5.2.2.3 behavior the single-use CAS alone does not provide (it only ever rejects
/// the presented token, never touches what superseded it). Uses [`state_no_reuse_grace`] -- the
/// replay below is immediate, which the real default grace window would treat as benign, not
/// theft; see that helper's doc comment.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_a_rotated_refresh_token_revokes_the_whole_chain(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second = body["refresh_token"].as_str().unwrap().to_string();

    // Replay the SUPERSEDED (already-rotated) first token.
    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replay of a superseded token must fail: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");

    // The newer, previously-valid token must now be dead too -- the whole chain was revoked.
    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={second}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the successor token must be revoked by the reuse cascade: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Gap 3, continued -- the negative space: a refresh token that was never issued must be a plain
/// `invalid_grant` and must NOT cascade-revoke anything. An unrelated, real, still-active chain
/// must keep working afterward.
#[sqlx::test(migrations = "../../migrations")]
async fn unknown_refresh_token_is_invalid_grant_without_cascading(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let real = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        "grant_type=refresh_token&client_id=lightbridge-ss&refresh_token=lgbr_rt_never_issued_garbage",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={real}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unrecognized refresh token must not revoke an unrelated, real chain: {body}"
    );
}

// ============================================================================================
// Refresh-reuse grace window (2026-08-30 console-401s incident): a replay of a just-rotated
// token, presented within `refresh_reuse_grace_seconds` of its own `rotated_at`, must NOT trigger
// gap 3's cascade -- it must mint a fresh, independent access+refresh pair instead. See
// `TokenExchangeOpStore::classify_replayed_refresh_token`'s doc comment for the full design,
// including why this is a SECOND live leaf on the chain rather than a replay of the first
// rotation's own response.
// ============================================================================================

/// The core grace-window behavior: replaying `first` immediately after it rotated to `second`
/// (well within the real default `refresh_reuse_grace_seconds: 30`, via plain [`state`]) succeeds
/// with a brand-new pair, AND -- the part that distinguishes this from the pre-incident cascade --
/// `second` (the original rotation's successor) is still live afterward. If the graced replay had
/// cascaded like an out-of-window one, `second` would be dead too.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_reuse_within_grace_window_mints_a_fresh_pair_without_cascading(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second = body["refresh_token"].as_str().unwrap().to_string();

    // Replay `first` immediately -- inside the grace window.
    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a replay within the grace window must succeed with a fresh pair, not cascade: {body}"
    );
    let third = body["refresh_token"]
        .as_str()
        .expect("a graced replay must still mint a refresh token")
        .to_string();
    assert_ne!(third, first, "the graced replay's own token must be fresh");
    assert_ne!(
        third, second,
        "the graced replay must mint its OWN successor, not reissue the original rotation's"
    );
    let claims = verify_access_token(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(claims.project_id, PROJECT_ID);
    assert_eq!(claims.account_id, ACCOUNT_ID);

    // The chain must NOT have been cascaded: `second`, the original rotation's successor, is
    // still live.
    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={second}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a graced replay must not revoke the chain -- the earlier successor must still work: {body}"
    );
}

/// The other half of the design: a replay presented AFTER the grace window has elapsed is not
/// forgiven -- gap 3's full cascade still applies, exactly as it did before this feature existed.
/// Uses a trivially short `refresh_reuse_grace_seconds: 1` (mirroring how
/// `refresh_after_absolute_cap_is_invalid_grant` makes its own TTL reachable) so the window can be
/// exceeded with a short, deterministic sleep instead of a mocked clock.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_reuse_outside_grace_window_still_cascades(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let cfg = Oauth2TokenExchange {
        refresh_reuse_grace_seconds: 1,
        ..exchange_cfg()
    };
    let state = || {
        state_with_cfg(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
            vec![public_client(PUBLIC_CLIENT_ID)],
            &redis_url(),
            cfg.clone(),
        )
    };

    let (status, body) = post_token(
        state(),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second = body["refresh_token"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    // Replay `first` AFTER its 1-second grace window has elapsed.
    let (status, body) = post_token(
        state(),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a replay past the grace window must still be refused: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");

    // And the cascade must still have fired: `second` is dead too.
    let (status, body) = post_token(
        state(),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={second}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a replay outside the grace window must still cascade-revoke the chain: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// `refresh_reuse_grace_seconds: 0` must reproduce today's pre-incident strict behavior exactly:
/// even an IMMEDIATE replay (age effectively 0 seconds) cascades, because `0` disables the grace
/// window rather than granting a zero-width one. This is what every other reuse-cascade test in
/// this file relies on via [`state_no_reuse_grace`]; this test asserts it directly, once, as its
/// own point.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_reuse_grace_disabled_cascades_on_immediate_replay(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // Replay `first` with NO delay at all -- `grace_seconds: 0` must still refuse it.
    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "grace_seconds: 0 must disable the grace window entirely, not grant a zero-width one: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Two racing pods can each replay the same rotated token during the same window (the actual
/// 2026-08-30 incident shape, generalized: nothing bounds this to exactly one extra replay).
/// Replaying `first` TWICE in a row, both within the grace window, must succeed both times, each
/// minting its own independent successor.
#[sqlx::test(migrations = "../../migrations")]
async fn two_sequential_graced_replays_of_the_same_token_each_succeed(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the first graced replay must succeed: {body}"
    );
    let third = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={first}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a SECOND graced replay of the same original token must also succeed: {body}"
    );
    let fourth = body["refresh_token"].as_str().unwrap().to_string();

    assert_ne!(
        third, fourth,
        "each graced replay must mint its own successor"
    );
    assert_ne!(second, third);
    assert_ne!(second, fourth);
}

/// Migration backfill (`20260815000001_exchange_refresh_tokens_add_chain`): a row created under
/// the PRE-hardening schema (no `chain_id`/`chain_expires_at` columns at all) must survive the
/// migration and receive `chain_id = id` plus a `chain_expires_at` BACKDATED from its own
/// `created_at` -- not from migration time, which would silently extend every existing session's
/// cap by however long it had already been alive. Runs the pre-hardening migrations, inserts a row
/// exactly as the old schema shape would have, then applies only the new migration and inspects
/// the result -- this is the one test in this file that cannot go through `#[sqlx::test(migrations
/// = "../../migrations")]`, since that would apply the hardening migration before any row exists.
#[sqlx::test(migrations = false)]
async fn migration_backfill_gives_existing_rows_a_chain_and_a_backdated_cap(pool: PgPool) {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("../../migrations"))
        .await
        .expect("migrator loads from the workspace migrations directory");
    // The migration immediately preceding the hardening one (`exchange_refresh_tokens_add_chain`)
    // -- everything up to and including client_id, but no chain_id/chain_expires_at yet.
    migrator
        .run_to(20260814000003, &pool)
        .await
        .expect("pre-hardening migrations apply");

    let old_created_at = chrono::Utc::now() - chrono::Duration::days(400);
    let old_expires_at = old_created_at + chrono::Duration::days(30);
    let id = cuid2();
    sqlx::query(
        r#"
        INSERT INTO exchange_refresh_tokens
          (id, subject, account_id, project_id, client_id, token_hash, scope, status, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, NULL, 'active', $7, $8)
        "#,
    )
    .bind(&id)
    .bind(SUBJECT)
    .bind(ACCOUNT_ID)
    .bind(PROJECT_ID)
    .bind(PUBLIC_CLIENT_ID)
    .bind("legacy-hash")
    .bind(old_created_at)
    .bind(old_expires_at)
    .execute(&pool)
    .await
    .expect("legacy-shaped row inserts under the pre-hardening schema");

    migrator
        .run(&pool)
        .await
        .expect("the hardening migration applies on top of an existing row");

    let (chain_id, chain_expires_at): (String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "SELECT chain_id, chain_expires_at FROM exchange_refresh_tokens WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .expect("the row survives the migration");

    assert_eq!(
        chain_id, id,
        "backfill must give a pre-existing row its own single-member chain (chain_id = id)"
    );
    let expected = old_created_at + chrono::Duration::days(90);
    let drift = (chain_expires_at - expected).num_seconds().abs();
    assert!(
        drift < 5,
        "chain_expires_at must be backdated from the row's own created_at ({old_created_at}), \
         not from migration time: got {chain_expires_at}, expected ~{expected}"
    );
}

/// #440's own migration-verification requirement: given pre-existing `exchange_refresh_tokens`
/// chains (already carrying `chain_id`/`chain_expires_at` from the earlier hardening migration),
/// when `20260823000002_sessions.sql` runs, then (a) every row ends up with a non-null
/// `session_id`, (b) rows sharing a `chain_id` end up sharing a `session_id` (= that `chain_id`,
/// per the id-reuse backfill), (c) a chain with its live member still active backfills to a
/// `sessions` row with `status = 'active'`, and (d) a chain whose only member is `revoked`
/// backfills to `status = 'revoked'`. Runs migrations up to the migration immediately preceding
/// the sessions one, seeds two chains by hand (mirroring `rpc_it_tests.rs`'s `seed_active_session`
/// shape), then applies the rest -- same `sqlx::test(migrations = false)` + `Migrator::run_to`
/// pattern `migration_backfill_gives_existing_rows_a_chain_and_a_backdated_cap` above uses, for
/// the same reason: this has to inspect state that no longer exists once the migration under test
/// has already run.
#[sqlx::test(migrations = false)]
async fn sessions_migration_backfills_session_id_and_status_from_existing_chains(pool: PgPool) {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("../../migrations"))
        .await
        .expect("migrator loads from the workspace migrations directory");
    // The migration immediately preceding `20260823000002_sessions.sql` -- chain_id/
    // chain_expires_at/client_id all already exist, sessions/session_id do not yet.
    migrator
        .run_to(20260823000001, &pool)
        .await
        .expect("pre-sessions migrations apply");

    let now = chrono::Utc::now();
    let insert_row = |id: String,
                      chain_id: String,
                      status: &'static str,
                      created_at: chrono::DateTime<chrono::Utc>| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                r#"
                INSERT INTO exchange_refresh_tokens
                  (id, subject, account_id, project_id, client_id, token_hash, scope, status, chain_id, chain_expires_at, created_at, expires_at)
                VALUES ($1, $2, $2, $3, $4, $5, NULL, $6, $7, $8, $9, $9)
                "#,
            )
            .bind(&id)
            .bind(SUBJECT)
            .bind(PROJECT_ID)
            .bind(PUBLIC_CLIENT_ID)
            .bind(format!("hash-{id}"))
            .bind(status)
            .bind(&chain_id)
            .bind(now + chrono::Duration::days(90))
            .bind(created_at)
            .execute(&pool)
            .await
            .expect("legacy-shaped row inserts under the pre-sessions schema");
        }
    };

    // Chain A: two rows (an already-rotated one, and its live successor) -- a chain with its live
    // member still active must backfill to `sessions.status = 'active'`.
    let chain_a = cuid2();
    insert_row(
        cuid2(),
        chain_a.clone(),
        "rotated",
        now - chrono::Duration::minutes(10),
    )
    .await;
    let chain_a_active_row = cuid2();
    insert_row(
        chain_a_active_row.clone(),
        chain_a.clone(),
        "active",
        now - chrono::Duration::minutes(5),
    )
    .await;

    // Chain B: a single, fully-revoked row -- must backfill to `sessions.status = 'revoked'`.
    let chain_b = cuid2();
    let chain_b_row = cuid2();
    insert_row(chain_b_row.clone(), chain_b.clone(), "revoked", now).await;

    migrator
        .run(&pool)
        .await
        .expect("the sessions migration applies on top of existing chains");

    let session_id_a: String =
        sqlx::query_scalar("SELECT session_id FROM exchange_refresh_tokens WHERE id = $1")
            .bind(&chain_a_active_row)
            .fetch_one(&pool)
            .await
            .expect("row survives the migration");
    assert_eq!(
        session_id_a, chain_a,
        "session_id must be the chain's own id (id-reuse backfill)"
    );

    let session_id_b: String =
        sqlx::query_scalar("SELECT session_id FROM exchange_refresh_tokens WHERE id = $1")
            .bind(&chain_b_row)
            .fetch_one(&pool)
            .await
            .expect("row survives the migration");
    assert_eq!(session_id_b, chain_b);

    let (status_a, expires_at_a): (String, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT status, expires_at FROM sessions WHERE id = $1")
            .bind(&chain_a)
            .fetch_one(&pool)
            .await
            .expect("chain A's session row exists");
    assert_eq!(
        status_a, "active",
        "a chain with its live member still active must backfill to an active session"
    );
    let expected_expires_a = now + chrono::Duration::days(90);
    assert!(
        (expires_at_a - expected_expires_a).num_seconds().abs() < 5,
        "session.expires_at must be backfilled from chain_expires_at: got {expires_at_a}, \
         expected ~{expected_expires_a}"
    );

    let status_b: String = sqlx::query_scalar("SELECT status FROM sessions WHERE id = $1")
        .bind(&chain_b)
        .fetch_one(&pool)
        .await
        .expect("chain B's session row exists");
    assert_eq!(
        status_b, "revoked",
        "a chain whose only member is revoked must backfill to a revoked session"
    );
}

// ============================================================================================
// #437's core fix: `revokeSubjectSessions`/`revokeOwnSessions` must actually stop an
// already-minted access token from introspecting active. Mints a real token-exchange access
// token, introspects it (active), revokes the subject's sessions, introspects the SAME token
// again (must now be inactive). This is the exact "prove the test catches the bug" cycle
// AGENTS.md requires: run against the pre-#437 code (no session-status check wired into
// `resolve_exchange_token_context`) and confirm it fails for the predicted reason (second
// introspect still `active: true`), then apply the fix and confirm it passes.
// ============================================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn revoking_a_subjects_sessions_makes_a_live_access_token_introspect_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();

    let state = opa_state(repo.clone());

    let (status, payload) = introspect(state.clone(), &access_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payload["active"], true,
        "a freshly minted token must introspect active: {payload}"
    );

    let revoked = repo
        .revoke_sessions_and_cascade(&AccountId::assert_already_resolved(ACCOUNT_ID))
        .await
        .expect("revoke should succeed");
    assert_eq!(
        revoked, 1,
        "exactly the one session just minted for this grant must be revoked"
    );

    let (status, payload) = introspect(state, &access_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payload["active"], false,
        "the SAME access token, presented again after its session was revoked, must now \
         introspect inactive -- this is #437's core fix: {payload}"
    );
}

/// Self-service parity (task 6e): `revokeOwnSessions`'s effect is the same repo call
/// (`AuthzStoreImpl::revoke_sessions`) regardless of which procedure dispatches into it -- this
/// test drives the same assertion through the account id a self-service caller's own `auth().id`
/// would supply, proving the caller's own live token goes inactive too, not only the admin path.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_own_sessions_makes_the_callers_own_live_access_token_introspect_inactive(
    pool: PgPool,
) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();

    let opa = opa_state(repo.clone());
    let (status, payload) = introspect(opa.clone(), &access_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true, "{payload}");

    // Self-service revoke targets `auth().id` -- for this seed, that's ACCOUNT_ID (== SUBJECT,
    // ADR-0006), the exact same value `revokeOwnSessions` would receive from the caller's own JWT.
    repo.revoke_sessions_and_cascade(&AccountId::assert_already_resolved(ACCOUNT_ID))
        .await
        .expect("self-service revoke should succeed");

    let (status, payload) = introspect(opa, &access_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payload["active"], false,
        "the caller's own cached access token must go inactive after revokeOwnSessions: {payload}"
    );
}

// ============================================================================================
// #492: `StoreRepo::revoke_sessions_and_cascade` must target the ACTOR (`sessions.subject`),
// not `sessions.account_id` -- which always holds the shared PROJECT'S OWNING account, identical
// for every session ever created against that project regardless of which real person minted it
// (`resolve_context`'s documented behavior, `crates/lightbridge-authz-api-key/src/repo.rs`).
// `seed_member_project` gives exactly the shape #492 needs: `OWNER_ACCOUNT` owns
// `MEMBER_PROJECT_ID` directly, `SUBJECT` holds only a roster `project_members` row on it -- so
// every session either of them mints against that one shared project carries the SAME
// `account_id` (`OWNER_ACCOUNT`), and only `subject` tells them apart. Sessions are built
// directly via `StoreRepo::create_session` (not a real token-exchange grant) so each row's
// `account_id`/`subject` pairing can be pinned exactly to what production code writes for an
// owner-created vs. a member-created session on the same project, isolating this to
// `revoke_sessions_and_cascade` itself rather than the whole HTTP token-exchange stack.
// ============================================================================================

async fn session_status(pool: &PgPool, session_id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM sessions WHERE id = $1")
        .bind(session_id)
        .fetch_one(pool)
        .await
        .expect("session row exists")
}

async fn seed_owner_and_member_sessions(
    repo: &StoreRepo,
    pool: &PgPool,
) -> (
    String, /* owner_session_id */
    String, /* member_session_id */
) {
    seed_member_project(repo).await;
    let now = chrono::Utc::now();

    // The OWNER's own session on the shared project: minted when OWNER_ACCOUNT themselves
    // exchange a token for MEMBER_PROJECT_ID -- `resolve_context`'s ownership branch resolves
    // `account_id` to OWNER_ACCOUNT, and the real actor (also OWNER_ACCOUNT) is who
    // `oauth2_op::store::TokenExchangeOpStore::handle_token_exchange` now persists into
    // `subject` (this PR's fix to that call site).
    let owner_session_id = cuid2();
    repo.create_session(NewSession {
        id: owner_session_id.clone(),
        account_id: OWNER_ACCOUNT.to_string(),
        project_id: MEMBER_PROJECT_ID.to_string(),
        client_id: Some(PUBLIC_CLIENT_ID.to_string()),
        kind: "token".to_string(),
        expires_at: now + chrono::Duration::hours(1),
        subject: Some(OWNER_ACCOUNT.to_string()),
    })
    .await
    .expect("owner session persists");

    // The MEMBER's session on the SAME shared project: `resolve_context` resolves `account_id`
    // to the project's owning account (OWNER_ACCOUNT) here too -- identical to the row above --
    // even though the real actor is SUBJECT, not OWNER_ACCOUNT. This is the exact collision
    // #492 is about: only `subject` distinguishes the two rows.
    let member_session_id = cuid2();
    repo.create_session(NewSession {
        id: member_session_id.clone(),
        account_id: OWNER_ACCOUNT.to_string(),
        project_id: MEMBER_PROJECT_ID.to_string(),
        client_id: Some(PUBLIC_CLIENT_ID.to_string()),
        kind: "token".to_string(),
        expires_at: now + chrono::Duration::hours(1),
        subject: Some(SUBJECT.to_string()),
    })
    .await
    .expect("member session persists");

    assert_eq!(session_status(pool, &owner_session_id).await, "active");
    assert_eq!(session_status(pool, &member_session_id).await, "active");

    (owner_session_id, member_session_id)
}

/// The issue's own scenario: a roster member calling "log out everywhere" on themselves
/// (`revokeOwnSessions`, which passes the caller's own `auth().id` -- see
/// `subject_from_ctx`/`AuthzStoreImpl::revoke_sessions`'s doc comment) must kill the MEMBER's own
/// session and must NOT touch the project OWNER's session, even though both sessions carry the
/// identical `account_id`. Pre-fix (`WHERE account_id = $1`), this assertion fails: matching on
/// `account_id = SUBJECT` hits neither row (both have `account_id = OWNER_ACCOUNT`), so the
/// member's own revoke is silently a no-op -- their session survives the very action meant to
/// kill it. Verified by running this test against the pre-fix query (verbatim output logged to
/// `/tmp/prove-fail-492.md`) before applying the `subject = $1` fix.
#[sqlx::test(migrations = "../../migrations")]
async fn roster_member_revoking_own_sessions_kills_only_the_members_session(pool: PgPool) {
    let repo = repo(pool.clone());
    let (owner_session_id, member_session_id) = seed_owner_and_member_sessions(&repo, &pool).await;

    let revoked = repo
        .revoke_sessions_and_cascade(&AccountId::assert_already_resolved(SUBJECT))
        .await
        .expect("member's self-revoke should succeed");
    assert_eq!(
        revoked, 1,
        "exactly the member's own session must be revoked, not the owner's, not zero"
    );

    assert_eq!(
        session_status(&pool, &member_session_id).await,
        "revoked",
        "the acting member's own session must be dead after their own 'log out everywhere'"
    );
    assert_eq!(
        session_status(&pool, &owner_session_id).await,
        "active",
        "the project owner's session must be untouched by a MEMBER's self-revoke"
    );
}

/// Regression guard, the reverse action: when the project OWNER calls their own
/// "log out everywhere," it must still kill the OWNER's own session -- and, now that the query is
/// scoped to the real actor rather than the shared `account_id`, must NOT collaterally revoke a
/// roster MEMBER's session on the same project (the pre-fix over-broad half of #492: matching on
/// `account_id = OWNER_ACCOUNT` used to hit every session sharing that project, member sessions
/// included, since they all carried the identical `account_id`).
#[sqlx::test(migrations = "../../migrations")]
async fn project_owner_revoking_own_sessions_still_works_and_spares_the_member(pool: PgPool) {
    let repo = repo(pool.clone());
    let (owner_session_id, member_session_id) = seed_owner_and_member_sessions(&repo, &pool).await;

    let revoked = repo
        .revoke_sessions_and_cascade(&AccountId::assert_already_resolved(OWNER_ACCOUNT))
        .await
        .expect("owner's self-revoke should succeed");
    assert_eq!(
        revoked, 1,
        "exactly the owner's own session must be revoked, not the member's, not both"
    );

    assert_eq!(
        session_status(&pool, &owner_session_id).await,
        "revoked",
        "the project owner's own session must still die on their own 'log out everywhere'"
    );
    assert_eq!(
        session_status(&pool, &member_session_id).await,
        "active",
        "a roster member's session on the same project must survive the OWNER's self-revoke"
    );
}

/// The cascade half of #492: revoking a subject's sessions must also revoke every
/// `exchange_refresh_tokens` row chained under one of THAT subject's sessions -- scoped by the
/// same actor semantic as the sessions themselves, not by the shared project owner.
#[sqlx::test(migrations = "../../migrations")]
async fn revoke_cascade_kills_only_the_actors_own_refresh_chain(pool: PgPool) {
    let repo = repo(pool.clone());
    let (owner_session_id, member_session_id) = seed_owner_and_member_sessions(&repo, &pool).await;
    let now = chrono::Utc::now();

    let owner_refresh_id = cuid2();
    repo.create_exchange_refresh_token(NewExchangeRefreshToken {
        id: owner_refresh_id.clone(),
        subject: OWNER_ACCOUNT.to_string(),
        account_id: OWNER_ACCOUNT.to_string(),
        project_id: MEMBER_PROJECT_ID.to_string(),
        client_id: PUBLIC_CLIENT_ID.to_string(),
        token_hash: format!("hash-{owner_refresh_id}"),
        scope: Some("offline_access".to_string()),
        email: None,
        email_verified: None,
        auth_time: None,
        preferred_username: None,
        name: None,
        chain_id: cuid2(),
        chain_expires_at: now + chrono::Duration::days(90),
        session_id: owner_session_id.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::days(30),
    })
    .await
    .expect("owner refresh token persists");

    let member_refresh_id = cuid2();
    repo.create_exchange_refresh_token(NewExchangeRefreshToken {
        id: member_refresh_id.clone(),
        subject: SUBJECT.to_string(),
        account_id: OWNER_ACCOUNT.to_string(),
        project_id: MEMBER_PROJECT_ID.to_string(),
        client_id: PUBLIC_CLIENT_ID.to_string(),
        token_hash: format!("hash-{member_refresh_id}"),
        scope: Some("offline_access".to_string()),
        email: None,
        email_verified: None,
        auth_time: None,
        preferred_username: None,
        name: None,
        chain_id: cuid2(),
        chain_expires_at: now + chrono::Duration::days(90),
        session_id: member_session_id.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::days(30),
    })
    .await
    .expect("member refresh token persists");

    repo.revoke_sessions_and_cascade(&AccountId::assert_already_resolved(SUBJECT))
        .await
        .expect("member's self-revoke should succeed");

    let owner_refresh_status: String =
        sqlx::query_scalar("SELECT status FROM exchange_refresh_tokens WHERE id = $1")
            .bind(&owner_refresh_id)
            .fetch_one(&pool)
            .await
            .expect("owner refresh row exists");
    let member_refresh_status: String =
        sqlx::query_scalar("SELECT status FROM exchange_refresh_tokens WHERE id = $1")
            .bind(&member_refresh_id)
            .fetch_one(&pool)
            .await
            .expect("member refresh row exists");

    assert_eq!(
        member_refresh_status, "revoked",
        "the member's own refresh-token chain must be revoked by their own session revoke"
    );
    assert_eq!(
        owner_refresh_status, "active",
        "the owner's refresh-token chain must survive a MEMBER's self-revoke"
    );
}

// ============================================================================================
// RFC 7009 OAuth 2.0 Token Revocation (`POST /oauth2/revoke`). There was previously no HTTP path
// to `revoke_exchange_refresh_token` at all -- every call site was a test. These are the first
// tests exercising it through a real caller.
// ============================================================================================

async fn post_revoke(state: TokenExchangeState, body: &str) -> (StatusCode, Value) {
    let response = token_exchange_router::<()>(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/revoke")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

/// Obtains a real, persisted refresh token via the exchange grant, for `client_id` (which must be
/// present in `state`'s own client registry and in `state`'s `MockBearer` audience).
async fn issue_refresh_token(state: TokenExchangeState, client_id: &str) -> String {
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={client_id}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    body["refresh_token"].as_str().unwrap().to_string()
}

/// Test 1: revoking a valid refresh token makes the very next refresh attempt fail. Proves
/// `revoke_endpoint` is actually wired to `TokenExchangeOpStore::revoke_refresh_token_for_client`
/// and not just returning `200` unconditionally without touching storage -- the follow-up refresh
/// attempt is what would catch a "revoke that doesn't revoke" regression.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_a_valid_refresh_token_blocks_the_next_refresh(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let refresh_token = issue_refresh_token(state(repo.clone(), true), PUBLIC_CLIENT_ID).await;

    let (status, body) = post_revoke(
        state(repo.clone(), true),
        &format!("token={refresh_token}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a revoked refresh token must not still work: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Test 2 (RFC 7009 §2.2): revoking an unknown/garbage token returns 200, not an error -- the
/// endpoint must never become an oracle for "does this token string exist".
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_an_unknown_token_returns_200(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_revoke(
        state(repo.clone(), true),
        &format!("token=totally-made-up-garbage&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

/// Test 3 (RFC 7009 §2.2): revoking an already-revoked token is idempotent -- still 200, not an
/// error, the second time.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_an_already_revoked_token_is_idempotent(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let refresh_token = issue_refresh_token(state(repo.clone(), true), PUBLIC_CLIENT_ID).await;

    let (status, _) = post_revoke(
        state(repo.clone(), true),
        &format!("token={refresh_token}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_revoke(
        state(repo.clone(), true),
        &format!("token={refresh_token}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "revoking an already-revoked token must still be 200: {body}"
    );
}

/// Test 4: client A cannot revoke client B's token. Presenting client B's own token to a revoke
/// request authenticated as client A must be a no-op (still 200 per §2.2 -- see test 2's doc
/// comment for why this can't be an error), and the token must still work afterward, proving it
/// was never actually touched.
#[sqlx::test(migrations = "../../migrations")]
async fn client_a_cannot_revoke_client_bs_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let client_a = "client-a";
    let client_b = "client-b";
    let redis = redis_url();
    let clients = || vec![public_client(client_a), public_client(client_b)];

    let state_b = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(true, vec![client_b.to_string()])),
        clients(),
        &redis,
    );
    let refresh_token = issue_refresh_token(state_b, client_b).await;

    // Authenticated as client_a, attempting to revoke a token issued to client_b.
    let state_a = state_with(
        repo.clone(),
        Arc::new(MockBearer::new(true, vec![client_a.to_string()])),
        clients(),
        &redis,
    );
    let (status, body) = post_revoke(
        state_a,
        &format!("token={refresh_token}&client_id={client_a}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // The token must still be live: client_b can still refresh with it.
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![client_b.to_string()])),
            clients(),
            &redis,
        ),
        &format!("grant_type=refresh_token&client_id={client_b}&refresh_token={refresh_token}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_a's revoke call must not have touched client_b's token: {body}"
    );
}

/// Test 5: client-authentication failure DOES return an error -- the one case RFC 7009 §2.2 does
/// NOT carve out as a bare 200. An unregistered `client_id` must be rejected with `invalid_client`
/// before the token itself is ever looked up.
#[sqlx::test(migrations = "../../migrations")]
async fn revoke_with_unknown_client_is_rejected(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_revoke(
        state(repo.clone(), true),
        "token=whatever&client_id=never-registered",
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

/// A confidential client presenting no assertion at all is also a client-authentication failure,
/// not a bare 200 -- same polarity as test 5, exercised through the `private_key_jwt` path this
/// deployment's confidential clients actually use.
#[sqlx::test(migrations = "../../migrations")]
async fn revoke_confidential_client_with_missing_assertion_is_rejected(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    let bearer = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));
    let state = state_with(repo.clone(), bearer, vec![fixture.client], &redis_url());

    let (status, body) = post_revoke(
        state,
        &format!("token=whatever&client_id={CONFIDENTIAL_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

/// A missing `token` form field is a malformed *request*, distinct from a malformed *token
/// value* -- `invalid_request` (400), not the RFC 7009 §2.2 bare-200 case, since that carve-out
/// is specifically about the token's *content*, not the request's shape.
#[sqlx::test(migrations = "../../migrations")]
async fn revoke_with_missing_token_field_is_invalid_request(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_revoke(
        state(repo.clone(), true),
        &format!("client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

/// A confidential client authenticating with a valid `private_key_jwt` assertion CAN revoke its
/// own token -- the success path through the mirrored `authenticate_revoke_client` branch that
/// `revoke_confidential_client_with_missing_assertion_is_rejected` only exercises the failure
/// side of.
#[sqlx::test(migrations = "../../migrations")]
async fn revoke_confidential_client_with_valid_assertion_succeeds(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let fixture = confidential_client(CONFIDENTIAL_CLIENT_ID);
    let bearer = Arc::new(MockBearer::new(
        true,
        vec![CONFIDENTIAL_CLIENT_ID.to_string()],
    ));

    // A confidential client is `PrivateKeyJwt`-bound at the token endpoint too (ADR-0011,
    // Decision 5) -- issuing its own refresh token needs a client assertion here, not the bare
    // `client_id` the public-client `issue_refresh_token` helper sends.
    let issue_assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        CONFIDENTIAL_CLIENT_ID,
        &cuid2(),
        300,
    );
    let issue_state = state_with(
        repo.clone(),
        bearer.clone(),
        vec![fixture.client.clone()],
        &redis_url(),
    );
    let (status, body) = post_token(
        issue_state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}\
             &client_assertion={issue_assertion}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // A fresh `jti` for the revoke call's own assertion -- `record_client_assertion_jti` refuses
    // a repeat, and the issuance call above already spent `issue_assertion`'s.
    let revoke_assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        CONFIDENTIAL_CLIENT_ID,
        &cuid2(),
        300,
    );
    let revoke_state = state_with(repo.clone(), bearer, vec![fixture.client], &redis_url());
    let (status, body) = post_revoke(
        revoke_state,
        &format!(
            "token={refresh_token}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={revoke_assertion}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

// ============================================================================================
// RFC 7662 OAuth 2.0 Token Introspection (`POST /oauth2/introspect`). Client authentication is
// byte-identical to `/oauth2/revoke`'s above (shared `extract_presented_credential`/
// `resolve_presented_client_id`/`authenticate_presented_client`), so the client-auth failure
// modes are not re-proven here -- `revoke_with_unknown_client_is_rejected`/
// `revoke_confidential_client_with_missing_assertion_is_rejected`/
// `revoke_with_missing_token_field_is_invalid_request` above already cover that shared code path,
// and `idp_server_tests.rs`'s offline `introspect_with_unknown_client_is_rejected`/
// `introspect_with_missing_token_field_is_invalid_request` re-prove the same two cases through
// `/oauth2/introspect` specifically without needing a real database. What's unique to
// introspection and needs a REAL Postgres to exercise: the two introspectable token families
// (opaque refresh-token rows, self-signed access-token JWTs) and RFC 7662 §2.1's anti-oracle
// collapse of "unknown"/"foreign client"/"azp mismatch" into an identical `{"active": false}`.
// ============================================================================================

async fn post_introspect(state: TokenExchangeState, body: &str) -> (StatusCode, Value) {
    let response = token_exchange_router::<()>(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

/// Test 1: a refresh token introspected by its OWNING client comes back `active: true` with the
/// claims RFC 7662 §2.2 defines (`sub`, `client_id`, `exp`) plus this deployment's own additions
/// (`account_id`/`project_id`/`iss`/`scope`/`iat`/`jti`), all traceable to the real row.
#[sqlx::test(migrations = "../../migrations")]
async fn introspecting_a_refresh_token_as_its_owning_client_is_active_with_correct_claims(
    pool: PgPool,
) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let refresh_token = issue_refresh_token(state(repo.clone(), true), PUBLIC_CLIENT_ID).await;

    let (status, body) = post_introspect(
        state(repo.clone(), true),
        &format!("token={refresh_token}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["active"], true, "body: {body}");
    assert!(
        body.get("token_type").is_none(),
        "refresh introspection must not claim a non-standard token_type (\"refresh_token\" \
         is not an RFC 6749 §7.1 type): {body}"
    );
    assert_eq!(body["client_id"], PUBLIC_CLIENT_ID);
    assert_eq!(body["sub"], SUBJECT);
    assert_eq!(body["account_id"], ACCOUNT_ID);
    assert_eq!(body["project_id"], PROJECT_ID);
    assert!(body["exp"].is_number(), "body: {body}");
    assert!(body["jti"].is_string(), "body: {body}");
}

/// Test 2: the SAME refresh token, introspected by a DIFFERENT registered client, must be
/// indistinguishable from an unknown token -- RFC 7662 §2.1's anti-oracle posture. Proves
/// `find_active_refresh_token_for_client` actually scopes the lookup to the caller's own
/// `client_id`, not just any presented token string.
#[sqlx::test(migrations = "../../migrations")]
async fn introspecting_a_refresh_token_as_a_different_client_is_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let owner_client = "introspect-owner";
    let other_client = "introspect-other";
    let clients = || vec![public_client(owner_client), public_client(other_client)];

    let refresh_token = issue_refresh_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![owner_client.to_string()])),
            clients(),
            &redis_url(),
        ),
        owner_client,
    )
    .await;

    let (status, body) = post_introspect(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![other_client.to_string()])),
            clients(),
            &redis_url(),
        ),
        &format!("token={refresh_token}&client_id={other_client}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["active"], false, "body: {body}");
}

/// Test 3: after `/oauth2/revoke` kills a refresh token, introspecting it (by its own, owning
/// client) must report `active: false` -- proves introspection actually reads live state off the
/// same row revocation writes, not a stale/cached view.
#[sqlx::test(migrations = "../../migrations")]
async fn introspecting_a_revoked_refresh_token_is_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let refresh_token = issue_refresh_token(state(repo.clone(), true), PUBLIC_CLIENT_ID).await;

    let (status, body) = post_revoke(
        state(repo.clone(), true),
        &format!("token={refresh_token}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, body) = post_introspect(
        state(repo.clone(), true),
        &format!("token={refresh_token}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["active"], false, "body: {body}");
}

/// Test 4: a self-signed access token (the OTHER introspectable family), introspected by the same
/// client it was minted for (`azp == client_id`), comes back `active: true` -- the real RFC 7662
/// `{"active": false}` counterpart to `idp_server_tests.rs`'s OFFLINE
/// `introspect_with_garbage_token_against_unreachable_db_returns_server_error` (that test pins
/// this offline harness's own DB-unreachable 500, not this contract).
#[sqlx::test(migrations = "../../migrations")]
async fn introspecting_a_garbage_token_returns_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_introspect(
        state(repo.clone(), true),
        &format!("token=totally-made-up-garbage&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["active"], false, "body: {body}");
}

/// Test 5: a self-signed access token minted via the exchange grant carries `azp == client_id`
/// (`signing.rs`'s `access_token_extra`) -- introspecting it as that SAME client must be
/// `active: true`, with the token's own claims (`sub`/`api_key_id`/`project_id`/`account_id`)
/// riding along in the response body, per this endpoint's "return every claim the token already
/// discloses to its holder" contract.
#[sqlx::test(migrations = "../../migrations")]
async fn introspecting_a_self_signed_access_token_with_matching_azp_is_active(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();

    let (status, body) = post_introspect(
        state(repo.clone(), true),
        &format!("token={access_token}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["active"], true, "body: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["client_id"], PUBLIC_CLIENT_ID);
    assert_eq!(body["sub"], SUBJECT);
    assert_eq!(body["account_id"], ACCOUNT_ID);
    assert_eq!(body["project_id"], PROJECT_ID);
}

/// Test 6: the same access token, introspected by a DIFFERENT registered client than the one it
/// was minted for -- `azp` (fixed at mint time to the requesting client) no longer matches the
/// caller's own `client_id`, so this must collapse to `active: false`, same anti-oracle posture
/// as test 2's refresh-token case.
#[sqlx::test(migrations = "../../migrations")]
async fn introspecting_a_self_signed_access_token_with_azp_mismatch_is_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let minting_client = "introspect-azp-owner";
    let other_client = "introspect-azp-other";
    let clients = vec![public_client(minting_client), public_client(other_client)];

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![minting_client.to_string()])),
            clients.clone(),
            &redis_url(),
        ),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={minting_client}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();

    let (status, body) = post_introspect(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![other_client.to_string()])),
            clients,
            &redis_url(),
        ),
        &format!("token={access_token}&client_id={other_client}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["active"], false, "body: {body}");
}

// ============================================================================================
// Composition: this file's own RFC 7009 revoke path vs. the reuse-detection cascade
// (`TokenExchangeOpStore::classify_replayed_refresh_token`, hardening PR #316). The two mechanisms flip
// `status` on the SAME rows via DIFFERENT triggers (explicit client action vs. automatic replay
// detection), so it is worth proving directly, not just by inspection, that neither confuses the
// other: an explicit revoke is never mistaken for a "stolen token" signal, and the cascade's own
// SQL tolerates a chain that already has no active member left.
// ============================================================================================

/// The cascade must still run cleanly -- no error, no panic, a plain `invalid_grant` -- when the
/// chain's current tip was already killed through `/oauth2/revoke` rather than through rotation.
/// Sequence: exchange (token1, chain born) -> refresh (token1 rotates to token2) -> explicitly
/// revoke token2 via `/oauth2/revoke` (the chain now has ZERO active rows: token1 is `rotated`,
/// token2 is `revoked`) -> replay the older, already-rotated token1. `consume_exchange_refresh_
/// token`'s CAS fails (token1 isn't `active`), `classify_replayed_refresh_token` cascades because
/// token1's status is `rotated` and (via [`state_no_reuse_grace`]) the grace window is disabled,
/// and `revoke_exchange_refresh_token_chain`'s `WHERE status = 'active'` update matches nothing --
/// a documented no-op, not an error. The replay must still be a clean `400 invalid_grant`, proving
/// the cascade composes safely with a chain this file's own revoke path already fully drained.
#[sqlx::test(migrations = "../../migrations")]
async fn reuse_cascade_is_a_clean_noop_on_a_chain_already_drained_by_explicit_revoke(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let token1 =
        issue_refresh_token(state_no_reuse_grace(repo.clone(), true), PUBLIC_CLIENT_ID).await;

    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={token1}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let token2 = body["refresh_token"].as_str().unwrap().to_string();

    // Explicitly revoke the chain's current (only active) tip via this file's own RFC 7009
    // endpoint -- NOT via rotation. The chain now has no `active` row at all.
    let (status, body) = post_revoke(
        state_no_reuse_grace(repo.clone(), true),
        &format!("token={token2}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // Replay the OLDER, already-rotated token1 -- this is what makes
    // `classify_replayed_refresh_token` cascade (its trigger is `status == "rotated"` outside the
    // grace window, which token1 satisfies regardless of what has since happened to the rest of
    // its chain).
    let (status, body) = post_token(
        state_no_reuse_grace(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={token1}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replaying an old, already-rotated token must stay a clean invalid_grant even when the \
         chain's tip was already killed by an explicit revoke, not an error: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// The other direction: an explicitly-revoked token (never rotated -- a single-member chain) is
/// NOT treated as a reuse-of-a-stolen-token signal when replayed. `classify_replayed_refresh_token`
/// only cascades (or grants a grace) when the presented token's own row has `status == "rotated"`;
/// an explicit
/// `/oauth2/revoke` call sets `status = "revoked"`, a different value, so replaying it must be a
/// plain `invalid_grant` with no cascade side effects -- verified here by confirming a second,
/// completely unrelated chain for the SAME subject is untouched by the replay attempt.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_an_explicitly_revoked_token_does_not_trigger_the_reuse_cascade(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let revoked = issue_refresh_token(state(repo.clone(), true), PUBLIC_CLIENT_ID).await;
    let (status, _) = post_revoke(
        state(repo.clone(), true),
        &format!("token={revoked}&client_id={PUBLIC_CLIENT_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // An unrelated, still-live chain for the same subject.
    let unrelated = issue_refresh_token(state(repo.clone(), true), PUBLIC_CLIENT_ID).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={revoked}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replaying an explicitly-revoked token must be invalid_grant: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!("grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={unrelated}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an explicit revoke's status ('revoked') must never be mistaken for the cascade's \
         ('rotated') trigger -- an unrelated chain for the same subject must be unaffected: {body}"
    );
}

// ============================================================================================
// ADR-0014: `budget_tier` is stamped on the access token at token-exchange/refresh mint time,
// resolved live from the budget ledger -- superseding ADR-0008's "write a Keycloak attribute"
// delivery mechanism. The fail-closed test below is the one that matters most: a budget-ledger
// outage must never omit the claim and must never fail the token exchange/refresh itself.
//
// ADR-0015 Decision 6 moved WHAT that fail-closed fallback resolves to off the compile-time
// `BudgetTier::B15` constant and onto the active policy document's `fail_closed_floor_micros`
// (shipped default: $6, below `B15`'s $15) -- see `FixedPolicyEngine`/`default_policy_engine`
// below and `TokenExchangeOpStore::resolve_budget_tier`'s own doc comment.
// ============================================================================================

/// A `PolicyEngine` double whose `fail_closed_floor_micros()` is caller-controlled, so the
/// fail-closed tests below can assert the exact claim value the exchange/refresh path stamps
/// without depending on whatever the real, DB-seeded active policy happens to contain right now.
/// `evaluate` panics if called -- `resolve_budget_tier` never calls it, and neither does any test
/// in this file that constructs this double.
#[derive(Debug)]
struct FixedPolicyEngine {
    allowed_amounts_micros: Vec<i64>,
    starting_amount_micros: i64,
    fail_closed_floor_micros: i64,
}

#[async_trait]
impl PolicyEngine for FixedPolicyEngine {
    async fn evaluate(
        &self,
        _facts: &Facts,
        _requested_amount_micros: i64,
    ) -> Result<Decision, BudgetError> {
        unreachable!("resolve_budget_tier never calls PolicyEngine::evaluate")
    }

    fn allowed_amounts_micros(&self) -> Vec<i64> {
        self.allowed_amounts_micros.clone()
    }

    fn starting_amount_micros(&self) -> i64 {
        self.starting_amount_micros
    }

    fn fail_closed_floor_micros(&self) -> i64 {
        self.fail_closed_floor_micros
    }
}

/// The ADR-0015 shipped defaults ($6/$15/$30 offered, $15 starting, $6 fail-closed floor --
/// matching `rule_data::default_rule_set_json` and the `20260819000001_...` migration), used by
/// every test in this file that does NOT specifically exercise the fail-closed floor value
/// itself.
fn default_policy_engine() -> Arc<dyn PolicyEngine> {
    Arc::new(FixedPolicyEngine {
        allowed_amounts_micros: vec![6_000_000, 15_000_000, 30_000_000],
        starting_amount_micros: 15_000_000,
        fail_closed_floor_micros: 6_000_000,
    })
}

const BUDGET_UNREACHABLE_URL: &str = "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz";

/// A `BudgetRepo` whose pool can never connect -- same lazy-pool trick `lazy_repo()`/
/// `lazy_signing_repo()` already use elsewhere in this workspace for "database unreachable"
/// scenarios, bounded so the test fails fast instead of paying sqlx's 30s default
/// `acquire_timeout`.
fn lazy_budget_repo() -> Arc<BudgetRepo> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy(BUDGET_UNREACHABLE_URL)
        .expect("lazy pool should be constructible");
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(BudgetRepo::new(pool))
}

/// Writes one tier-representing grant directly against the real ledger (bypassing
/// `RefillService`/policy evaluation entirely -- this test suite only needs a grant to exist, not
/// to exercise how one gets approved).
async fn seed_budget_grant(
    budget_repo: &BudgetRepo,
    account_id: &str,
    period: &str,
    tier: BudgetTier,
) {
    budget_repo
        .grant(GrantRequest {
            budget_account_id: account_id.to_string(),
            account_id: account_id.to_string(),
            project_id: None,
            period: Period::parse(period).expect("valid period"),
            amount_micros: tier.amount().get(),
            source: GrantSource::Admin,
            actor_id: None,
            reason: None,
            policy_revision: None,
            matched_rule_ids: None,
            idempotency_key: None,
            trigger_key: None,
            expires_at: None,
        })
        .await
        .expect("seeding a budget grant must succeed");
}

/// The calendar period `Period::current`/`BudgetRepo::current_tier` resolve against at the moment
/// this test suite runs, formatted the same `"YYYY-MM"` way `Period::to_string` produces --
/// needed so a seeded grant lands in the SAME period the token-mint path reads.
fn current_period_string() -> String {
    let now = chrono::Utc::now();
    Period::current(now).to_string()
}

#[sqlx::test(migrations = "../../migrations")]
async fn token_exchange_stamps_the_lowest_rung_when_the_account_has_no_grant_yet(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
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
        claims["budget_tier"], "b-15",
        "a brand-new account with no grant history this period must land on the lowest rung: \
         {claims:?}"
    );
}

/// Proves the claim genuinely reads the ledger, not just its own `B15` default -- the same
/// correctness bar `current_tier_resolves_the_most_recent_qualifying_grant` pins at the
/// `BudgetRepo` layer, exercised here end-to-end through the actual minted JWT.
#[sqlx::test(migrations = "../../migrations")]
async fn token_exchange_stamps_the_accounts_real_current_tier(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    let budget_repo = BudgetRepo::new(repo.pool.clone());
    seed_budget_grant(
        &budget_repo,
        ACCOUNT_ID,
        &current_period_string(),
        BudgetTier::B120,
    )
    .await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(claims["budget_tier"], "b-120", "claims: {claims:?}");
}

/// The refresh grant re-mints through the SAME `resolve_budget_tier` call the exchange grant
/// uses (verified here, not just trusted from the doc comment): a grant that lands AFTER the
/// original exchange must be visible on the NEXT refresh, proving refresh re-resolves live
/// rather than copying the tier forward from the token it is replacing.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_re_resolves_the_budget_tier_live_rather_than_copying_the_old_claim(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    let budget_repo = BudgetRepo::new(repo.pool.clone());
    let period = current_period_string();
    seed_budget_grant(&budget_repo, ACCOUNT_ID, &period, BudgetTier::B15).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x\
             &project_id={PROJECT_ID}&scope=offline_access"
        ),
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
        claims["budget_tier"], "b-15",
        "initial exchange claims: {claims:?}"
    );
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // A refill lands between the exchange and the refresh -- exactly the ADR-0014 scenario: the
    // claim must catch up on the next refresh (bounded by access-token TTL / refresh timing),
    // not require a fresh login.
    seed_budget_grant(&budget_repo, ACCOUNT_ID, &period, BudgetTier::B60).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
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
        claims["budget_tier"], "b-60",
        "refresh must re-resolve the tier live, not copy the prior token's claim forward: \
         {claims:?}"
    );
}

/// **The fail-closed test that matters most.** With the budget ledger unreachable, the
/// token-exchange grant must still succeed and the `budget_tier` claim must still be stamped --
/// at the policy-configured fail-closed floor (ADR-0015 Decision 6), never omitted, never
/// turning into a failed exchange. Proven by first showing the SAME setup succeeds with a real
/// budget ledger reachable (so a later regression that broke the exchange for an unrelated
/// reason wouldn't be mistaken for this fail-closed path specifically), then swapping only the
/// budget repo for a dead one and re-asserting.
///
/// Deliberately uses a floor ($9, `9_000_000`) that matches neither a legacy `BudgetTier` rung
/// nor the ADR-0015-shipped $6 default -- if this assertion ever passed against a hard-coded
/// `B15`/$6 fallback instead of genuinely reading `PolicyEngine::fail_closed_floor_micros()` off
/// the engine this test supplies, it would fail loudly rather than accidentally match.
#[sqlx::test(migrations = "../../migrations")]
async fn budget_tier_claim_survives_a_budget_ledger_outage_on_exchange(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let state = state_with_cfg_and_budget_repo(
        repo.clone(),
        repo.clone(),
        lazy_budget_repo(),
        Arc::new(FixedPolicyEngine {
            allowed_amounts_micros: vec![9_000_000],
            starting_amount_micros: 15_000_000,
            fail_closed_floor_micros: 9_000_000,
        }),
        Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
        exchange_cfg(),
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a budget-ledger outage is orthogonal to authentication -- the exchange itself must \
         still succeed: {body}"
    );
    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(
        claims["budget_tier"], "b-9",
        "an unreachable budget ledger must fall back to the policy-configured fail-closed floor \
         (b-9), never a hard-coded rung, and never omit the claim: {claims:?}"
    );
}

/// Same fail-closed guarantee, on the refresh grant -- ADR-0011 re-mints both grants through the
/// same signing calls, so this pins that the fallback applies there too, not only on the initial
/// exchange. The refresh token itself is minted with a REAL budget repo (proving the account had
/// a resolvable tier once); only the ledger backing the *refresh* call is swapped to unreachable.
/// Uses the same deliberately-distinctive $9 floor as
/// [`budget_tier_claim_survives_a_budget_ledger_outage_on_exchange`], for the same reason.
#[sqlx::test(migrations = "../../migrations")]
async fn budget_tier_claim_survives_a_budget_ledger_outage_on_refresh(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    let budget_repo = BudgetRepo::new(repo.pool.clone());
    seed_budget_grant(
        &budget_repo,
        ACCOUNT_ID,
        &current_period_string(),
        BudgetTier::B250,
    )
    .await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x\
             &project_id={PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    let state = state_with_cfg_and_budget_repo(
        repo.clone(),
        repo.clone(),
        lazy_budget_repo(),
        Arc::new(FixedPolicyEngine {
            allowed_amounts_micros: vec![9_000_000],
            starting_amount_micros: 15_000_000,
            fail_closed_floor_micros: 9_000_000,
        }),
        Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
        exchange_cfg(),
    );
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a budget-ledger outage must not fail a refresh: {body}"
    );
    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(
        claims["budget_tier"], "b-9",
        "refresh must also fall back to the policy-configured fail-closed floor (b-9) on a \
         ledger outage, not surface the previously-known real tier (b-250), not a hard-coded \
         rung, and never omit the claim: {claims:?}"
    );
}

// ============================================================================================
// ADR-0017: `quota_tier` is stamped on the access token at token-exchange/refresh mint time,
// resolved live from `project_members` -- carving `quota_tier` (not `role`/`project_quota`) out
// of ADR-0011 Decision 7's "role/quota data stays out of both JWTs".
//
// Three outcomes, kept deliberately distinct on the wire (this is the crux the ADR exists to get
// right, see `TokenExchangeOpStore::resolve_quota_tier`'s own doc comment):
//   1. resolved, tier present               -> claim stamped verbatim
//   2. resolved, tier legitimately absent   -> claim OMITTED (a resolved, safe answer)
//   3. could not resolve (lookup failed)    -> the WHOLE exchange/refresh is REFUSED, so no
//      token -- and therefore no `quota_tier` value of any kind -- ever reaches the wire.
// Outcome 3 must never look like outcome 2: that is exactly the "an outage becomes a quota
// bypass" failure mode issue #385 and this ADR both call out by name.
// ============================================================================================

/// Outcome 1: a resolvable, real per-member tier is stamped verbatim. Uses `seed_member_project`
/// (SUBJECT is a plain roster *member* of `MEMBER_PROJECT_ID`, owned by `OWNER_ACCOUNT`) rather
/// than `seed`'s own `PROJECT_ID` (which SUBJECT owns directly and therefore never gets a roster
/// row for) -- this is deliberately the "person with an actual per-member ceiling" shape, not the
/// "project owner" shape outcome-2's tests below cover.
#[sqlx::test(migrations = "../../migrations")]
async fn token_exchange_stamps_the_real_quota_tier_when_the_subject_has_one(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed_member_project(&repo).await;
    repo.set_project_member_quota_tier(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        MEMBER_PROJECT_ID,
        SUBJECT,
        Some("t-gold"),
    )
    .await
    .expect("owner may set a roster member's quota tier");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={MEMBER_PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(claims["quota_tier"], "t-gold", "claims: {claims:?}");
}

/// Outcome 2, second shape: SUBJECT holds a real `project_members` row on `MEMBER_PROJECT_ID`,
/// but its `quota_tier` column is NULL (never set) -- a distinct code path from "no row at all"
/// above (a real row is returned; `Option<String>` inside it is `None`), that
/// `StoreRepo::project_member_quota_tier`'s `.flatten()` must collapse to the exact same "omit
/// the claim" outcome. Proves the omission is not an accident of "no row found" specifically.
#[sqlx::test(migrations = "../../migrations")]
async fn token_exchange_omits_quota_tier_when_the_members_row_has_a_null_tier(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed_member_project(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={MEMBER_PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert!(
        claims.get("quota_tier").is_none(),
        "a roster row with a NULL quota_tier must omit the claim, exactly like no row at all: \
         {claims:?}"
    );
}

/// The refresh grant re-mints through the SAME `resolve_quota_tier` call the exchange grant uses
/// (verified here, not just trusted from the doc comment) -- mirrors
/// `refresh_re_resolves_the_budget_tier_live_rather_than_copying_the_old_claim` exactly, on the
/// `quota_tier` axis: a lead's tier edit made AFTER the original exchange must be visible on the
/// NEXT refresh, proving refresh re-resolves live rather than copying the tier forward from the
/// token it is replacing.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_re_resolves_the_quota_tier_live_rather_than_copying_the_old_claim(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed_member_project(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x\
             &project_id={MEMBER_PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert!(
        claims.get("quota_tier").is_none(),
        "initial exchange claims (no tier set yet): {claims:?}"
    );
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // A lead sets the tier between the exchange and the refresh -- the claim must catch up on
    // the next refresh (bounded by access-token TTL / refresh timing), not require a fresh login.
    repo.set_project_member_quota_tier(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        MEMBER_PROJECT_ID,
        SUBJECT,
        Some("t-silver"),
    )
    .await
    .expect("owner may set a roster member's quota tier");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
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
        claims["quota_tier"], "t-silver",
        "refresh must re-resolve the tier live, not copy the prior token's (absent) claim \
         forward: {claims:?}"
    );
}

/// ADR-0018: `model_policy` has no dedicated write path yet (the schema field is `@readonly` --
/// see `authz.cstack`'s own comment on `Project.modelPolicy`), so this test sets it directly
/// against the real Postgres row rather than through `StoreRepo`, purely as test fixture setup --
/// exactly the kind of direct-SQL test plumbing this file already uses for scenarios no
/// application write path covers yet.
async fn set_project_model_policy(repo: &StoreRepo, project_id: &str, policy: &str) {
    sqlx::query("UPDATE projects SET model_policy = $1 WHERE id = $2")
        .bind(policy)
        .bind(project_id)
        .execute(repo.pool.pool())
        .await
        .expect("direct model_policy update should succeed");
}

/// ADR-0018 acceptance criterion: a token-exchange call stamps `model_policy` on the minted access
/// token, reflecting the project's current value at mint time -- default `allow_all` here (the
/// value `seed()` leaves every project at, matching the migration's own backfill default).
#[sqlx::test(migrations = "../../migrations")]
async fn token_exchange_stamps_the_projects_model_policy_allow_all_by_default(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let claims = decode_access_token_claims(
        &repo,
        body["access_token"].as_str().unwrap(),
        PUBLIC_CLIENT_ID,
    )
    .await;
    assert_eq!(claims["model_policy"], "allow_all", "claims: {claims:?}");
}

/// Each of the three `model_policy` values round-trips onto the minted access-token claim,
/// mirroring `introspect_round_trips_each_model_policy_value` on the human/OIDC plane.
#[sqlx::test(migrations = "../../migrations")]
async fn token_exchange_stamps_each_model_policy_value(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    for wire_value in ["allow_all", "allowlist", "deny_all"] {
        set_project_model_policy(&repo, PROJECT_ID, wire_value).await;

        let (status, body) = post_token(
            state(repo.clone(), true),
            &format!(
                "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}"
            ),
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
            claims["model_policy"], wire_value,
            "stored value {wire_value:?} must round-trip onto the claim: {claims:?}"
        );
    }
}

/// The refresh grant re-mints through the SAME project lookup the exchange grant uses (verified
/// here, not just trusted from the doc comment) -- mirrors
/// `refresh_re_resolves_the_budget_tier_live_rather_than_copying_the_old_claim`/
/// `refresh_re_resolves_the_quota_tier_live_rather_than_copying_the_old_claim` exactly, on the
/// `model_policy` axis: an operator flipping the policy AFTER the original exchange must be
/// visible on the NEXT refresh, proving refresh re-resolves live rather than copying the value
/// forward from the token it is replacing.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_re_resolves_the_model_policy_live_rather_than_copying_the_old_claim(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x\
             &project_id={PROJECT_ID}&scope=offline_access"
        ),
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
        claims["model_policy"], "allow_all",
        "initial exchange claims: {claims:?}"
    );
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // The project is flipped to deny_all between the exchange and the refresh -- the claim must
    // catch up on the next refresh (bounded by access-token TTL / refresh timing), not require a
    // fresh login.
    set_project_model_policy(&repo, PROJECT_ID, "deny_all").await;

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
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
        claims["model_policy"], "deny_all",
        "refresh must re-resolve model_policy live, not copy the prior token's claim forward: \
         {claims:?}"
    );
}

/// ADR-0018 acceptance criterion: "the migration backfills every existing row to `allow_all` and
/// is verified against a pre-migration fixture, not just a fresh schema." Mirrors
/// `migration_backfill_gives_existing_rows_a_chain_and_a_backdated_cap`'s own `run_to`/`run`
/// pattern: apply every migration up to (but not including)
/// `20260821000001_projects_model_policy.sql`, insert a project row the way the pre-ADR-0018
/// schema shaped it (no `model_policy` column exists yet), THEN apply the remaining migrations
/// and assert the pre-existing row now reads `model_policy = 'allow_all'` -- the exact value that
/// reproduces its current "all models allowed" behavior, with no application code involved.
#[sqlx::test(migrations = false)]
async fn migration_backfills_a_pre_existing_project_row_to_allow_all(pool: PgPool) {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("../../migrations"))
        .await
        .expect("migrator loads from the workspace migrations directory");
    // The migration immediately preceding ADR-0018's own -- everything up to and including
    // `api_keys_require_expiry`, but no `projects.model_policy` column yet.
    migrator
        .run_to(20260820000001, &pool)
        .await
        .expect("pre-ADR-0018 migrations apply");

    sqlx::query(
        r#"
        INSERT INTO accounts (id, created_at, updated_at)
        VALUES ($1, now(), now())
        "#,
    )
    .bind(SUBJECT)
    .execute(&pool)
    .await
    .expect("pre-existing account inserts under the pre-ADR-0018 schema");

    let project_id = cuid2();
    sqlx::query(
        r#"
        INSERT INTO projects
          (id, account_id, name, allowed_models, default_limits, billing_plan, billing_identity,
           created_at, updated_at)
        VALUES ($1, $2, 'pre-existing-project', NULL, '{}'::jsonb, 'free', $3, now(), now())
        "#,
    )
    .bind(&project_id)
    .bind(SUBJECT)
    .bind(format!("bill-{}", cuid2()))
    .execute(&pool)
    .await
    .expect("pre-existing project row inserts under the pre-ADR-0018 schema (no model_policy column yet)");

    migrator
        .run(&pool)
        .await
        .expect("the ADR-0018 migration applies on top of an existing project row");

    let model_policy: String =
        sqlx::query_scalar("SELECT model_policy FROM projects WHERE id = $1")
            .bind(&project_id)
            .fetch_one(&pool)
            .await
            .expect("the row survives the migration and gained the new column");

    assert_eq!(
        model_policy, "allow_all",
        "a pre-existing row must backfill to allow_all -- the value that reproduces its current \
         NULL-allowed_models 'all models allowed' behavior exactly"
    );
}

/// **Outcome 3, the fail-closed test that matters most.** `repo` (subject/context resolution)
/// stays a REAL, reachable Postgres -- `resolve_context` succeeds -- while `quota_repo` (the
/// `project_members` lookup `resolve_quota_tier` reads) is pointed at an unreachable pool
/// (`lazy_repo`, the same "dead Postgres" fixture `totally_unreachable_repo_...` tests elsewhere
/// in this file already use). This is what proves the refusal is `resolve_quota_tier`'s OWN
/// fail-closed branch firing, not merely `resolve_context` failing first: if `resolve_quota_tier`
/// ever regressed to swallowing its error into `Ok(None)` (the exact bug this ADR exists to
/// prevent), this test would flip from `500 server_error` to `200 OK` with the claim silently
/// omitted -- indistinguishable, on the wire, from every genuinely-tierless account.
#[sqlx::test(migrations = "../../migrations")]
async fn quota_tier_lookup_failure_refuses_the_exchange_even_though_context_resolution_succeeds(
    pool: PgPool,
) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed_member_project(&repo).await;
    repo.set_project_member_quota_tier(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        MEMBER_PROJECT_ID,
        SUBJECT,
        Some("t-gold"),
    )
    .await
    .expect("owner may set a roster member's quota tier");

    let state = state_with_cfg_and_budget_repo(
        repo.clone(),
        lazy_repo(),
        Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
            repo.pool.clone(),
        )),
        default_policy_engine(),
        Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
        exchange_cfg(),
    );

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={MEMBER_PROJECT_ID}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unresolvable quota-tier lookup must refuse the mint outright -- never mint a token \
         with the claim silently omitted, which would be indistinguishable from a genuinely \
         tierless account: {body}"
    );
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("access_token").is_none(),
        "no token of any kind may be issued on this path: {body}"
    );
}

/// Same fail-closed guarantee, on the refresh grant -- ADR-0011 re-mints both grants through the
/// same signing calls, so this pins that the refusal applies there too, not only on the initial
/// exchange. The refresh token itself is minted with a fully reachable `quota_repo` (proving the
/// account had a resolvable roster once); only the lookup backing the *refresh* call is swapped
/// to unreachable.
#[sqlx::test(migrations = "../../migrations")]
async fn quota_tier_lookup_failure_refuses_the_refresh_even_though_context_resolution_succeeds(
    pool: PgPool,
) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed_member_project(&repo).await;
    repo.set_project_member_quota_tier(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        MEMBER_PROJECT_ID,
        SUBJECT,
        Some("t-gold"),
    )
    .await
    .expect("owner may set a roster member's quota tier");

    let (status, body) = post_token(
        state(repo.clone(), true),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x\
             &project_id={MEMBER_PROJECT_ID}&scope=offline_access"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    let state = state_with_cfg_and_budget_repo(
        repo.clone(),
        lazy_repo(),
        Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
            repo.pool.clone(),
        )),
        default_policy_engine(),
        Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
        vec![public_client(PUBLIC_CLIENT_ID)],
        &redis_url(),
        exchange_cfg(),
    );
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type=refresh_token&client_id={PUBLIC_CLIENT_ID}&refresh_token={refresh_token}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unresolvable quota-tier lookup must refuse the refresh outright, same as the \
         exchange grant: {body}"
    );
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("access_token").is_none(),
        "no token of any kind may be issued on this path: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn device_grant_persists_pending_state_enforces_polling_and_consumes_once(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let client_id = "opencode-cli";
    let (status, body) = post_device_authorization(
        device_state(repo.clone(), client_id),
        &format!("client_id={client_id}&scope=openid%20offline_access&project_id={PROJECT_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["verification_uri"],
        "https://authz.example.test/device/verify"
    );
    assert!(
        body["verification_uri_complete"]
            .as_str()
            .is_some_and(|uri| uri.contains("user_code="))
    );
    let device_code = body["device_code"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        device_state(repo.clone(), client_id),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "authorization_pending");

    let (status, body) = post_token(
        device_state(repo.clone(), client_id),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "slow_down");

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let (status, body) = post_token(
        device_state(repo.clone(), client_id),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "authorization_pending");

    repo.approve_device_authorization(
        &device_code,
        &AccountId::assert_already_resolved(SUBJECT),
        chrono::Utc::now(),
    )
    .await
    .unwrap()
    .expect("pending device authorization must approve");
    let (status, body) = post_token(
        device_state(repo.clone(), client_id),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.get("issued_token_type").is_none());
    let refresh_token = body["refresh_token"]
        .as_str()
        .expect("offline_access must issue a refresh token")
        .to_string();
    let claims =
        verify_access_token(&repo, body["access_token"].as_str().unwrap(), client_id).await;
    assert_eq!(claims.sub, SUBJECT);
    assert_eq!(claims.project_id, PROJECT_ID);

    let (status, body) = post_token(
        device_state(repo.clone(), client_id),
        &format!("grant_type=refresh_token&client_id={client_id}&refresh_token={refresh_token}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["refresh_token"].as_str().is_some());
    assert_ne!(body["refresh_token"], refresh_token);

    let (status, body) = post_token(
        device_state(repo, client_id),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[sqlx::test(migrations = "../../migrations")]
async fn device_grant_omits_refresh_without_offline_access(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let client_id = "opencode-cli";
    let (status, body) = post_device_authorization(
        device_state(repo.clone(), client_id),
        &format!("client_id={client_id}&scope=openid&project_id={PROJECT_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let device_code = body["device_code"].as_str().unwrap().to_string();
    repo.approve_device_authorization(
        &device_code,
        &AccountId::assert_already_resolved(SUBJECT),
        chrono::Utc::now(),
    )
    .await
    .unwrap()
    .expect("pending device authorization must approve");

    let (status, body) = post_token(
        device_state(repo, client_id),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.get("refresh_token").is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn device_grant_rejects_denied_expired_wrong_client_and_invalid_scope(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;

    let client_id = "opencode-cli";
    let other_client_id = "other-cli";
    let clients = vec![device_client(client_id), device_client(other_client_id)];
    let (status, body) = post_device_authorization(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, Vec::new())),
            clients.clone(),
            &redis_url(),
        ),
        &format!("client_id={client_id}&scope=not-permitted"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_scope");

    let (status, body) = post_device_authorization(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, Vec::new())),
            clients.clone(),
            &redis_url(),
        ),
        &format!("client_id={client_id}&scope=openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let denied_code = body["device_code"].as_str().unwrap().to_string();
    repo.deny_device_authorization(&denied_code, chrono::Utc::now())
        .await
        .unwrap()
        .expect("pending device authorization must deny");
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, Vec::new())),
            clients.clone(),
            &redis_url(),
        ),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={denied_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error"], "access_denied");

    let (status, body) = post_device_authorization(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, Vec::new())),
            clients.clone(),
            &redis_url(),
        ),
        &format!("client_id={client_id}&scope=openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let wrong_client_code = body["device_code"].as_str().unwrap().to_string();
    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, Vec::new())),
            clients.clone(),
            &redis_url(),
        ),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={other_client_id}&device_code={wrong_client_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");

    let mut expiring_cfg = exchange_cfg();
    expiring_cfg.device_code_ttl_seconds = 1;
    let (status, body) = post_device_authorization(
        state_with_cfg(
            repo.clone(),
            Arc::new(MockBearer::new(true, Vec::new())),
            clients.clone(),
            &redis_url(),
            expiring_cfg.clone(),
        ),
        &format!("client_id={client_id}&scope=openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["expires_in"], 1);
    let expired_code = body["device_code"].as_str().unwrap().to_string();
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let (status, body) = post_token(
        state_with_cfg(
            repo,
            Arc::new(MockBearer::new(true, Vec::new())),
            clients,
            &redis_url(),
            expiring_cfg,
        ),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={expired_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "expired_token");
}

#[sqlx::test(migrations = "../../migrations")]
async fn approved_device_code_is_one_shot_when_context_resolution_refuses(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let client_id = "opencode-cli";
    let (status, body) = post_device_authorization(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![device_client(client_id)],
            &redis_url(),
        ),
        &format!("client_id={client_id}&project_id=unknown-project"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let device_code = body["device_code"].as_str().unwrap().to_string();
    repo.approve_device_authorization(
        &device_code,
        &AccountId::assert_already_resolved(SUBJECT),
        chrono::Utc::now(),
    )
    .await
    .unwrap()
    .expect("pending device authorization must approve");

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![device_client(client_id)],
            &redis_url(),
        ),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error"], "access_denied");

    let (status, body) = post_token(
        state_with(
            repo,
            Arc::new(MockBearer::new(true, vec![])),
            vec![device_client(client_id)],
            &redis_url(),
        ),
        &format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// #524: the browser `authorization_code` grant must carry the SAME enforcement claims a device
/// or exchange login already carries.
///
/// Before the `handle_authorization_code_grant` override this failed on the first assertion:
/// authkestra's default handler minted a perfectly valid token with none of these claims, so a
/// console authenticating here was authenticated but unauthorized -- refused by every RBAC-gated
/// procedure, with nothing in the token to explain why.
#[sqlx::test(migrations = "../../migrations")]
async fn authorization_code_grant_stamps_the_same_enforcement_claims_as_the_other_grants(
    pool: PgPool,
) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    store_browser_code(repo.clone(), "claims-code", CLIENT, REDIRECT_URI, VERIFIER).await;

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=claims-code&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let claims =
        decode_access_token_claims(&repo, body["access_token"].as_str().unwrap(), CLIENT).await;

    assert_eq!(
        claims["budget_tier"], "b-15",
        "the browser grant must resolve budget_tier live from the ledger, exactly as the exchange \
         grant does -- an account with no grant history lands on the lowest rung: {claims:?}"
    );
    assert_eq!(
        claims["project_id"], PROJECT_ID,
        "the browser grant must carry tenant context: {claims:?}"
    );
    assert!(
        claims.get("sid").is_some_and(|v| !v.is_null()),
        "a session row must be created for a browser login, so the session is revocable: \
         {claims:?}"
    );
    assert_eq!(
        claims["model_policy"], "allow_all",
        "model policy travels with every human-plane token: {claims:?}"
    );
    assert_eq!(
        claims["account_id"], SUBJECT,
        "tenant context must name the acting account: {claims:?}"
    );
    assert_eq!(
        claims["azp"], CLIENT,
        "azp binds the token to the client that redeemed the code: {claims:?}"
    );
    // `issued_token_type` is REQUIRED by RFC 8693 §2.2.1 on a token-exchange response and only
    // there. Asserting its absence here keeps the two grants from silently converging.
    assert!(
        body.get("issued_token_type").is_none(),
        "issued_token_type belongs to the token-exchange response only: {body}"
    );
}

/// #525: the browser grant must yield a rotating refresh token when `offline_access` is granted,
/// and the superseded token must be refused on reuse -- the same single-use CAS + RFC 6819
/// §5.2.2.3 cascade the device and exchange grants already get, because all three now mint
/// through `mint_human_plane_tokens`. `refresh_reuse_grace_seconds: 0` -- the final replay below
/// is immediate, which the real default grace window would treat as benign rather than the refusal
/// this test asserts; see [`state_no_reuse_grace`]'s doc comment.
#[sqlx::test(migrations = "../../migrations")]
async fn authorization_code_grant_issues_a_rotating_refresh_token(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    store_browser_code_with_scope(
        repo.clone(),
        "refresh-code",
        CLIENT,
        REDIRECT_URI,
        VERIFIER,
        "openid offline_access",
    )
    .await;

    let state = || {
        state_with_cfg(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
            Oauth2TokenExchange {
                refresh_reuse_grace_seconds: 0,
                ..exchange_cfg()
            },
        )
    };

    let (status, body) = post_token(
        state(),
        &format!(
            // Deliberately NO `scope` parameter -- RFC 6749 §4.1.3 says an authorization_code
            // token request carries none, and the granted scope is the authorization grant's own.
            // `store_browser_code` issued this code with `offline_access`, so the refresh token
            // must follow from that alone. Passing scope here would have hidden the bug where the
            // token request's (absent) scope was used instead of the code's.
            "grant_type=authorization_code&client_id={CLIENT}&code=refresh-code&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let first = body["refresh_token"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("offline_access on the browser grant must yield a refresh token: {body}")
        })
        .to_string();

    let (status, body) = post_token(
        state(),
        &format!("grant_type=refresh_token&client_id={CLIENT}&refresh_token={first}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let second = body["refresh_token"].as_str().expect("rotated").to_string();
    assert_ne!(
        second, first,
        "the refresh token must ROTATE, not be reissued"
    );

    let (status, body) = post_token(
        state(),
        &format!("grant_type=refresh_token&client_id={CLIENT}&refresh_token={first}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replaying a superseded refresh token must be refused: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// The other half of the contract: no `offline_access`, no refresh token. A browser client that
/// did not ask for one must not silently receive a long-lived credential.
#[sqlx::test(migrations = "../../migrations")]
async fn authorization_code_grant_omits_refresh_without_offline_access(pool: PgPool) {
    const CLIENT: &str = "browser-client";
    const REDIRECT_URI: &str = "https://dashboard.example.test/oauth/callback";
    const VERIFIER: &str = "this-is-a-sufficiently-long-pkce-verifier-value-123456789";

    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    seed(&repo).await;
    store_browser_code(repo.clone(), "no-offline", CLIENT, REDIRECT_URI, VERIFIER).await;

    let (status, body) = post_token(
        state_with(
            repo.clone(),
            Arc::new(MockBearer::new(true, vec![])),
            vec![browser_client(CLIENT, REDIRECT_URI)],
            &redis_url(),
        ),
        &format!(
            "grant_type=authorization_code&client_id={CLIENT}&code=no-offline&redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}&scope=openid"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("refresh_token").is_none() || body["refresh_token"].is_null(),
        "no offline_access means no refresh token: {body}"
    );
}

// ============================================================================================
// RFC 6749 §4.4 `client_credentials` (M2M, #534/ADR-0030). This grant is intercepted BEFORE
// `handle_token` ever runs (`token_exchange::client_credentials_token_endpoint`), so none of the
// `MockBearer`/`seed`/`ACCOUNT_ID`/`PROJECT_ID` fixtures the token-exchange grant above needs are
// relevant here -- a machine client authenticates and is minted a token with no subject_token, no
// account, and no project in the picture at all.
// ============================================================================================

fn client_credentials_state(
    repo: Arc<StoreRepo>,
    clients: Vec<OauthClient>,
    redis_url: &str,
) -> TokenExchangeState {
    // The client_credentials grant never calls into `BearerTokenServiceTrait` at all (there is no
    // subject_token to validate), so any implementation satisfies the type -- `MockBearer::new`
    // with an empty `aud` mirrors what every other non-exchange-grant fixture in this file already
    // passes (see `device_state`).
    state_with(
        repo,
        Arc::new(MockBearer::new(true, Vec::new())),
        clients,
        redis_url,
    )
}

/// Test 1: no credential presented at all against a `Service` (private_key_jwt-bound) client ->
/// `401 invalid_client`, the same outcome `confidential_client_with_missing_assertion_is_refused`
/// already proves for the token-exchange grant, now proven for `client_credentials` too.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_with_no_credential_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!("grant_type={CLIENT_CREDENTIALS_GRANT}&client_id=it-machine"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

/// Test 2: an assertion signed by the WRONG key (not the client's own) -> `401 invalid_client`.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_signed_by_wrong_key_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let forger = generate_rs256_key().unwrap();
    let bad_assertion = sign_client_assertion(
        &forger.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={bad_assertion}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

/// Test 3: the replay polarity test -- the SAME assertion presented twice must succeed once and be
/// refused the second time (mirrors `replayed_client_assertion_jti_is_refused` for the token-
/// exchange grant).
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_replayed_assertion_jti_is_refused(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let jti = cuid2();
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &jti,
        300,
    );
    let redis = redis_url();
    let body_str = format!(
        "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}"
    );

    let state1 = client_credentials_state(repo.clone(), vec![fixture.client.clone()], &redis);
    let (status, body) = post_token(state1, &body_str).await;
    assert_eq!(status, StatusCode::OK, "first use must succeed: {body}");

    // Fresh state (jti tracking lives in Redis, not in-process).
    let state2 = client_credentials_state(repo, vec![fixture.client], &redis);
    let (status, body) = post_token(state2, &body_str).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed assertion must be refused: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

/// Test 4 (DECISIVE): Redis unreachable while spending the assertion's `jti` must refuse with
/// `server_error`/500 -- NEVER a mint, and NEVER collapsed into `invalid_client` the way upstream
/// `handle_token`'s own `authenticate_client` would (see `authenticate_presented_client`'s doc
/// comment / this file's `redis_unreachable_refuses_confidential_client_rather_than_admitting` for
/// why the two grants deliberately differ here). Prove-fail-first, actually run (recorded verbatim
/// in the PR body -- pointing this endpoint at upstream's own `pub(crate)`
/// `extract_credential`/`resolve_client_id`/`authenticate_client` is not an achievable mutation
/// from this crate, since none of the three is reachable outside `authkestra-op`; the mutation
/// below is the smallest one that actually compiles and exercises the same claim): temporarily
/// changed `authenticate_presented_client`'s `Err(_) =>` arm (`token_exchange.rs`) from
/// `EndpointAuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", ...)` to
/// `Err(invalid_client())`, reran just this test, and it went red for the predicted reason --
/// `401 invalid_client` instead of `500 server_error` -- confirming the assertion actually
/// distinguishes the two outcomes rather than passing vacuously. Reverted immediately after.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_redis_unreachable_is_server_error_never_a_mint(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], UNREACHABLE_REDIS_URL);

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}"
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "redis-down must refuse as server_error, never mint and never collapse into \
         invalid_client: {body}"
    );
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("access_token").is_none(),
        "no access_token may ever be present on a failure response: {body}"
    );
}

/// Test 5: a `Service` client that is correctly authenticated but whose `grant_types` does not
/// list `client_credentials` -> `400 unauthorized_client`.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_absent_from_client_grant_types_is_unauthorized_client(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let mut fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    // A Service client legitimately holding some OTHER grant only -- e.g. it also participates in
    // token-exchange -- must still be refused this ONE grant it never registered for.
    fixture.client.grant_types = vec![TOKEN_EXCHANGE_GRANT.to_string()];
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "unauthorized_client");
}

/// Test 6: a requested `audience` outside `client.allowed_audiences` -> `400 invalid_target`.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_disallowed_audience_is_invalid_target(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}&audience=not-allowed"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_target");
}

/// Test 7: a requested scope not listed on `client.scopes` -> `400 invalid_scope`. Also proves the
/// server-wide `oauth2.token_exchange.allowed_scopes` ceiling is NOT consulted for this grant --
/// `openid` is never in `client.scopes` here, so requesting it must fail even though it is very
/// much a member of `exchange_cfg().allowed_scopes`.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_scope_outside_client_scopes_is_invalid_scope(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}&scope=openid"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_scope");
}

/// Test 10: an unregistered `client_id` is REFUSED indistinguishably from a wrong key -- the same
/// anti-oracle posture `unknown_client_id_is_rejected` already proves for the token-exchange grant.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_unknown_client_id_is_rejected(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let state = client_credentials_state(repo, Vec::new(), &redis_url());

    let (status, body) = post_token(
        state,
        &format!("grant_type={CLIENT_CREDENTIALS_GRANT}&client_id=never-registered"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "invalid_client");
}

/// Test 11: the happy path -- `200 OK`, and RFC 6749 §4.4.3's MUST NOT is honored: no
/// `refresh_token`, and no `id_token` (there is no human identity to describe one).
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_happy_path_has_no_refresh_token_and_no_id_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].as_str().is_some_and(|t| !t.is_empty()));
    assert!(
        body.get("refresh_token").is_none() || body["refresh_token"].is_null(),
        "RFC 6749 §4.4.3 MUST NOT: {body}"
    );
    assert!(
        body.get("id_token").is_none() || body["id_token"].is_null(),
        "no human identity to describe: {body}"
    );
    assert!(
        body.get("issued_token_type").is_none() || body["issued_token_type"].is_null(),
        "issued_token_type is a token-exchange (RFC 8693) concept, not RFC 6749 §4.4: {body}"
    );
}

/// Tests 12 & 14: the full claim-shape contract, decoded and signature-verified against the SAME
/// JWKS `/.well-known/jwks.json` serves (proving it verifies against the real `kid`) -- `sub =
/// "svc:<client_id>"`, `azp = <client_id>` (never the `svc:`-prefixed sub), `typ = "Bearer"`, `jti`
/// carries this repo's own `lgbr:` prefix (never a bare UUIDv4), `lightbridge_caller_kind =
/// "service"`, granted `scope`, and every tenant/session claim (`account_id`, `project_id`,
/// `api_key_id`, `sid`) plus `identity`/`budget_tier`/`quota_tier` are ALL absent.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_claim_shape_matches_the_service_token_contract(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string(), "write:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo.clone(), vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}&scope=read%3Ausage"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["scope"], "read:usage");

    let access_token = body["access_token"].as_str().unwrap().to_string();
    // Signature verification against the real DB-backed JWKS (`/.well-known/jwks.json` serves
    // exactly this set) IS test 14 -- `decode_access_token_claims` panics if this doesn't verify.
    let claims = decode_access_token_claims(&repo, &access_token, "it-machine").await;

    assert_eq!(claims["sub"], "svc:it-machine", "claims: {claims}");
    assert_eq!(claims["azp"], "it-machine", "claims: {claims}");
    assert_eq!(claims["typ"], "Bearer", "claims: {claims}");
    assert_eq!(
        claims["lightbridge_caller_kind"], "service",
        "claims: {claims}"
    );
    assert!(
        claims["jti"]
            .as_str()
            .is_some_and(|jti| jti.starts_with("lgbr:")),
        "jti must be this repo's own CUID2, never a bare UUIDv4: {claims}"
    );
    for absent in [
        "account_id",
        "project_id",
        "api_key_id",
        "sid",
        "identity",
        "budget_tier",
        "quota_tier",
        "allowed_models",
    ] {
        assert!(
            claims.get(absent).is_none() || claims[absent].is_null(),
            "{absent} must be absent from a client_credentials token: {claims}"
        );
    }
}

/// Test 13 (both directions): with no `audience` requested, `aud` defaults to the client's own
/// `client_id`; with an explicitly requested, allowed audience, `aud` is that value instead -- the
/// ONE grant where a granted `aud` may legitimately differ from `azp`/the authenticated client.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_audience_defaults_to_client_id_or_honors_an_allowed_one(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );

    // No audience requested -> defaults to the client's own client_id.
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo.clone(), vec![fixture.client.clone()], &redis_url());
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();
    let claims = decode_access_token_claims(&repo, &access_token, "it-machine").await;
    assert_eq!(
        claims["aud"], "it-machine",
        "no audience requested must default to the client's own client_id: {claims}"
    );

    // Explicit, allowed audience -> `aud` is that value, DIFFERENT from `azp`.
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo.clone(), vec![fixture.client], &redis_url());
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}&audience=lightbridge-api-key"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();
    let claims = decode_access_token_claims(&repo, &access_token, "lightbridge-api-key").await;
    assert_eq!(claims["aud"], "lightbridge-api-key", "claims: {claims}");
    assert_eq!(
        claims["azp"], "it-machine",
        "azp must still name the authenticated client, even when aud names a different \
         resource: {claims}"
    );
}

/// Test 15: `/oauth2/introspect` (RFC 7662) reports `active: true` for a freshly minted
/// `client_credentials` access token, introspected by the same client it was minted for.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_introspects_as_active(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let mint_assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo.clone(), vec![fixture.client.clone()], &redis_url());
    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={mint_assertion}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();

    let introspect_assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());
    let (status, body) = post_introspect(
        state,
        &format!(
            "token={access_token}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={introspect_assertion}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["active"], true, "body: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["client_id"], "it-machine");
    assert_eq!(body["sub"], "svc:it-machine");
    assert_eq!(body["lightbridge_caller_kind"], "service", "body: {body}");
}

/// Test 16: scope narrowing -- requesting a strict subset of `client.scopes` grants exactly that
/// subset, not the client's full configured scope list.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_scope_narrows_to_the_requested_subset(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string(), "write:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}&scope=read%3Ausage"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["scope"], "read:usage",
        "requesting a subset must narrow, not grant the full configured scope list: {body}"
    );
}

/// The default-scope companion to the narrowing test above: no `scope` requested at all grants
/// EVERY scope the client is configured for.
#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_absent_scope_grants_every_configured_client_scope(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();

    let fixture = service_client(
        "it-machine",
        vec!["read:usage".to_string(), "write:usage".to_string()],
        vec!["lightbridge-api-key".to_string()],
    );
    let assertion = sign_client_assertion(
        &fixture.private_key_pem,
        &fixture.kid,
        "it-machine",
        &cuid2(),
        300,
    );
    let state = client_credentials_state(repo, vec![fixture.client], &redis_url());

    let (status, body) = post_token(
        state,
        &format!(
            "grant_type={CLIENT_CREDENTIALS_GRANT}&client_assertion_type={CLIENT_ASSERTION_TYPE}&client_assertion={assertion}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let scope = body["scope"].as_str().expect("scope present");
    let granted: std::collections::BTreeSet<&str> = scope.split_whitespace().collect();
    assert_eq!(
        granted,
        std::collections::BTreeSet::from(["read:usage", "write:usage"]),
        "an absent scope parameter must grant every scope the client is configured for: {body}"
    );
}

/// A browser logout must not revoke a DIFFERENT client's `offline_access` refresh chain.
///
/// The production defect (`/oauth2/end_session` -> `revoke_sessions_and_cascade`, which matches on
/// `subject` alone): every CLI grant persists a `kind = "token"` session, so signing out of the
/// console silently killed the refresh chain of every other client that person had authorised.
/// Their `opencode-cli` -- working fine moments earlier -- answered `400 invalid_grant` on its next
/// refresh and demanded a fresh device-code login, at no fixed interval, because the trigger was a
/// browser action in another client rather than anything time-based (refresh TTLs are 30/90 days).
/// Nothing was logged: `handle_refresh_token`'s plain `invalid_grant` arm is silent.
///
/// `revoke_for_logout` scopes the blast radius to the browser session plus the RP that asked for
/// the logout, so the console's own tokens still die (asserted below -- the fix must not become a
/// licence for a logout that logs nothing out) while other clients' `offline_access` survives, per
/// OIDC Core §11's definition of that scope as access outliving the browser session.
///
/// Prove-fail-first (run, 2026-09-02): swapping `revoke_for_logout(.., Some(CONSOLE))` for
/// `revoke_sessions_and_cascade(..)` panics at the `cli_id` session assertion --
/// `assertion left == right failed: another client's session must survive a browser logout it had
/// no part in / left: "revoked" / right: "active"`. That is the first of the two `opencode`
/// assertions; the refresh-chain one below it never runs, since the session check panics first.
#[sqlx::test(migrations = "../../migrations")]
async fn browser_logout_spares_another_clients_offline_refresh_chain(pool: PgPool) {
    const CONSOLE: &str = "lightbridge-console";
    const CLI: &str = "opencode-cli";
    let repo = repo(pool.clone());
    seed_member_project(&repo).await;
    let now = chrono::Utc::now();

    let session = |kind: &str, client: Option<&str>| {
        let id = cuid2();
        let row = NewSession {
            id: id.clone(),
            account_id: OWNER_ACCOUNT.to_string(),
            project_id: MEMBER_PROJECT_ID.to_string(),
            client_id: client.map(str::to_string),
            kind: kind.to_string(),
            expires_at: now + chrono::Duration::days(90),
            subject: Some(SUBJECT.to_string()),
        };
        (id, row)
    };
    let (browser_id, browser_row) = session("browser", None);
    let (console_id, console_row) = session("token", Some(CONSOLE));
    let (cli_id, cli_row) = session("token", Some(CLI));
    for row in [browser_row, console_row, cli_row] {
        repo.create_session(row).await.expect("session persists");
    }

    let chain = |session_id: &str, client: &str| {
        let id = cuid2();
        let row = NewExchangeRefreshToken {
            id: id.clone(),
            subject: SUBJECT.to_string(),
            account_id: OWNER_ACCOUNT.to_string(),
            project_id: MEMBER_PROJECT_ID.to_string(),
            client_id: client.to_string(),
            token_hash: format!("hash-{id}"),
            scope: Some("offline_access".to_string()),
            email: None,
            email_verified: None,
            auth_time: None,
            preferred_username: None,
            name: None,
            chain_id: cuid2(),
            chain_expires_at: now + chrono::Duration::days(90),
            session_id: session_id.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::days(30),
        };
        (id, row)
    };
    let (console_refresh_id, console_refresh) = chain(&console_id, CONSOLE);
    let (cli_refresh_id, cli_refresh) = chain(&cli_id, CLI);
    for row in [console_refresh, cli_refresh] {
        repo.create_exchange_refresh_token(row)
            .await
            .expect("refresh token persists");
    }

    repo.revoke_for_logout(&AccountId::assert_already_resolved(SUBJECT), Some(CONSOLE))
        .await
        .expect("browser logout should succeed");

    async fn refresh_status(pool: &PgPool, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM exchange_refresh_tokens WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("refresh row exists")
    }

    assert_eq!(
        session_status(&pool, &browser_id).await,
        "revoked",
        "the browser SSO session is what logout exists to end"
    );
    assert_eq!(
        session_status(&pool, &console_id).await,
        "revoked",
        "the RP that asked for the logout must lose its own session"
    );
    assert_eq!(
        refresh_status(&pool, &console_refresh_id).await,
        "revoked",
        "signing out of the console must still invalidate the console's own refresh token"
    );

    assert_eq!(
        session_status(&pool, &cli_id).await,
        "active",
        "another client's session must survive a browser logout it had no part in"
    );
    assert_eq!(
        refresh_status(&pool, &cli_refresh_id).await,
        "active",
        "the reported bug: opencode's offline_access chain must survive a console logout"
    );
}
