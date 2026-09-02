// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! Proof tests for two adversarial-review findings against `POST /oauth2/introspect`
//! (`token_exchange.rs`, added alongside RFC 7662 introspection/OIDC session management).
//! Deliberately a standalone file, not an addition to `tests/token_exchange_tests.rs` /
//! `tests/idp_server_tests.rs` -- another agent is concurrently adding its own introspection
//! coverage to those two files, and a shared file edited by two agents at once is exactly how
//! test additions silently clobber each other. Everything here is self-contained: its own
//! fixtures, deliberately minimal and copied down from `token_exchange_tests.rs`'s (private,
//! per-test-binary) equivalents rather than importing them, since integration-test binaries
//! cannot share private items across files.
//!
//! **F3 (token-type confusion):** `introspect_endpoint`'s access-token branch used to gate only
//! on `claims.azp == caller's client_id`. An ID token minted alongside an access token
//! (`id_token_extra`, `signing.rs`) carries that SAME `azp` (the requesting client's own id), so
//! the pre-fix gate would introspect a presented ID token as an active Bearer access token.
//! `access_token_extra` (`signing.rs`) is the only place that stamps `typ: "Bearer"`;
//! `id_token_extra` stamps no `typ` at all -- the fix adds `typ == "Bearer"` to the gate.
//!
//! **F2 (fail-open refresh-token introspection):** `find_active_refresh_token_for_client` only
//! checks `status = 'active' AND expires_at > now AND client_id matches`. The real redemption
//! path, `handle_refresh_token` (`oauth2_op/store.rs`), additionally refuses when the chain's
//! absolute cap has passed, when `resolve_context` no longer finds the subject on the project, or
//! when `require_active_project_and_account` finds the account/project suspended. Before the fix,
//! introspection could report `active: true` for a refresh token the refresh grant itself would
//! reject outright -- exactly the case RFC 7662 exists to prevent. The fix,
//! `find_introspectable_refresh_token_for_client`, re-runs those same checks and, separately,
//! propagates a genuine lookup error as `Err` rather than collapsing it to `active: false`.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use lightbridge_authz_api_key::entities::exchange_refresh_token_row::NewExchangeRefreshToken;
use lightbridge_authz_api_key::entities::session_row::NewSession;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{
    JwtSigning, Oauth2TokenExchange, OauthClient, OauthClientType,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{CreateAccount, CreateProject, ResourceStatus, hash_api_key};
use lightbridge_authz_rest::oauth2_op::client_assertion_store::RedisClientAssertionStore;
use lightbridge_authz_rest::oauth2_op::client_store::ConfigClientStore;
use lightbridge_authz_rest::oauth2_op::store::TokenExchangeOpStore;
use lightbridge_authz_rest::signing::{ApiKeyJwtSigner, bootstrap_signing_key};
use lightbridge_authz_rest::token_exchange::{TokenExchangeState, token_exchange_router};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

const ISSUER: &str = "https://authz.example.test";
const GRANDFATHER_ISSUER: &str = "https://keycloak.example.test/realms/dev";
const SUBJECT: &str = "kc-user-123";
const ACCOUNT_ID: &str = SUBJECT;
const PROJECT_ID: &str = "proj_xchg";
const OWNER_ACCOUNT: &str = "kc-owner-999";
const MEMBER_PROJECT_ID: &str = "proj_member_scope";
const PUBLIC_CLIENT_ID: &str = "lightbridge-ss";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Configurable mock of the upstream Keycloak validator -- copied down from
/// `token_exchange_tests.rs`'s own `MockBearer` (private to that test binary, so this file needs
/// its own copy rather than an import).
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
            iss: GRANDFATHER_ISSUER.to_string(),
            exp: 0,
            aud: self.aud.clone(),
            roles: vec![],
            permissions: Default::default(),
            caller_kind: None,
            access_token: String::new(),
        })
    }
}

fn repo(pool: PgPool) -> Arc<StoreRepo> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(pool))
}

/// An unreachable-DB `StoreRepo`, for the fail-closed proof: a short `acquire_timeout` so the
/// test fails fast instead of paying sqlx's 30s default.
fn unreachable_repo() -> Arc<StoreRepo> {
    let pool = sqlx::postgres::PgPoolOptions::new()
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

fn public_client(client_id: &str) -> OauthClient {
    OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Public,
        scopes: exchange_cfg().allowed_scopes,
        grant_types: vec![
            TOKEN_EXCHANGE_GRANT.to_string(),
            "refresh_token".to_string(),
        ],
        allowed_audiences: vec![client_id.to_string()],
        jwks: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

fn redis_url() -> String {
    std::env::var("AUTHZ_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

/// One public client (`PUBLIC_CLIENT_ID`), a `MockBearer` accepting it as `aud`, and a real,
/// reachable Redis (client-assertion replay tracking, unused by the public-client requests this
/// file sends, but still required to construct the store).
fn state(repo: Arc<StoreRepo>) -> TokenExchangeState {
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        repo.pool.clone(),
    ));
    let cfg = exchange_cfg();
    let device_code_ttl_secs = cfg.device_code_ttl_seconds as u64;
    let device_poll_interval_secs = cfg.device_poll_interval_seconds as u64;
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(), repo.clone()).unwrap();
    let client_store = ConfigClientStore::from_config(&[public_client(PUBLIC_CLIENT_ID)], &cfg);
    let assertions =
        RedisClientAssertionStore::connect(&redis_url(), None, "test:introspection-failclosed:")
            .expect("lazy connection manager always builds");
    let op_config = authkestra_op::config::OpConfig {
        issuer: ISSUER.to_string(),
        scopes_supported: cfg.allowed_scopes.clone(),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            TOKEN_EXCHANGE_GRANT.to_string(),
            "refresh_token".to_string(),
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
        repo.clone(),
        repo.clone(),
        repo,
        budget_repo,
        Arc::new(FixedFloorPolicyEngine),
        Arc::new(MockBearer::new(true, vec![PUBLIC_CLIENT_ID.to_string()])),
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

/// A `TokenExchangeState` whose `repo`/`quota_repo`/`budget_repo` are all the SAME unreachable
/// pool -- proves what happens when the DB is down at introspection time, with no reachable
/// fallback anywhere in the store.
fn state_with_unreachable_repo() -> TokenExchangeState {
    let repo = unreachable_repo();
    state(repo)
}

/// ADR-0015 Decision 6's fail-closed floor engine, fixed rather than resolved from a real policy
/// store -- these tests never exercise a refill decision, only token issuance/introspection.
/// `evaluate` is never called by `resolve_budget_tier` (the only thing these tests' minting path
/// touches on this trait), matching `token_exchange_tests.rs`'s own `FixedPolicyEngine` double.
#[derive(Debug)]
struct FixedFloorPolicyEngine;

#[async_trait]
impl lightbridge_authz_budget::PolicyEngine for FixedFloorPolicyEngine {
    async fn evaluate(
        &self,
        _facts: &lightbridge_authz_budget::Facts,
        _requested_amount_micros: i64,
    ) -> Result<lightbridge_authz_budget::Decision, lightbridge_authz_budget::error::BudgetError>
    {
        unreachable!("resolve_budget_tier never calls PolicyEngine::evaluate")
    }

    fn allowed_amounts_micros(&self) -> Vec<i64> {
        vec![6_000_000, 15_000_000, 30_000_000]
    }

    fn starting_amount_micros(&self) -> i64 {
        15_000_000
    }

    fn fail_closed_floor_micros(&self) -> i64 {
        6_000_000
    }
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
            allowed_models: None,
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

/// A second account (`OWNER_ACCOUNT`) owning `MEMBER_PROJECT_ID`, with `SUBJECT` added as a
/// roster member -- so the roster row (not project ownership) is the only thing standing between
/// `SUBJECT` and a `resolve_context` `NotFound`.
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

/// Directly inserts a `sessions` row (`exchange_refresh_tokens.session_id`'s foreign key target)
/// plus an `exchange_refresh_tokens` row (bypassing the real token-exchange grant entirely) so
/// each test can hand-pick exactly the fields under test -- `chain_expires_at` in the past, or a
/// project the caller is about to suspend/un-roster. Returns the plaintext to present at
/// `/oauth2/introspect`.
#[allow(clippy::too_many_arguments)]
async fn insert_refresh_token_row(
    repo: &StoreRepo,
    project_id: &str,
    client_id: &str,
    chain_expires_at: chrono::DateTime<Utc>,
) -> String {
    let plaintext = format!("rt-{}", cuid2());
    let now = Utc::now();
    let session = repo
        .create_session(NewSession {
            id: cuid2(),
            account_id: SUBJECT.to_string(),
            project_id: project_id.to_string(),
            client_id: Some(client_id.to_string()),
            kind: "token".to_string(),
            expires_at: now + Duration::seconds(3600),
            subject: Some(SUBJECT.to_string()),
        })
        .await
        .expect("insert session row");
    repo.create_exchange_refresh_token(NewExchangeRefreshToken {
        id: cuid2(),
        subject: SUBJECT.to_string(),
        account_id: SUBJECT.to_string(),
        project_id: project_id.to_string(),
        client_id: client_id.to_string(),
        token_hash: hash_api_key(&plaintext),
        scope: Some("openid offline_access".to_string()),
        email: None,
        email_verified: None,
        auth_time: None,
        preferred_username: None,
        name: None,
        chain_id: cuid2(),
        chain_expires_at,
        session_id: session.id,
        created_at: now,
        expires_at: now + Duration::seconds(3600),
    })
    .await
    .expect("insert refresh token row");
    plaintext
}

/// Every token these fixtures present (`insert_refresh_token_row`'s `rt-<cuid2>` plaintexts, and
/// real self-signed JWTs -- base64url + `.` separators) is already `x-www-form-urlencoded`-safe,
/// so this builds the body with a plain `format!` rather than a percent-encoding step, matching
/// `token_exchange_tests.rs`'s own `post_token` convention.
async fn post_introspect(state: TokenExchangeState, token: &str) -> (StatusCode, Value) {
    let body = format!("token={token}&client_id={PUBLIC_CLIENT_ID}");
    let response = token_exchange_router::<()>(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn post_token(state: TokenExchangeState, body: &str) -> Value {
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
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "token mint must succeed for these fixtures"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ================================================================================================
// F2: refresh-token introspection must re-run handle_refresh_token's own gates, not just the base
// active/not-expired/client-matches lookup.
// ================================================================================================

/// A refresh token past its chain's absolute cap (`chain_expires_at` in the past) still passes
/// the base `status = 'active' AND expires_at > now` lookup -- `handle_refresh_token` would
/// refuse to rotate it (`now >= old_row.chain_expires_at`), so introspection must not report it
/// active either.
#[sqlx::test(migrations = "../../migrations")]
async fn chain_expired_refresh_token_introspects_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let token = insert_refresh_token_row(
        &repo,
        PROJECT_ID,
        PUBLIC_CLIENT_ID,
        Utc::now() - Duration::seconds(60),
    )
    .await;

    let (status, body) = post_introspect(state(repo), &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["active"],
        Value::Bool(false),
        "a refresh token past its chain's absolute cap must introspect inactive: {body}"
    );
}

/// A refresh token whose project has been suspended since it was issued still passes the base
/// lookup -- `handle_refresh_token` would refuse via `require_active_project_and_account`
/// (`Forbidden`), so introspection must not report it active either.
#[sqlx::test(migrations = "../../migrations")]
async fn suspended_project_refresh_token_introspects_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let token = insert_refresh_token_row(
        &repo,
        PROJECT_ID,
        PUBLIC_CLIENT_ID,
        Utc::now() + Duration::seconds(3600),
    )
    .await;

    repo.set_project_status(
        &AccountId::assert_already_resolved(SUBJECT),
        PROJECT_ID,
        ResourceStatus::Suspended,
    )
    .await
    .expect("suspend project");

    let (status, body) = post_introspect(state(repo), &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["active"],
        Value::Bool(false),
        "a refresh token for a suspended project must introspect inactive: {body}"
    );
}

/// A refresh token minted while `SUBJECT` was still a roster member of `MEMBER_PROJECT_ID`, after
/// `SUBJECT` has since been removed from that roster, still passes the base lookup --
/// `handle_refresh_token` would refuse via `resolve_context` (`NotFound`), so introspection must
/// not report it active either.
#[sqlx::test(migrations = "../../migrations")]
async fn removed_roster_member_refresh_token_introspects_inactive(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed_member_project(&repo).await;

    let token = insert_refresh_token_row(
        &repo,
        MEMBER_PROJECT_ID,
        PUBLIC_CLIENT_ID,
        Utc::now() + Duration::seconds(3600),
    )
    .await;

    repo.remove_project_member(
        &AccountId::assert_already_resolved(OWNER_ACCOUNT),
        MEMBER_PROJECT_ID,
        SUBJECT,
    )
    .await
    .expect("remove subject from the roster");

    let (status, body) = post_introspect(state(repo), &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["active"],
        Value::Bool(false),
        "a refresh token for a subject removed from the project's roster must introspect \
         inactive: {body}"
    );
}

/// Control: an otherwise-valid refresh token (no chain expiry, no suspension, still a roster
/// member) still introspects active after the fix -- the re-validation must not be a blanket
/// refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn valid_refresh_token_still_introspects_active(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let token = insert_refresh_token_row(
        &repo,
        PROJECT_ID,
        PUBLIC_CLIENT_ID,
        Utc::now() + Duration::seconds(3600),
    )
    .await;

    let (status, body) = post_introspect(state(repo), &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["active"],
        Value::Bool(true),
        "a genuinely valid refresh token must still introspect active: {body}"
    );
    assert_eq!(body["sub"], SUBJECT);
    assert_eq!(body["project_id"], PROJECT_ID);
    // F10: RFC 7662 §2.2 lists `token_type` as OPTIONAL, and "refresh_token" is not an RFC 6749
    // §7.1 access token type -- the refresh-token response omits it entirely rather than
    // populating it with a value the spec never defines.
    assert!(
        body.get("token_type").is_none(),
        "a refresh-token introspection response should omit token_type rather than claim a \
         non-RFC-6749 type: {body}"
    );
}

/// Fail-closed proof: when the re-validation lookup itself cannot run (DB unreachable), the
/// endpoint must answer `500 server_error`, never `200 {"active": false}` -- collapsing a
/// dependency outage into "inactive" would let an attacker use a forced outage to make a live,
/// stolen refresh token introspect as dead.
#[sqlx::test(migrations = "../../migrations")]
async fn repo_outage_during_refresh_introspection_is_server_error_not_inactive(_pool: PgPool) {
    let (status, body) = post_introspect(
        state_with_unreachable_repo(),
        "any-refresh-token-shaped-string",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a DB outage during introspection must be a 500, not a disguised inactive answer: {body}"
    );
    assert_eq!(body["error"], "server_error");
    assert_ne!(
        body.get("active"),
        Some(&Value::Bool(false)),
        "must never answer active:false for an outage it could not actually check: {body}"
    );
}

// ================================================================================================
// F3: the access-token introspection branch must require typ == "Bearer", not just azp match --
// otherwise a presented ID token (which carries the same azp) introspects as a live access token.
// ================================================================================================

/// Mints an access token + id_token together (openid scope) via a real token-exchange grant, then
/// introspects the ID TOKEN. Before the fix this reported `active: true` (azp matched, typ was
/// never checked); after the fix it must report inactive, since `id_token_extra` never stamps
/// `typ`.
#[sqlx::test(migrations = "../../migrations")]
async fn id_token_does_not_introspect_as_an_active_bearer_token(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_signing_key(&repo, &signing_cfg()).await.unwrap();
    seed(&repo).await;

    let minted = post_token(
        state(repo.clone()),
        &format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={PUBLIC_CLIENT_ID}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token=x&project_id={PROJECT_ID}&scope=openid"
        ),
    )
    .await;
    let id_token = minted["id_token"]
        .as_str()
        .expect("openid scope must mint an id_token")
        .to_string();
    let access_token = minted["access_token"]
        .as_str()
        .expect("token mint must produce an access_token")
        .to_string();

    let (status, body) = post_introspect(state(repo.clone()), &id_token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["active"],
        Value::Bool(false),
        "an id_token must never introspect as an active Bearer access token: {body}"
    );

    // Control: the REAL access token minted in the same response still introspects active --
    // the fix must not be a blanket refusal of every self-signed JWT.
    let (status, body) = post_introspect(state(repo), &access_token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["active"],
        Value::Bool(true),
        "the real access token minted alongside the id_token must still introspect active: {body}"
    );
    assert_eq!(body["token_type"], "Bearer");
}
