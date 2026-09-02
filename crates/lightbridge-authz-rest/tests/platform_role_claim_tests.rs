// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! `ClaimSource::PlatformRoles` end to end over the real `POST /oauth2/token` handler (ADR-0033).
//!
//! What is pinned here, and why each one matters:
//!
//! * **Union, not overwrite.** Two mappers naming `lightbridge_api_roles` — `project_role` (owner
//!   → `lightbridge-viewer`, the post-cutover default) and `platform_roles` — merge, deduplicated.
//!   This is the whole mechanism the prod cutover depends on; last-one-wins would make the roles
//!   claim depend on YAML ordering.
//! * **An owner is NOT an admin.** The negative half of the same test: with the mapper configured
//!   the owner's way, a person holding no platform grant is minted `lightbridge-viewer` and
//!   explicitly NOT `lightbridge-admin`. That is the exact prod defect this story exists to close.
//! * **Zero grants is not a failure.** An empty grant set mints normally.
//! * **A grants-read failure REFUSES the mint.** Pointed at a dead pool while subject/context
//!   resolution stays real, so the refusal is this claim source's own fail-closed branch firing —
//!   not `resolve_context` failing first. If it ever regressed to swallowing the error, this test
//!   flips from `500` to `200` with a silently-narrower roles claim, indistinguishable on the wire
//!   from a legitimately unprivileged user.
//! * **Refresh re-resolves LIVE.** Grant, refresh, see it; revoke, refresh, see it gone. This is
//!   what bounds propagation to one access-token TTL rather than one session lifetime — the ADR-0014
//!   property, asserted rather than assumed.
//!
//! Needs Postgres (`DATABASE_URL`, via `sqlx::test`) and Redis (`AUTHZ_REDIS_URL`), same as
//! `token_exchange_tests.rs`. Builds its own compact harness rather than growing that 8k-line
//! file's shared one.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use lightbridge_authz_api_key::entities::platform_role_grant_row::NewPlatformRoleGrant;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{
    ClaimMapper, ClaimSource, JwtSigning, Oauth2TokenExchange, OauthClient, OauthClientType,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{CreateAccount, CreateProject};
use lightbridge_authz_rest::oauth2_op::client_assertion_store::RedisClientAssertionStore;
use lightbridge_authz_rest::oauth2_op::client_store::ConfigClientStore;
use lightbridge_authz_rest::oauth2_op::refresh_signing::bootstrap_idp_signing_keys;
use lightbridge_authz_rest::oauth2_op::store::TokenExchangeOpStore;
use lightbridge_authz_rest::signing::ApiKeyJwtSigner;
use lightbridge_authz_rest::token_exchange::{TokenExchangeState, token_exchange_router};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

const ISSUER: &str = "https://authz.example.test";
const GRANDFATHER_ISSUER: &str = "https://keycloak.example.test/realms/dev";
const CLIENT_ID: &str = "console";
const ROLES_CLAIM: &str = "lightbridge_api_roles";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

struct MockBearer {
    subject: String,
}

#[async_trait]
impl BearerTokenServiceTrait for MockBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        Ok(TokenInfo {
            active: true,
            sub: self.subject.clone(),
            iss: GRANDFATHER_ISSUER.to_string(),
            exp: 0,
            aud: vec![CLIENT_ID.to_string()],
            roles: vec![],
            permissions: Default::default(),
            caller_kind: None,
            access_token: String::new(),
        })
    }
}

/// The ADR-0015 shipped defaults, as a fixed double. `evaluate` is unreachable: nothing on the
/// claim-mapper path calls it, and `resolve_budget_tier` (which does run) only reads the three
/// amount accessors.
#[derive(Debug)]
struct FixedPolicyEngine;

#[async_trait]
impl lightbridge_authz_budget::decision::PolicyEngine for FixedPolicyEngine {
    async fn evaluate(
        &self,
        _facts: &lightbridge_authz_budget::facts::Facts,
        _requested_amount_micros: i64,
    ) -> Result<
        lightbridge_authz_budget::decision::Decision,
        lightbridge_authz_budget::error::BudgetError,
    > {
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

fn redis_url() -> String {
    std::env::var("AUTHZ_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

fn repo(pool: PgPool) -> Arc<StoreRepo> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(pool))
}

/// A pool that can never connect, with a short acquire timeout so a deliberately-dead dependency
/// fails fast instead of paying sqlx's 30s default.
fn dead_repo() -> Arc<StoreRepo> {
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
        allowed_scopes: vec!["openid".to_string(), "offline_access".to_string()],
        refresh_absolute_ttl_seconds: 7_776_000,
        refresh_reuse_grace_seconds: 30,
        device_code_ttl_seconds: 600,
        device_poll_interval_seconds: 5,
        device_verification_uri: "https://authz.example.test/device/verify".to_string(),
        client_credentials_ttl_seconds: 900,
    }
}

fn client() -> OauthClient {
    OauthClient {
        client_id: CLIENT_ID.to_string(),
        client_type: OauthClientType::Public,
        scopes: exchange_cfg().allowed_scopes,
        grant_types: vec![
            TOKEN_EXCHANGE_GRANT.to_string(),
            "refresh_token".to_string(),
        ],
        allowed_audiences: vec![CLIENT_ID.to_string()],
        jwks: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

/// The EXACT pair of mappers B1 deploys to prod: an owner defaults to `lightbridge-viewer` (the
/// owner's binding ruling -- never `lightbridge-admin` again), and platform grants are unioned on
/// top of it.
fn prod_shaped_mappers() -> Vec<ClaimMapper> {
    vec![
        ClaimMapper {
            claim: ROLES_CLAIM.to_string(),
            source: ClaimSource::ProjectRole,
            map: std::collections::HashMap::from([
                ("owner".to_string(), vec!["lightbridge-viewer".to_string()]),
                ("lead".to_string(), vec!["lightbridge-editor".to_string()]),
                ("member".to_string(), vec!["lightbridge-viewer".to_string()]),
            ]),
            default_values: Vec::new(),
        },
        ClaimMapper {
            claim: ROLES_CLAIM.to_string(),
            source: ClaimSource::PlatformRoles,
            map: std::collections::HashMap::new(),
            default_values: Vec::new(),
        },
    ]
}

fn state(
    repo: Arc<StoreRepo>,
    platform_repo: Arc<StoreRepo>,
    subject: &str,
    mappers: Vec<ClaimMapper>,
) -> TokenExchangeState {
    let cfg = exchange_cfg();
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(), repo.clone()).unwrap();
    let op_store = Arc::new(TokenExchangeOpStore::new(
        ConfigClientStore::from_config(&[client()], &cfg),
        RedisClientAssertionStore::connect(&redis_url(), None, "test:platform-roles-jti:").unwrap(),
        repo.clone(),
        repo,
        platform_repo,
        // The budget ledger plays no part in any assertion here; `resolve_budget_tier` is
        // fail-OPEN (it falls back to the policy floor), so an unreachable pool is the cheapest
        // honest double. Bounded `acquire_timeout` -- sqlx's 30s default is paid on every single
        // mint these tests make, and it dominated the runtime before this.
        Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
            sqlx::postgres::PgPoolOptions::new()
                .acquire_timeout(std::time::Duration::from_millis(250))
                .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/x")
                .map(|pool| Arc::new(DbPool::from_pool(pool)) as Arc<dyn DbPoolTrait>)
                .unwrap(),
        )),
        Arc::new(FixedPolicyEngine),
        Arc::new(MockBearer {
            subject: subject.to_string(),
        }),
        Arc::new(mappers),
        cfg.clone(),
        GRANDFATHER_ISSUER.to_string(),
    ));
    TokenExchangeState::new(
        signer,
        authkestra_op::config::OpConfig {
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
            device_code_ttl_secs: cfg.device_code_ttl_seconds as u64,
            token_exchange_enabled: true,
        },
        op_store,
        "https://authz.example.test/device/verify".to_string(),
        cfg.device_code_ttl_seconds as u64,
        cfg.device_poll_interval_seconds as u64,
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
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// The subject owns its own account and one project — the ADR-0026 shape every signed-in person
/// has, and the reason `owner` used to mean `lightbridge-admin` for everybody.
async fn seed_owner(repo: &StoreRepo, subject: &str) -> String {
    repo.create_account(
        &AccountId::assert_already_resolved(subject),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .unwrap();
    let project_id = cuid2();
    repo.create_project(
        &AccountId::assert_already_resolved(subject),
        subject,
        CreateProject {
            name: "roles-project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: format!("bill-{}", cuid2()),
            project_quota: None,
        },
        project_id.clone(),
    )
    .await
    .unwrap();
    project_id
}

/// Decodes the roles claim off a minted access token without verifying the signature -- these
/// tests are about the claim's CONTENT; `signing_tests.rs` owns the signature.
fn roles_claim(access_token: &str) -> Vec<String> {
    let payload = access_token.split('.').nth(1).expect("a JWT has 3 parts");
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload.as_bytes(),
    )
    .expect("payload is base64url");
    let claims: Value = serde_json::from_slice(&decoded).unwrap();
    claims[ROLES_CLAIM]
        .as_array()
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn exchange_body(project_id: &str, scope: &str) -> String {
    format!(
        "grant_type={TOKEN_EXCHANGE_GRANT}&client_id={CLIENT_ID}\
         &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token\
         &subject_token=x&project_id={project_id}&scope={scope}"
    )
}

async fn grant(repo: &StoreRepo, user_id: &str, role: &str) -> String {
    repo.grant_platform_role(NewPlatformRoleGrant {
        id: cuid2(),
        user_id: user_id.to_string(),
        role: role.to_string(),
        granted_by: None,
        reason: Some("test".to_string()),
    })
    .await
    .unwrap()
    .id
}

/// The headline test: the prod-shaped mapper pair, an account owner, and a platform grant. The
/// claim is the UNION -- and, crucially, an owner with NO grant is a viewer, never an admin.
#[sqlx::test(migrations = "../../migrations")]
async fn owner_defaults_to_viewer_and_platform_grants_union_on_top(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let subject = format!("owner-{}", cuid2());
    let project_id = seed_owner(&repo, &subject).await;

    let (status, body) = post_token(
        state(repo.clone(), repo.clone(), &subject, prod_shaped_mappers()),
        &exchange_body(&project_id, "openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let roles = roles_claim(body["access_token"].as_str().unwrap());
    assert_eq!(
        roles,
        vec!["lightbridge-viewer".to_string()],
        "an account owner holding no platform grant must NOT be minted lightbridge-admin -- that \
         is the prod defect (ai-helm-values .../lightbridge-app.yaml:266-273) this whole story \
         exists to close: {roles:?}"
    );

    grant(&repo, &subject, "lightbridge-admin").await;
    let (status, body) = post_token(
        state(repo.clone(), repo.clone(), &subject, prod_shaped_mappers()),
        &exchange_body(&project_id, "openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let mut roles = roles_claim(body["access_token"].as_str().unwrap());
    roles.sort();
    assert_eq!(
        roles,
        vec![
            "lightbridge-admin".to_string(),
            "lightbridge-viewer".to_string()
        ],
        "two mappers on one claim MERGE (union, deduped); last-one-wins would make the roles claim \
         depend on YAML ordering: {roles:?}"
    );
}

/// The dedupe half of the union: a platform grant that names the same role the project mapper
/// already contributed appears exactly once.
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_contributed_by_both_sources_appears_once(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let subject = format!("dupe-{}", cuid2());
    let project_id = seed_owner(&repo, &subject).await;
    grant(&repo, &subject, "lightbridge-viewer").await;

    let (status, body) = post_token(
        state(repo.clone(), repo.clone(), &subject, prod_shaped_mappers()),
        &exchange_body(&project_id, "openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        roles_claim(body["access_token"].as_str().unwrap()),
        vec!["lightbridge-viewer".to_string()]
    );
}

/// A `platform_roles` mapper alone, with no grants at all: mints fine, claim empty. An empty grant
/// set is an ANSWER, not a lookup failure.
#[sqlx::test(migrations = "../../migrations")]
async fn zero_grants_still_mints(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let subject = format!("ungranted-{}", cuid2());
    let project_id = seed_owner(&repo, &subject).await;

    let (status, body) = post_token(
        state(
            repo.clone(),
            repo.clone(),
            &subject,
            vec![ClaimMapper {
                claim: ROLES_CLAIM.to_string(),
                source: ClaimSource::PlatformRoles,
                map: std::collections::HashMap::new(),
                default_values: Vec::new(),
            }],
        ),
        &exchange_body(&project_id, "openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(roles_claim(body["access_token"].as_str().unwrap()).is_empty());
}

/// Fail-closed, isolated: `repo` (subject/context resolution) stays a REAL Postgres so
/// `resolve_context` succeeds, while ONLY the `platform_role_grants` handle is unreachable. A
/// regression that swallowed the error into an empty claim would flip this from 500 to 200 with a
/// silently-unprivileged token -- indistinguishable, on the wire, from a legitimate viewer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_grants_read_failure_refuses_the_mint(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let subject = format!("failclosed-{}", cuid2());
    let project_id = seed_owner(&repo, &subject).await;

    let (status, body) = post_token(
        state(repo.clone(), dead_repo(), &subject, prod_shaped_mappers()),
        &exchange_body(&project_id, "openid"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unresolvable platform-roles lookup must refuse the mint outright: {body}"
    );
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("access_token").is_none(),
        "no token of any kind may be issued on this path: {body}"
    );
}

/// The propagation contract, asserted rather than assumed: the refresh grant re-resolves the grants
/// table LIVE on every rotation, so a grant appears and a revocation disappears within one
/// access-token TTL rather than one session lifetime (ADR-0014's precedent).
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_re_resolves_grants_live_in_both_directions(pool: PgPool) {
    let repo = repo(pool);
    bootstrap_idp_signing_keys(&repo, &signing_cfg())
        .await
        .unwrap();
    let subject = format!("refresh-{}", cuid2());
    let project_id = seed_owner(&repo, &subject).await;

    let (status, body) = post_token(
        state(repo.clone(), repo.clone(), &subject, prod_shaped_mappers()),
        &exchange_body(&project_id, "openid offline_access"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        roles_claim(body["access_token"].as_str().unwrap()),
        vec!["lightbridge-viewer".to_string()],
        "no grant yet"
    );
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // Grant AFTER the session already exists: the next refresh must see it.
    let grant_id = grant(&repo, &subject, "lightbridge-admin").await;
    let (status, body) = post_token(
        state(repo.clone(), repo.clone(), &subject, prod_shaped_mappers()),
        &format!("grant_type=refresh_token&client_id={CLIENT_ID}&refresh_token={refresh_token}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let mut roles = roles_claim(body["access_token"].as_str().unwrap());
    roles.sort();
    assert_eq!(
        roles,
        vec![
            "lightbridge-admin".to_string(),
            "lightbridge-viewer".to_string()
        ],
        "the refresh grant must RE-RESOLVE the table, not replay the claim minted at exchange time"
    );
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // And the other direction, which is the security-relevant one.
    repo.revoke_platform_role(&grant_id, Some("offboarded"))
        .await
        .unwrap()
        .expect("the grant was active");
    let (status, body) = post_token(
        state(repo.clone(), repo.clone(), &subject, prod_shaped_mappers()),
        &format!("grant_type=refresh_token&client_id={CLIENT_ID}&refresh_token={refresh_token}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        roles_claim(body["access_token"].as_str().unwrap()),
        vec!["lightbridge-viewer".to_string()],
        "a revoked grant must be gone from the very next re-mint"
    );
}
