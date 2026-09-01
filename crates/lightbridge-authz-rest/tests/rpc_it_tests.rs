// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database integration tests for the cratestack RPC CRUD surface (ADR-0003/ADR-0013). Gated
//! behind `it-tests` and `just it-tests` (needs a migrated Postgres via `DATABASE_URL` *and* Redis
//! via `AUTHZ_REDIS_URL`/localhost, both reached by the assembled `build_api_router`).
//!
//! Covers, over the real HTTP RPC transport:
//!   * full create/read/update/delete/list for accounts/projects/api-keys, over CBOR — the only
//!     wire format the router accepts post-ADR-0013 (`Wire::Json` still exists in `common` but only
//!     as a negative-path probe, see `json_content_type_is_rejected` below);
//!   * the RBAC gate end-to-end (admin succeeds on every mapped op; a viewer who is a legitimate
//!     account member still 403s on writes but 200s on reads) — the privilege-escalation regression;
//!   * the soft-delete + `api_key_validation`-view security fix (a soft-deleted key must not
//!     validate at the OPA layer);
//!   * an `@@audit` row landing on create/update/delete for an audited model;
//!   * idempotent replay of a mutating call under a repeated `Idempotency-Key`;
//!   * per-frame independent success/failure on `POST /rpc/batch` (bare router — dispatch behavior
//!     only, independent of RBAC), and, against the *real* assembled router, per-frame RBAC: one
//!     token, one batch call, mixed permitted/forbidden frames each authorized independently;
//!   * `createAccount` seeding the creator's membership so a subsequent project create succeeds
//!     (and a non-member is refused).
//!
//! This consolidates the lifecycle coverage the deleted `store_it_tests.rs` /
//! `controllers_tests.rs` / `router_tests.rs` used to carry, re-expressed against the RPC surface.
#![cfg(feature = "it-tests")]

mod common;

use lightbridge_authz_core::identity::AccountId;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use common::{MapBearer, Wire, admin_perms, as_json, rpc_call, token_info, viewer_perms};
use cratestack::SqlxIdempotencyStore;
use cratestack::{DEFAULT_BODY_LIMIT_BYTES, Json, Value as CValue, ratelimit::RateLimitStore};
use cratestack_codec_cbor::CborCodec;
use cratestack_core::CratestackCodec;
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::authz::Permission;
use lightbridge_authz_core::config::{BasicAuth, Billing, BillingPlan};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::auth_provider::CratestackAuthProvider;
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
use lightbridge_authz_rest::rpc_authorize::RpcScope;
use lightbridge_authz_rest::{OpaRepoTrait, OpaState, Procedures};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for it-tests (just it-tests)")
}

fn redis_url() -> String {
    std::env::var("AUTHZ_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

fn billing() -> Billing {
    Billing {
        plans: vec![
            BillingPlan {
                id: "free".to_string(),
                name: "Free".to_string(),
                limits: None,
            },
            BillingPlan {
                id: "pro".to_string(),
                name: "Pro".to_string(),
                limits: None,
            },
        ],
    }
}

// Each `#[tokio::test]` calls `setup()`, which builds its own `core_pool()` + `cratestack_pool()`
// + `verify` pool -- with `cargo test`'s default full parallelism, that's N tests running
// concurrently, each holding its own small pool, against Postgres's `max_connections = 100`
// (local compose default, `compose.yaml`'s `postgresql` service). At 5 connections apiece the
// combined ceiling (2 pools x 5 x ~16 tests = 160) exceeds 100, so a busy run intermittently hits
// "pool timed out while waiting for an open connection" -- each test's actual concurrent need is
// low (mostly one sequential transaction at a time), so a small per-test cap has ample headroom
// without slowing any individual test down.
const TEST_POOL_MAX_CONNECTIONS: u32 = 2;

async fn core_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        .max_connections(TEST_POOL_MAX_CONNECTIONS)
        .connect(&database_url())
        .await
        .expect("connect core pool");
    Arc::new(DbPool::from_pool(pool))
}

async fn cratestack_pool() -> cratestack::sqlx::PgPool {
    cratestack::sqlx::postgres::PgPoolOptions::new()
        .max_connections(TEST_POOL_MAX_CONNECTIONS)
        .connect(&database_url())
        .await
        .expect("connect cratestack pool")
}

/// Everything a live RPC test needs: the assembled router (bearer-driven), plus direct handles for
/// out-of-band seeding / verification. `verify` is a *workspace*-sqlx (0.9) pool for raw
/// verification SQL — distinct from `cratestack_pool` (cratestack's sqlx 0.8), which the two crates
/// keep separate; a 0.9 query cannot run on a 0.8 pool.
struct Ctx {
    router: Router,
    core: Arc<dyn DbPoolTrait>,
    cratestack_pool: cratestack::sqlx::PgPool,
    verify: sqlx::PgPool,
    issuer: Arc<AuthzStoreImpl>,
    policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    refill_service: Arc<lightbridge_authz_budget::RefillService>,
    review_service: Arc<lightbridge_authz_budget::ReviewService>,
    budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
}

// `SqlxIdempotencyStore::ensure_schema()` issues its `CREATE TYPE`/`CREATE TABLE` DDL without
// `IF NOT EXISTS`-safe concurrency handling, so when every one of this file's ~16 tests calls it
// from `setup()` against the same fresh (just-migrated) database under `cargo test`'s default
// parallelism, several race and hit `duplicate key value violates unique constraint
// "pg_type_typname_nsp_index"`. The schema is process-wide idempotent (identical DDL, no
// per-test state), so it only needs to run once per test binary -- guarded by a `OnceCell` shared
// across every `setup()` call; concurrent callers await the same in-flight future rather than
// each issuing their own DDL.
static IDEMPOTENCY_SCHEMA_READY: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// Build the full `build_api_router` for `bearer`, connecting the cratestack CRUD client,
/// Postgres-backed idempotency store, and Redis rate-limit store to the live backends.
async fn setup(bearer: Arc<dyn BearerTokenServiceTrait>) -> Ctx {
    setup_with_resolver(bearer, common::test_resolver()).await
}

/// Like [`setup`], but with a caller-supplied [`SubjectResolver`] instead of the trust-everything
/// default -- for `crud_authorizes_via_the_federated_account_not_the_raw_subject` below, which
/// needs a REAL `FederatedSubjectResolver` against this test's own live Postgres to prove
/// translation actually happens, not merely that a trust-everything stub passes the raw subject
/// through unchanged (which every other test in this file relies on, deliberately, so bearer
/// subjects can double as account ids without seeding a federated_identities row each time).
async fn setup_with_resolver(
    bearer: Arc<dyn BearerTokenServiceTrait>,
    resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver>,
) -> Ctx {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let core = core_pool().await;
    let cpool = cratestack_pool().await;
    let cdb = schema::Cratestack::builder(cpool.clone()).build();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()).with_billing(billing()));
    let idempotency = Arc::new(SqlxIdempotencyStore::new(cpool.clone()));
    IDEMPOTENCY_SCHEMA_READY
        .get_or_init(|| async {
            idempotency
                .ensure_schema()
                .await
                .expect("ensure idempotency schema");
        })
        .await;
    // A per-`setup()`-call namespace, not a shared literal: `RateLimitLayer`'s default key hashes
    // the raw `Authorization` header value, and every test in this file authenticates with the
    // literal bearer token `"admin"` (or another fixed literal like `"owner"`/`"viewer"`) -- a
    // shared `"authz-api-it"` prefix would put every concurrently-running test's "admin" calls
    // into the SAME token-bucket, so a big-enough test file blows through the shared burst budget
    // under `cargo test`'s default parallelism regardless of any single test's own call volume.
    let rate_limit: Arc<dyn RateLimitStore> =
        build_redis_rate_limit_store(&redis_url(), None, format!("authz-api-it-{}", cuid2()))
            .expect("redis rate-limit store");

    // Migrations seed an active `budget-refill` revision (ADR-0007), so a real
    // `load_active_from_db` against this test's live Postgres works here.
    let policy_store = Arc::new(
        lightbridge_authz_budget::PolicyStore::load_active_from_db(
            core.clone(),
            "budget-refill",
            10_000,
        )
        .await
        .expect("migrations seed an active budget-refill revision"),
    );

    // Real budget-refill dependencies against the same live `core` pool (PR 3.4, #191). No
    // `usage_service` is configured for this test file (it does not exercise spend-dependent
    // policy rules), so `UnavailableSpendReader` stands in -- see that type's own doc comment.
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        core.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
        core.clone(),
    ));
    let refill_service = Arc::new(lightbridge_authz_budget::RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_store.engine(),
        Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
    ));
    let review_service = Arc::new(lightbridge_authz_budget::ReviewService::new(
        budget_repo.clone(),
        augmentation_repo,
    ));

    let router = lightbridge_authz_rest::build_api_router(
        bearer,
        resolver,
        issuer.clone(),
        policy_store.clone(),
        refill_service.clone(),
        review_service.clone(),
        budget_repo.clone(),
        cdb,
        core.clone(),
        idempotency,
        rate_limit,
        false,
        None,
    );

    let verify = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url())
        .await
        .expect("connect verify pool");

    Ctx {
        router,
        core,
        cratestack_pool: cpool,
        verify,
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
    }
}

/// A single-identity admin bearer whose subject is `subject`, token string `"admin"`.
fn admin_bearer(subject: &str) -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(MapBearer::new().with("admin", token_info(subject, admin_perms())))
}

/// Decode a CBOR RPC success body into `serde_json::Value` (CBOR is the only wire format the
/// router accepts post-ADR-0013 — see `common::Wire`).
fn json_body(bytes: &[u8]) -> Value {
    Wire::Cbor.decode(bytes)
}

/// Create an account over RPC and return its id, asserting 200.
async fn create_account(router: &Router, token: &str, _unused: &str) -> String {
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.createAccount",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some(token),
    )
    .await;
    assert!(
        status.is_success(),
        "createAccount: {status} {}",
        String::from_utf8_lossy(&body)
    );
    json_body(&body)["id"]
        .as_str()
        .expect("account id")
        .to_string()
}

/// Build a typed `CreateProjectInput`. `defaultLimits` carries cratestack's own `Value` enum,
/// which serializes *externally tagged* (`{}` → `{"Map":{}}`), so a hand-built `serde_json` body
/// would be rejected as an invalid payload — encoding the generated input type is the only correct
/// wire shape for both JSON and CBOR. `allowedModels` is NOT a field here (#415, ADR-0018 Decision
/// 5): it is `@readonly` on the generic verb now, so a fresh project always starts with
/// `allowedModels = NULL` — see `set_project_allowed_models_over_cbor` below for setting it
/// afterward via `procedure.setProjectAllowedModels`.
fn project_input(id: &str, account_id: &str, name: &str) -> schema::inputs::CreateProjectInput {
    schema::inputs::CreateProjectInput {
        id: id.to_string(),
        accountId: account_id.to_string(),
        name: name.to_string(),
        defaultLimits: Json(CValue::Map(std::collections::BTreeMap::new())),
        billingPlan: "free".to_string(),
        billingIdentity: format!("bill-{}", cuid2()),
    }
}

/// Create a project over RPC and return its id, asserting 200.
async fn create_project(router: &Router, token: &str, account_id: &str, name: &str) -> String {
    let project_id = cuid2();
    let input = project_input(&project_id, account_id, name);
    let (status, body) = rpc_call(
        router.clone(),
        "model.Project.create",
        Wire::Cbor,
        &input,
        Some(token),
    )
    .await;
    assert!(
        status.is_success(),
        "createProject: {status} {}",
        String::from_utf8_lossy(&body)
    );
    json_body(&body)["id"]
        .as_str()
        .expect("project id")
        .to_string()
}

/// A `createApiKey`/`rotateApiKey` test payload's `expiresAt`: comfortably inside the default
/// 90-day `ApiKeyExpiry` ceiling (lightbridge-authz#395) `setup()`'s `AuthzStoreImpl` uses, and
/// always in the future -- unlike a hardcoded calendar literal, which would eventually violate one
/// rule or the other as real time passes.
fn near_future_expiry() -> String {
    (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339()
}

/// Create an api-key over RPC and return (key_id, secret), asserting 200. `expiresAt` is required
/// as of lightbridge-authz#395, so every caller of this helper gets a real, compliant one.
async fn create_api_key(
    router: &Router,
    token: &str,
    project_id: &str,
    name: &str,
) -> (String, String) {
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.createApiKey",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "name": name, "billingPlan": "free", "expiresAt": near_future_expiry() } }),
        Some(token),
    )
    .await;
    assert!(
        status.is_success(),
        "createApiKey: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let v = json_body(&body);
    (
        v["apiKey"]["id"].as_str().expect("key id").to_string(),
        v["secret"].as_str().expect("secret").to_string(),
    )
}

/// Like [`create_api_key`], but with a caller-supplied `expires_at` instead of the fixed
/// `near_future_expiry()` -- used by the `listMyExpiringApiKeys` boundary tests
/// (lightbridge-authz#436) to seed keys at precise offsets from "now", exactly at, just inside,
/// and just outside the expiry window under test.
async fn create_api_key_with_expiry(
    router: &Router,
    token: &str,
    project_id: &str,
    name: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> (String, String) {
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.createApiKey",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "name": name, "billingPlan": "free", "expiresAt": expires_at.to_rfc3339() } }),
        Some(token),
    )
    .await;
    assert!(
        status.is_success(),
        "createApiKey: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let v = json_body(&body);
    (
        v["apiKey"]["id"].as_str().expect("key id").to_string(),
        v["secret"].as_str().expect("secret").to_string(),
    )
}

// ---------------------------------------------------------------------------------------------
// Section 2: full CRUD lifecycle over the RPC router (CBOR — the only wire format post-ADR-0013).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn crud_lifecycle_for_all_resources() {
    let subject = format!("owner-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    // Account: create → get → list → update.
    let billing_id = format!("tenant-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.get",
        Wire::Cbor,
        &json!({ "id": account_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["id"], account_id);

    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.list",
        Wire::Cbor,
        &json!({}),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // `Account` carries `@@paged`: the list route wraps results in
    // `Page<T> { items, totalCount, pageInfo }` rather than a bare array.
    let accounts = json_body(&body);
    assert!(
        accounts["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == account_id),
        "list should include the created account"
    );
    assert!(accounts["totalCount"].as_i64().unwrap() >= 1);

    // `Account.defaultQuota` is `@readonly` on the generic verb since #379 -- updated via the
    // dedicated `updateAccountDefaultQuota` procedure instead. `model.Account.update` itself was
    // removed entirely by #398, since #379 had left it with zero generically-writable fields.
    let new_quota = format!("tenant2-{}", cuid2());
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.updateAccountDefaultQuota",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id, "defaultQuota": new_quota } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["defaultQuota"], new_quota);

    // Project: create → get → list → update.
    let project_id = create_project(r, "admin", &account_id, "proj").await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["id"], project_id);

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.list",
        Wire::Cbor,
        &json!({}),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "list projects: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        json_body(&body)["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == project_id)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.update",
        Wire::Cbor,
        &json!({ "id": project_id, "patch": { "name": "proj-renamed" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["name"], "proj-renamed");

    // Api-key: create (procedure) → get → list → update → delete (soft).
    let (key_id, _secret) = create_api_key(r, "admin", &project_id, "k").await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.get",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["id"], key_id);
    assert!(
        json_body(&body).get("keyHash").is_none(),
        "keyHash must be @server_only (never on the wire)"
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.list",
        Wire::Cbor,
        &json!({}),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json_body(&body)["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["id"] == key_id)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.update",
        Wire::Cbor,
        &json!({ "id": key_id, "patch": { "name": "k-renamed" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["name"], "k-renamed");

    let (status, _) = rpc_call(
        r.clone(),
        "model.ApiKey.delete",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Excluded from subsequent reads (soft-delete filter).
    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.list",
        Wire::Cbor,
        &json!({}),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !json_body(&body)["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["id"] == key_id),
        "a soft-deleted api-key must not appear in list"
    );

    // Project hard delete. `project_id` above is this account's default (first-ever) project,
    // which `model.Project.delete` now correctly refuses (see
    // `default_project_cannot_be_hard_deleted_only_suspended` below) -- so hard-delete is
    // exercised against a second, non-default project instead.
    let second_project_id = create_project(r, "admin", &account_id, "proj-2").await;
    let (status, _) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Cbor,
        &json!({ "id": second_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Account hard delete. Unlike `Project`, `Account` carries no default-project-style
    // protection at all post-ADR-0006 -- since `accounts.id` IS the caller's subject (one account
    // = one person), a second `createAccount` for the same subject conflicts rather than minting
    // a second, non-default account to delete instead (see
    // `a_second_account_for_the_same_subject_is_refused`), so this deletes `account_id` itself.
    // Account deletion is owner-only and no longer the generic `model.Account.delete` verb
    // (ADR-0005); "admin" is this account's owner.
    let (status, _) = rpc_call(
        r.clone(),
        "procedure.deleteAccountPermanently",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// ADR-0025 Stage 2: `auth().id` (set by `auth_provider::build_context` via
/// `SubjectResolver::resolve`) must be the FEDERATED account id a `federated_identities` row
/// resolves the presented bearer subject to -- never the raw subject claim itself. Deliberately
/// seeds a `federated_identities` row where `subject != account_id` (a real Keycloak subject
/// linked to a lightbridge account under a different id) via raw SQL, since none of this repo's
/// own write paths in Stage 1-3 produce that shape yet (the self-healing grandfather branch
/// always adopts `subject == account_id`) -- this test proves the GENERAL translation mechanism
/// (`resolve_account_for_federated_subject`'s "existing row" fast path), not only the
/// grandfathered special case every other test in this file relies on via the trust-everything
/// resolver.
#[tokio::test]
async fn crud_authorizes_via_the_federated_account_not_the_raw_subject() {
    const ISSUER: &str = "https://keycloak.example.test/realms/dev";
    let account_id = format!("real-account-{}", cuid2());
    let raw_kc_subject = format!("kc-raw-sub-{}", cuid2());

    let core = core_pool().await;
    let repo = StoreRepo::new(core.clone());
    repo.create_account(
        &AccountId::assert_already_resolved(account_id.clone()),
        lightbridge_authz_core::CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .expect("account creation must succeed");
    sqlx::query(
        "INSERT INTO federated_identities (id, issuer, subject, account_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(cuid2())
    .bind(ISSUER)
    .bind(&raw_kc_subject)
    .bind(&account_id)
    .execute(core.pool())
    .await
    .expect("seeding the federated_identities row must succeed");

    let resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver> = Arc::new(
        lightbridge_authz_rest::auth_provider::FederatedSubjectResolver::new(
            Arc::new(repo),
            None,
            ISSUER.to_string(),
        ),
    );
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&raw_kc_subject, admin_perms())));
    let ctx = setup_with_resolver(bearer, resolver).await;

    // `@@allow("read", account.id == auth().id)` on `Account` -- succeeds only if `auth().id`
    // resolved to `account_id`, the federated target, not `raw_kc_subject`, the presented claim.
    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Account.get",
        Wire::Cbor,
        &json!({ "id": account_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a bearer subject with a federated_identities row must authorize as its target account: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_body(&body)["id"], account_id);
}

/// ADR-0025 Correction: the Stage 2..5 bootstrap window. With Stage 2 live (every ingress
/// translates `(iss, sub)` to an account id BEFORE any procedure runs) and Stage 5 NOT YET
/// IMPLEMENTED (a minted `accounts.id` for brand-new accounts, written by `createAccount` itself
/// in the same transaction as the adopting `federated_identities` row), a subject the deployment
/// has genuinely never seen before -- no `accounts` row, no `federated_identities` row -- has no
/// way to bootstrap: `createAccount` is the ONLY procedure that could ever create the account
/// resolution needs, and Stage 2's own translation seam was refusing it before it could run.
/// Every other test in this file seeds an account first (directly or via `create_account`'s own
/// helper against a resolver that already trusts the subject), so none of them exercised a
/// truly-fresh subject; this is what a real compose e2e run (`just it-authorino`) hits the moment
/// a genuinely new identity shows up, and unit/it coverage missed it entirely until then.
///
/// Proves the full bootstrap end-to-end: `createAccount` succeeds via the TEMPORARY
/// grandfather-issuer fallback (`FederatedSubjectResolver::resolve`'s `NoAccount` arm, which
/// resolves to the subject's own pre-Stage-5 identity), then `createProject` and `createApiKey`
/// for the SAME subject succeed too -- by then `accounts.id == subject` exists, so those two
/// calls go through the ORDINARY, pre-existing self-healing grandfather adoption path
/// (`resolve_account_for_federated_subject`'s steady-state branch, unchanged by this fix), not
/// the bootstrap fallback itself. Prove-fail: reverting the fallback (making `NoAccount` refuse,
/// like `RogueIssuer`) reds this test's very first assertion with the 401/Unauthorized shape
/// `build_context` maps every resolver refusal to.
#[tokio::test]
async fn a_brand_new_subject_bootstraps_create_account_then_project_then_key_end_to_end() {
    const ISSUER: &str = "https://keycloak.example.test/realms/dev";
    let subject = format!("brand-new-subject-{}", cuid2());

    let core = core_pool().await;
    let repo = StoreRepo::new(core.clone());
    let resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver> = Arc::new(
        lightbridge_authz_rest::auth_provider::FederatedSubjectResolver::new(
            Arc::new(repo),
            None,
            ISSUER.to_string(),
        ),
    );
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&subject, admin_perms())));
    let ctx = setup_with_resolver(bearer, resolver).await;

    let account_id = create_account(&ctx.router, "admin", &subject).await;
    assert_eq!(
        account_id, subject,
        "the bootstrap fallback must mint the account under the subject's own pre-Stage-5 \
         identity (accounts.id == subject), matching the grandfather branch it stands in for"
    );

    let project_id = create_project(&ctx.router, "admin", &account_id, "bootstrap-project").await;
    let (_key_id, secret) =
        create_api_key(&ctx.router, "admin", &project_id, "bootstrap-key").await;
    assert!(
        !secret.is_empty(),
        "createApiKey must succeed once the bootstrapped account/project exist"
    );

    let fi_row_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM federated_identities WHERE issuer = $1 AND subject = $2)",
    )
    .bind(ISSUER)
    .bind(&subject)
    .fetch_one(&ctx.verify)
    .await
    .expect("checking federated_identities must succeed");
    assert!(
        fi_row_exists,
        "createProject's resolution must have self-healed a federated_identities row via the \
         ordinary grandfather adoption path, now that the account exists"
    );
}

/// Security twin of the bootstrap test above: a brand-new subject presented by a NON-grandfather
/// issuer must still be refused outright, never bootstrapped -- the fallback is issuer-pinned
/// exactly like the steady-state adoption path it temporarily stands in for
/// (`FederatedResolution::RogueIssuer`, not `NoAccount`). Proves the fix did not widen the trust
/// boundary: only the ONE configured `oauth2.federation.issuer` can bootstrap; every other issuer
/// dead-ends exactly as it did before this fix.
#[tokio::test]
async fn a_brand_new_subject_from_a_rogue_issuer_cannot_bootstrap() {
    const GRANDFATHER_ISSUER: &str = "https://keycloak.example.test/realms/dev";
    const ROGUE_ISSUER: &str = "https://rogue-issuer.example/realms/evil";
    let subject = format!("rogue-brand-new-subject-{}", cuid2());

    let core = core_pool().await;
    let repo = StoreRepo::new(core.clone());
    let resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver> = Arc::new(
        lightbridge_authz_rest::auth_provider::FederatedSubjectResolver::new(
            Arc::new(repo),
            None,
            GRANDFATHER_ISSUER.to_string(),
        ),
    );
    let info = TokenInfo {
        iss: ROGUE_ISSUER.to_string(),
        ..token_info(&subject, admin_perms())
    };
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(MapBearer::new().with("admin", info));
    let ctx = setup_with_resolver(bearer, resolver).await;

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "procedure.createAccount",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a brand-new subject from a non-grandfather issuer must be refused, never bootstrapped: {}",
        String::from_utf8_lossy(&body)
    );

    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1)")
        .bind(&subject)
        .fetch_one(&ctx.verify)
        .await
        .expect("checking accounts must succeed");
    assert!(
        !exists,
        "a refused bootstrap attempt must leave no accounts row behind"
    );
}

/// Regression for the legacy jsonb-`null` `allowed_models` decode failure (migration
/// `20260723000001`). Pre-cratestack projects stored an empty `allowed_models` as the jsonb `null`
/// LITERAL (`'null'::jsonb`), not SQL NULL.
///
/// **Updated by the cratestack 0.5.1 -> 0.7.16 lockstep bump.** Before that bump, cratestack's
/// `allowedModels Json?` decode failed on the literal with `expected value at line 1 column 1`,
/// so `model.Project.list`/`get` 500'd for that account -- migration `20260723000001` existed to
/// normalize it away. Verified empirically against the bumped server: the jsonb `null` literal now
/// decodes cleanly with no normalization needed at all (`Value`'s untagged decode,
/// cratestack/cratestack#506, is more lenient here than the old externally-tagged decode was).
/// `20260723000001` is not reverted -- it is harmless and idempotent against already-`NULL` rows --
/// but this test's own "must reproduce the 500" assumption no longer holds, so it now asserts the
/// corrected reality directly instead. See `list_and_get_recover_from_legacy_cratestack_tagged_value_json`
/// below for the *new* decode risk this same version bump introduced.
#[tokio::test]
async fn list_projects_tolerates_legacy_jsonb_null_allowed_models() {
    let subject = format!("owner-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;
    let billing_id = format!("tenant-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;
    let project_id = create_project(r, "admin", &account_id, "legacy").await;

    // Legacy write shape: the jsonb `null` literal (jsonb_typeof = 'null'), not SQL NULL.
    sqlx::query("UPDATE projects SET allowed_models = 'null'::jsonb WHERE id = $1")
        .bind(&project_id)
        .execute(&ctx.verify)
        .await
        .expect("force jsonb null literal");
    let (sql_null, json_type): (bool, Option<String>) = sqlx::query_as(
        "SELECT allowed_models IS NULL, jsonb_typeof(allowed_models) FROM projects WHERE id = $1",
    )
    .bind(&project_id)
    .fetch_one(&ctx.verify)
    .await
    .unwrap();
    assert!(!sql_null && json_type.as_deref() == Some("null"));

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.list",
        Wire::Cbor,
        &json!({ "filters": [{ "key": "accountId", "value": account_id }] }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the jsonb null literal must decode cleanly on 0.7.16 without normalization: {}",
        String::from_utf8_lossy(&body)
    );
    let ids: Vec<String> = json_body(&body)["items"]
        .as_array()
        .expect("items array")
        .iter()
        .filter_map(|p| p["id"].as_str().map(str::to_string))
        .collect();
    assert!(
        ids.contains(&project_id),
        "project must be listed; got {ids:?}"
    );
}

/// Regression for the legacy plain-`{}` `default_limits` decode failure (migration
/// `20260723000002`). Pre-cratestack projects stored an empty `default_limits` as plain JSON `{}`.
///
/// **Updated by the cratestack 0.5.1 -> 0.7.16 lockstep bump.** Before that bump, cratestack
/// persisted/expected `Value`'s externally-tagged form (an empty map was `{"Map": {}}`), so reading
/// the plain `{}` failed with `expected value at line 1 column 2` and `20260723000002` normalized
/// plain `{}` INTO the tagged `{"Map": {}}` shape to match. cratestack/cratestack#162 (0.7.2) moved
/// column persistence to plain JSON, and #506 (0.7.11) made `Value`'s wire serde plain too -- so
/// after this bump, plain `{}` is the CORRECT, expected shape and decodes with no normalization at
/// all, while the OLD tagged `{"Map": {}}` shape -- what `20260723000002` itself produced, and what
/// every row this service wrote before this bump also has, since production has only ever run
/// cratestack-pg 0.5.1 until now -- is what now needs fixing. See migration
/// `20260814000001_untag_legacy_cratestack_value_json.sql` and
/// `list_and_get_recover_from_legacy_cratestack_tagged_value_json` below.
#[tokio::test]
async fn list_projects_tolerates_legacy_plain_empty_default_limits() {
    let subject = format!("owner-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;
    let billing_id = format!("tenant-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;
    let project_id = create_project(r, "admin", &account_id, "legacy-dl").await;

    // Legacy write shape: plain JSON empty object -- now also the CURRENT, expected shape.
    sqlx::query("UPDATE projects SET default_limits = '{}'::jsonb WHERE id = $1")
        .bind(&project_id)
        .execute(&ctx.verify)
        .await
        .expect("force plain empty default_limits");
    let stored: String =
        sqlx::query_scalar("SELECT default_limits::text FROM projects WHERE id = $1")
            .bind(&project_id)
            .fetch_one(&ctx.verify)
            .await
            .unwrap();
    assert_eq!(
        stored, "{}",
        "must be plain empty object, not the tagged form"
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.list",
        Wire::Cbor,
        &json!({ "filters": [{ "key": "accountId", "value": account_id }] }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "plain `{{}}` must decode cleanly on 0.7.16 without normalization: {}",
        String::from_utf8_lossy(&body)
    );
    let ids: Vec<String> = json_body(&body)["items"]
        .as_array()
        .expect("items array")
        .iter()
        .filter_map(|p| p["id"].as_str().map(str::to_string))
        .collect();
    assert!(
        ids.contains(&project_id),
        "project must be listed; got {ids:?}"
    );
}

/// The regression the cratestack 0.5.1 -> 0.7.16 lockstep bump itself introduces: `Value`'s wire
/// serde went from externally-tagged (`{"Map": {...}}`, `{"List": [...]}`, `{"String": "x"}`, ...)
/// to plain JSON (cratestack/cratestack#162, #506). The untagged decoder does not error on an old
/// tagged row -- it decodes the tag wrapper literally as ordinary content, silently. Since
/// production has only ever run cratestack-pg 0.5.1 before this bump, EVERY existing
/// `projects.allowed_models`/`default_limits` row with non-null content is in the old tagged
/// shape, not a rare corner case. Confirmed by first reproducing the corruption directly (this
/// test's own `before_migration` assertions below, run before the corrective SQL executes a
/// second time), then confirming migration `20260814000001_untag_legacy_cratestack_value_json.sql`
/// fixes it -- both `allowedModels` (`List`-tagged) and `default_limits` (`Map`-tagged, with a
/// nested `Int`-tagged scalar, proving the unwrap recurses) in one project row.
#[tokio::test]
async fn list_and_get_recover_from_legacy_cratestack_tagged_value_json() {
    let subject = format!("owner-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;
    let billing_id = format!("tenant-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;
    let project_id = create_project(r, "admin", &account_id, "legacy-tagged").await;

    // Simulate data as every existing production row actually looks today: written (or, for
    // `default_limits`, historically normalized by `20260723000002`) under cratestack-pg 0.5.1's
    // externally-tagged `Value` serde -- NOT a synthetic/hypothetical shape.
    sqlx::query(
        r#"UPDATE projects SET
            allowed_models = '{"List": [{"String": "gpt-4"}, {"String": "gpt-3.5"}]}'::jsonb,
            default_limits = '{"Map": {"requestsPerSecond": {"Int": 5}}}'::jsonb
        WHERE id = $1"#,
    )
    .bind(&project_id)
    .execute(&ctx.verify)
    .await
    .expect("seed legacy 0.5.1-era tagged Value JSON");

    let get = |r: Router| {
        let project_id = project_id.clone();
        async move {
            rpc_call(
                r,
                "model.Project.get",
                Wire::Cbor,
                &json!({ "id": project_id }),
                Some("admin"),
            )
            .await
        }
    };

    // Before the fix: the tag wrapper leaks into the API response verbatim instead of being
    // interpreted -- a real, silent correctness bug, not a decode error (status is 200).
    let (before_status, before_body) = get(r.clone()).await;
    assert_eq!(before_status, StatusCode::OK);
    let before_json = json_body(&before_body);
    assert_eq!(
        before_json["allowedModels"],
        json!({"List": [{"String": "gpt-4"}, {"String": "gpt-3.5"}]}),
        "reproduces the tagged-Value corruption before the untag migration runs"
    );
    assert_eq!(
        before_json["defaultLimits"],
        json!({"Map": {"requestsPerSecond": {"Int": 5}}}),
        "reproduces the tagged-Value corruption before the untag migration runs"
    );

    // Migration 20260814000001's exact corrective SQL (already applied once at `migrate` time,
    // before this test seeded fresh legacy data above -- re-running it here is what proves it
    // would fix real legacy rows, and that it is safe to re-run/idempotent).
    sqlx::raw_sql(include_str!(
        "../../../migrations/20260814000001_untag_legacy_cratestack_value_json.sql"
    ))
    .execute(&ctx.verify)
    .await
    .expect("re-apply the untag-legacy-Value migration");

    let (after_status, after_body) = get(r.clone()).await;
    assert_eq!(after_status, StatusCode::OK);
    let after_json = json_body(&after_body);
    assert_eq!(
        after_json["allowedModels"],
        json!(["gpt-4", "gpt-3.5"]),
        "allowedModels must be a plain string array after the untag migration"
    );
    assert_eq!(
        after_json["defaultLimits"],
        json!({"requestsPerSecond": 5}),
        "defaultLimits must be a plain object (nested Int unwrapped too) after the untag migration"
    );
}

/// Regression for the `Cuid -> String` schema fix: `model.Project.list` filtered by a real
/// account id must succeed over the wire. cratestack's `Cuid` scalar rejected any id not starting
/// with `'c'`, but the app mints cuid2 ids (e.g. `go17t93z1vbd99yl5toj7eu5`), so the frontend's
/// list-by-account 400'd with `invalid cuid '<id>': expected ... starting with 'c'`. This exercises
/// the exact `{filters:[{key:accountId,value:<id>}]}` wire shape the generated client emits, with a
/// server-minted cuid2 account id.
#[tokio::test]
async fn list_projects_filtered_by_a_cuid2_account_id_is_accepted() {
    let subject = format!("owner-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let billing_id = format!("tenant-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;
    let project_id = create_project(r, "admin", &account_id, "proj-filter").await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.list",
        Wire::Cbor,
        &json!({ "filters": [{ "key": "accountId", "value": account_id }] }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "list-by-accountId must not be rejected as an invalid cuid (got {status}): {}",
        String::from_utf8_lossy(&body)
    );
    let page = json_body(&body);
    let returned: Vec<&str> = page["items"]
        .as_array()
        .expect("paged list returns an items array")
        .iter()
        .filter_map(|p| p["id"].as_str())
        .collect();
    assert!(
        returned.contains(&project_id.as_str()),
        "the accountId-filtered list must return the created project; got {returned:?}"
    );
}

/// Proves the ADR-0013 cutover, not just documents it: a well-formed request encoded with
/// `Wire::Json` — the format this router served as a secondary codec before ADR-0013, and the
/// format dev/CI defaulted to under the old, now-removed `server.api.codec` split — must now be
/// refused, never dispatched. Without this test, a regression that accidentally re-widens the
/// router back to a `CodecSet` would show up as nothing louder than "an extra content type is now
/// accepted" — silent from every other test in this file, since they all speak CBOR.
///
/// Two distinct rejections, both proven: `rpc_call`/`Wire::Json` sets *both* `Content-Type` and
/// `Accept` to `application/json`, and cratestack-axum's header validation checks `Accept` first
/// (`validate_codec_request_headers` → `validate_accept_header` then `validate_content_type_header`,
/// `cratestack-axum` 0.7.16's `codec/headers.rs`), so that combination fails on the *response*
/// codec with `406 Not Acceptable` before the *request* codec is ever consulted — not the `415`
/// intuition would suggest. The second call isolates the request-codec half specifically (a valid
/// `Accept: application/cbor` paired with an invalid `Content-Type: application/json`), which does
/// reach `415 Unsupported Media Type`. A regression that silently re-added JSON to only one side
/// (encoder or decoder) would still be caught by whichever of these two continues to pass.
#[tokio::test]
async fn json_content_type_is_rejected() {
    let subject = format!("owner-json-rejected-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.createAccount",
        Wire::Json,
        &json!({ "args": {} }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_ACCEPTABLE,
        "a caller asking for a JSON response must be refused outright, not dispatched: {}",
        String::from_utf8_lossy(&body)
    );

    let request = Request::builder()
        .method("POST")
        .uri("/rpc/procedure.createAccount")
        .header("content-type", "application/json")
        .header("accept", "application/cbor")
        .header("authorization", "Bearer admin")
        .body(Body::from(Wire::Json.encode(&json!({ "args": {} }))))
        .unwrap();
    let response = r.clone().oneshot(request).await.expect("router responds");
    assert_eq!(
        response.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "a JSON-encoded request body must be refused outright, not dispatched"
    );
}

#[tokio::test]
async fn crud_lifecycle_over_cbor() {
    let subject = format!("owner-cbor-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    // Account create → get → update → delete, all CBOR-encoded (no optional/null fields on this
    // path, so the CBOR codec's None-handling caveat never bites).
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.createAccount",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let account_id = Wire::Cbor.decode::<Value>(&body)["id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.get",
        Wire::Cbor,
        &json!({ "id": account_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(Wire::Cbor.decode::<Value>(&body)["id"], account_id);

    // A project create+get over CBOR too. `allowedModels` is `@readonly` on the generic verb since
    // #415 (ADR-0018 Decision 5), so it starts NULL and is set afterward via
    // `procedure.setProjectAllowedModels` -- see that call below (carried as a real list, not
    // `None`, to exercise the same `Json` tagged-value encoding this comment used to describe on
    // create).
    let project_id = cuid2();
    let input = project_input(&project_id, &account_id, "p-cbor");
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.create",
        Wire::Cbor,
        &input,
        Some("admin"),
    )
    .await;
    assert!(
        status.is_success(),
        "cbor project create: {status} {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(Wire::Cbor.decode::<Value>(&body)["id"], project_id);

    let allowed_models_value = serde_json::to_value(Json(CValue::List(vec![CValue::String(
        "gpt-4.1-mini".to_string(),
    )])))
    .expect("Json<Value> serializes");
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.setProjectAllowedModels",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "allowedModels": allowed_models_value } }),
        Some("admin"),
    )
    .await;
    assert!(
        status.is_success(),
        "cbor setProjectAllowedModels: {status} {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let decoded = Wire::Cbor.decode::<Value>(&body);
    assert_eq!(decoded["name"], "p-cbor");
    assert_eq!(decoded["allowedModels"], json!(["gpt-4.1-mini"]));

    // Account deletion is owner-only and no longer the generic `model.Account.delete` verb
    // (ADR-0005) -- the account's creator ("admin", the token subject used throughout this test)
    // was seeded as "owner" by `createAccount`, so this still succeeds. Unlike `Project`,
    // `Account` carries no default-project-style undeletable-default protection post-ADR-0006
    // (see `account_has_no_default_protection_and_is_freely_suspendable_and_hard_deletable`), and
    // since `accounts.id` IS the caller's subject, a second `createAccount` call for the same
    // "admin" subject would conflict rather than mint a second account (see
    // `a_second_account_for_the_same_subject_is_refused`) -- so this deletes `account_id` itself.
    let (status, _) = rpc_call(
        r.clone(),
        "procedure.deleteAccountPermanently",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cbor cascade delete");
}

/// `rpc_call`'s body encoding goes through `T: Serialize`, which can only ever produce a `None`
/// field as CBOR `null` (0xf6) — Rust has no way to emit CBOR's distinct `undefined` (0xf7). The
/// regression below needs the literal `undefined` wire byte the frontend's `cborg` encoder
/// actually sends for a JS `undefined` property value, so this builds the raw frame by hand
/// instead of going through the typed `SetProjectAllowedModelsInput`.
///
/// Targets `procedure.setProjectAllowedModels`, not `model.Project.create` (the original #341
/// production incident this regression documents): #415 (ADR-0018 Decision 5) made `allowedModels`
/// `@readonly` on the generic create/update verbs, moving its only write path onto this procedure
/// -- a picker that clears its selection is exactly the shape that would send `allowedModels:
/// undefined` again, so this keeps covering the real risk rather than a structurally-closed one.
fn raw_cbor_set_project_allowed_models_with_undefined(project_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = minicbor::Encoder::new(&mut out);
    e.map(1).unwrap();
    e.str("args").unwrap();
    e.map(2).unwrap();
    e.str("projectId").unwrap();
    e.str(project_id).unwrap();
    e.str("allowedModels").unwrap();
    e.undefined().unwrap();
    out
}

/// Like `common::rpc_call`, but takes an already-encoded body instead of a `T: Serialize` value —
/// needed to send the hand-built raw CBOR frame above verbatim.
async fn rpc_call_raw(
    router: &Router,
    op_id: &str,
    wire: Wire,
    raw_body: Vec<u8>,
    token: &str,
) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/rpc/{op_id}"))
        .header("content-type", wire.content_type())
        .header("accept", wire.content_type())
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(raw_body))
        .unwrap();
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body readable");
    (status, bytes.to_vec())
}

#[tokio::test]
async fn cbor_set_project_allowed_models_accepts_undefined_allowed_models() {
    // Regression test for the prod-only "invalid_argument" / "invalid request payload" bug: the
    // TS client's `cborg` CBOR encoder (`converse-frontends/packages/authz-rpc/src/codec.ts`)
    // encodes a JS `undefined` property value as the CBOR `undefined` simple value instead of
    // omitting the key. Originally reproduced on `model.Project.create`'s `allowedModels` (the
    // create-project screen never collected it); #415 (ADR-0018 Decision 5) moved that field's
    // only write path onto `procedure.setProjectAllowedModels`, so this test moved with it -- see
    // `raw_cbor_set_project_allowed_models_with_undefined`'s own doc comment.
    // `codec_undefined_regression_tests.rs` covers `LenientCborCodec` in isolation; this exercises
    // the same frame through the real router + a live DB.
    let subject = format!("owner-cbor-undefined-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let billing_id = format!("tenant-cbor-undefined-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;
    let project_id = create_project(r, "admin", &account_id, "p-cbor-undefined").await;

    let raw = raw_cbor_set_project_allowed_models_with_undefined(&project_id);
    let (status, body) = rpc_call_raw(
        r,
        "procedure.setProjectAllowedModels",
        Wire::Cbor,
        raw,
        "admin",
    )
    .await;
    assert!(
        status.is_success(),
        "cbor setProjectAllowedModels with undefined allowedModels: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let decoded = Wire::Cbor.decode::<Value>(&body);
    assert_eq!(decoded["id"], project_id);
    assert!(decoded["allowedModels"].is_null());
}

// ---------------------------------------------------------------------------------------------
// Section 3: the RBAC gate end-to-end (highest priority) — admin succeeds, member-viewer reads
// but cannot write.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn rbac_gate_admin_succeeds_and_member_viewer_reads_but_cannot_write() {
    let admin_subject = format!("admin-{}", cuid2());
    let viewer_subject = format!("viewer-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("admin", token_info(&admin_subject, admin_perms()))
            .with("viewer", token_info(&viewer_subject, viewer_perms()))
            .with(
                "viewer-bootstrap",
                token_info(
                    &viewer_subject,
                    [Permission::AccountCreate].into_iter().collect(),
                ),
            ),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    // Admin (all perms + creator membership) builds a tenant and adds the viewer as a member.
    let account_id = create_account(r, "admin", &format!("tenant-rbac-{}", cuid2())).await;
    let project_id = create_project(r, "admin", &account_id, "proj-rbac").await;
    // `project_members.account_id` carries a real FK to `accounts` (ADR-0006 -- "a project member
    // IS an account", migration `20260727000001_create_project_members.sql`), so the viewer must
    // already have an account of their own before anyone can add them to a roster. In production
    // this happens once, at account self-provisioning time (`account:create`); `viewer_perms()`
    // deliberately excludes it (a pure viewer never mints an account of their own once created), so
    // a one-off elevated bootstrap token creates it here, distinct from the read-only "viewer" token
    // used for every assertion below.
    let viewer_account_id = create_account(
        r,
        "viewer-bootstrap",
        &format!("tenant-rbac-viewer-{}", cuid2()),
    )
    .await;
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.addProjectMember",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "accountId": viewer_subject } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin adds viewer as member: {}",
        String::from_utf8_lossy(&body)
    );

    // Viewer (a legitimate project member) may READ the project (gate + `members.some.accountId
    // == auth().id` membership policy both pass) → 200. `Account.list` also passes the gate; per
    // ADR-0006 (`@@allow("read", id == auth().id)` on `Account`, schema comment "no more
    // membership/role concept") it is filtered to the caller's own account, so it still 200s
    // (returning just the viewer's own row, not admin's) rather than being rejected outright.
    for (op, input) in [
        ("model.Project.get", json!({ "id": project_id })),
        ("model.Account.list", json!({})),
        ("model.Project.list", json!({})),
        ("model.Account.get", json!({ "id": viewer_account_id })),
    ] {
        let (status, body) = rpc_call(r.clone(), op, Wire::Cbor, &input, Some("viewer")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "viewer read `{op}` should be 200: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // Project membership does NOT extend to reading the project's *owning account* — since
    // ADR-0006 dropped account-level membership entirely, `Account` visibility is owner-only
    // (`id == auth().id`), unlike `Project`'s `members.some.accountId == auth().id` clause. A
    // member reading someone else's account gets the policy's uniform not-found, not a 200.
    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.get",
        Wire::Cbor,
        &json!({ "id": account_id }),
        Some("viewer"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a project member must not be able to read the project's owning account: {}",
        String::from_utf8_lossy(&body)
    );

    // Viewer is blocked by the coarse RBAC gate (403) on every mutating op — even though membership
    // would otherwise permit it. This is the privilege-escalation regression under test.
    // `model.Account.update` is deliberately absent from this loop: since #398 it is unmapped
    // (denied unconditionally, see below), not merely permission-gated, so a viewer 403 on it
    // would prove nothing about *this* regression specifically.
    for (op, input) in [
        ("model.Account.delete", json!({ "id": account_id })),
        (
            "model.Project.create",
            json!({ "id": cuid2(), "accountId": account_id, "name": "n", "defaultLimits": {}, "billingPlan": "free", "status": "active" }),
        ),
        (
            "model.Project.update",
            json!({ "id": project_id, "patch": { "name": "n" } }),
        ),
        ("model.Project.delete", json!({ "id": project_id })),
        (
            "procedure.createApiKey",
            json!({ "args": { "projectId": project_id, "name": "k", "billingPlan": "free", "expiresAt": near_future_expiry() } }),
        ),
        (
            "procedure.disableAccount",
            json!({ "args": { "accountId": account_id } }),
        ),
        (
            "procedure.setProjectModelPolicy",
            json!({ "args": { "projectId": project_id, "modelPolicy": "deny_all" } }),
        ),
    ] {
        let (status, _) = rpc_call(r.clone(), op, Wire::Cbor, &input, Some("viewer")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "viewer write `{op}` must be 403"
        );
    }

    // `model.Account.update` (#398, completing #379): #379 marked `Account.defaultQuota`, the
    // verb's only settable field, `@readonly`, leaving it with zero writable fields, so it 422ed
    // unconditionally for every caller -- a live endpoint that could only ever fail. #398 removed
    // the schema's `@@allow("update")` and its `rpc_authorize.rs` permission mapping, so it is now
    // unreachable at both layers. Proven here against the real DB-backed dispatch pipeline, with a
    // fully-privileged admin, specifically to rule out the old 422: if this ever regressed back to
    // a mapped-but-empty verb, this assertion would catch the reappearing 422, not just a 403.
    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.update",
        Wire::Cbor,
        &json!({ "id": account_id, "patch": { "defaultQuota": "x" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "model.Account.update must be unreachable (403), not the old unconditional 422: {}",
        String::from_utf8_lossy(&body)
    );

    // Admin succeeds on a representative mutating op the viewer was denied.
    // `procedure.updateAccountDefaultQuota` is the real write path post-#379/#398.
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.updateAccountDefaultQuota",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id, "defaultQuota": format!("t-{}", cuid2()) } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin update must succeed: {}",
        String::from_utf8_lossy(&body)
    );

    // Admin also succeeds on `setProjectModelPolicy`, the op the viewer was 403'd on above.
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.setProjectModelPolicy",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "modelPolicy": "deny_all" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin setProjectModelPolicy must succeed: {}",
        String::from_utf8_lossy(&body)
    );
}

// ---------------------------------------------------------------------------------------------
// Section 3: soft-delete + api_key_validation view security fix.
// ---------------------------------------------------------------------------------------------

/// Shared OPA state backed by a real `StoreRepo` on the live pool, so both the assembled router
/// and a direct call into `handlers::opa::validate_api_key_context` exercise exactly the same
/// validation SQL authz-opa reads.
fn opa_state(core: Arc<dyn DbPoolTrait>) -> Arc<OpaState> {
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(core));
    Arc::new(OpaState {
        repo,
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "secret".to_string(),
        },
        billing: Arc::new(billing()),
        api_key_audience: None,
        resolver: common::test_resolver(),
        federation_issuer: "https://keycloak.example.test/realms/dev".to_string(),
    })
}

/// Build the OPA introspection router backed by a real `StoreRepo` on the live pool, so a POST to
/// `/v1/authorino/validate/introspect` exercises exactly the validation SQL view authz-opa reads.
fn opa_router(core: Arc<dyn DbPoolTrait>) -> Router {
    let state = opa_state(core.clone());
    lightbridge_authz_rest::build_opa_router(state, core)
}

/// Introspect `secret` through the OPA endpoint; returns the full decoded JSON body.
async fn introspect_response(router: &Router, secret: &str) -> Value {
    let creds = base64::engine::general_purpose::STANDARD.encode("authorino:secret");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorino/validate/introspect")
                .header("authorization", format!("Basic {creds}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={secret}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "introspect should be 200"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Introspect `secret` through the OPA endpoint; returns the `active` flag.
async fn introspect_active(router: &Router, secret: &str) -> bool {
    introspect_response(router, secret)
        .await
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[tokio::test]
async fn soft_deleted_api_key_is_excluded_and_fails_opa_validation() {
    let subject = format!("owner-sd-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;
    let opa = opa_router(ctx.core.clone());

    let account_id = create_account(r, "admin", &format!("tenant-sd-{}", cuid2())).await;
    let project_id = create_project(r, "admin", &account_id, "proj-sd").await;
    let (key_id, secret) = create_api_key(r, "admin", &project_id, "k-sd").await;

    // Live key validates at the OPA layer.
    assert!(
        introspect_active(&opa, &secret).await,
        "a live key must validate"
    );

    // Soft-delete it through the cratestack CRUD surface.
    let (status, _) = rpc_call(
        r.clone(),
        "model.ApiKey.delete",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Physically still present, deleted_at now set (soft, not hard).
    let deleted_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM api_keys WHERE id = $1")
            .bind(&key_id)
            .fetch_one(&ctx.verify)
            .await
            .expect("row still physically present");
    assert!(
        deleted_at.is_some(),
        "delete must be soft (deleted_at set), not a hard DELETE"
    );

    // Security-critical: the soft-deleted key must NO LONGER validate (the view's new
    // `deleted_at IS NULL` filter). This is the fail-open hazard the migration had to close.
    assert!(
        !introspect_active(&opa, &secret).await,
        "a soft-deleted api-key must NOT validate at the OPA layer"
    );
}

/// PATH B REGRESSION -- guards a fail-open, not a cosmetic response-shape bug.
///
/// `list_and_get_recover_from_legacy_cratestack_tagged_value_json` above covers Path A: the
/// cratestack CRUD client leaking the tag wrapper into `model.Project.get`/`list` responses. This
/// test covers the distinct Path B: the hand-written sqlx path
/// (`StoreRepo::get_project_by_id` -> `StoreRepo::json_to_vec`,
/// `crates/lightbridge-authz-api-key/src/repo.rs`), which every OPA/Authorino/introspect/MCP/
/// token-exchange consumer reads through `handlers::opa::validate_api_key_context`
/// (`crates/lightbridge-authz-rest/src/handlers/opa.rs:77-81`) and
/// `handlers::introspect::introspect_api_key` (`crates/lightbridge-authz-rest/src/handlers/
/// introspect.rs:62`).
///
/// `json_to_vec` decodes `allowed_models` by calling `serde_json::Value::as_array()`. A legacy
/// 0.5.1-era tagged value (`{"List": [...]}`) is a JSON *object*, not an array, so `as_array()`
/// returns `None` -- indistinguishable from SQL NULL, the documented "no restriction" sentinel
/// (see `opa_tests.rs::introspect_omits_allowed_models_when_null`, which shows `None` == "omit the
/// field == unrestricted"). Without migration
/// `20260814000001_untag_legacy_cratestack_value_json.sql`, a project restricted to
/// `["gpt-4.1-mini"]` silently reports UNRESTRICTED through every enforcement path: a model-
/// allowlist bypass.
#[tokio::test]
async fn legacy_tagged_allowed_models_still_enforces_allowlist() {
    let subject = format!("owner-legacy-am-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;
    let opa = opa_router(ctx.core.clone());
    let state = opa_state(ctx.core.clone());

    let account_id = create_account(r, "admin", &format!("tenant-legacy-am-{}", cuid2())).await;

    // Restricted project: seed 0.5.1-era externally-tagged `Value` JSON, the exact shape
    // `list_and_get_recover_from_legacy_cratestack_tagged_value_json` seeds for `allowedModels`
    // above, so both tests agree on what "legacy tagged data" looks like on disk.
    let restricted_project_id =
        create_project(r, "admin", &account_id, "legacy-am-restricted").await;
    sqlx::query(
        r#"UPDATE projects SET allowed_models = '{"List": [{"String": "gpt-4.1-mini"}]}'::jsonb WHERE id = $1"#,
    )
    .bind(&restricted_project_id)
    .execute(&ctx.verify)
    .await
    .expect("seed legacy 0.5.1-era tagged allowed_models");

    // Companion project: genuinely NULL `allowed_models` (the real "no restriction" sentinel),
    // so the test distinguishes the two states rather than merely checking non-null.
    let unrestricted_project_id =
        create_project(r, "admin", &account_id, "legacy-am-unrestricted").await;
    let unrestricted_raw: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT allowed_models FROM projects WHERE id = $1")
            .bind(&unrestricted_project_id)
            .fetch_one(&ctx.verify)
            .await
            .expect("fetch unrestricted project allowed_models");
    assert!(
        unrestricted_raw.is_none(),
        "a newly created project must default allowed_models to SQL NULL, not jsonb null"
    );

    // Migration `20260814000001_untag_legacy_cratestack_value_json.sql`'s exact corrective SQL,
    // re-applied here for the same reason `list_and_get_recover_from_legacy_cratestack_tagged_value_json`
    // re-applies it above: this test's seed simulates a row that predates the migration, so
    // running the migration's own fix against it (rather than relying on the one pass that ran at
    // `migrate` time, before this row existed) is what proves the fix actually reaches rows like
    // this one in production. Temporarily commenting out this block reproduces the pre-fix
    // fail-open (see the PR description's captured `cargo test` output).
    sqlx::raw_sql(include_str!(
        "../../../migrations/20260814000001_untag_legacy_cratestack_value_json.sql"
    ))
    .execute(&ctx.verify)
    .await
    .expect("re-apply the untag-legacy-Value migration");

    let (_, restricted_secret) =
        create_api_key(r, "admin", &restricted_project_id, "k-legacy-am-restricted").await;
    let (_, unrestricted_secret) = create_api_key(
        r,
        "admin",
        &unrestricted_project_id,
        "k-legacy-am-unrestricted",
    )
    .await;

    // Path 1: the OPA/Authorino validate path -- call `validate_api_key_context` directly (the
    // shared function at opa.rs:77-81 every consumer above sits on top of).
    let restricted_ctx = lightbridge_authz_rest::handlers::opa::validate_api_key_context(
        &state,
        &restricted_secret,
        None,
    )
    .await
    .expect("validate restricted key")
    .expect("restricted key must be active");
    assert_eq!(
        restricted_ctx.project.allowed_models,
        Some(vec!["gpt-4.1-mini".to_string()]),
        "legacy tagged allowed_models must still resolve to the restricted list, not None \
         (the fail-open under test)"
    );

    let unrestricted_ctx = lightbridge_authz_rest::handlers::opa::validate_api_key_context(
        &state,
        &unrestricted_secret,
        None,
    )
    .await
    .expect("validate unrestricted key")
    .expect("unrestricted key must be active");
    assert_eq!(
        unrestricted_ctx.project.allowed_models, None,
        "a genuinely NULL allowed_models must still resolve to None (unrestricted)"
    );

    // Path 2: the introspection path -- the real `/v1/authorino/validate/introspect` HTTP
    // endpoint (introspect.rs:62), asserting the concrete field value on the wire.
    let restricted_body = introspect_response(&opa, &restricted_secret).await;
    assert_eq!(restricted_body["active"], true);
    assert_eq!(
        restricted_body["allowed_models"],
        json!(["gpt-4.1-mini"]),
        "introspection must report the restricted allowlist, not an absent/empty field: {restricted_body}"
    );

    let unrestricted_body = introspect_response(&opa, &unrestricted_secret).await;
    assert_eq!(unrestricted_body["active"], true);
    assert!(
        unrestricted_body.get("allowed_models").is_none(),
        "introspection must omit allowed_models for a genuinely unrestricted project: {unrestricted_body}"
    );
}

// ---------------------------------------------------------------------------------------------
// Section 3: @@audit row existence on an audited model.
// ---------------------------------------------------------------------------------------------

async fn audit_count(pool: &sqlx::PgPool, model: &str, operation: &str, pk: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cratestack_audit WHERE model = $1 AND operation = $2 AND primary_key::text LIKE '%' || $3 || '%'",
    )
    .bind(model)
    .bind(operation)
    .bind(pk)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

#[tokio::test]
async fn audit_rows_land_on_create_update_delete_for_an_audited_model() {
    let subject = format!("owner-audit-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let account_id = create_account(r, "admin", &format!("tenant-audit-{}", cuid2())).await;
    // Project CRUD runs through the generated cratestack client, so every verb writes an audit row
    // in the same transaction as the mutation.
    let project_id = create_project(r, "admin", &account_id, "proj-audit").await;
    let (status, _) = rpc_call(
        r.clone(),
        "model.Project.update",
        Wire::Cbor,
        &json!({ "id": project_id, "patch": { "name": "renamed" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // `project_id` above is the account's default (first-ever) project, which `model.Project.delete`
    // now correctly refuses (see `default_project_cannot_be_hard_deleted_only_suspended` below) --
    // the delete-audit-row assertion is exercised against a second, non-default project instead.
    let second_project_id = create_project(r, "admin", &account_id, "proj-audit-delete").await;
    let (status, _) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Cbor,
        &json!({ "id": second_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let pool = &ctx.verify;
    assert!(
        audit_count(pool, "Project", "create", &project_id).await >= 1,
        "create audit row"
    );
    assert!(
        audit_count(pool, "Project", "update", &project_id).await >= 1,
        "update audit row"
    );
    assert!(
        audit_count(pool, "Project", "delete", &second_project_id).await >= 1,
        "delete audit row"
    );

    // An audited api-key soft-delete also lands a row. Per ADR-0003 (known cratestack-pg 0.4.9 bug
    // #2) the before/after snapshot for a soft-deleted ApiKey is wrong, so we assert only existence.
    let project_id2 = create_project(r, "admin", &account_id, "proj-audit-2").await;
    let (key_id, _) = create_api_key(r, "admin", &project_id2, "k-audit").await;
    let (status, _) = rpc_call(
        r.clone(),
        "model.ApiKey.delete",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        audit_count(pool, "ApiKey", "delete", &key_id).await >= 1,
        "an api-key soft-delete must still write an audit row (snapshot content not asserted)"
    );
}

// ---------------------------------------------------------------------------------------------
// Section 3: idempotency replay under a repeated Idempotency-Key.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn idempotent_replay_does_not_double_a_mutation() {
    let subject = format!("owner-idem-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let body = Wire::Cbor.encode(&json!({ "args": {} }));
    let idem_key = format!("idem-{}", cuid2());

    let send = |body: Vec<u8>, key: String| {
        let router = r.clone();
        async move {
            let request = Request::builder()
                .method("POST")
                .uri("/rpc/procedure.createAccount")
                .header("content-type", Wire::Cbor.content_type())
                .header("accept", Wire::Cbor.content_type())
                .header("authorization", "Bearer admin")
                .header("idempotency-key", key)
                .body(Body::from(body))
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            (status, bytes.to_vec())
        }
    };

    let (status1, body1) = send(body.clone(), idem_key.clone()).await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "first create: {}",
        String::from_utf8_lossy(&body1)
    );
    let (status2, body2) = send(body.clone(), idem_key.clone()).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "replayed create: {}",
        String::from_utf8_lossy(&body2)
    );

    let id1 = json_body(&body1)["id"].as_str().unwrap().to_string();
    let id2 = json_body(&body2)["id"].as_str().unwrap().to_string();
    assert_eq!(
        id1, id2,
        "a replayed idempotent request must return the cached response, not re-create"
    );

    // Exactly one account row exists for that id — the mutation ran once, not twice.
    // `accounts` carries no `billing_identity` column (that moved to `projects` under
    // ADR-0006 -- "billing_identity (unique -- 'who is paying' moved here from accounts, so one
    // person can bill projects to different parties)"), so this checks DB state directly by the
    // id the replayed create returned rather than a since-removed column.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE id = $1")
        .bind(&id1)
        .fetch_one(&ctx.verify)
        .await
        .unwrap();
    assert_eq!(count, 1, "the mutation must have executed exactly once");
}

// ---------------------------------------------------------------------------------------------
// Section 3: batch RPC per-frame independence and per-frame RBAC.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn batch_rpc_frames_succeed_and_fail_independently() {
    let subject = format!("owner-batch-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;

    // A bare RPC router (no rpc_authorize gate), matching how `build_api_router` assembles the inner
    // router, so we can exercise `/rpc/batch` directly.
    let cdb = schema::Cratestack::builder(ctx.cratestack_pool.clone()).build();
    let bare: Router = schema::axum::rpc_router(
        cdb,
        Procedures::new(
            ctx.issuer.clone(),
            ctx.policy_store.clone(),
            ctx.refill_service.clone(),
            ctx.review_service.clone(),
            ctx.budget_repo.clone(),
        ),
        // cratestack 0.8.11 (@computed) added this parameter; `()` is a no-op since
        // `authz.cstack` declares no `@computed` field (see src/lib.rs's own call sites).
        (),
        CborCodec,
        CratestackAuthProvider::new(
            admin_bearer(&subject),
            RpcScope::Crud,
            common::test_resolver(),
        ),
        DEFAULT_BODY_LIMIT_BYTES,
    );

    let batch = json!([
        { "id": 1, "op": "procedure.createAccount", "input": { "args": {} } },
        { "id": 2, "op": "model.Account.get", "input": {} }
    ]);

    let response = bare
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rpc/batch")
                .header("content-type", "application/cbor")
                .header("accept", "application/cbor")
                .header("authorization", "Bearer admin")
                .body(Body::from(CborCodec.encode(&batch).expect("cbor encode")))
                .unwrap(),
        )
        .await
        .unwrap();

    // The envelope itself is 200 even though one frame fails.
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "batch envelope must be 200"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let frames: Vec<Value> = CborCodec
        .decode(&bytes)
        .expect("batch response is a cbor frame array");
    assert_eq!(frames.len(), 2);

    let frame1 = frames.iter().find(|f| f["id"] == 1).expect("frame 1");
    let frame2 = frames.iter().find(|f| f["id"] == 2).expect("frame 2");
    assert!(
        frame1.get("output").is_some() && frame1.get("error").is_none(),
        "frame 1 (valid) should succeed: {frame1}"
    );
    assert!(
        frame2.get("error").is_some() && frame2.get("output").is_none(),
        "frame 2 (invalid input) should fail independently: {frame2}"
    );
}

/// `POST /rpc/batch` used to be denied wholesale for every caller, admin included (a single
/// URL-derived op-id can't represent per-frame permissions — see `rpc_authorize.rs`). It now enforces
/// RBAC per frame instead: one viewer token, one batch call, two frames — a permitted read and a
/// forbidden write — against the *real*, fully-assembled router (`rpc_authorize` included, not the
/// bare bypass router `batch_rpc_frames_succeed_and_fail_independently` uses above). Both frames must
/// be authorized independently, against the same op-id -> permission map unary calls use.
#[tokio::test]
async fn batch_rpc_frames_enforce_permission_per_frame() {
    let admin_subject = format!("admin-batch-rbac-{}", cuid2());
    let viewer_subject = format!("viewer-batch-rbac-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("admin", token_info(&admin_subject, admin_perms()))
            .with("viewer", token_info(&viewer_subject, viewer_perms()))
            .with(
                "viewer-bootstrap",
                token_info(
                    &viewer_subject,
                    [Permission::AccountCreate].into_iter().collect(),
                ),
            ),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let account_id = create_account(r, "admin", &format!("tenant-batch-rbac-{}", cuid2())).await;
    let project_id = create_project(r, "admin", &account_id, "proj-batch-rbac").await;
    // See `rbac_gate_admin_succeeds_and_member_viewer_reads_but_cannot_write`'s comment: the
    // viewer needs an account of their own before `addProjectMember` can satisfy
    // `project_members.account_id`'s FK to `accounts` (ADR-0006).
    let _viewer_account_id = create_account(
        r,
        "viewer-bootstrap",
        &format!("tenant-batch-rbac-viewer-{}", cuid2()),
    )
    .await;
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.addProjectMember",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "accountId": viewer_subject } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin adds viewer as member: {}",
        String::from_utf8_lossy(&body)
    );

    let batch = json!([
        { "id": 1, "op": "model.Project.get", "input": { "id": project_id } },
        { "id": 2, "op": "model.Project.update", "input": { "id": project_id, "patch": { "name": "renamed" } } }
    ]);

    let response = r
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rpc/batch")
                .header("content-type", Wire::Cbor.content_type())
                .header("accept", Wire::Cbor.content_type())
                .header("authorization", "Bearer viewer")
                .body(Body::from(Wire::Cbor.encode(&batch)))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "batch envelope must be 200 even though one frame is forbidden"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let frames: Vec<Value> = Wire::Cbor.decode(&bytes);
    assert_eq!(frames.len(), 2);

    let read_frame = frames.iter().find(|f| f["id"] == 1).expect("frame 1");
    assert!(
        read_frame.get("output").is_some() && read_frame.get("error").is_none(),
        "viewer's permitted read (frame 1) should succeed: {read_frame}"
    );

    let write_frame = frames.iter().find(|f| f["id"] == 2).expect("frame 2");
    let error = write_frame
        .get("error")
        .expect("viewer's forbidden write (frame 2) should fail, not succeed");
    assert_eq!(
        error["code"], "permission_denied",
        "frame 2 must be denied with permission_denied, not silently succeed: {write_frame}"
    );
}

/// Issue #383's fail-closed obligation, stated explicitly: the `"batch"` special case in
/// `CratestackAuthProvider::authenticate` (see that module's doc comment) is the single most
/// dangerous line in the fix, because it is the one place that authenticates-and-attaches a
/// context instead of denying outright. It must attach the caller's REAL, computed permission set
/// -- never a blanket-permissive one -- so a caller holding a valid, active token but genuinely
/// ZERO permissions must have EVERY bundled frame refused, not silently let through because the
/// envelope-level check only required "some valid caller". This is the negative-space complement
/// to `batch_rpc_frames_enforce_permission_per_frame` above (which proves a MIXED-permission
/// caller gets a MIXED result) -- this test proves a ZERO-permission caller gets an ALL-denied
/// result, which a bug that granted broad access on successful envelope authentication (the
/// "naive fix" #383's own Risks section warns against) would NOT catch, since a mixed-result test
/// alone can pass even if the envelope-level context is wrongly permissive for every op the
/// caller genuinely lacks.
///
/// Scoped to `procedure.*` and `model.*` write verbs (`create`/`update`/`delete`) deliberately --
/// NOT `model.*` `list`/`get`. Those two verb families are enforced through genuinely different
/// cratestack mechanisms: a write verb's policy denial is an explicit `CratestackError::Forbidden`
/// (`cratestack-sqlx/src/query/support/create.rs`'s `evaluate_create_policy_expr`; `update.rs`'s
/// existence-probe-then-`Forbidden`), matching `authorize_procedure`'s all-or-nothing behavior for
/// procedures. A `list`/`get` verb's `@@allow("read", ...)` is compiled into the SQL `WHERE`
/// clause itself (`cratestack-sqlx/src/render/policy.rs`) -- a caller whose permission field is
/// `false` simply matches zero rows, the same as any other caller-scoping predicate (e.g. "only
/// rows this account owns"). That is a pre-existing, upstream cratestack property of read
/// policies, not something this fix changed or could change without a much larger rewrite (there
/// is no schema-level way to make a `@@allow("read", ...)` clause reject instead of filter) -- see
/// `batch_rpc_read_verbs_filter_to_empty_not_an_error_for_a_caller_lacking_read_permission` below
/// for the read-verb half of this same fail-closed obligation, and `auth_provider.rs`'s module doc
/// for where this is recorded as the second accepted, documented behavior difference (alongside
/// the 403-vs-404 scope one).
#[tokio::test]
async fn batch_rpc_frames_all_deny_for_a_caller_with_zero_permissions() {
    let subject = format!("zero-perm-batch-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(MapBearer::new().with(
        "zero",
        token_info(
            &subject,
            lightbridge_authz_core::authz::PermissionSet::new(),
        ),
    ));
    let ctx = setup(bearer).await;

    let create_project_input = serde_json::to_value(project_input(&cuid2(), &subject, "x"))
        .expect("CreateProjectInput serializes");
    let batch = json!([
        { "id": 1, "op": "procedure.listBillingPlans", "input": { "args": {} } },
        { "id": 2, "op": "model.Project.create", "input": create_project_input },
        { "id": 3, "op": "procedure.createAccount", "input": { "args": {} } }
    ]);

    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rpc/batch")
                .header("content-type", Wire::Cbor.content_type())
                .header("accept", Wire::Cbor.content_type())
                .header("authorization", "Bearer zero")
                .body(Body::from(Wire::Cbor.encode(&batch)))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the envelope itself is 200 -- the caller IS validly authenticated, just permission-less; \
         per-frame denial happens deeper, in schema policy"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let frames: Vec<Value> = Wire::Cbor.decode(&bytes);
    assert_eq!(frames.len(), 3);
    for frame in &frames {
        let error = frame.get("error").unwrap_or_else(|| {
            panic!("zero-permission caller's frame must be refused, not succeed: {frame}")
        });
        assert_eq!(
            error["code"], "permission_denied",
            "every frame must be denied with permission_denied for a zero-permission caller: {frame}"
        );
    }
}

/// The read-verb half of the fail-closed obligation the test above documents: a caller lacking
/// `account:read` must never see another account's row (or, here, their OWN not-yet-visible
/// permission state) through `model.Account.list`/`.get` inside a batch call. Per that test's own
/// doc comment, cratestack compiles `@@allow("read", ...)` into the SQL `WHERE` clause rather than
/// a hard pre-check, so the OBSERVABLE shape is "zero rows" / "not found", not `permission_denied`
/// -- verified here so that shape is pinned down explicitly rather than assumed. The
/// security-relevant assertion is the same either way: no row this caller cannot read is ever
/// returned. Unary calls never exercise this path at all (the outer `rpc_authorize` gate already
/// rejects a `model.Account.list` call from a caller lacking `account:read` with a clean `403`
/// before cratestack's dispatch/query layer ever runs) -- this divergence is therefore scoped to
/// `POST /rpc/batch` specifically, same as the 403-vs-404 scope trade-off.
#[tokio::test]
async fn batch_rpc_read_verbs_filter_to_empty_not_an_error_for_a_caller_lacking_read_permission() {
    let owner = format!("owner-readfilter-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("owner", token_info(&owner, admin_perms()))
            .with(
                "zero",
                token_info(&owner, lightbridge_authz_core::authz::PermissionSet::new()),
            ),
    );
    let ctx = setup(bearer).await;
    let account_id = create_account(&ctx.router, "owner", "unused").await;
    assert_eq!(account_id, owner, "account id is the subject per ADR-0006");

    // Same subject as the account owner, but the `"zero"` token carries no permissions at all --
    // `model.Account.get`/`.list` for their OWN account must not return it.
    let batch = json!([
        { "id": 1, "op": "model.Account.get", "input": { "id": account_id } },
        { "id": 2, "op": "model.Account.list", "input": {} }
    ]);
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rpc/batch")
                .header("content-type", Wire::Cbor.content_type())
                .header("accept", Wire::Cbor.content_type())
                .header("authorization", "Bearer zero")
                .body(Body::from(Wire::Cbor.encode(&batch)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "batch envelope is 200");
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let frames: Vec<Value> = Wire::Cbor.decode(&bytes);
    assert_eq!(frames.len(), 2);

    let get_frame = frames.iter().find(|f| f["id"] == 1).expect("frame 1");
    assert!(
        get_frame.get("output").is_none() || get_frame["output"].is_null(),
        "get must not return the caller's own account row when they lack account:read: {get_frame}"
    );

    let list_frame = frames.iter().find(|f| f["id"] == 2).expect("frame 2");
    if let Some(output) = list_frame.get("output") {
        let items = output["items"]
            .as_array()
            .expect("list output has an items array");
        assert!(
            items.is_empty(),
            "list must not return the caller's own account row when they lack account:read: \
             {list_frame}"
        );
    }
}

/// The unary counterpart to the batch test above (#401) -- pins the OTHER half of the asymmetry
/// that test's own doc comment claims but does not itself exercise: a UNARY `model.Account.get`/
/// `.list` call from a caller lacking `account:read` never reaches cratestack's dispatch/query
/// layer at all. Both `rpc_authorize` (the outer Axum middleware) and
/// `CratestackAuthProvider::authenticate`'s unary branch (`auth_provider.rs`) hard-gate on the
/// *coarse* `op_id` -> permission map from `rpc_authorize::required_permission` BEFORE dispatch, so
/// the caller gets a clean `403`, never the SQL-filtered empty/not-found shape
/// `batch_rpc_read_verbs_filter_to_empty_not_an_error_for_a_caller_lacking_read_permission` proves
/// for the batch path. Together the two tests pin the full, decided contract #401 asked for: read
/// verbs hard-refuse on the unary surface and filter only inside `/rpc/batch`, where cratestack's
/// per-frame `CachedAuthProvider` change (0.8.4) leaves no pre-dispatch hook to hard-gate a read
/// verb -- see `docs/rbac.md`'s "Read verbs filter, they do not refuse" section for the decision
/// this documents and why routing these three models' reads through hand-written procedures (the
/// only structural fix) was rejected as disproportionate to a diagnosability-only risk.
#[tokio::test]
async fn unary_read_verb_hard_refuses_a_caller_lacking_read_permission() {
    let owner = format!("owner-unary-readfilter-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("owner", token_info(&owner, admin_perms()))
            .with(
                "zero",
                token_info(&owner, lightbridge_authz_core::authz::PermissionSet::new()),
            ),
    );
    let ctx = setup(bearer).await;
    let account_id = create_account(&ctx.router, "owner", "unused").await;
    assert_eq!(account_id, owner, "account id is the subject per ADR-0006");

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Account.get",
        Wire::Cbor,
        &json!({ "id": account_id }),
        Some("zero"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unary get for a caller lacking account:read must hard-refuse before dispatch, not \
         filter to not-found: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Account.list",
        Wire::Cbor,
        &json!({}),
        Some("zero"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unary list for a caller lacking account:read must hard-refuse before dispatch, not \
         filter to empty: {}",
        String::from_utf8_lossy(&body)
    );
}

// ---------------------------------------------------------------------------------------------
// Section 3: createAccount seeds the creator's membership, enabling a subsequent project create;
// a non-member is refused.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn create_account_seeds_membership_enabling_project_create() {
    let owner = format!("owner-chain-{}", cuid2());
    let stranger = format!("stranger-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("owner", token_info(&owner, admin_perms()))
            .with("stranger", token_info(&stranger, admin_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    // createAccount seeds the creator's membership in the same transaction, so the creator can
    // immediately create a project under it (the membership `@@allow` policy passes).
    let account_id = create_account(r, "owner", &format!("tenant-chain-{}", cuid2())).await;
    let _project_id = create_project(r, "owner", &account_id, "proj-chain").await;

    // A stranger (holds every RBAC permission, so passes the coarse gate, but is NOT a member of
    // this account) is refused by the membership policy — a non-member cannot create under it.
    let stranger_input = project_input(&cuid2(), &account_id, "nope");
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.create",
        Wire::Cbor,
        &stranger_input,
        Some("stranger"),
    )
    .await;
    assert!(
        status.is_client_error(),
        "a non-member must be refused project creation under someone else's account (got {status}: {})",
        String::from_utf8_lossy(&body)
    );
}

// ---------------------------------------------------------------------------------------------
// Section 4: the default *project* (an account's first-ever project) can be suspended but never
// hard-deleted -- a second project stays freely deletable. Prevents a tenant from accidentally
// deleting their only project and losing every API key underneath it.
//
// There is a sibling concept for *accounts* pre-ADR-0006 -- see the now-corrected
// `account_has_no_default_protection_and_is_freely_suspendable_and_hard_deletable` below, which
// used to assert an "undeletable default account," a concept ADR-0006 removed on purpose: once
// `accounts.id` IS the caller's subject (one account = one person), there is no longer a second,
// non-default account for that subject to compare against, so "default" stopped being a
// meaningful distinction for `Account` -- only `Project` keeps it (an account can still have
// several projects). The `Account` model in `authz.cstack` has no `isDefault` field and no
// `@@allow("delete", ...)` restriction at all; its own comment says so explicitly.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn account_has_no_default_protection_and_is_freely_suspendable_and_hard_deletable() {
    let subject = format!("owner-default-acct-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    // This subject's one-and-only account (ADR-0006: `accounts.id` IS the subject, so a second
    // `createAccount` for the same subject conflicts -- see
    // `a_second_account_for_the_same_subject_is_refused`). `Account` carries no `isDefault`
    // field at all (unlike `Project`), so there is nothing to assert about default-ness here.
    let account_id = create_account(r, "admin", &format!("tenant-default-{}", cuid2())).await;

    // Suspend works on it.
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.disableAccount",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the account must be suspendable: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_body(&body)["status"], "suspended");

    // ...and, unlike a default *project*, hard delete is never refused for an account -- there is
    // no undeletable-default concept at the account level post-ADR-0006.
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.deleteAccountPermanently",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an account's own sole account must still be hard-deletable, suspended or not: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn default_project_cannot_be_hard_deleted_only_suspended() {
    let subject = format!("owner-default-proj-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let account_id = create_account(r, "admin", &format!("tenant-default-proj-{}", cuid2())).await;
    // This account's first-ever project -- is_default is computed true by the DB trigger.
    let project_id = create_project(r, "admin", &account_id, "proj-default").await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_body(&body)["isDefault"],
        true,
        "an account's first project must be marked default"
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert!(
        !status.is_success(),
        "deleting the default project must be refused (got {status}: {})",
        String::from_utf8_lossy(&body)
    );

    // Still there.
    let (status, _) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the default project must survive the refused delete"
    );

    // Suspend still works on it.
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.disableProject",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the default project must still be suspendable: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_body(&body)["status"], "suspended");

    // A second project under the SAME account is NOT default, and stays freely deletable.
    let second_project_id = create_project(r, "admin", &account_id, "proj-default-2nd").await;
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": second_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_body(&body)["isDefault"],
        false,
        "an account's second project must not be marked default"
    );
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Cbor,
        &json!({ "id": second_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a non-default project must still be hard-deletable: {}",
        String::from_utf8_lossy(&body)
    );
}

// ---------------------------------------------------------------------------------------------
// Section 5: the `setDefaultProject` escape hatch -- promoting a different
// row to default atomically demotes the old one, freeing it up for hard deletion (otherwise a
// subject's first-ever account/project would be permanently undeletable).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn promoting_a_second_project_to_default_frees_the_old_default_for_deletion() {
    let subject = format!("owner-promote-proj-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let account_id = create_account(r, "admin", &format!("tenant-promote-proj-{}", cuid2())).await;
    let first_project_id = create_project(r, "admin", &account_id, "proj-first").await;
    let second_project_id = create_project(r, "admin", &account_id, "proj-second").await;

    // Sanity: still the pre-promotion state (first is default, second is not).
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": first_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["isDefault"], true);

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.setDefaultProject",
        Wire::Cbor,
        &json!({ "args": { "projectId": second_project_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "setDefaultProject: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_body(&body)["isDefault"], true);
    assert_eq!(json_body(&body)["id"], second_project_id);

    // The old default flipped false.
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": first_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_body(&body)["isDefault"],
        false,
        "the old default project must be demoted"
    );

    // ...and is now freely hard-deletable.
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Cbor,
        &json!({ "id": first_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the demoted project must now be hard-deletable: {}",
        String::from_utf8_lossy(&body)
    );

    // The new default cannot itself be hard-deleted.
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Cbor,
        &json!({ "id": second_project_id }),
        Some("admin"),
    )
    .await;
    assert!(
        !status.is_success(),
        "the newly-promoted default project must be refused deletion (got {status}: {})",
        String::from_utf8_lossy(&body)
    );
}

/// `Account.name` end-to-end over the real CBOR RPC dispatch pipeline: settable at creation,
/// renameable afterwards through `procedure.updateAccountName` (the only write path -- the field
/// is `@readonly` and `model.Account.update` was removed by #398), and gated on the SAME
/// `account:update` permission `updateAccountDefaultQuota` already required, not a new one.
///
/// The rename path is not a nicety: every account that predates
/// `migrations/20260829000001_accounts_add_name.sql` reads back `name = null`, so without this
/// procedure they would all be permanently unnamed.
#[tokio::test]
async fn account_name_is_settable_at_creation_and_renameable_afterwards() {
    let admin_subject = format!("owner-name-{}", cuid2());
    let viewer_subject = format!("viewer-name-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("admin", token_info(&admin_subject, admin_perms()))
            .with("viewer", token_info(&viewer_subject, viewer_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.createAccount",
        Wire::Cbor,
        &json!({ "args": { "name": "Acme Corp" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "createAccount with a name: {}",
        String::from_utf8_lossy(&body)
    );
    let created = json_body(&body);
    let account_id = created["id"].as_str().expect("account id").to_string();
    assert_eq!(
        created["name"], "Acme Corp",
        "the created account must carry the name back on the wire"
    );

    // Reading it back through the generic read verb -- what a console actually calls -- must also
    // carry `name`, not just the procedure's own response.
    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.get",
        Wire::Cbor,
        &json!({ "id": account_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["name"], "Acme Corp");

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.updateAccountName",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id, "name": "Acme Holdings" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "updateAccountName: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_body(&body)["name"], "Acme Holdings");

    // A read-only caller holds `account:read` but not `account:update`, so the rename is refused
    // by the same coarse gate the quota update already sits behind -- the new procedure did not
    // widen anything.
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.updateAccountName",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id, "name": "Hijacked" } }),
        Some("viewer"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a caller without account:update must be refused the rename: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.get",
        Wire::Cbor,
        &json!({ "id": account_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_body(&body)["name"],
        "Acme Holdings",
        "the refused rename must not have landed"
    );
}

#[tokio::test]
async fn a_second_account_for_the_same_subject_is_a_second_account() {
    // ADR-0026 reverses this test's original assertion. Under ADR-0006 the account id WAS the
    // caller's subject, so a repeat createAccount collided on the primary key and returned 409;
    // one identity may now own several accounts, so it returns 200 and a genuinely new row. The
    // anchor keeps `id = subject`; the second gets a minted id and inherits the anchor's owner.
    let subject = format!("owner-single-acct-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let account_id = create_account(r, "admin", "unused").await;
    assert_eq!(
        account_id, subject,
        "the identity's anchor account is keyed by the subject"
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.createAccount",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a subject's second createAccount now mints a second account: {}",
        String::from_utf8_lossy(&body)
    );
    let second = json_body(&body);
    assert_ne!(second["id"], json!(account_id), "a distinct row");
    assert_ne!(
        second["id"],
        json!(subject),
        "only the anchor is keyed by the subject"
    );
    assert_eq!(
        second["userId"],
        json!(subject),
        "the second account inherits the anchor's owner -- this is what `userId == auth().id` \
         matches on"
    );

    // The anchor cannot be deleted while the secondary is still owned (it would strand it).
    let (status, _) = rpc_call(
        r.clone(),
        "procedure.deleteAccountPermanently",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "deleting the anchor while another account is owned must be refused"
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.deleteAccountPermanently",
        Wire::Cbor,
        &json!({ "args": { "accountId": second["id"].as_str().unwrap() } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a secondary account is deletable by its owner: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.deleteAccountPermanently",
        Wire::Cbor,
        &json!({ "args": { "accountId": account_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the sole account is deletable — the undeletable-default rule applies to projects only: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn set_default_project_rejects_a_project_the_caller_is_not_a_member_of() {
    let owner = format!("owner-promote-foreign-{}", cuid2());
    let stranger = format!("stranger-promote-foreign-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("owner", token_info(&owner, admin_perms()))
            .with("stranger", token_info(&stranger, admin_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let account_id = create_account(r, "owner", &format!("tenant-foreign-{}", cuid2())).await;
    let project_id = create_project(r, "owner", &account_id, "proj-foreign").await;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.setDefaultProject",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id } }),
        Some("stranger"),
    )
    .await;
    assert!(
        !status.is_success(),
        "a non-member must be refused promoting someone else's project to default (got {status}: {})",
        String::from_utf8_lossy(&body)
    );
}

// ---------------------------------------------------------------------------------------------
// `ApiKey`'s ownership disjunction (`authz.cstack` `@@allow("read"|"update"|"delete", ...)`):
//   (project.account.id == auth().id || project.members.some.accountId == auth().id)
//   && auth().rpcScope == "crud" && auth().permApikey<Verb> == true
//
// Every other `model.ApiKey.*` call site in this file uses `"admin"`, the same subject that
// created the key -- so the ownership half of the disjunction has never been exercised failing.
// `rbac_gate_admin_succeeds_and_member_viewer_reads_but_cannot_write` above proves only the
// coarse RBAC-gate half (a legitimate *member*, refused by permission). This proves the
// complementary half: a caller who holds every permission (passes the gate) but is neither the
// project's owning account nor a project member must still be refused. Restores the coverage
// `StoreRepo::delete_api_key`'s test used to carry before it was removed as dead/unsafe code
// (PR #429 follow-up) -- see the comment in
// `crates/lightbridge-authz-api-key/tests/access_control_scenarios_tests.rs` this test backs.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn api_key_ownership_boundary_refuses_a_non_member_stranger() {
    let owner = format!("owner-apikey-boundary-{}", cuid2());
    let stranger = format!("stranger-apikey-boundary-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("owner", token_info(&owner, admin_perms()))
            .with("stranger", token_info(&stranger, admin_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let account_id =
        create_account(r, "owner", &format!("tenant-apikey-boundary-{}", cuid2())).await;
    let project_id = create_project(r, "owner", &account_id, "proj-apikey-boundary").await;
    let (key_id, _secret) = create_api_key(r, "owner", &project_id, "k-boundary").await;

    // Stranger holds every RBAC permission (`admin_perms()`), so the coarse gate passes; only the
    // model policy's ownership disjunction stands between them and someone else's key. Observed
    // (not assumed) via a temporary prove-fail-first run: a filtered read comes back 404 (the
    // policy's uniform not-found), while update/delete come back 403 -- the two verb families are
    // NOT interchangeable here, so each gets its own exact assertion rather than a shared loose
    // one.
    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.get",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("stranger"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-member must be refused reading someone else's api key: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.update",
        Wire::Cbor,
        &json!({ "id": key_id, "patch": { "name": "hijacked" } }),
        Some("stranger"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-member must be refused updating someone else's api key: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.delete",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("stranger"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-member must be refused deleting someone else's api key: {}",
        String::from_utf8_lossy(&body)
    );

    // The key must still be intact for its rightful owner -- proves the stranger's attempts had
    // no effect, not merely that they returned an error status.
    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.get",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("owner"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "owner get after stranger's refused attempts: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        json_body(&body)["name"],
        "k-boundary",
        "stranger's update must not have applied"
    );
}

// ---------------------------------------------------------------------------------------------
// `procedure.listMyExpiringApiKeys` (lightbridge-authz#436) -- the self-scoped, cross-project
// "expiring soon" aggregate. Two concerns:
//   1. the boundary predicate (`status = active AND expiresAt > now AND expiresAt <= cutoff`) --
//      already-expired excluded, comfortably-outside-the-window excluded, comfortably-inside
//      included, and the two window edges tested with enough slack to absorb real HTTP/DB
//      round-trip latency (see `boundary_slack` below for why exact single-second precision
//      against the window edge is not attempted here);
//   2. cross-tenant isolation -- this procedure calls the generated `db.api_key()` delegate
//      precisely so it inherits `ApiKey`'s own compiled `@@allow("read", ...)` policy rather than
//      a second, hand-written ownership join (see the schema doc comment on
//      `listMyExpiringApiKeys`), so this test also stands as a regression test for that policy
//      actually firing when invoked this way, not just when invoked via `model.ApiKey.list`.
// ---------------------------------------------------------------------------------------------

/// A little slack around a window boundary so "just inside"/"just outside" seeding survives the
/// real network+DB round trip between this test computing its own reference clock and the
/// procedure computing its own `Utc::now()` server-side moments later -- chasing literal
/// single-second precision against a live HTTP call would make this test flaky, not more
/// rigorous. The comparison operators themselves (`>`/`<=`) are cratestack's own, already
/// covered by its own test suite; what this test verifies is that THIS procedure wires the right
/// fields/operators/window to them.
const BOUNDARY_SLACK_SECONDS: i64 = 5;

async fn call_list_my_expiring_api_keys(
    router: &Router,
    token: &str,
    within_days: i64,
) -> (StatusCode, Vec<u8>) {
    rpc_call(
        router.clone(),
        "procedure.listMyExpiringApiKeys",
        Wire::Cbor,
        &json!({ "args": { "withinDays": within_days } }),
        Some(token),
    )
    .await
}

#[tokio::test]
async fn list_my_expiring_api_keys_applies_the_window_boundary_and_excludes_already_expired() {
    let owner = format!("owner-expiring-boundary-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("owner", token_info(&owner, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let account_id =
        create_account(r, "owner", &format!("tenant-expiring-boundary-{}", cuid2())).await;
    let project_id = create_project(r, "owner", &account_id, "proj-expiring-boundary").await;

    let now = chrono::Utc::now();
    let within_days = 7;
    let cutoff = now + chrono::Duration::days(within_days);

    // Comfortably inside the 7-day window.
    let (comfortably_inside_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &project_id,
        "k-comfortably-inside",
        now + chrono::Duration::days(1),
    )
    .await;
    // Just inside the window edge (within slack of the cutoff, but before it).
    let (just_inside_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &project_id,
        "k-just-inside",
        cutoff - chrono::Duration::seconds(BOUNDARY_SLACK_SECONDS),
    )
    .await;
    // Just outside the window edge (within slack of the cutoff, but after it).
    let (just_outside_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &project_id,
        "k-just-outside",
        cutoff + chrono::Duration::seconds(BOUNDARY_SLACK_SECONDS),
    )
    .await;
    // Comfortably outside the window (30 days out, well beyond the 7-day ask).
    let (comfortably_outside_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &project_id,
        "k-comfortably-outside",
        now + chrono::Duration::days(30),
    )
    .await;
    // Already expired: created with a valid future expiry (write-time validation requires it),
    // then pushed into the past directly via the verify pool -- `createApiKey` itself refuses a
    // past `expiresAt` (lightbridge-authz#395's `validate_expires_at`), so this is the only way
    // to get an expired row seeded through the real create path rather than hand-inserting one.
    let (expired_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &project_id,
        "k-already-expired",
        now + chrono::Duration::days(1),
    )
    .await;
    sqlx::query("UPDATE api_keys SET expires_at = $1 WHERE id = $2")
        .bind(now - chrono::Duration::days(1))
        .bind(&expired_id)
        .execute(&ctx.verify)
        .await
        .expect("push key into the past");

    let (status, body) = call_list_my_expiring_api_keys(r, "owner", within_days).await;
    assert!(
        status.is_success(),
        "listMyExpiringApiKeys: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let returned_ids: std::collections::HashSet<String> = json_body(&body)
        .as_array()
        .expect("array response")
        .iter()
        .map(|k| k["id"].as_str().expect("id").to_string())
        .collect();

    assert!(
        returned_ids.contains(&comfortably_inside_id),
        "a key expiring well inside the window must be returned"
    );
    assert!(
        returned_ids.contains(&just_inside_id),
        "a key expiring just inside the window edge must be returned"
    );
    assert!(
        !returned_ids.contains(&just_outside_id),
        "a key expiring just outside the window edge must NOT be returned"
    );
    assert!(
        !returned_ids.contains(&comfortably_outside_id),
        "a key expiring well outside the window must NOT be returned"
    );
    assert!(
        !returned_ids.contains(&expired_id),
        "an already-expired key must NOT be returned -- that is a separate, existing concern \
         from \"about to expire\""
    );
}

#[tokio::test]
async fn list_my_expiring_api_keys_does_not_leak_another_tenants_keys() {
    let owner = format!("owner-expiring-tenant-{}", cuid2());
    let stranger = format!("stranger-expiring-tenant-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("owner", token_info(&owner, admin_perms()))
            .with("stranger", token_info(&stranger, admin_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let owner_account =
        create_account(r, "owner", &format!("tenant-expiring-owner-{}", cuid2())).await;
    let owner_project = create_project(r, "owner", &owner_account, "proj-expiring-owner").await;
    let now = chrono::Utc::now();
    let (owner_key_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &owner_project,
        "k-owner-expiring",
        now + chrono::Duration::days(1),
    )
    .await;

    let stranger_account = create_account(
        r,
        "stranger",
        &format!("tenant-expiring-stranger-{}", cuid2()),
    )
    .await;
    let stranger_project =
        create_project(r, "stranger", &stranger_account, "proj-expiring-stranger").await;
    let (stranger_key_id, _) = create_api_key_with_expiry(
        r,
        "stranger",
        &stranger_project,
        "k-stranger-expiring",
        now + chrono::Duration::days(1),
    )
    .await;

    let (status, body) = call_list_my_expiring_api_keys(r, "owner", 7).await;
    assert!(
        status.is_success(),
        "{status} {}",
        String::from_utf8_lossy(&body)
    );
    let owner_view: std::collections::HashSet<String> = json_body(&body)
        .as_array()
        .expect("array response")
        .iter()
        .map(|k| k["id"].as_str().expect("id").to_string())
        .collect();
    assert!(
        owner_view.contains(&owner_key_id),
        "owner must see their own expiring key"
    );
    assert!(
        !owner_view.contains(&stranger_key_id),
        "owner must NOT see the stranger's expiring key"
    );

    let (status, body) = call_list_my_expiring_api_keys(r, "stranger", 7).await;
    assert!(
        status.is_success(),
        "{status} {}",
        String::from_utf8_lossy(&body)
    );
    let stranger_view: std::collections::HashSet<String> = json_body(&body)
        .as_array()
        .expect("array response")
        .iter()
        .map(|k| k["id"].as_str().expect("id").to_string())
        .collect();
    assert!(
        stranger_view.contains(&stranger_key_id),
        "stranger must see their own expiring key"
    );
    assert!(
        !stranger_view.contains(&owner_key_id),
        "stranger must NOT see the owner's expiring key"
    );
}

#[tokio::test]
async fn list_my_expiring_api_keys_aggregates_across_every_project_the_caller_can_see() {
    // The whole point of this procedure (lightbridge-authz#436): the self-service UI's
    // `listApiKeys` is scoped to one project at a time, so nobody aggregates across projects
    // without opening each one. This proves a single call surfaces expiring keys from BOTH an
    // owned project AND a project the caller is merely a MEMBER of (not the owning account) --
    // the exact ownership disjunction `ApiKey`'s `@@allow("read", ...)` compiles
    // (`project.account.id == auth().id || project.members.some.accountId == auth().id`).
    let owner = format!("owner-expiring-aggregate-{}", cuid2());
    let member = format!("member-expiring-aggregate-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("owner", token_info(&owner, admin_perms()))
            .with("member", token_info(&member, admin_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let owner_account = create_account(
        r,
        "owner",
        &format!("tenant-expiring-aggregate-owner-{}", cuid2()),
    )
    .await;
    let _member_account = create_account(
        r,
        "member",
        &format!("tenant-expiring-aggregate-member-{}", cuid2()),
    )
    .await;

    let project_a = create_project(r, "owner", &owner_account, "proj-expiring-aggregate-a").await;
    let project_b = create_project(r, "owner", &owner_account, "proj-expiring-aggregate-b").await;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.addProjectMember",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_b, "accountId": member, "role": "member" } }),
        Some("owner"),
    )
    .await;
    assert!(
        status.is_success(),
        "addProjectMember: {status} {}",
        String::from_utf8_lossy(&body)
    );

    let now = chrono::Utc::now();
    let (key_a_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &project_a,
        "k-project-a-expiring",
        now + chrono::Duration::days(1),
    )
    .await;
    let (key_b_id, _) = create_api_key_with_expiry(
        r,
        "owner",
        &project_b,
        "k-project-b-expiring",
        now + chrono::Duration::days(1),
    )
    .await;

    // The member calls it as themselves -- they hold no account-owner relationship to either
    // project, only a `project_members` row on project B.
    let (status, body) = call_list_my_expiring_api_keys(r, "member", 7).await;
    assert!(
        status.is_success(),
        "{status} {}",
        String::from_utf8_lossy(&body)
    );
    let member_view: std::collections::HashSet<String> = json_body(&body)
        .as_array()
        .expect("array response")
        .iter()
        .map(|k| k["id"].as_str().expect("id").to_string())
        .collect();
    assert!(
        member_view.contains(&key_b_id),
        "a project member must see that project's expiring keys"
    );
    assert!(
        !member_view.contains(&key_a_id),
        "a project member must NOT see another project's expiring keys just because its owner \
         happens to also own the project they ARE a member of"
    );

    // The owner calls it as themselves -- one call, both projects' expiring keys.
    let (status, body) = call_list_my_expiring_api_keys(r, "owner", 7).await;
    assert!(
        status.is_success(),
        "{status} {}",
        String::from_utf8_lossy(&body)
    );
    let owner_view: std::collections::HashSet<String> = json_body(&body)
        .as_array()
        .expect("array response")
        .iter()
        .map(|k| k["id"].as_str().expect("id").to_string())
        .collect();
    assert!(
        owner_view.contains(&key_a_id) && owner_view.contains(&key_b_id),
        "the owner's single call must aggregate expiring keys across BOTH of their projects, \
         not just whichever one a UI happens to have open"
    );
}

// ---------------------------------------------------------------------------------------------
// Refresh-token session revocation RPC (`revokeOwnSessions` / `revokeSubjectSessions`).
// `exchange_refresh_tokens` carries no foreign keys to accounts/projects, so these tests seed rows
// directly against `ctx.verify` rather than driving a real token-exchange grant (this file's
// router is `build_api_router`, which no longer mounts token-exchange at all -- see that
// function's doc comment).
// ---------------------------------------------------------------------------------------------

/// Inserts one active `sessions` row (`kind = 'token'`) for `subject`, plus one active
/// `exchange_refresh_tokens` row chained under it (`session_id` set), and returns the SESSION's
/// `id` -- so a test can assert on which specific sessions a revocation touched, and (via
/// [`refresh_token_status_for_session`]) that the cascade reaches the chained refresh token too.
async fn seed_active_session(pool: &sqlx::PgPool, subject: &str) -> String {
    seed_session_with_refresh_token(pool, subject, "token").await
}

/// Inserts one active `sessions` row of the given `kind` (`"token"` or `"browser"`) for `subject`.
/// `kind = "browser"` rows get no `exchange_refresh_tokens` row chained under them (ADR-0021
/// Decision 3: a browser session is never presented as a bearer token, so it structurally cannot
/// have a refresh-token chain) and no `client_id` (`sessions_kind_client_id_check`).
///
/// Sets BOTH `account_id` and `subject` to `subject` -- these tests each model a single caller
/// acting on their own session, never the owner/roster-member split #492 is about (see
/// `token_exchange_tests.rs`'s `seed_owner_and_member_sessions` for that scenario), so the two
/// legitimately coincide here. `revoke_sessions_and_cascade` matches on `subject` (#492), so a
/// row this helper leaves with `subject IS NULL` would never be reachable by any of these tests'
/// revoke calls.
async fn seed_session(pool: &sqlx::PgPool, subject: &str, kind: &str) -> String {
    let id = cuid2();
    let client_id: Option<String> = (kind == "token").then(|| "test-client".to_string());
    sqlx::query(
        r#"
        INSERT INTO sessions (id, account_id, project_id, client_id, kind, status, expires_at, subject)
        VALUES ($1, $2, $3, $4, $5, 'active', now() + interval '1 hour', $2)
        "#,
    )
    .bind(&id)
    .bind(subject)
    .bind(cuid2())
    .bind(client_id)
    .bind(kind)
    .execute(pool)
    .await
    .expect("seed session row");
    id
}

/// [`seed_session`] plus one active `exchange_refresh_tokens` row chained under it via
/// `session_id` -- only meaningful for `kind = "token"` (a browser session has no refresh-token
/// chain, see [`seed_session`]'s doc comment). Returns the session's `id`.
async fn seed_session_with_refresh_token(pool: &sqlx::PgPool, subject: &str, kind: &str) -> String {
    let session_id = seed_session(pool, subject, kind).await;
    // `chain_id`/`chain_expires_at` (migration `20260815000001_exchange_refresh_tokens_add_chain`)
    // are `NOT NULL` with no default -- a single-member chain (`chain_id` = the refresh token's
    // own fresh id) with a cap far enough out that none of these tests' assertions ever race it.
    let refresh_id = cuid2();
    sqlx::query(
        r#"
        INSERT INTO exchange_refresh_tokens
          (id, subject, account_id, project_id, client_id, token_hash, status, chain_id, chain_expires_at, session_id, created_at, expires_at)
        VALUES ($1, $2, $2, $3, 'test-client', $4, 'active', $1, now() + interval '90 days', $5, now(), now() + interval '30 days')
        "#,
    )
    .bind(&refresh_id)
    .bind(subject)
    .bind(cuid2())
    .bind(cuid2())
    .bind(&session_id)
    .execute(pool)
    .await
    .expect("seed active refresh token chained under the session");
    session_id
}

/// The `status` of the `sessions` row with `id`.
async fn session_status(pool: &sqlx::PgPool, id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM sessions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("session row exists")
}

/// The `status` of the `exchange_refresh_tokens` row chained under `session_id` (ADR-0020
/// Decision 9's cascade requirement: bulk-revoking a session must also revoke the refresh token
/// rows chained under it, not leave a live one behind).
async fn refresh_token_status_for_session(pool: &sqlx::PgPool, session_id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM exchange_refresh_tokens WHERE session_id = $1")
        .bind(session_id)
        .fetch_one(pool)
        .await
        .expect("chained refresh token row exists")
}

/// Test 6 (task list): the self-service procedure revokes only the caller's own sessions, and
/// cannot be aimed at another subject -- proven two ways at once: the caller's own two sessions
/// both flip to `revoked`, and a bystander subject's session, seeded in the very same test, is
/// left untouched (there is no field on this procedure's input the caller could have used to name
/// the bystander even if they wanted to -- see `authz.cstack`'s `RevokeOwnSessionsInput`).
#[tokio::test]
async fn revoke_own_sessions_revokes_only_the_callers_sessions() {
    use lightbridge_authz_core::authz::{Permission, PermissionSet};

    let caller = format!("self-revoke-{}", cuid2());
    let bystander = format!("self-revoke-bystander-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(MapBearer::new().with(
        "caller",
        token_info(
            &caller,
            PermissionSet::from_iter([Permission::SessionRevokeOwn]),
        ),
    ));
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let caller_session_a = seed_active_session(&ctx.verify, &caller).await;
    let caller_session_b = seed_active_session(&ctx.verify, &caller).await;
    let bystander_session = seed_active_session(&ctx.verify, &bystander).await;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.revokeOwnSessions",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("caller"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Cbor, &body);
    assert_eq!(
        parsed["revokedCount"], 2,
        "must report exactly the two sessions it revoked: {parsed}"
    );

    assert_eq!(
        session_status(&ctx.verify, &caller_session_a).await,
        "revoked"
    );
    assert_eq!(
        session_status(&ctx.verify, &caller_session_b).await,
        "revoked"
    );
    assert_eq!(
        session_status(&ctx.verify, &bystander_session).await,
        "active",
        "a bystander's session must never be touched by another subject's self-service call"
    );
    // ADR-0020 Decision 9's cascade requirement: bulk-revoking a session must also revoke the
    // exchange_refresh_tokens row chained under it, not leave a live refresh token behind for a
    // session that was just killed. Self-service parity with the admin path (task 6e).
    assert_eq!(
        refresh_token_status_for_session(&ctx.verify, &caller_session_a).await,
        "revoked",
        "revokeOwnSessions must cascade to the refresh token chained under the caller's session"
    );
}

/// A caller lacking `session:revoke-own` gets 403 from `revokeOwnSessions` -- proves the
/// permission gate is actually wired, not merely present in `rpc_authorize`'s map with nothing
/// enforcing it.
#[tokio::test]
async fn revoke_own_sessions_without_permission_is_forbidden() {
    let caller = format!("self-revoke-denied-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("caller", token_info(&caller, viewer_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let (status, _) = rpc_call(
        r.clone(),
        "procedure.revokeOwnSessions",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("caller"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer_perms holds no session:revoke-own"
    );
}

/// Test 7 (task list): the admin procedure revokes a target subject's sessions, and a caller
/// without `session:revoke` is refused with 403.
#[tokio::test]
async fn revoke_subject_sessions_admin_revokes_target_others_get_403() {
    let admin_subject = format!("session-admin-{}", cuid2());
    let editor_subject = format!("session-editor-{}", cuid2());
    let target = format!("offboarded-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with("admin", token_info(&admin_subject, admin_perms()))
            // An editor holds `session:revoke-own` (see `default_role_permissions`) but not the
            // admin-only `session:revoke` -- exactly the boundary this test asserts.
            .with(
                "editor",
                token_info(
                    &editor_subject,
                    lightbridge_authz_core::authz::PermissionSet::from_iter([
                        lightbridge_authz_core::authz::Permission::SessionRevokeOwn,
                    ]),
                ),
            ),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let target_session_a = seed_active_session(&ctx.verify, &target).await;
    let target_session_b = seed_active_session(&ctx.verify, &target).await;
    let target_session_c = seed_active_session(&ctx.verify, &target).await;

    // A caller holding only `session:revoke-own` cannot reach the admin procedure at all.
    let (status, _) = rpc_call(
        r.clone(),
        "procedure.revokeSubjectSessions",
        Wire::Cbor,
        &json!({ "args": { "accountId": target } }),
        Some("editor"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "session:revoke-own must not also grant the admin session:revoke capability"
    );
    assert_eq!(
        session_status(&ctx.verify, &target_session_a).await,
        "active",
        "the forbidden call above must not have touched anything"
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.revokeSubjectSessions",
        Wire::Cbor,
        &json!({ "args": { "accountId": target } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Cbor, &body);
    assert_eq!(
        parsed["revokedCount"], 3,
        "the offboarding kill switch must report the true count: {parsed}"
    );

    for id in [target_session_a, target_session_b, target_session_c] {
        assert_eq!(session_status(&ctx.verify, &id).await, "revoked");
    }
}

/// A second call to `revokeSubjectSessions` for an already-fully-revoked subject reports `0`, not
/// an error -- there being nothing left to revoke is not a failure.
#[tokio::test]
async fn revoke_subject_sessions_reports_zero_when_nothing_is_active() {
    let admin_subject = format!("session-admin-noop-{}", cuid2());
    let target = format!("already-clean-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.revokeSubjectSessions",
        Wire::Cbor,
        &json!({ "args": { "accountId": target } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Cbor, &body);
    assert_eq!(parsed["revokedCount"], 0);
}

/// #441's own required regression test: `revokeSubjectSessions`'s underlying query must cover
/// BOTH `kind`s, proven by seeding a `kind = 'browser'` row directly (no RP-leg caller exists yet
/// to create one for real -- ADR-0021 Follow-up 6/#441's own scope note; this is fine and expected
/// per that ticket's own acceptance criteria) alongside a normal `kind = 'token'` one, and
/// asserting the bulk cascade reaches BOTH in the same call -- not just asserted by code review,
/// per ADR-0021 Decision 3's own explicit "must be proven, not assumed" requirement.
#[tokio::test]
async fn revoke_subject_sessions_reaches_a_browser_kind_session_too() {
    let admin_subject = format!("session-admin-kind-{}", cuid2());
    let target = format!("kind-mixed-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let token_session = seed_session(&ctx.verify, &target, "token").await;
    let browser_session = seed_session(&ctx.verify, &target, "browser").await;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.revokeSubjectSessions",
        Wire::Cbor,
        &json!({ "args": { "accountId": target } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Cbor, &body);
    assert_eq!(
        parsed["revokedCount"], 2,
        "must revoke both sessions, of either kind, in one call: {parsed}"
    );

    assert_eq!(session_status(&ctx.verify, &token_session).await, "revoked");
    assert_eq!(
        session_status(&ctx.verify, &browser_session).await,
        "revoked",
        "a kind='browser' row must be reached by the same bulk cascade as a kind='token' one -- \
         a kind-blind-in-the-wrong-direction bug here would leave this row silently active"
    );
}

/// #441's cross-subject isolation criterion: revoking one subject's sessions must not touch a
/// different subject's rows, of EITHER kind. Seeds both kinds for both a target and a bystander,
/// revokes only the target, and asserts the bystander's rows (both kinds) are untouched.
#[tokio::test]
async fn revoke_subject_sessions_does_not_touch_a_different_subjects_sessions_of_either_kind() {
    let admin_subject = format!("session-admin-cross-{}", cuid2());
    let target = format!("cross-target-{}", cuid2());
    let bystander = format!("cross-bystander-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let target_token = seed_session(&ctx.verify, &target, "token").await;
    let target_browser = seed_session(&ctx.verify, &target, "browser").await;
    let bystander_token = seed_session(&ctx.verify, &bystander, "token").await;
    let bystander_browser = seed_session(&ctx.verify, &bystander, "browser").await;

    let (status, _) = rpc_call(
        r.clone(),
        "procedure.revokeSubjectSessions",
        Wire::Cbor,
        &json!({ "args": { "accountId": target } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(session_status(&ctx.verify, &target_token).await, "revoked");
    assert_eq!(
        session_status(&ctx.verify, &target_browser).await,
        "revoked"
    );
    assert_eq!(
        session_status(&ctx.verify, &bystander_token).await,
        "active",
        "a bystander's token-kind session must never be touched by another subject's revoke call"
    );
    assert_eq!(
        session_status(&ctx.verify, &bystander_browser).await,
        "active",
        "a bystander's browser-kind session must never be touched by another subject's revoke call"
    );
}

// ---------------------------------------------------------------------------------------------
// Section: self-provisioning -- lightbridge-viewer/lightbridge-editor must be able to create their
// own account (#219: the account row must exist before `project_members.account_id`'s FK to
// `accounts` can be satisfied, so a low-privilege first-time caller who lacks `account:create`
// can never be added to a project roster by anyone).
// ---------------------------------------------------------------------------------------------

/// The real, effective permission set for `role` as configured in the shipped
/// `config/default.yaml`, loaded and compiled through the exact same `Rbac::compile()` path a
/// running server takes at startup -- mirrors `editor_perms_from_shipped_config` in
/// `rpc_router_tests.rs`, duplicated here rather than shared via `common` to keep each test file's
/// edit surface independent.
fn perms_from_shipped_config(role: &str) -> lightbridge_authz_core::authz::PermissionSet {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/default.yaml");
    let config = lightbridge_authz_core::config::load_from_path(path)
        .expect("shipped config/default.yaml must parse");
    config
        .oauth2
        .rbac
        .compile()
        .roles
        .get(role)
        .cloned()
        .unwrap_or_else(|| panic!("config/default.yaml must configure role `{role}`"))
}

/// A genuine first-time `lightbridge-viewer`/`lightbridge-editor` caller must be able to
/// self-provision their own account over the real RPC dispatch, against real Postgres. Also
/// asserts the two invariants that make this safe to grant (ADR-0006, one account is one person):
/// the created account's id is always the caller's own JWT subject -- `CreateAccountInput` carries
/// no id/accountId field at all, so creating an account "for a different subject" is structurally
/// unreachable, not merely denied -- and a second `createAccount` for that same subject conflicts
/// rather than minting a second account.
#[tokio::test]
async fn viewer_and_editor_can_self_provision_their_own_account() {
    for role in ["lightbridge-viewer", "lightbridge-editor"] {
        let subject = format!("{role}-selfprovision-{}", cuid2());
        let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(MapBearer::new().with(
            "caller",
            token_info(&subject, perms_from_shipped_config(role)),
        ));
        let ctx = setup(bearer).await;

        let (status, body) = rpc_call(
            ctx.router.clone(),
            "procedure.createAccount",
            Wire::Cbor,
            &json!({ "args": {} }),
            Some("caller"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{role} must be able to create their own account: {}",
            String::from_utf8_lossy(&body)
        );
        let created = json_body(&body);
        assert_eq!(
            created["id"], subject,
            "{role}'s ANCHOR account id must equal their own JWT subject -- \
             `federated_identities` adopts by matching exactly this"
        );

        let (status, body) = rpc_call(
            ctx.router.clone(),
            "procedure.createAccount",
            Wire::Cbor,
            &json!({ "args": {} }),
            Some("caller"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{role}'s second createAccount now mints a second account (ADR-0026); it used to \
             conflict on the accounts primary key: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            json_body(&body)["userId"],
            created["id"],
            "{role}'s second account must join the person the anchor already established, not \
             mint a new one"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Section 9 (formerly): the budget:*-gated procedures. Moved off this file onto
// `budget_rpc_it_tests.rs` (`authz-budget`'s own real-DB integration coverage, exercised through
// `build_budget_router` at `/budget/rpc/{op_id}` instead of `build_api_router`'s `/rpc/{op_id}`)
// as part of the budget-domain microservice split -- see docs/architecture/budget.md, "Service
// boundary". What stays here is the cutover proof: every budget:*-gated op-id must now be
// unreachable on `authz-api`, for ANY caller, permission included.
// ---------------------------------------------------------------------------------------------

/// Every op-id `rpc_authorize.rs`'s `required_permission` map gates on a `budget:*` permission
/// (the 15 procedures enumerated in `docs/architecture/budget.md` -- `procedure.
/// listMyAugmentationRequests` added by #295). Hand-copied here deliberately -- unlike the
/// hermetic `rpc_authorize.rs`-internal unit tests, which re-derive this list from the map
/// itself, this integration test exists specifically to catch drift between "what the map says
/// is a budget op" and "what the real router, wired exactly like production, actually refuses"
/// -- a hand-copied list is the point, not a shortcut.
const MOVED_BUDGET_OP_IDS: [&str; 15] = [
    "procedure.activateBudgetPolicy",
    "procedure.getBudgetPolicyStatus",
    "procedure.simulateBudgetPolicy",
    "procedure.requestBudgetRefill",
    "procedure.listPendingAugmentationRequests",
    "procedure.approveAugmentationRequest",
    "procedure.rejectAugmentationRequest",
    "procedure.getMyBudgetBalance",
    "procedure.listMyBudgetGrants",
    "procedure.listMyAugmentationRequests",
    "procedure.getBudgetBalance",
    "procedure.listBudgetGrants",
    "procedure.grantBudget",
    "procedure.revokeBudgetGrant",
    "procedure.createBudgetPolicyRevision",
];

/// Proves the hard cutover against the REAL, fully-wired `authz-api` router (live Postgres +
/// Redis, exactly as production runs it) -- not just the hermetic, lazily-wired coverage in
/// `rpc_router_tests.rs`. An admin bearer (every permission, including all `budget:*` ones) is
/// used deliberately: if any of these 404s were actually a `403`, an admin token would unmask it,
/// proving the refusal is the `RpcScope::Crud` scope gate, not a permission gate that merely
/// happens to look the same from a non-admin caller.
#[tokio::test]
async fn budget_gated_op_ids_are_unreachable_on_authz_api_even_for_an_admin() {
    let subject = format!("budget-moved-admin-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;

    for op in MOVED_BUDGET_OP_IDS {
        let (status, body) = rpc_call(
            ctx.router.clone(),
            op,
            Wire::Cbor,
            &json!({}),
            Some("admin"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{op} must be unreachable on authz-api (moved to authz-budget), even for an admin \
             holding every permission: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // Same op-ids, bundled into ONE `/rpc/batch` call -- proves the scope check also closes the
    // batch-frame bypass (`CratestackAuthProvider::authenticate`), not merely the outer unary gate.
    let frames: Vec<Value> = MOVED_BUDGET_OP_IDS
        .iter()
        .enumerate()
        .map(|(i, op)| json!({ "id": i, "op": op, "input": {} }))
        .collect();
    let (status, body) = rpc_call(
        ctx.router.clone(),
        "batch",
        Wire::Cbor,
        &json!(frames),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the outer batch endpoint only requires a valid caller -- per-frame scope is enforced \
         deeper: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Cbor, &body);
    let results = parsed.as_array().expect("batch results array");
    assert_eq!(results.len(), MOVED_BUDGET_OP_IDS.len());
    for (op, frame) in MOVED_BUDGET_OP_IDS.iter().zip(results) {
        assert!(
            frame.get("error").is_some(),
            "{op}'s batch frame must carry an error (moved off authz-api): {frame}"
        );
    }
}

/// Regression coverage for lightbridge-authz#395's `createApiKey` half. Before that hard cutover,
/// this test proved the *direct* `/rpc/procedure.createApiKey` half of an older production bug
/// (creating a non-expiring API key -- the "No expiry" option added in converse-frontends#182 --
/// failed with a generic `invalid_argument` error even though it should have succeeded): a frame
/// byte-for-byte what `cborg` produces for `{ args: { name, expiresAt: null, projectId,
/// billingPlan } }` used to decode fine into `Option<DateTime<Utc>>::None` and create a
/// non-expiring key. Since #395, `expiresAt` is required (non-nullable) on `CreateApiKeyInput`, so
/// the *same* bytes must now be rejected -- there is no more "no expiry" to create. Kept as a
/// permanent regression test with the assertion flipped: a future schema/codec change that made
/// `null` decode successfully again into a required field would silently reopen the "no expiry"
/// hole this whole rule exists to close.
#[tokio::test]
async fn create_api_key_rejects_real_cborg_null_expires_at_bytes() {
    let subject = format!("owner-cborg-null-expiry-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let billing_id = format!("tenant-cborg-null-expiry-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;
    let project_id = create_project(r, "admin", &account_id, "p-cborg-null-expiry").await;

    let mut raw = Vec::new();
    let mut e = minicbor::Encoder::new(&mut raw);
    e.map(1).unwrap();
    e.str("args").unwrap();
    e.map(4).unwrap();
    e.str("name").unwrap();
    e.str("Miaou").unwrap();
    e.str("expiresAt").unwrap();
    e.null().unwrap();
    e.str("projectId").unwrap();
    e.str(&project_id).unwrap();
    e.str("billingPlan").unwrap();
    e.str("free").unwrap();

    let (status, body) = rpc_call_raw(r, "procedure.createApiKey", Wire::Cbor, raw, "admin").await;
    assert!(
        !status.is_success(),
        "createApiKey with a null expiresAt must be rejected now that it is required \
         (lightbridge-authz#395): {status} {}",
        String::from_utf8_lossy(&body)
    );
}

/// Companion to `create_api_key_rejects_real_cborg_null_expires_at_bytes` for the settings/edit
/// screen's old clear-expiry path (`useUpdateApiKey` -> `apiKeys.update(id, { name, expiresAt })`).
/// Before lightbridge-authz#395 this proved the PATCH double-Option path
/// (`UpdateApiKeyInput.expiresAt` wraps as `Option<Option<DateTime>>` per `field_definition`'s
/// `wrap_for_patch`) correctly cleared an api key's expiry via real cborg-shaped null bytes. That
/// was itself the security bypass #395 closes: `expiresAt` no longer exists on the generated
/// `UpdateApiKeyInput` at all (`@readonly` in `authz.cstack`), so this now proves the opposite --
/// the exact same bytes can no longer clear (or touch) the key's expiry, whether the schema
/// silently drops the now-unrecognized field (success, only `name` changes) or rejects the call
/// outright. Either response is acceptable; what must never happen again is the key ending up with
/// a cleared `expiresAt`.
#[tokio::test]
async fn update_api_key_cannot_clear_expiry_with_real_cborg_null_bytes() {
    let subject = format!("owner-cborg-null-patch-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let billing_id = format!("tenant-cborg-null-patch-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;
    let project_id = create_project(r, "admin", &account_id, "p-cborg-null-patch").await;
    let (key_id, _secret) = create_api_key(r, "admin", &project_id, "k-cborg-null-patch").await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.get",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("admin"),
    )
    .await;
    assert!(
        status.is_success(),
        "get-api-key before update: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let original_expires_at = json_body(&body)["expiresAt"].clone();
    assert!(
        !original_expires_at.is_null(),
        "fixture key must have a real expiry to make this test meaningful"
    );

    let mut raw = Vec::new();
    let mut e = minicbor::Encoder::new(&mut raw);
    e.map(2).unwrap();
    e.str("id").unwrap();
    e.str(&key_id).unwrap();
    e.str("patch").unwrap();
    e.map(2).unwrap();
    e.str("name").unwrap();
    e.str("k-cborg-null-patch-renamed").unwrap();
    e.str("expiresAt").unwrap();
    e.null().unwrap();

    let (status, body) = rpc_call_raw(r, "model.ApiKey.update", Wire::Cbor, raw, "admin").await;
    if status.is_success() {
        let decoded = Wire::Cbor.decode::<Value>(&body);
        assert_eq!(
            decoded["expiresAt"], original_expires_at,
            "model.ApiKey.update must not be able to change expiresAt at all, let alone clear \
             it: {decoded}"
        );
    }

    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.get",
        Wire::Cbor,
        &json!({ "id": key_id }),
        Some("admin"),
    )
    .await;
    assert!(status.is_success());
    let after = json_body(&body);
    assert!(
        !after["expiresAt"].is_null(),
        "the bypass this test used to demonstrate must stay closed -- expiresAt is still set \
         after the update attempt: {after}"
    );
    assert_eq!(after["expiresAt"], original_expires_at);
}

/// The actual reproduction of the production bug report, found only after the two direct-call
/// tests above passed and testing the real captured request/response bytes (not a reconstruction)
/// through the real batch envelope was the only thing left to try.
///
/// `converse-frontends` wires `createBatchLink()` (`@cratestack/link-batch`) into every unary
/// authz RPC call (`apps/self-service/src/app/_layout.tsx`) -- it is a *terminal* link: it never
/// calls `next` for a `kind: "unary"` request, it always queues the call and sends it later as its
/// own `POST /rpc/batch` request (`dispatchPartition` in `@cratestack/link-batch`'s `dispatch.js`,
/// building `{ id, op: request.opId, input: request.input }` per queued call). So `createApiKey`
/// never actually reaches `/rpc/procedure.createApiKey` directly in this app -- every real call
/// takes this path.
///
/// Root cause, confirmed with a standalone minimal reproduction outside this whole stack
/// (`serde_json::json!(null)` through `minicbor_serde::to_vec` alone) before touching this test:
/// `cratestack-axum`'s generated `rpc_batch_dispatch` decodes each frame's `input` into
/// `cratestack_core::rpc::RpcRequest.input: serde_json::Value` (an intentionally opaque carrier --
/// the dispatcher doesn't know the target procedure's concrete input type until it looks up `op`),
/// then re-encodes *that* `serde_json::Value` back to bytes (`encode_rpc_value`) before
/// redispatching through the normal per-op decode path. `serde_json::Value::Null`'s `Serialize`
/// impl calls `serializer.serialize_unit()`, not `serialize_none()`; `minicbor-serde`'s own
/// `serialize_unit()` encodes Rust's `()` as CBOR's empty-array marker (`0x80`) by default, not
/// `null` (`0xf6`) -- confirmed directly against `cratestack-codec-cbor`'s own source and test
/// comments (see `codec.rs`'s module doc comment for the full citation). So `expiresAt: null`
/// survives the *first* decode (into the opaque `serde_json::Value`) fine, gets corrupted into an
/// empty array on the *re-encode*, and then fails the *second* decode (into the concrete
/// `CreateApiKeyInput.expiresAt: Option<chrono::DateTime<Utc>>`) with exactly the generic
/// `invalid_argument` / "invalid request payload" the production report described -- a CBOR empty
/// array has no mapping onto `Option<DateTime<Utc>>` any more than it did onto a plain `DateTime`.
///
/// Originally fixed in `LenientCborCodec::encode` (`codec.rs`) by constructing a
/// `minicbor_serde::Serializer` with `serialize_unit_as_null(true)` instead of delegating to
/// `cratestack_codec_cbor::CborCodec::encode`'s hardcoded default. As of cratestack 0.8.6
/// (cratestack/cratestack#675, closing #657) the raw `CborCodec::encode` does this itself, so
/// `LenientCborCodec::encode` now just delegates straight through -- see `codec.rs`'s module doc
/// comment for the full mechanism and the upstream commit link. This test was the end-to-end
/// proof, byte-for-byte, that the frontend's `createBatchLink()` + `cborg` output for a batched
/// `createApiKey` call with `expiresAt: null` decoded correctly and *succeeded*.
///
/// Since lightbridge-authz#395 made `expiresAt` required (non-nullable) on `CreateApiKeyInput`,
/// the correct outcome for these exact bytes flipped: `null` now decodes cleanly (the codec fix
/// above still holds) but is then rejected by the required-field check, so the batch frame must
/// carry an error instead of a created key. Kept as a permanent regression test with the
/// assertion flipped, for the same reason its direct-call sibling above was flipped rather than
/// deleted.
#[tokio::test]
async fn batch_create_api_key_rejects_real_cborg_null_expires_at_bytes() {
    let subject = format!("owner-batch-null-expiry-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;

    let billing_id = format!("tenant-batch-null-expiry-{}", cuid2());
    let account_id = create_account(&ctx.router, "admin", &billing_id).await;
    let project_id = create_project(&ctx.router, "admin", &account_id, "p-batch-null-expiry").await;

    // `[{ id: 0, op: "procedure.createApiKey", input: { args: { name, billingPlan, expiresAt:
    // null, projectId } } }]` -- the exact frame `dispatchPartition` builds for a single queued
    // `createApiKey` call. `project_id` substituted below since the real one is generated per
    // test run; every other byte matches a real `cborg.encode(stripUndefined(...))` run verbatim.
    let mut raw = Vec::new();
    let mut e = minicbor::Encoder::new(&mut raw);
    e.array(1).unwrap();
    e.map(3).unwrap();
    e.str("id").unwrap();
    e.u32(0).unwrap();
    e.str("op").unwrap();
    e.str("procedure.createApiKey").unwrap();
    e.str("input").unwrap();
    e.map(1).unwrap();
    e.str("args").unwrap();
    e.map(4).unwrap();
    e.str("name").unwrap();
    e.str("Miaou").unwrap();
    e.str("billingPlan").unwrap();
    e.str("free").unwrap();
    e.str("expiresAt").unwrap();
    e.null().unwrap();
    e.str("projectId").unwrap();
    e.str(&project_id).unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/rpc/batch")
        .header("content-type", "application/cbor")
        .header("accept", "application/cbor")
        .header("authorization", "Bearer admin")
        .body(Body::from(raw))
        .unwrap();
    let response = ctx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(
        status.is_success(),
        "batch envelope must be 200 even if a frame fails: {status} {}",
        String::from_utf8_lossy(&bytes)
    );

    let frames: Vec<Value> = Wire::Cbor.decode(&bytes);
    assert_eq!(frames.len(), 1);
    let frame = &frames[0];
    assert!(
        frame.get("error").is_some(),
        "createApiKey batch frame with a null expiresAt must carry an error now that it is \
         required (lightbridge-authz#395), not create a key: {frame}"
    );
}

/// The response-side half of the same bug -- and the one with the much larger blast radius.
/// `rpc_batch_dispatch`'s `response_to_frame` decodes each inner dispatch's SUCCESS body into a
/// generic `serde_json::Value` (`RpcResponseFrame.output: Option<serde_json::Value>`) before
/// folding it into the batch's response array, which then goes through the exact same
/// `LenientCborCodec::encode` this module's doc comment describes. So this bug corrupts not just
/// a batched *request*'s `null` fields, but *every* `null` anywhere in *every* batched response --
/// independent of which procedure/model was called, and independent of the field's original Rust
/// type, since by the time `response_to_frame` sees it, `None` has already been fully erased into
/// the generic `serde_json::Value::Null`.
///
/// This is the resolution to converse-frontends#180's `oauth2Url` mystery: that investigation
/// proved (independently, exhaustively) that prod's `authz-api` can only ever send `null` for
/// `oauth2Url`, yet the deployed bundle demonstrably crashed on a *present, non-string* value.
/// `null` -> `[]` through this exact mechanism resolves the contradiction -- `[]` is present,
/// non-nullish, and has no `.trim` method, so neither the `?.` in the caller nor a naive falsy
/// check would have caught it.
///
/// The request built here carries no `null` anywhere (`expiresAt` is a real, present date --
/// computed relative to `now`, not hardcoded, so it stays within the `ApiKeyExpiry` ceiling
/// lightbridge-authz#395 added regardless of when this test runs) -- deliberately isolating the
/// RESPONSE-side encode from the already-covered REQUEST-side bug
/// (`batch_create_api_key_rejects_real_cborg_null_expires_at_bytes` above). The response naturally
/// carries several `None` fields on a freshly created key (`oauth2Url`, `lastUsedAt`, `lastIp`,
/// `revokedAt`, `deletedAt`) -- this asserts on `oauth2Url` specifically since that's the field
/// converse-frontends#180 was stuck on, but confirmed by hand (see this PR's description) that
/// all five decoded as CBOR's empty array before the fix and as real `null` after it.
#[tokio::test]
async fn batch_response_null_fields_encode_as_cbor_null_not_empty_array() {
    let subject = format!("owner-batch-resp-null-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;

    let billing_id = format!("tenant-batch-resp-null-{}", cuid2());
    let account_id = create_account(&ctx.router, "admin", &billing_id).await;
    let project_id = create_project(&ctx.router, "admin", &account_id, "p-batch-resp-null").await;

    let mut raw = Vec::new();
    let mut e = minicbor::Encoder::new(&mut raw);
    e.array(1).unwrap();
    e.map(3).unwrap();
    e.str("id").unwrap();
    e.u32(0).unwrap();
    e.str("op").unwrap();
    e.str("procedure.createApiKey").unwrap();
    e.str("input").unwrap();
    e.map(1).unwrap();
    e.str("args").unwrap();
    e.map(4).unwrap();
    e.str("name").unwrap();
    e.str("Miaou").unwrap();
    e.str("billingPlan").unwrap();
    e.str("free").unwrap();
    e.str("expiresAt").unwrap();
    e.str(&near_future_expiry()).unwrap();
    e.str("projectId").unwrap();
    e.str(&project_id).unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/rpc/batch")
        .header("content-type", "application/cbor")
        .header("accept", "application/cbor")
        .header("authorization", "Bearer admin")
        .body(Body::from(raw))
        .unwrap();
    let response = ctx.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    // Assert on the raw wire byte directly, not just the decoded value: a lenient decoder could
    // in principle paper over a `[]` and hand back `Null` (this codec's own decoder does exactly
    // that normalization for `undefined`), which would hide a real wire-level corruption behind a
    // clean-looking assertion.
    let key = b"ioauth2Url";
    let pos = bytes
        .windows(key.len())
        .position(|w| w == key)
        .expect("oauth2Url key present in raw response bytes");
    assert_eq!(
        bytes[pos + key.len()],
        0xf6,
        "oauth2Url's wire value must be CBOR null (0xf6), not CBOR's empty array (0x80)"
    );

    let frames: Vec<Value> = Wire::Cbor.decode(&bytes);
    let output = &frames[0]["output"];
    {
        let field = "oauth2Url";
        assert!(
            output[field].is_null(),
            "{field} must decode as JSON null: {output}"
        );
    }
    for field in ["lastUsedAt", "lastIp", "revokedAt", "deletedAt"] {
        assert!(
            output["apiKey"][field].is_null(),
            "apiKey.{field} must decode as JSON null: {}",
            output["apiKey"]
        );
    }
}

/// Same mechanism, a non-string `Option<T>` field: `Project.allowedModels: Option<Vec<String>>`.
/// Confirms the corruption is type-independent (any `None` collapses to the same
/// `serde_json::Value::Null` before `response_to_frame` ever sees it, regardless of what Rust type
/// originally held it) rather than something specific to `Option<String>`.
///
/// Deliberately does NOT assert this breaks anything user-visible -- for this one field the
/// corruption was harmless by convention (`AGENTS.md`: `NULL`/`[]` both mean "all models allowed"
/// for `allowed_models`), which is exactly why it went unnoticed while `oauth2Url`/`defaultQuota`
/// did not: this field happened to have a semantics where `null` and `[]` coincide, not because
/// the encode bug spared it.
#[tokio::test]
async fn batch_response_null_allowed_models_encodes_as_cbor_null_not_empty_array() {
    let subject = format!("owner-batch-resp-null-am-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;

    let billing_id = format!("tenant-batch-resp-null-am-{}", cuid2());
    let account_id = create_account(&ctx.router, "admin", &billing_id).await;
    let project_id =
        create_project(&ctx.router, "admin", &account_id, "p-batch-resp-null-am").await;

    let mut raw = Vec::new();
    let mut e = minicbor::Encoder::new(&mut raw);
    e.array(1).unwrap();
    e.map(3).unwrap();
    e.str("id").unwrap();
    e.u32(0).unwrap();
    e.str("op").unwrap();
    e.str("model.Project.get").unwrap();
    e.str("input").unwrap();
    e.map(1).unwrap();
    e.str("id").unwrap();
    e.str(&project_id).unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/rpc/batch")
        .header("content-type", "application/cbor")
        .header("accept", "application/cbor")
        .header("authorization", "Bearer admin")
        .body(Body::from(raw))
        .unwrap();
    let response = ctx.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    let key = b"mallowedModels";
    let pos = bytes
        .windows(key.len())
        .position(|w| w == key)
        .expect("allowedModels key present in raw response bytes");
    assert_eq!(
        bytes[pos + key.len()],
        0xf6,
        "allowedModels' wire value must be CBOR null (0xf6), not CBOR's empty array (0x80)"
    );

    let frames: Vec<Value> = Wire::Cbor.decode(&bytes);
    assert!(frames[0]["output"]["allowedModels"].is_null());
}
