// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database integration tests for the cratestack RPC CRUD surface (ADR-0003). Gated behind
//! `it-tests` and `just it-tests` (needs a migrated Postgres via `DATABASE_URL` *and* Redis via
//! `AUTHZ_REDIS_URL`/localhost, both reached by the assembled `build_api_router`).
//!
//! Covers, over the real HTTP RPC transport:
//!   * full create/read/update/delete/list for accounts/projects/api-keys, over JSON **and** CBOR;
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

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use common::{
    MapBearer, Wire, admin_perms, as_json, external_oauth2, rpc_call, token_info, viewer_perms,
};
use cratestack::SqlxIdempotencyStore;
use cratestack::{
    CodecSet, DEFAULT_BODY_LIMIT_BYTES, Json, Value as CValue, ratelimit::RateLimitStore,
};
use cratestack_codec_cbor::CborCodec;
use cratestack_codec_json::JsonCodec;
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::authz::Permission;
use lightbridge_authz_core::config::{BasicAuth, Billing, BillingPlan};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::auth_provider::CratestackAuthProvider;
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let core = core_pool().await;
    let cpool = cratestack_pool().await;
    let cdb = schema::Cratestack::builder(cpool.clone()).build();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()).with_billing(billing()));
    let signing_repo = Arc::new(StoreRepo::new(core.clone()));
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
        build_redis_rate_limit_store(&redis_url(), format!("authz-api-it-{}", cuid2()))
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
        &external_oauth2(),
        bearer,
        issuer.clone(),
        policy_store.clone(),
        refill_service.clone(),
        review_service.clone(),
        budget_repo.clone(),
        cdb,
        core.clone(),
        signing_repo,
        None,
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

/// Decode a JSON RPC success body into `serde_json::Value`.
fn json_body(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("valid json body")
}

/// Create an account over RPC (JSON) and return its id, asserting 200.
async fn create_account(router: &Router, token: &str, _unused: &str) -> String {
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.createAccount",
        Wire::Json,
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

/// Build a typed `CreateProjectInput`. The `Json` columns (`defaultLimits`, `allowedModels`) carry
/// cratestack's own `Value` enum, which serializes *externally tagged* (`{}` → `{"Map":{}}`), so a
/// hand-built `serde_json` body would be rejected as an invalid payload — encoding the generated
/// input type is the only correct wire shape for both JSON and CBOR.
fn project_input(
    id: &str,
    account_id: &str,
    name: &str,
    allowed_models: Option<Vec<&str>>,
) -> schema::inputs::CreateProjectInput {
    schema::inputs::CreateProjectInput {
        id: id.to_string(),
        accountId: account_id.to_string(),
        name: name.to_string(),
        allowedModels: allowed_models.map(|models| {
            Json(CValue::List(
                models
                    .into_iter()
                    .map(|m| CValue::String(m.to_string()))
                    .collect(),
            ))
        }),
        defaultLimits: Json(CValue::Map(std::collections::BTreeMap::new())),
        billingPlan: "free".to_string(),
        billingIdentity: format!("bill-{}", cuid2()),
        projectQuota: None,
    }
}

/// Create a project over RPC (JSON) and return its id, asserting 200.
async fn create_project(router: &Router, token: &str, account_id: &str, name: &str) -> String {
    let project_id = cuid2();
    let input = project_input(&project_id, account_id, name, None);
    let (status, body) = rpc_call(
        router.clone(),
        "model.Project.create",
        Wire::Json,
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

/// Create an api-key over RPC (JSON) and return (key_id, secret), asserting 200.
async fn create_api_key(
    router: &Router,
    token: &str,
    project_id: &str,
    name: &str,
) -> (String, String) {
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.createApiKey",
        Wire::Json,
        &json!({ "args": { "projectId": project_id, "name": name, "billingPlan": "free" } }),
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
// Section 2: full CRUD lifecycle over the RPC router, JSON and CBOR.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn crud_lifecycle_for_all_resources_over_json() {
    let subject = format!("owner-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    // Account: create → get → list → update.
    let billing_id = format!("tenant-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.get",
        Wire::Json,
        &json!({ "id": account_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["id"], account_id);

    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.list",
        Wire::Json,
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

    let new_billing = format!("tenant2-{}", cuid2());
    let (status, body) = rpc_call(
        r.clone(),
        "model.Account.update",
        Wire::Json,
        &json!({ "id": account_id, "patch": { "defaultQuota": new_billing } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["defaultQuota"], new_billing);

    // Project: create → get → list → update.
    let project_id = create_project(r, "admin", &account_id, "proj").await;

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Json,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["id"], project_id);

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.list",
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
        &json!({ "id": key_id, "patch": { "name": "k-renamed" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["name"], "k-renamed");

    let (status, _) = rpc_call(
        r.clone(),
        "model.ApiKey.delete",
        Wire::Json,
        &json!({ "id": key_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Excluded from subsequent reads (soft-delete filter).
    let (status, body) = rpc_call(
        r.clone(),
        "model.ApiKey.list",
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
        &json!({ "args": { "accountId": account_id } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
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
        Wire::Json,
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
        Wire::Json,
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
                Wire::Json,
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
        Wire::Json,
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

    // A project create+get over CBOR too (allowedModels carried as a real list).
    let project_id = cuid2();
    let input = project_input(
        &project_id,
        &account_id,
        "p-cbor",
        Some(vec!["gpt-4.1-mini"]),
    );
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

    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(Wire::Cbor.decode::<Value>(&body)["name"], "p-cbor");

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
/// instead of going through the typed `CreateProjectInput`.
fn raw_cbor_create_project_with_undefined_allowed_models(
    id: &str,
    account_id: &str,
    name: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = minicbor::Encoder::new(&mut out);
    // Seven fields, not six: ADR-0006 moved `billingIdentity` from `Account` onto `Project` and
    // it is non-optional there (matches `codec_undefined_regression_tests.rs`'s
    // `frontend_frame_with_undefined_allowed_models`, the real frontend's own wire shape) -- an
    // omitted `billingIdentity` fails decode with the same generic "invalid request payload" this
    // test is trying to prove is fixed for `allowedModels`, masking the real regression.
    e.map(7).unwrap();
    e.str("id").unwrap();
    e.str(id).unwrap();
    e.str("accountId").unwrap();
    e.str(account_id).unwrap();
    e.str("name").unwrap();
    e.str(name).unwrap();
    e.str("allowedModels").unwrap();
    e.undefined().unwrap();
    e.str("defaultLimits").unwrap();
    e.map(1).unwrap();
    e.str("Map").unwrap();
    e.map(0).unwrap();
    e.str("billingPlan").unwrap();
    e.str("free").unwrap();
    e.str("billingIdentity").unwrap();
    e.str(&format!("bill-{}", cuid2())).unwrap();
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
async fn cbor_project_create_accepts_the_frontends_undefined_allowed_models() {
    // Regression test for the prod-only "invalid_argument" / "invalid request payload" bug: the
    // TS client's `cborg` CBOR encoder (`converse-frontends/packages/authz-rpc/src/codec.ts`)
    // encodes a JS `undefined` property value as the CBOR `undefined` simple value instead of
    // omitting the key. The create-project screen never collects `allowedModels`, so every real
    // `createProject` call on the CBOR path (`authz-api`'s production default) sent exactly this
    // frame and 400'd — `crud_lifecycle_over_cbor` above sidesteps it entirely (its comment notes
    // "allowedModels carried as a real list", never `None`). `codec_undefined_regression_tests.rs`
    // covers `LenientCborCodec` in isolation; this exercises the same frame through the real
    // router + a live DB.
    let subject = format!("owner-cbor-undefined-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let billing_id = format!("tenant-cbor-undefined-{}", cuid2());
    let account_id = create_account(r, "admin", &billing_id).await;

    let project_id = cuid2();
    let raw = raw_cbor_create_project_with_undefined_allowed_models(
        &project_id,
        &account_id,
        "p-cbor-undefined",
    );
    let (status, body) = rpc_call_raw(r, "model.Project.create", Wire::Cbor, raw, "admin").await;
    assert!(
        status.is_success(),
        "cbor project create with undefined allowedModels: {status} {}",
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
        Wire::Json,
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
        let (status, body) = rpc_call(r.clone(), op, Wire::Json, &input, Some("viewer")).await;
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
        Wire::Json,
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
    for (op, input) in [
        (
            "model.Account.update",
            json!({ "id": account_id, "patch": { "defaultQuota": "x" } }),
        ),
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
            json!({ "args": { "projectId": project_id, "name": "k", "billingPlan": "free" } }),
        ),
        (
            "procedure.disableAccount",
            json!({ "args": { "accountId": account_id } }),
        ),
    ] {
        let (status, _) = rpc_call(r.clone(), op, Wire::Json, &input, Some("viewer")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "viewer write `{op}` must be 403"
        );
    }

    // Admin succeeds on a representative mutating op the viewer was denied.
    let (status, _) = rpc_call(
        r.clone(),
        "model.Account.update",
        Wire::Json,
        &json!({ "id": account_id, "patch": { "defaultQuota": format!("t-{}", cuid2()) } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin update must succeed");
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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

    let body = Wire::Json.encode(&json!({ "args": {} }));
    let idem_key = format!("idem-{}", cuid2());

    let send = |body: Vec<u8>, key: String| {
        let router = r.clone();
        async move {
            let request = Request::builder()
                .method("POST")
                .uri("/rpc/procedure.createAccount")
                .header("content-type", "application/json")
                .header("accept", "application/json")
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
        CodecSet::new(CborCodec, JsonCodec),
        CratestackAuthProvider::new(admin_bearer(&subject)),
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
                .header("content-type", "application/json")
                .header("accept", "application/json")
                .header("authorization", "Bearer admin")
                .body(Body::from(serde_json::to_vec(&batch).unwrap()))
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
    let frames: Vec<Value> =
        serde_json::from_slice(&bytes).expect("batch response is a frame array");
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
        Wire::Json,
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
                .header("content-type", "application/json")
                .header("accept", "application/json")
                .header("authorization", "Bearer viewer")
                .body(Body::from(serde_json::to_vec(&batch).unwrap()))
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
    let frames: Vec<Value> =
        serde_json::from_slice(&bytes).expect("batch response is a frame array");
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
    let stranger_input = project_input(&cuid2(), &account_id, "nope", None);
    let (status, body) = rpc_call(
        r.clone(),
        "model.Project.create",
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
        &json!({ "id": first_project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["isDefault"], true);

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.setDefaultProject",
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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

#[tokio::test]
async fn a_second_account_for_the_same_subject_is_refused() {
    // Replaces the old `promoting_a_second_account_to_default_frees_the_old_default_for_deletion`.
    // Since ADR-0006 the account id IS the caller's subject, so there is no second account to
    // promote and no default-account concept to reassign — a repeat createAccount conflicts.
    let subject = format!("owner-single-acct-{}", cuid2());
    let ctx = setup(admin_bearer(&subject)).await;
    let r = &ctx.router;

    let account_id = create_account(r, "admin", "unused").await;

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
        StatusCode::CONFLICT,
        "a subject's second createAccount must conflict, not mint a second account: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.deleteAccountPermanently",
        Wire::Json,
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
        Wire::Json,
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
// Refresh-token session revocation RPC (`revokeOwnSessions` / `revokeSubjectSessions`).
// `exchange_refresh_tokens` carries no foreign keys to accounts/projects, so these tests seed rows
// directly against `ctx.verify` rather than driving a real token-exchange grant (this file's
// router is built with `token_exchange: None`, see `setup`'s `external_oauth2()`).
// ---------------------------------------------------------------------------------------------

/// Inserts one active `exchange_refresh_tokens` row for `subject` and returns its `id`, so a test
/// can assert on which specific rows a revocation touched.
async fn seed_active_session(pool: &sqlx::PgPool, subject: &str) -> String {
    let id = cuid2();
    // `chain_id`/`chain_expires_at` (migration `20260815000001_exchange_refresh_tokens_add_chain`)
    // are `NOT NULL` with no default -- mirrors that migration's own backfill convention for a
    // pre-existing row: a single-member chain (`chain_id = id`) with a cap far enough out that
    // none of these tests' assertions ever race it.
    sqlx::query(
        r#"
        INSERT INTO exchange_refresh_tokens
          (id, subject, account_id, project_id, client_id, token_hash, status, chain_id, chain_expires_at, created_at, expires_at)
        VALUES ($1, $2, $2, $3, 'test-client', $4, 'active', $1, now() + interval '90 days', now(), now() + interval '30 days')
        "#,
    )
    .bind(&id)
    .bind(subject)
    .bind(cuid2())
    .bind(cuid2())
    .execute(pool)
    .await
    .expect("seed active session");
    id
}

/// The `status` of the `exchange_refresh_tokens` row with `id`.
async fn session_status(pool: &sqlx::PgPool, id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM exchange_refresh_tokens WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("session row exists")
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
        Wire::Json,
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
    let parsed = as_json(Wire::Json, &body);
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
        Wire::Json,
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
        Wire::Json,
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
        Wire::Json,
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
    let parsed = as_json(Wire::Json, &body);
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
        Wire::Json,
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
    let parsed = as_json(Wire::Json, &body);
    assert_eq!(parsed["revokedCount"], 0);
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
            Wire::Json,
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
            "{role}'s created account id must equal their own JWT subject"
        );

        let (status, body) = rpc_call(
            ctx.router.clone(),
            "procedure.createAccount",
            Wire::Json,
            &json!({ "args": {} }),
            Some("caller"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{role}'s second createAccount for the same subject must conflict, not mint a \
             second account: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Section 9: the five previously-inert `budget:*` permissions -- direct balance/ledger reads,
// admin grant/revoke, and policy-revision authoring. `budget_grants`/`budget_balances` carry a
// real FK to `accounts`, so every test here seeds an `accounts` row directly (mirroring
// `lightbridge-authz-budget`'s own `budget_repo_grant_tests.rs::insert_account`) rather than
// driving a real `createAccount` RPC call.
// ---------------------------------------------------------------------------------------------

async fn seed_budget_account(pool: &sqlx::PgPool, id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(id)
        .execute(pool)
        .await
        .expect("seed account for budget FK");
}

/// Test 1 (task list): reading your own balance succeeds with the self-scoped permission, and
/// reports the zero-valued default before any grant exists -- then reflects an admin grant made
/// against the same account, proving `getMyBudgetBalance` reads live data, not a cached/stale
/// value.
#[tokio::test]
async fn get_my_budget_balance_reads_own_zero_then_granted_balance() {
    use lightbridge_authz_core::authz::PermissionSet;

    let subject = format!("budget-self-{}", cuid2());
    let admin_subject = format!("budget-self-admin-{}", cuid2());
    let period = "2026-08";
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with(
                "caller",
                token_info(
                    &subject,
                    PermissionSet::from_iter([Permission::BudgetReadOwn]),
                ),
            )
            .with("admin", token_info(&admin_subject, admin_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;
    seed_budget_account(&ctx.verify, &subject).await;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.getMyBudgetBalance",
        Wire::Json,
        &json!({ "args": { "period": period } }),
        Some("caller"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Json, &body);
    assert_eq!(
        parsed["effectiveBudgetMicros"], "0",
        "no grant exists yet this period -- must read as zero, not an error"
    );
    assert_eq!(parsed["budgetAccountId"], subject);

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.grantBudget",
        Wire::Json,
        &json!({ "args": {
            "budgetAccountId": subject,
            "accountId": subject,
            "period": period,
            "amountMicros": "5000000"
        } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.getMyBudgetBalance",
        Wire::Json,
        &json!({ "args": { "period": period } }),
        Some("caller"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed = as_json(Wire::Json, &body);
    assert_eq!(
        parsed["effectiveBudgetMicros"], "5000000",
        "the caller's own read must reflect the admin grant: {parsed}"
    );
}

/// Test 2 (task list): reading ANOTHER subject's balance requires the admin `budget:read`
/// permission -- `budget:read-own` alone must not also unlock it. Proven both ways in one test:
/// the self-scoped-only caller is refused, and an admin succeeds against the exact same input.
#[tokio::test]
async fn get_budget_balance_requires_budget_read_not_merely_read_own() {
    use lightbridge_authz_core::authz::PermissionSet;

    let target = format!("budget-target-{}", cuid2());
    let bystander_subject = format!("budget-bystander-{}", cuid2());
    let admin_subject = format!("budget-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with(
                "self-only",
                token_info(
                    &bystander_subject,
                    PermissionSet::from_iter([Permission::BudgetReadOwn]),
                ),
            )
            .with("admin", token_info(&admin_subject, admin_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;
    seed_budget_account(&ctx.verify, &target).await;

    let (status, _) = rpc_call(
        r.clone(),
        "procedure.getBudgetBalance",
        Wire::Json,
        &json!({ "args": { "budgetAccountId": target, "period": "2026-08" } }),
        Some("self-only"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "budget:read-own must not also grant the admin budget:read capability"
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.getBudgetBalance",
        Wire::Json,
        &json!({ "args": { "budgetAccountId": target, "period": "2026-08" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an admin holding budget:read must succeed against the same input: {}",
        String::from_utf8_lossy(&body)
    );
}

/// Test 3 (task list): the ledger's audit-read path returns entries newest-first and paginates
/// correctly -- proven end-to-end over real HTTP, on top of the exhaustive repo-level pagination
/// coverage in `lightbridge-authz-budget`'s `budget_repo_query_tests.rs`.
#[tokio::test]
async fn list_budget_grants_returns_ledger_history_newest_first_and_paginates() {
    let target = format!("budget-audit-{}", cuid2());
    let admin_subject = format!("budget-audit-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;
    seed_budget_account(&ctx.verify, &target).await;

    for amount in ["1000000", "2000000", "3000000"] {
        let (status, body) = rpc_call(
            r.clone(),
            "procedure.grantBudget",
            Wire::Json,
            &json!({ "args": {
                "budgetAccountId": target,
                "accountId": target,
                "period": "2026-08",
                "amountMicros": amount
            } }),
            Some("admin"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
    }

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.listBudgetGrants",
        Wire::Json,
        &json!({ "args": { "budgetAccountId": target, "limit": 2 } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Json, &body);
    let entries = parsed["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2, "the requested page size must be honored");
    assert_eq!(
        entries[0]["amountMicros"], "3000000",
        "newest grant must be first: {parsed}"
    );
    assert_eq!(entries[1]["amountMicros"], "2000000");
    let cursor = parsed["nextCursor"]
        .as_str()
        .expect("a full page must carry a nextCursor -- there is a third, older grant");

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.listBudgetGrants",
        Wire::Json,
        &json!({ "args": { "budgetAccountId": target, "limit": 2, "before": cursor } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed = as_json(Wire::Json, &body);
    let entries = parsed["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len(),
        1,
        "the second page must return exactly the one remaining, oldest grant"
    );
    assert_eq!(entries[0]["amountMicros"], "1000000");
    assert!(
        parsed["nextCursor"].is_null(),
        "a short page must report no further cursor"
    );
}

/// Test 4 (task list): a direct admin grant appends a ledger row AND updates the balance
/// projection, in the one transactional write path `BudgetRepo::grant` already uses for every
/// other grant source.
#[tokio::test]
async fn grant_budget_appends_ledger_row_and_updates_balance_atomically() {
    let target = format!("budget-grant-{}", cuid2());
    let admin_subject = format!("budget-grant-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;
    seed_budget_account(&ctx.verify, &target).await;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.grantBudget",
        Wire::Json,
        &json!({ "args": {
            "budgetAccountId": target,
            "accountId": target,
            "period": "2026-08",
            "amountMicros": "7000000",
            "reason": "support top-up"
        } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Json, &body);
    assert_eq!(parsed["source"], "admin");
    let grant_id = parsed["id"].as_str().expect("grant id").to_string();

    let (stored_amount,): (i64,) =
        sqlx::query_as("SELECT amount_micros FROM budget_grants WHERE id = $1")
            .bind(&grant_id)
            .fetch_one(&ctx.verify)
            .await
            .expect("the ledger row must exist");
    assert_eq!(stored_amount, 7_000_000);

    let (effective,): (i64,) = sqlx::query_as(
        "SELECT effective_budget_micros FROM budget_balances \
         WHERE budget_account_id = $1 AND period = '2026-08'",
    )
    .bind(&target)
    .fetch_one(&ctx.verify)
    .await
    .expect("the balance projection row must exist in the same transaction as the grant");
    assert_eq!(
        effective, 7_000_000,
        "the balance projection must reflect the grant immediately"
    );
}

/// Test 5 (task list): the compensating-correction counterpart writes a NEW row and leaves the
/// original completely unchanged -- proven directly against the DB (the append-only trigger is
/// what actually enforces this; this asserts the observable effect, not just the response shape).
#[tokio::test]
async fn revoke_budget_grant_writes_a_compensating_row_and_leaves_the_original_unchanged() {
    let target = format!("budget-revoke-{}", cuid2());
    let admin_subject = format!("budget-revoke-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;
    seed_budget_account(&ctx.verify, &target).await;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.grantBudget",
        Wire::Json,
        &json!({ "args": {
            "budgetAccountId": target,
            "accountId": target,
            "period": "2026-08",
            "amountMicros": "4000000"
        } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let grant_id = as_json(Wire::Json, &body)["id"]
        .as_str()
        .expect("grant id")
        .to_string();

    let (amount_before, created_at_before): (i64, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT amount_micros, created_at FROM budget_grants WHERE id = $1")
            .bind(&grant_id)
            .fetch_one(&ctx.verify)
            .await
            .expect("the original row must exist before revocation");

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.revokeBudgetGrant",
        Wire::Json,
        &json!({ "args": { "grantId": grant_id, "reason": "issued in error" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Json, &body);
    assert_eq!(parsed["source"], "correction");
    assert_eq!(parsed["amountMicros"], "-4000000");
    assert_ne!(
        parsed["id"], grant_id,
        "the correction must be a NEW row, not a mutation of the original"
    );

    let (amount_after, created_at_after): (i64, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT amount_micros, created_at FROM budget_grants WHERE id = $1")
            .bind(&grant_id)
            .fetch_one(&ctx.verify)
            .await
            .expect("the original row must still exist, untouched");
    assert_eq!(
        amount_after, amount_before,
        "the append-only DB trigger means the original row's amount must be unchanged"
    );
    assert_eq!(created_at_after, created_at_before);

    let (effective,): (i64,) = sqlx::query_as(
        "SELECT effective_budget_micros FROM budget_balances \
         WHERE budget_account_id = $1 AND period = '2026-08'",
    )
    .bind(&target)
    .fetch_one(&ctx.verify)
    .await
    .expect("balance row must exist");
    assert_eq!(
        effective, 0,
        "the correction must net the original grant out of the effective balance"
    );
}

/// Test 6 (task list): authoring a new budget-policy revision must not activate it -- the
/// previously active revision keeps serving. Complements `lightbridge-authz-budget`'s
/// `policy_store_tests.rs::create_revision_inserts_without_activating`, which asserts the same
/// property directly against `PolicyStore`; this proves the RPC wiring preserves it too.
#[tokio::test]
async fn create_budget_policy_revision_does_not_activate_it() {
    let admin_subject = format!("budget-policy-write-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.getBudgetPolicyStatus",
        Wire::Json,
        &json!({ "args": { "policySetId": "budget-refill" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before = as_json(Wire::Json, &body)["activePolicyRevision"]
        .as_str()
        .expect("active revision string")
        .to_string();

    let rule_data = format!(
        r#"{{
          "policy_revision": "authored-not-activated-{}",
          "rules": [
            {{
              "id": "r1",
              "condition": {{ "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": 9 }},
              "effect": "auto_approve",
              "reason_code": "ok"
            }}
          ],
          "default_effect": "manual_review",
          "default_reason_code": "no"
        }}"#,
        cuid2()
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.createBudgetPolicyRevision",
        Wire::Json,
        &json!({ "args": { "policySetId": "budget-refill", "ruleDataJson": rule_data } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.getBudgetPolicyStatus",
        Wire::Json,
        &json!({ "args": { "policySetId": "budget-refill" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after = as_json(Wire::Json, &body)["activePolicyRevision"]
        .as_str()
        .expect("active revision string")
        .to_string();
    assert_eq!(
        before, after,
        "authoring a new revision must not change what's currently serving"
    );
}

/// Test 7 (task list): a caller holding none of the six wired-up budget permissions
/// (`budget:read-own`/`budget:read`/`budget:audit-read`/`budget:grant`/`budget:revoke`/
/// `budget:policy-write`) is refused 403 on every one of the seven procedures they gate --
/// proves the RBAC gate is actually wired for each, not merely present in `rpc_authorize`'s map.
#[tokio::test]
async fn each_budget_permission_is_actually_enforced() {
    let subject = format!("budget-noperm-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("no-budget-perms", token_info(&subject, viewer_perms())));
    let ctx = setup(bearer).await;
    let r = &ctx.router;
    seed_budget_account(&ctx.verify, &subject).await;

    let cases: [(&str, Value); 7] = [
        (
            "procedure.getMyBudgetBalance",
            json!({ "period": "2026-08" }),
        ),
        ("procedure.listMyBudgetGrants", json!({})),
        (
            "procedure.getBudgetBalance",
            json!({ "budgetAccountId": subject, "period": "2026-08" }),
        ),
        (
            "procedure.listBudgetGrants",
            json!({ "budgetAccountId": subject }),
        ),
        (
            "procedure.grantBudget",
            json!({
                "budgetAccountId": subject,
                "accountId": subject,
                "period": "2026-08",
                "amountMicros": "1000000"
            }),
        ),
        (
            "procedure.revokeBudgetGrant",
            json!({ "grantId": "whatever", "reason": "x" }),
        ),
        (
            "procedure.createBudgetPolicyRevision",
            json!({ "policySetId": "budget-refill", "ruleDataJson": "{}" }),
        ),
    ];

    for (op, args) in cases {
        let (status, _) = rpc_call(
            r.clone(),
            op,
            Wire::Json,
            &json!({ "args": args }),
            Some("no-budget-perms"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{op} must be 403 for a caller holding none of the budget:* permissions"
        );
    }
}
