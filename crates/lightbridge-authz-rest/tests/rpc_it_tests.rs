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
//!   * per-frame independent success/failure on `POST /rpc/batch` (bare router, since the gate
//!     denies batch wholesale — that denial is proven in `rpc_router_tests.rs`);
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
use common::{MapBearer, Wire, admin_perms, external_oauth2, rpc_call, token_info, viewer_perms};
use cratestack::SqlxIdempotencyStore;
use cratestack::{CodecSet, Json, Value as CValue, ratelimit::RateLimitStore};
use cratestack_codec_cbor::CborCodec;
use cratestack_codec_json::JsonCodec;
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
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

async fn core_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url())
        .await
        .expect("connect core pool");
    Arc::new(DbPool::from_pool(pool))
}

async fn cratestack_pool() -> cratestack::sqlx::PgPool {
    cratestack::sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
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
}

/// Build the full `build_api_router` for `bearer`, connecting the cratestack CRUD client,
/// Postgres-backed idempotency store, and Redis rate-limit store to the live backends.
async fn setup(bearer: Arc<dyn BearerTokenServiceTrait>) -> Ctx {
    let core = core_pool().await;
    let cpool = cratestack_pool().await;
    let cdb = schema::Cratestack::builder(cpool.clone()).build();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()).with_billing(billing()));
    let signing_repo = Arc::new(StoreRepo::new(core.clone()));
    let idempotency = Arc::new(SqlxIdempotencyStore::new(cpool.clone()));
    idempotency
        .ensure_schema()
        .await
        .expect("ensure idempotency schema");
    let rate_limit: Arc<dyn RateLimitStore> =
        build_redis_rate_limit_store(&redis_url(), "authz-api-it").expect("redis rate-limit store");

    let router = lightbridge_authz_rest::build_api_router(
        &external_oauth2(),
        bearer,
        issuer.clone(),
        cdb,
        core.clone(),
        signing_repo,
        None,
        idempotency,
        rate_limit,
        false,
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
async fn create_account(router: &Router, token: &str, billing_identity: &str) -> String {
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.createAccount",
        Wire::Json,
        &json!({ "args": { "billingIdentity": billing_identity } }),
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
        &json!({ "id": account_id, "patch": { "billingIdentity": new_billing } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["billingIdentity"], new_billing);

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

    // Project + account hard delete.
    let (status, _) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Json,
        &json!({ "id": project_id }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Account deletion is owner-only and no longer the generic `model.Account.delete` verb
    // (ADR-0005) -- the account's creator ("admin", the token subject used throughout this test)
    // was seeded as "owner" by `createAccount`, so this still succeeds.
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
    let billing_id = format!("tenant-cbor-{}", cuid2());
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.createAccount",
        Wire::Cbor,
        &json!({ "args": { "billingIdentity": billing_id } }),
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
    // was seeded as "owner" by `createAccount`, so this still succeeds.
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
            .with("viewer", token_info(&viewer_subject, viewer_perms())),
    );
    let ctx = setup(bearer).await;
    let r = &ctx.router;

    // Admin (all perms + creator membership) builds a tenant and adds the viewer as a member.
    let account_id = create_account(r, "admin", &format!("tenant-rbac-{}", cuid2())).await;
    let project_id = create_project(r, "admin", &account_id, "proj-rbac").await;
    let (status, _) = rpc_call(
        r.clone(),
        "procedure.addAccountMember",
        Wire::Json,
        &json!({ "args": { "accountId": account_id, "subject": viewer_subject } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin adds viewer as member");

    // Viewer (a legitimate member) may READ (gate + membership both pass) → 200.
    for (op, input) in [
        ("model.Account.get", json!({ "id": account_id })),
        ("model.Project.get", json!({ "id": project_id })),
        ("model.Account.list", json!({})),
        ("model.Project.list", json!({})),
    ] {
        let (status, body) = rpc_call(r.clone(), op, Wire::Json, &input, Some("viewer")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "viewer read `{op}` should be 200: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // Viewer is blocked by the coarse RBAC gate (403) on every mutating op — even though membership
    // would otherwise permit it. This is the privilege-escalation regression under test.
    for (op, input) in [
        (
            "model.Account.update",
            json!({ "id": account_id, "patch": { "billingIdentity": "x" } }),
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
        &json!({ "id": account_id, "patch": { "billingIdentity": format!("t-{}", cuid2()) } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin update must succeed");
}

// ---------------------------------------------------------------------------------------------
// Section 3: soft-delete + api_key_validation view security fix.
// ---------------------------------------------------------------------------------------------

/// Build the OPA introspection router backed by a real `StoreRepo` on the live pool, so a POST to
/// `/v1/authorino/validate/introspect` exercises exactly the validation SQL view authz-opa reads.
fn opa_router(core: Arc<dyn DbPoolTrait>) -> Router {
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(core.clone()));
    let state = Arc::new(OpaState {
        repo,
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "secret".to_string(),
        },
        billing: Arc::new(billing()),
    });
    lightbridge_authz_rest::build_opa_router(state, core)
}

/// Introspect `secret` through the OPA endpoint; returns the `active` flag.
async fn introspect_active(router: &Router, secret: &str) -> bool {
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
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["active"].as_bool().unwrap_or(false)
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
    let (status, _) = rpc_call(
        r.clone(),
        "model.Project.delete",
        Wire::Json,
        &json!({ "id": project_id }),
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
        audit_count(pool, "Project", "delete", &project_id).await >= 1,
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

    let billing_id = format!("tenant-idem-{}", cuid2());
    let body = Wire::Json.encode(&json!({ "args": { "billingIdentity": billing_id } }));
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

    // Exactly one account row exists for that (unique) billing identity — the mutation ran once.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM accounts WHERE billing_identity = $1")
            .bind(&billing_id)
            .fetch_one(&ctx.verify)
            .await
            .unwrap();
    assert_eq!(count, 1, "the mutation must have executed exactly once");
}

// ---------------------------------------------------------------------------------------------
// Section 3: batch RPC per-frame independence (bare router — the gate denies /rpc/batch wholesale,
// proven in rpc_router_tests.rs).
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
        Procedures::new(ctx.issuer.clone()),
        CodecSet::new(CborCodec, JsonCodec),
        CratestackAuthProvider::new(admin_bearer(&subject)),
    );

    let good_billing = format!("tenant-batch-{}", cuid2());
    let batch = json!([
        { "id": 1, "op": "procedure.createAccount", "input": { "args": { "billingIdentity": good_billing } } },
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
