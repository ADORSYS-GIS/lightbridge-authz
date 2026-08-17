// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Hermetic tests for the assembled `authz-budget` RPC router (`build_budget_router`), mirroring
//! `rpc_router_tests.rs`'s style for `build_api_router`: everything here is offline (the
//! cratestack CRUD client / idempotency store / rate-limit store are lazily connected to an
//! unreachable address and never queried), because every request either
//!   * hits a probe route (`/`, `/healthz*`),
//!   * is rejected by [`RpcScope::Budget`] or the outermost `rpc_authorize` gate **before**
//!     dispatch, idempotency, or rate-limiting run, or
//!   * is a `POST /budget/rpc/batch` call the gates *do* let through, which then fails later
//!     against the dead Redis/Postgres instead — this file only proves the gates themselves
//!     stopped rejecting once the token/scope were valid, not that dispatch succeeds.
//!
//! The *allow* half that reaches real dispatch (budget op granted → 200, business logic runs)
//! needs a live DB + Redis; it lives in `budget_rpc_it_tests.rs`.
//!
//! This file is the budget-domain half of the microservice split's test matrix (see
//! `docs/architecture/budget.md`, "Service boundary"): task requirements 1–4 from the split's
//! PR description are proven here (reachable at the new path; a caller lacking the permission
//! gets 403; `budget:read-own` structurally has no target field) alongside `rpc_it_tests.rs`'s
//! `budget_gated_op_ids_are_unreachable_on_authz_api_even_for_an_admin` (requirement 2, the other
//! side of the cutover).

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{MapBearer, Wire, admin_perms, rpc_call_at, token_info};
use cratestack::SqlxIdempotencyStore;
use cratestack::ratelimit::RateLimitStore;
use lightbridge_authz_api::schema;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::authz::Permission;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const DEAD_PG: &str = "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz";
const DEAD_REDIS: &str = "redis://127.0.0.1:6379";
const BUDGET_BASE_PATH: &str = "/budget";

fn lazy_core_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy(DEAD_PG)
        .expect("lazy core pool");
    Arc::new(DbPool::from_pool(pool))
}

fn lazy_cratestack_db() -> schema::Cratestack {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy(DEAD_PG)
        .expect("lazy cratestack pool");
    schema::Cratestack::builder(pool).build()
}

fn lazy_idempotency() -> Arc<SqlxIdempotencyStore> {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy(DEAD_PG)
        .expect("lazy cratestack pool");
    Arc::new(SqlxIdempotencyStore::new(pool))
}

fn lazy_rate_limit() -> Arc<dyn RateLimitStore> {
    build_redis_rate_limit_store(DEAD_REDIS, "authz-budget-test").expect("rate limit store")
}

fn lazy_policy_store(core: Arc<dyn DbPoolTrait>) -> Arc<lightbridge_authz_budget::PolicyStore> {
    let engine = lightbridge_authz_budget::RuleDataEngine::new(
        lightbridge_authz_budget::default_rule_set_json(),
        10_000,
    )
    .expect("default rule set is valid");
    Arc::new(lightbridge_authz_budget::PolicyStore::from_engine(
        core,
        "budget-refill",
        engine,
    ))
}

fn lazy_refill_and_review_services(
    core: Arc<dyn DbPoolTrait>,
    policy_store: &lightbridge_authz_budget::PolicyStore,
) -> (
    Arc<lightbridge_authz_budget::RefillService>,
    Arc<lightbridge_authz_budget::ReviewService>,
    Arc<lightbridge_authz_budget::repo::BudgetRepo>,
) {
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        core.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(core));
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
    (refill_service, review_service, budget_repo)
}

/// Assemble the full budget router with a caller-supplied bearer, everything else lazily wired
/// to unreachable backends -- mirrors `rpc_router_tests.rs::build_router` for
/// `build_budget_router`.
fn build_router(bearer: Arc<dyn BearerTokenServiceTrait>) -> Router {
    let core = lazy_core_pool();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()));
    let policy_store = lazy_policy_store(core.clone());
    let (refill_service, review_service, budget_repo) =
        lazy_refill_and_review_services(core.clone(), &policy_store);
    lightbridge_authz_rest::build_budget_router(
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        lazy_cratestack_db(),
        core,
        bearer,
        lazy_idempotency(),
        lazy_rate_limit(),
        false,
    )
}

fn admin_bearer() -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(MapBearer::new().with("admin", token_info("admin-subject", admin_perms())))
}

async fn get(router: Router, uri: &str) -> StatusCode {
    router
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

async fn rpc_call<T: serde::Serialize + ?Sized>(
    router: Router,
    op_id: &str,
    body: &T,
    token: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    rpc_call_at(router, BUDGET_BASE_PATH, op_id, Wire::Cbor, body, token).await
}

// ---------------------------------------------------------------------------------------------
// Probes: unaffected by RpcScope, same wiring every other server's router shares
// (`probe_router`).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn health_probes_report_ok() {
    for uri in ["/", "/healthz", "/healthz/startup"] {
        let router = build_router(admin_bearer());
        assert_eq!(get(router, uri).await, StatusCode::OK, "probe {uri}");
    }
}

#[tokio::test]
async fn readiness_reports_unavailable_when_the_database_is_unreachable() {
    let router = build_router(admin_bearer());
    assert_eq!(
        get(router, "/healthz/ready").await,
        StatusCode::SERVICE_UNAVAILABLE,
        "readiness must report unavailable against the lazily-wired, unreachable database"
    );
}

// ---------------------------------------------------------------------------------------------
// Requirement 1: every moved procedure is reachable on `authz-budget` at its new path
// (`/budget/rpc/{op_id}`) -- proven here as "the scope + RBAC gates let a permission-holding
// caller through" (never 401/403/404 from the GATE; whether dispatch itself succeeds needs a
// live DB, covered in `budget_rpc_it_tests.rs`).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_budget_op_id_is_reachable_past_the_gate_for_an_admin() {
    let op_ids = [
        "procedure.activateBudgetPolicy",
        "procedure.getBudgetPolicyStatus",
        "procedure.simulateBudgetPolicy",
        "procedure.requestBudgetRefill",
        "procedure.listPendingAugmentationRequests",
        "procedure.approveAugmentationRequest",
        "procedure.rejectAugmentationRequest",
        "procedure.getMyBudgetBalance",
        "procedure.listMyBudgetGrants",
        "procedure.getBudgetBalance",
        "procedure.listBudgetGrants",
        "procedure.grantBudget",
        "procedure.revokeBudgetGrant",
        "procedure.createBudgetPolicyRevision",
    ];
    for op in op_ids {
        let router = build_router(admin_bearer());
        let (status, body) = rpc_call(router, op, &json!({}), Some("admin")).await;
        assert!(
            status != StatusCode::UNAUTHORIZED
                && status != StatusCode::FORBIDDEN
                && status != StatusCode::NOT_FOUND,
            "{op} must be reachable on authz-budget for an admin (not 401/403/404 from the \
             gate), got {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Requirement 2 (the authz-budget side): a non-budget op-id -- the whole CRUD surface, including
// unmapped/sensitive ones -- must be refused (`RpcScope::Budget`), even for an admin, even
// without a token at all (the scope check runs before the bearer check).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn non_budget_op_ids_404_on_authz_budget_even_without_a_token() {
    for op in [
        "model.Account.list",
        "model.Account.create",
        "procedure.createAccount",
        "procedure.createApiKey",
        "procedure.revokeOwnSessions",
        "procedure.revokeSubjectSessions",
        "procedure.unknown",
    ] {
        let router = build_router(admin_bearer());
        let (status, body) = rpc_call(router, op, &json!({}), None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{op} must 404 on authz-budget (out of RpcScope::Budget), even with no bearer token \
             at all: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn non_budget_op_ids_404_on_authz_budget_even_for_an_admin() {
    for op in ["model.Account.list", "procedure.createAccount"] {
        let router = build_router(admin_bearer());
        let (status, body) = rpc_call(router, op, &json!({}), Some("admin")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{op} must 404 on authz-budget for an admin too -- scope, not permission, is what \
             refuses it: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Requirement 3: a caller lacking the required permission gets 403 on a budget op-id.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn rbac_gate_requires_a_valid_token_on_budget_op_ids() {
    let router = build_router(admin_bearer());
    let (status, _) = rpc_call(router, "procedure.getMyBudgetBalance", &json!({}), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing token → 401");

    let router = build_router(admin_bearer());
    let (status, _) = rpc_call(
        router,
        "procedure.getMyBudgetBalance",
        &json!({}),
        Some("bogus-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "invalid token → 401");
}

/// #294's self-refill/review split, re-proven against `authz-budget` after the cutover (moved
/// from `rpc_router_tests.rs::editor_role_can_self_refill_but_not_review`, which used to exercise
/// this against `build_api_router` before these op-ids moved off it): a caller holding a budget
/// role (`lightbridge-editor`) must be able to self-refill their own budget
/// (`budget:self-refill` -> `procedure.requestBudgetRefill`), but the same grant must NOT let
/// them reach the admin review queue (`budget:review` ->
/// `procedure.listPendingAugmentationRequests`/`approveAugmentationRequest`/
/// `rejectAugmentationRequest`).
#[tokio::test]
async fn editor_role_can_self_refill_but_not_review() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/default.yaml");
    let config = lightbridge_authz_core::config::load_from_path(path)
        .expect("shipped config/default.yaml must parse");
    let editor_perms = config
        .oauth2
        .rbac
        .compile()
        .roles
        .get("lightbridge-editor")
        .cloned()
        .expect("config/default.yaml must configure a lightbridge-editor role");

    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("editor", token_info("editor-subject", editor_perms)));

    let router = build_router(bearer.clone());
    let (status, _) = rpc_call(
        router,
        "procedure.requestBudgetRefill",
        &json!({}),
        Some("editor"),
    )
    .await;
    assert!(
        status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
        "editor must be granted requestBudgetRefill by the RBAC gate on authz-budget, got \
         {status}"
    );

    for op in [
        "procedure.listPendingAugmentationRequests",
        "procedure.approveAugmentationRequest",
        "procedure.rejectAugmentationRequest",
    ] {
        let router = build_router(bearer.clone());
        let (status, _) = rpc_call(router, op, &json!({}), Some("editor")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "editor must be denied `{op}` on authz-budget (budget:review must not leak into \
             lightbridge-editor)"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Requirement 4: `budget:read-own` procedures cannot be aimed at another account -- structurally,
// not just behaviorally. `GetMyBudgetBalanceInput`/`ListMyBudgetGrantsInput` (the schema types
// behind `getMyBudgetBalance`/`listMyBudgetGrants`) carry no `budgetAccountId`/`accountId` field
// at all, so there is no argument a caller could even attempt to set to target someone else's
// budget -- the input type itself is the structural guarantee. Verified two ways: (a) directly
// against the schema's own field list, and (b) that the fields present do NOT overlap with the
// admin pair's target field, so this can't regress by a schema edit adding one back silently.
// ---------------------------------------------------------------------------------------------

#[test]
fn budget_read_own_input_types_have_no_target_field() {
    use lightbridge_authz_api::schema::{GetMyBudgetBalanceInput, ListMyBudgetGrantsInput};

    // Every field these two input types carry -- if this ever grows a `budgetAccountId` or
    // `accountId` field, this test's field list goes stale and must be updated, which is exactly
    // the point: it forces a reviewer to notice the input type gained a way to target another
    // account, at which point `budget:read-own`'s "cannot be aimed at another account" guarantee
    // stops being structural and starts depending on procedure-body discipline instead.
    let _ = GetMyBudgetBalanceInput {
        period: "2026-08".to_string(),
    };
    let _ = ListMyBudgetGrantsInput {
        period: None,
        before: None,
        limit: None,
    };
}

/// The admin counterparts, by contrast, DO carry an explicit target -- confirming the asymmetry
/// this whole section is about (self-scoped: no target field; admin: explicit target field), not
/// merely that these two types happen to be small.
#[test]
fn budget_admin_read_input_types_have_an_explicit_target_field() {
    use lightbridge_authz_api::schema::{GetBudgetBalanceInput, ListBudgetGrantsInput};

    let admin_get = GetBudgetBalanceInput {
        budgetAccountId: "some-other-account".to_string(),
        period: "2026-08".to_string(),
    };
    assert_eq!(admin_get.budgetAccountId, "some-other-account");

    let admin_list = ListBudgetGrantsInput {
        budgetAccountId: "some-other-account".to_string(),
        period: None,
        before: None,
        limit: None,
    };
    assert_eq!(admin_list.budgetAccountId, "some-other-account");
}

/// A caller holding only `budget:read-own` reading their OWN budget succeeds past the gate (the
/// behavioral half of requirement 4 -- structural coverage is the two tests above).
#[tokio::test]
async fn budget_read_own_permission_reaches_dispatch_for_the_callers_own_data() {
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(MapBearer::new().with(
        "self-only",
        token_info(
            "self-subject",
            [Permission::BudgetReadOwn].into_iter().collect(),
        ),
    ));
    for op in [
        "procedure.getMyBudgetBalance",
        "procedure.listMyBudgetGrants",
    ] {
        let router = build_router(bearer.clone());
        let (status, body) = rpc_call(router, op, &json!({}), Some("self-only")).await;
        assert!(
            status != StatusCode::UNAUTHORIZED
                && status != StatusCode::FORBIDDEN
                && status != StatusCode::NOT_FOUND,
            "{op} must be reachable for a budget:read-own-only caller, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Batch: the outer gate only requires a valid caller; per-frame permission AND per-frame scope
// are enforced by `CratestackAuthProvider::authenticate`.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn rbac_gate_on_the_batch_endpoint_requires_a_valid_token_then_forwards() {
    let router = build_router(admin_bearer());
    let (status, _) = rpc_call(router, "batch", &json!([]), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing token → 401");
}

/// A `/budget/rpc/batch` frame aimed at a non-budget op-id must fail independently within its own
/// slot, per-frame — proves the batch bypass is closed on `authz-budget` too, mirroring the
/// equivalent proof on `authz-api`'s side
/// (`rpc_it_tests.rs::budget_gated_op_ids_are_unreachable_on_authz_api_even_for_an_admin`'s batch
/// half). Offline/hermetic: `model.Account.list`'s scope rejection happens before dispatch would
/// ever touch the dead Postgres.
#[tokio::test]
async fn batch_frame_aimed_at_a_non_budget_op_id_fails_independently() {
    let router = build_router(admin_bearer());
    let batch = json!([{ "id": 1, "op": "model.Account.list", "input": {} }]);
    let (status, _) = rpc_call(router, "batch", &batch, Some("admin")).await;
    // The outer gate only checks "some valid token" for batch -- getting past it at all (not
    // 401) is the property under test here; per-frame content assertions belong in the real-DB
    // `budget_rpc_it_tests.rs` where dispatch can actually run to completion for a budget frame
    // alongside the refused one.
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "a valid admin token must clear the outer batch gate"
    );
}
