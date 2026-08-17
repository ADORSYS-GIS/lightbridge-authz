// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database integration tests for `authz-budget` (`build_budget_router`), gated behind
//! `it-tests` and run with real Postgres + Redis (same requirements as `rpc_it_tests.rs`).
//!
//! This is where the budget-domain HTTP surface's real-dispatch coverage lives after the
//! budget-domain microservice split (see `docs/architecture/budget.md`, "Service boundary"):
//! everything here used to be "Section 9" of `rpc_it_tests.rs`, built against
//! `build_api_router`; it now runs against `build_budget_router` at `/budget/rpc/{op_id}`
//! instead, since that op-id set is no longer reachable on `authz-api` at all (see
//! `rpc_it_tests.rs::budget_gated_op_ids_are_unreachable_on_authz_api_even_for_an_admin` for the
//! cutover proof on the other side).
//!
//! Covers, over the real HTTP RPC transport:
//!   * every moved procedure is reachable at its new path;
//!   * the self/admin permission split (`budget:read-own` vs `budget:read`/`budget:audit-read`);
//!   * the append-only ledger invariant survives through the new service (a correction appends, the
//!     original row is unchanged);
//!   * authoring a policy revision does not activate it;
//!   * every wired-up `budget:*` permission is actually enforced, not merely mapped;
//!   * a caller-facing non-budget op-id (the CRUD surface) is refused on this service too
//!     (`RpcScope::Budget`'s other half);
//!   * spend-unavailable (no usage service reachable) still routes self-service refill to
//!     `pending_review`, never `auto_approve` (CLAUDE.md's fail-closed-dependency rule, proven
//!     through the real HTTP surface this time, not just `RefillService` directly).
#![cfg(feature = "it-tests")]

mod common;

use std::sync::Arc;

use axum::Router;
use common::{MapBearer, Wire, admin_perms, as_json, rpc_call_at, token_info, viewer_perms};
use cratestack::SqlxIdempotencyStore;
use cratestack::ratelimit::RateLimitStore;
use lightbridge_authz_api::schema;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::authz::Permission;
use lightbridge_authz_core::config::{Billing, UsageServiceClient};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

/// Every route on `authz-budget` is mounted under this fixed prefix (`build_budget_router`) —
/// see `config::BudgetServer`'s doc comment for why it is not configurable like
/// `ApiServer.rpc_base_path`.
const BUDGET_BASE_PATH: &str = "/budget";

async fn rpc_call<T: serde::Serialize + ?Sized>(
    router: Router,
    op_id: &str,
    wire: Wire,
    body: &T,
    token: Option<&str>,
) -> (axum::http::StatusCode, Vec<u8>) {
    rpc_call_at(router, BUDGET_BASE_PATH, op_id, wire, body, token).await
}

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for it-tests (just it-tests)")
}

fn redis_url() -> String {
    std::env::var("AUTHZ_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

fn billing() -> Billing {
    Billing { plans: vec![] }
}

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

struct Ctx {
    router: Router,
    verify: sqlx::PgPool,
}

// Mirrors `rpc_it_tests.rs`'s identical guard: `SqlxIdempotencyStore::ensure_schema()` races under
// `cargo test`'s default parallelism when every test in this binary calls it from `setup()`
// against the same fresh database.
static IDEMPOTENCY_SCHEMA_READY: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// Build the full `build_budget_router` for `bearer`, connecting the cratestack CRUD client,
/// Postgres-backed idempotency store, and Redis rate-limit store to the live backends -- the same
/// shape `rpc_it_tests.rs::setup` builds for `build_api_router`, pointed at the budget-only router
/// instead. `usage_service` lets each test opt into a spend reader (`None` -> `UnavailableSpendReader`,
/// same fail-closed default `start_budget_server` uses when unconfigured).
async fn setup(
    bearer: Arc<dyn BearerTokenServiceTrait>,
    usage_service: Option<UsageServiceClient>,
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
    // Own namespace per `setup()` call, same reasoning as `rpc_it_tests.rs::setup`'s identical
    // comment: every test authenticates with a fixed literal bearer token, so a shared prefix
    // would put every concurrently-running test's calls into the same token bucket.
    let rate_limit: Arc<dyn RateLimitStore> =
        build_redis_rate_limit_store(&redis_url(), format!("authz-budget-it-{}", cuid2()))
            .expect("redis rate-limit store");

    let policy_store = Arc::new(
        lightbridge_authz_budget::PolicyStore::load_active_from_db(
            core.clone(),
            "budget-refill",
            10_000,
        )
        .await
        .expect("migrations seed an active budget-refill revision"),
    );

    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        core.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
        core.clone(),
    ));
    let policy_engine: Arc<dyn lightbridge_authz_budget::PolicyEngine> = policy_store.engine();
    let spend_reader: Arc<dyn lightbridge_authz_budget::SpendReader> = match usage_service {
        Some(usage_service) => Arc::new(
            lightbridge_authz_budget::UsageServiceSpendReader::new(
                usage_service.base_url,
                usage_service.insecure_skip_verify,
                usage_service.ca_bundle_path.as_deref(),
                std::time::Duration::from_millis(usage_service.timeout_ms),
            )
            .expect("valid usage-service spend reader config"),
        ),
        None => Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
    };
    let refill_service = Arc::new(lightbridge_authz_budget::RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_engine,
        spend_reader,
    ));
    let review_service = Arc::new(lightbridge_authz_budget::ReviewService::new(
        budget_repo.clone(),
        augmentation_repo,
    ));

    let router = lightbridge_authz_rest::build_budget_router(
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        cdb,
        core.clone(),
        bearer,
        idempotency,
        rate_limit,
        false,
    );

    let verify = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url())
        .await
        .expect("connect verify pool");

    Ctx { router, verify }
}

fn admin_bearer(subject: &str) -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(MapBearer::new().with("admin", token_info(subject, admin_perms())))
}

async fn seed_budget_account(pool: &sqlx::PgPool, id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(id)
        .execute(pool)
        .await
        .expect("seed account for budget FK");
}

// ---------------------------------------------------------------------------------------------
// Reachability: every moved procedure is dispatchable at its new path (`/budget/rpc/{op_id}`).
// ---------------------------------------------------------------------------------------------

/// Every one of the 14 moved procedures reaches real dispatch on `authz-budget` for an admin
/// bearer — proven by asserting the response is never `401`/`403`/`404` (some legitimately return
/// a different error, e.g. `revokeBudgetGrant` on a nonexistent `grantId`, which is a business
/// error, not an authorization/routing one).
#[tokio::test]
async fn every_moved_procedure_is_reachable_on_authz_budget() {
    let subject = format!("budget-reachable-{}", cuid2());
    let ctx = setup(admin_bearer(&subject), None).await;
    seed_budget_account(&ctx.verify, &subject).await;

    let cases: [(&str, Value); 14] = [
        (
            "procedure.activateBudgetPolicy",
            json!({ "policySetId": "budget-refill", "revisionId": "budget-refill-v1" }),
        ),
        (
            "procedure.getBudgetPolicyStatus",
            json!({ "policySetId": "budget-refill" }),
        ),
        (
            "procedure.simulateBudgetPolicy",
            json!({
                "ruleDataJson": "{\"policy_revision\":\"sim\",\"rules\":[],\"default_effect\":\"manual_review\",\"default_reason_code\":\"x\"}",
                "scenarioJson": "{}",
                "requestedAmountMicros": "1000000"
            }),
        ),
        (
            "procedure.requestBudgetRefill",
            json!({ "budgetAccountId": subject, "accountId": subject, "period": "2026-08" }),
        ),
        (
            "procedure.listPendingAugmentationRequests",
            json!({ "budgetAccountId": subject }),
        ),
        (
            "procedure.approveAugmentationRequest",
            json!({ "requestId": "nonexistent" }),
        ),
        (
            "procedure.rejectAugmentationRequest",
            json!({ "requestId": "nonexistent", "reason": "x" }),
        ),
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
            json!({ "grantId": "nonexistent", "reason": "x" }),
        ),
        (
            "procedure.createBudgetPolicyRevision",
            json!({
                "policySetId": "budget-refill",
                "ruleDataJson": "{\"policy_revision\":\"reach\",\"rules\":[],\"default_effect\":\"manual_review\",\"default_reason_code\":\"x\"}"
            }),
        ),
    ];

    for (op, args) in cases {
        let (status, body) = rpc_call(
            ctx.router.clone(),
            op,
            Wire::Json,
            &json!({ "args": args }),
            Some("admin"),
        )
        .await;
        assert!(
            status != axum::http::StatusCode::UNAUTHORIZED
                && status != axum::http::StatusCode::FORBIDDEN,
            "{op} must be reachable (not unauthorized/forbidden) on authz-budget, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
        // `404` alone is ambiguous here: `RpcScope`'s routing refusal ("unknown RPC op") and a
        // legitimate domain-level "no such row" (e.g. `approveAugmentationRequest`/
        // `revokeBudgetGrant` against the deliberately-nonexistent ids above) both surface as
        // `404`. Only the former means "not reachable" -- distinguish by the error message rather
        // than treating every 404 as a routing failure.
        if status == axum::http::StatusCode::NOT_FOUND {
            let message = String::from_utf8_lossy(&body);
            assert!(
                !message.contains("unknown RPC op"),
                "{op} must be routed to real dispatch on authz-budget, not refused by RpcScope: {message}"
            );
        }
    }
}

/// The other half of `RpcScope::Budget`: a CRUD op-id (never budget-gated) must be refused on
/// `authz-budget` too — this service is budget-only, not "budget plus everything authz-api
/// forgot to gate".
#[tokio::test]
async fn non_budget_op_ids_are_unreachable_on_authz_budget() {
    let subject = format!("budget-scope-{}", cuid2());
    let ctx = setup(admin_bearer(&subject), None).await;

    for op in [
        "model.Account.list",
        "procedure.createAccount",
        "procedure.revokeOwnSessions",
    ] {
        let (status, body) = rpc_call(
            ctx.router.clone(),
            op,
            Wire::Json,
            &json!({}),
            Some("admin"),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "{op} is not a budget:* op-id and must be unreachable on authz-budget: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The following tests are the migrated "Section 9" of `rpc_it_tests.rs` (moved here as part of
// the budget-domain microservice split), unchanged in behavior, exercised through
// `build_budget_router` at `/budget/rpc/{op_id}` instead of `build_api_router`.
// ---------------------------------------------------------------------------------------------

/// Reading your own balance succeeds with the self-scoped permission, and reports the zero-valued
/// default before any grant exists -- then reflects an admin grant made against the same account,
/// proving `getMyBudgetBalance` reads live data, not a cached/stale value.
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
    let ctx = setup(bearer, None).await;
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
        axum::http::StatusCode::OK,
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
        axum::http::StatusCode::OK,
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
    assert_eq!(status, axum::http::StatusCode::OK);
    let parsed = as_json(Wire::Json, &body);
    assert_eq!(
        parsed["effectiveBudgetMicros"], "5000000",
        "the caller's own read must reflect the admin grant: {parsed}"
    );
}

/// Reading ANOTHER subject's balance requires the admin `budget:read` permission --
/// `budget:read-own` alone must not also unlock it. Proven both ways in one test: the
/// self-scoped-only caller is refused, and an admin succeeds against the exact same input.
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
    let ctx = setup(bearer, None).await;
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
        axum::http::StatusCode::FORBIDDEN,
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
        axum::http::StatusCode::OK,
        "an admin holding budget:read must succeed against the same input: {}",
        String::from_utf8_lossy(&body)
    );
}

/// The ledger's audit-read path returns entries newest-first and paginates correctly -- proven
/// end-to-end over real HTTP, on top of the exhaustive repo-level pagination coverage in
/// `lightbridge-authz-budget`'s `budget_repo_query_tests.rs`.
#[tokio::test]
async fn list_budget_grants_returns_ledger_history_newest_first_and_paginates() {
    let target = format!("budget-audit-{}", cuid2());
    let admin_subject = format!("budget-audit-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer, None).await;
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
            axum::http::StatusCode::OK,
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
        axum::http::StatusCode::OK,
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
    assert_eq!(status, axum::http::StatusCode::OK);
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

/// A direct admin grant appends a ledger row AND updates the balance projection, in the one
/// transactional write path `BudgetRepo::grant` already uses for every other grant source.
#[tokio::test]
async fn grant_budget_appends_ledger_row_and_updates_balance_atomically() {
    let target = format!("budget-grant-{}", cuid2());
    let admin_subject = format!("budget-grant-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer, None).await;
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
        axum::http::StatusCode::OK,
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

/// The ledger's append-only invariant, proven through `authz-budget`: the compensating-correction
/// counterpart writes a NEW row and leaves the original completely unchanged -- asserted directly
/// against the DB (the append-only trigger is what actually enforces this; this checks the
/// observable effect, not just the response shape).
#[tokio::test]
async fn revoke_budget_grant_writes_a_compensating_row_and_leaves_the_original_unchanged() {
    let target = format!("budget-revoke-{}", cuid2());
    let admin_subject = format!("budget-revoke-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer, None).await;
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
    assert_eq!(status, axum::http::StatusCode::OK);
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
        axum::http::StatusCode::OK,
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

/// Authoring a new budget-policy revision must not activate it -- the previously active revision
/// keeps serving. Complements `lightbridge-authz-budget`'s
/// `policy_store_tests.rs::create_revision_inserts_without_activating`, which asserts the same
/// property directly against `PolicyStore`; this proves the RPC wiring on `authz-budget`
/// preserves it too.
#[tokio::test]
async fn create_budget_policy_revision_does_not_activate_it() {
    let admin_subject = format!("budget-policy-write-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("admin", token_info(&admin_subject, admin_perms())));
    let ctx = setup(bearer, None).await;
    let r = &ctx.router;

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.getBudgetPolicyStatus",
        Wire::Json,
        &json!({ "args": { "policySetId": "budget-refill" } }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
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
        axum::http::StatusCode::OK,
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
    assert_eq!(status, axum::http::StatusCode::OK);
    let after = as_json(Wire::Json, &body)["activePolicyRevision"]
        .as_str()
        .expect("active revision string")
        .to_string();
    assert_eq!(
        before, after,
        "authoring a new revision must not change what's currently serving"
    );
}

/// A caller holding none of the six wired-up budget permissions is refused 403 on every one of
/// the seven procedures they gate -- proves the RBAC gate is actually wired for each on
/// `authz-budget`, not merely present in `rpc_authorize`'s map.
#[tokio::test]
async fn each_budget_permission_is_actually_enforced() {
    let subject = format!("budget-noperm-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(MapBearer::new().with("no-budget-perms", token_info(&subject, viewer_perms())));
    let ctx = setup(bearer, None).await;
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
            axum::http::StatusCode::FORBIDDEN,
            "{op} must be 403 for a caller holding none of the budget:* permissions"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Dependency-unavailable fails closed (CLAUDE.md: "the unavailable branch never becomes the
// permissive branch"). Proven here through the real HTTP surface of the new service, on top of
// `lightbridge-authz-budget`'s own unit-level coverage
// (`rule_data.rs::spend_unavailable_for_a_referenced_field_routes_to_manual_review_not_auto_approve`).
// ---------------------------------------------------------------------------------------------

/// `UsageServiceSpendReader` pointed at an unreachable host degrades to `Spend::Unavailable`
/// exactly like an unconfigured `usage_service` does -- and a self-service refill request must
/// still route to `pending_review`, never auto-approve, once a policy that references spend is
/// active. This activates such a policy first (the seeded default policy does NOT reference
/// spend at all -- see `docs/architecture/budget.md`'s "What is actually live" section -- so this
/// test would pass trivially, for the wrong reason, without it).
#[tokio::test]
async fn spend_unavailable_routes_self_service_refill_to_manual_review_never_auto_approve() {
    let subject = format!("budget-spend-unavailable-{}", cuid2());
    let admin_subject = format!("budget-spend-unavailable-admin-{}", cuid2());
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new()
            .with(
                "caller",
                token_info(
                    &subject,
                    [Permission::BudgetSelfRefill].into_iter().collect(),
                ),
            )
            .with("admin", token_info(&admin_subject, admin_perms())),
    );
    // A genuinely unreachable host (RFC 5737 TEST-NET-1, never routable) -- the same class of
    // failure `UsageServiceSpendReader`'s own doc comment says degrades to `Spend::Unavailable`
    // (unreachable, timeout, non-2xx, unparseable body all resolve the same way, never a hard
    // error and never `Spend::Known(0)`).
    let unreachable_usage_service = UsageServiceClient {
        base_url: "https://192.0.2.1:9".to_string(),
        insecure_skip_verify: true,
        ca_bundle_path: None,
        timeout_ms: 500,
    };
    let ctx = setup(bearer, Some(unreachable_usage_service)).await;
    let r = &ctx.router;
    seed_budget_account(&ctx.verify, &subject).await;

    // `policy_revision` must be unique per row (`budget_policy_revisions`), so -- exactly like
    // `create_budget_policy_revision_does_not_activate_it` above -- this is suffixed with a fresh
    // `cuid2()` rather than a fixed literal, or a second run against the same database (a retry,
    // or another test in this same process) would 500 on a uniqueness violation instead of
    // exercising the behavior under test.
    let spend_referencing_policy = format!(
        r#"{{
      "policy_revision": "spend-unavailable-manual-review-test-{}",
      "rules": [
        {{
          "id": "spend-gate",
          "condition": {{ "type": "threshold", "field": "spend_this_period_micros", "operator": "lt", "value": 1000000000 }},
          "effect": "auto_approve",
          "reason_code": "under_spend_cap"
        }}
      ],
      "default_effect": "deny",
      "default_reason_code": "over_spend_cap"
    }}"#,
        cuid2()
    );
    let (status, body) = rpc_call(
        r.clone(),
        "procedure.activateBudgetPolicy",
        Wire::Json,
        &json!({ "args": { "policySetId": "budget-refill", "ruleDataJson": spend_referencing_policy } }),
        Some("admin"),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "activating a spend-referencing policy must succeed: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        r.clone(),
        "procedure.requestBudgetRefill",
        Wire::Json,
        &json!({ "args": {
            "budgetAccountId": subject,
            "accountId": subject,
            "period": "2026-08"
        } }),
        Some("caller"),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let parsed = as_json(Wire::Json, &body);
    assert_eq!(
        parsed["status"], "pending_review",
        "spend unavailable + a policy that references it must fail closed to manual review, \
         never auto-approve: {parsed}"
    );
    assert_eq!(
        parsed["policyReasonCodes"][0], "required_fact_unavailable",
        "the reason code must name the actual cause (spend unreachable), not a generic denial: \
         {parsed}"
    );
}
