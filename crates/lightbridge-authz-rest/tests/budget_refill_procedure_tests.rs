// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Direct-call coverage for the self-service refill and admin review-queue procedures (#191, PR
//! 3.4; `Procedures::request_budget_refill` / `list_pending_augmentation_requests` /
//! `approve_augmentation_request` / `reject_augmentation_request`, backed by
//! `lightbridge_authz_budget::refill::RefillService` / `review::ReviewService`).
//!
//! Same rationale as `budget_policy_procedure_tests.rs` for calling `Procedures` methods directly
//! rather than standing up the full HTTP router: it keeps this file independent of Redis (needed
//! only by the rate-limiting middleware `rpc_it_tests.rs` exercises) while still proving the real
//! `Procedures` -> `RefillService`/`ReviewService` -> `BudgetRepo`/`AugmentationRepo` code path a
//! genuine RPC call would take past `rpc_authorize` and cratestack's own dispatch.
//!
//! No Redis needed here despite the new `SpendReader` dependency `RefillService` now carries:
//! `UnavailableSpendReader` (no HTTP calls, no network of any kind) stands in, which is also what
//! a real deployment falls back to when `Config.usage_service` is not configured -- see that
//! type's own doc comment in `lightbridge-authz-budget`. The seeded default policy
//! (`budget-policy-v2-adr0015`, migrated by
//! `migrations/20260819000001_budget_policy_adr0015_amounts.sql`, superseding
//! `20260804000001`'s original `budget-policy-v1`)
//! only reads `self_service_grant_count`, never `spend_this_period`/`spend_last_period`, so
//! `Spend::Unavailable` never actually changes any outcome in this file -- it is simply the
//! correct, honest choice of reader for a test that seeds no usage data.
//!
//! `rpc_authorize.rs`'s own `every_mapped_op_id_maps_to_the_documented_permission` test is where
//! the RBAC-gate-matters case for these four op-ids lives (`procedure.requestBudgetRefill` ->
//! `BudgetSelfRefill`, the other three -> `BudgetReview`) -- `Procedures` itself never enforces
//! RBAC (that is `rpc_authorize`'s job, a layer above the direct calls this file makes), so there
//! is nothing for a direct-call test here to usefully assert about permission denial.
#![cfg(feature = "it-tests")]

mod common;

use std::sync::Arc;

use cratestack::{CratestackContext, CratestackError, Value};
use lightbridge_authz_api::schema;
use lightbridge_authz_api::schema::procedures::ProcedureRegistry;
use lightbridge_authz_budget::PolicyStore;
use lightbridge_authz_budget::augmentation::AugmentationRepo;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::refill::RefillService;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::review::ReviewService;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::UnavailableSpendReader;
use lightbridge_authz_budget::tier::BudgetTier;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::Procedures;
use lightbridge_authz_rest::auth_provider;
use lightbridge_authz_rest::auth_provider::build_context;
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::rpc_authorize::RpcScope;
use sqlx::PgPool;

const SEEDED_POLICY_SET_ID: &str = "budget-refill";
const EVALUATION_BUDGET: usize = 10_000;
const PERIOD: &str = "2026-08";

/// A `schema::Cratestack` lazily wired to an unreachable address -- every procedure under test
/// takes `_db: &schema::Cratestack` but never uses it (they delegate entirely to
/// `RefillService`/`ReviewService`), so this is never actually queried, matching the pattern
/// already used for the same purpose in `budget_policy_procedure_tests.rs`.
fn lazy_cratestack_db() -> schema::Cratestack {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy cratestack pool should be constructible");
    schema::Cratestack::builder(pool).build()
}

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

// Issue #383 follow-up: a bare `authenticated([("id", ...)])` context satisfied the schema's old
// `@allow(auth() != null)` but silently fails the `auth().rpcScope`/`auth().perm*` clauses #383
// added to every mapped op-id (including these four budget procedures) -- this file's own module
// doc already says permission DENIAL is not what's under test here, so this grants the full
// permission set via the SAME shared helper `CratestackAuthProvider`/MCP use (`build_context`),
// scoped `RpcScope::Budget`, rather than hand-rolling a second, out-of-sync context shape.
async fn ctx_for(subject: &str) -> CratestackContext {
    build_context(
        &common::token_info(subject, common::admin_perms()),
        RpcScope::Budget,
        common::test_resolver().as_ref(),
    )
    .await
    .expect("the trust-everything test resolver never refuses")
}

/// Like [`ctx_for`], but stamped with [`auth_provider::CALLER_KIND_CONTEXT_KEY`] as
/// [`lightbridge_authz_rest::auth_provider::CratestackAuthProvider::authenticate`] would for a
/// token carrying `lightbridge_authz_bearer::API_KEY_CALLER_KIND` -- i.e. an `oauth2.type: self`
/// self-signed API-key JWT, or (per #419) the RFC 8693-exchanged token every human dashboard
/// caller presents too, since `signing.rs`'s `access_token_extra` stamps this claim
/// unconditionally regardless of caller. Kept after #419 deleted `request_budget_refill`'s own
/// `caller_kind` gate specifically to prove the claim is now irrelevant to that procedure's
/// outcome -- see `request_refill_accepts_api_key_shaped_caller_holding_the_permission` below.
async fn ctx_for_api_key_caller(subject: &str) -> CratestackContext {
    let mut ctx = ctx_for(subject).await;
    ctx.extensions.insert(
        auth_provider::CALLER_KIND_CONTEXT_KEY.to_owned(),
        Value::String(lightbridge_authz_bearer::API_KEY_CALLER_KIND.to_owned()),
    );
    ctx
}

/// Builds a real `Procedures` instance against `pool` (a genuinely migrated, seeded database),
/// mirroring `budget_policy_procedure_tests.rs::procedures_and_ctx` but also wiring the new
/// `refill_service`/`review_service` fields this PR adds. Returns the `Procedures`, a `CratestackContext`
/// sealed to `subject`, and the raw `BudgetRepo` handle so tests can pre-seed grants directly
/// (mirroring `lightbridge-authz-budget`'s own `refill_service_tests.rs` pattern for exercising
/// the "allowance exhausted" branch).
async fn procedures_and_ctx(
    pool: PgPool,
    subject: &str,
) -> (Procedures, CratestackContext, Arc<BudgetRepo>) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    let issuer = Arc::new(AuthzStoreImpl::with_pool(db_pool.clone()));
    let policy_store = Arc::new(
        PolicyStore::load_active_from_db(db_pool.clone(), SEEDED_POLICY_SET_ID, EVALUATION_BUDGET)
            .await
            .expect("migrations seed an active budget-refill revision"),
    );
    let budget_repo = Arc::new(BudgetRepo::new(db_pool.clone()));
    let augmentation_repo = Arc::new(AugmentationRepo::new(db_pool.clone()));
    let refill_service = Arc::new(RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_store.engine(),
        Arc::new(UnavailableSpendReader),
    ));
    let review_service = Arc::new(ReviewService::new(budget_repo.clone(), augmentation_repo));
    // ADR-0032: `Procedures::new` takes the reset scheduler unconditionally, the same type-level
    // obligation the refill/review services above already carry -- no test in this file reaches a
    // schedule procedure, and `UnavailableSpendReader` keeps it network-free.
    let reset_scheduler = Arc::new(lightbridge_authz_budget::ResetScheduler::new(
        db_pool,
        budget_repo.clone(),
        Arc::new(UnavailableSpendReader),
    ));
    let procedures = Procedures::new(
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo.clone(),
        reset_scheduler,
    );
    let ctx = ctx_for(subject).await;
    (procedures, ctx, budget_repo)
}

/// Thin `invoke_with_db` wrappers (cratestack#512: `ProcedureRegistry` methods now require an
/// `Authorized` witness only `authorize_with_db`/`invoke_with_db` can produce). Each of the four
/// budget-refill/review procedures below declares only `@allow(auth() != null)`, so this runs
/// that check before invoking the registry method, matching what the generated RPC dispatch
/// handler does for a real request -- see `budget_policy_procedure_tests.rs`'s identical pattern.
async fn request_refill(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::request_budget_refill::Args,
) -> Result<schema::procedures::request_budget_refill::Output, CratestackError> {
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

async fn list_pending(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::list_pending_augmentation_requests::Args,
) -> Result<schema::procedures::list_pending_augmentation_requests::Output, CratestackError> {
    let call_args = args.clone();
    schema::procedures::list_pending_augmentation_requests::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .list_pending_augmentation_requests(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

async fn list_my(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::list_my_augmentation_requests::Args,
) -> Result<schema::procedures::list_my_augmentation_requests::Output, CratestackError> {
    let call_args = args.clone();
    schema::procedures::list_my_augmentation_requests::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .list_my_augmentation_requests(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

async fn approve(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::approve_augmentation_request::Args,
) -> Result<schema::procedures::approve_augmentation_request::Output, CratestackError> {
    let call_args = args.clone();
    schema::procedures::approve_augmentation_request::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .approve_augmentation_request(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

async fn reject(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::reject_augmentation_request::Args,
) -> Result<schema::procedures::reject_augmentation_request::Output, CratestackError> {
    let call_args = args.clone();
    schema::procedures::reject_augmentation_request::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .reject_augmentation_request(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

/// ADR-0015: `requestedAmountMicros` is required -- #387 removed the pre-ADR-0015 optional wire
/// shape (an absent value deriving `current_tier.next()`). `amount` is checked against the active
/// policy's `allowed_amounts_micros` before the policy engine is ever called.
fn refill_args(
    budget_account_id: &str,
    idempotency_key: Option<String>,
    requested_amount_micros: &str,
) -> schema::procedures::request_budget_refill::Args {
    schema::procedures::request_budget_refill::Args {
        args: schema::RequestBudgetRefillInput {
            budgetAccountId: budget_account_id.to_string(),
            accountId: budget_account_id.to_string(),
            projectId: None,
            period: PERIOD.to_string(),
            idempotencyKey: idempotency_key,
            requestedAmountMicros: requested_amount_micros.to_string(),
        },
    }
}

async fn get_ladder(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::get_my_budget_refill_ladder::Args,
) -> Result<schema::procedures::get_my_budget_refill_ladder::Output, CratestackError> {
    let call_args = args.clone();
    schema::procedures::get_my_budget_refill_ladder::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .get_my_budget_refill_ladder(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

fn ladder_args() -> schema::procedures::get_my_budget_refill_ladder::Args {
    schema::procedures::get_my_budget_refill_ladder::Args {
        args: schema::GetMyBudgetRefillLadderInput {
            period: PERIOD.to_string(),
        },
    }
}

fn list_pending_args(
    budget_account_id: Option<&str>,
) -> schema::procedures::list_pending_augmentation_requests::Args {
    list_pending_args_paged(budget_account_id, None, None)
}

fn list_pending_args_paged(
    budget_account_id: Option<&str>,
    after: Option<chrono::DateTime<chrono::Utc>>,
    limit: Option<i64>,
) -> schema::procedures::list_pending_augmentation_requests::Args {
    schema::procedures::list_pending_augmentation_requests::Args {
        args: schema::ListPendingAugmentationRequestsInput {
            budgetAccountId: budget_account_id.map(str::to_string),
            after,
            limit,
        },
    }
}

fn list_my_args(
    before: Option<chrono::DateTime<chrono::Utc>>,
    limit: Option<i64>,
) -> schema::procedures::list_my_augmentation_requests::Args {
    schema::procedures::list_my_augmentation_requests::Args {
        args: schema::ListMyAugmentationRequestsInput { before, limit },
    }
}

fn approve_args(request_id: &str) -> schema::procedures::approve_augmentation_request::Args {
    schema::procedures::approve_augmentation_request::Args {
        args: schema::ApproveAugmentationRequestInput {
            requestId: request_id.to_string(),
        },
    }
}

fn reject_args(
    request_id: &str,
    reason: &str,
) -> schema::procedures::reject_augmentation_request::Args {
    schema::procedures::reject_augmentation_request::Args {
        args: schema::RejectAugmentationRequestInput {
            requestId: request_id.to_string(),
            reason: reason.to_string(),
        },
    }
}

/// Directly grants `amount_micros` via `BudgetRepo`, bypassing the RPC surface entirely -- used to
/// pre-seed an account's self-service grant history so a subsequent `requestBudgetRefill` call
/// exercises the "allowance exhausted" branch, mirroring
/// `lightbridge-authz-budget`'s own `refill_service_tests.rs::exhausting_unaided_allowance_routes_to_pending_review`.
async fn seed_self_service_grant(budget_repo: &BudgetRepo, account_id: &str, tier: BudgetTier) {
    budget_repo
        .grant(GrantRequest {
            budget_account_id: account_id.to_string(),
            account_id: account_id.to_string(),
            project_id: None,
            period: Period::parse(PERIOD).expect("valid period"),
            amount_micros: tier.amount().get(),
            source: GrantSource::SelfService,
            actor_id: None,
            reason: None,
            policy_revision: None,
            matched_rule_ids: None,
            idempotency_key: None,
            trigger_key: None,
            expires_at: None,
        })
        .await
        .expect("seed grant must succeed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_auto_approves_and_the_response_reflects_it(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    let output = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "15000000"),
    )
    .await
    .expect("a fresh account's first refill must be auto-approved");

    assert_eq!(
        output.status, "auto_approved",
        "the seeded default policy auto-approves the first two self-service refills per period"
    );
    assert!(
        output.grantId.is_some(),
        "an auto-approved request must carry the grant it produced"
    );
    // ADR-0015: `requestedTier` is a best-effort `BudgetTier` label for the requested amount, not
    // a server-chosen "next rung" -- `15000000` maps exactly to `b-15`.
    assert_eq!(output.requestedTier, "b-15");
    assert_eq!(output.approvedAmountMicros.as_deref(), Some("15000000"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_exhausting_allowance_returns_pending_review(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    // The seeded default policy auto-approves only the first two self-service refills per period
    // (`self_service_grant_count < 2`); pre-seed exactly that many so the next request is the
    // third and must route to `pending_review`.
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B15).await;
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B30).await;

    let output = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "30000000"),
    )
    .await
    .expect("an exhausted-allowance refill must still succeed (queued, not erroring)");

    assert_eq!(output.status, "pending_review");
    assert_eq!(
        output.grantId, None,
        "a pending_review outcome must not carry a grant"
    );
    assert_eq!(
        output.requestedTier, "b-30",
        "requestedTier labels the amount actually requested, not derived from grant history"
    );
}

/// ADR-0015: the caller names the amount directly, checked against the active policy's
/// `allowed_amounts_micros` ($6/$15/$30 in the ADR-0015 seed migration). `$6` is the new floor,
/// below any `BudgetTier` variant.
#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_with_a_named_amount_in_the_offered_set_auto_approves(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    let output = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "6000000"),
    )
    .await
    .expect("an amount in the offered set must succeed");

    assert_eq!(output.status, "auto_approved");
    assert_eq!(output.approvedAmountMicros.as_deref(), Some("6000000"));
    assert_eq!(
        output.requestedTier, "b-15",
        "$6 has no exact BudgetTier label, falls back to b-15"
    );
}

/// ADR-0015's structural rejection: an amount that is not a member of the active policy's
/// `allowed_amounts_micros` must be refused before an `AugmentationRequest` row is ever created
/// or the policy engine is ever consulted -- distinct from a policy `Deny`/`ManualReview`
/// decision, which only exists for amounts that were legitimately offered.
#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_with_an_amount_not_offered_is_rejected(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    // $17 is not one of the seeded $6/$15/$30 offered amounts.
    let result = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "17000000"),
    )
    .await;

    assert!(
        matches!(result, Err(CratestackError::BadRequest(_))),
        "an amount outside the offered set must be a BadRequest, not silently accepted or a \
         different error kind: {result:?}"
    );
}

/// #419: before this fix, an `oauth2.type: self` self-signed API-key JWT's
/// `lightbridge_authz_bearer::API_KEY_CALLER_KIND` claim -- projected into the context as
/// `auth_provider::CALLER_KIND_CONTEXT_KEY` -- caused `request_budget_refill` to refuse the
/// caller outright, *even though the same signal is stamped on every human-plane RFC 8693
/// exchange token too* (see `token_exchange_tests.rs`'s
/// `request_refill_accepts_a_real_human_plane_token_that_still_carries_the_stale_api_key_signal`
/// for the real-signer proof). Authorization is `budget:self-refill` alone now: a caller stamped
/// with this signal, who holds the permission, must be served exactly like any other caller.
#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_accepts_api_key_shaped_caller_holding_the_permission(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, _human_ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let ctx = ctx_for_api_key_caller(&account_id).await;
    let db = lazy_cratestack_db();

    let output = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "15000000"),
    )
    .await
    .expect(
        "a caller stamped with the API-key caller-kind signal, holding budget:self-refill, must \
         be served -- the permission is the only gate now",
    );

    assert_eq!(output.status, "auto_approved");
}

/// Regression guard: a caller whose token carries no caller-kind signal at all (the ordinary case
/// for most callers) must still be served normally -- absence of the claim must never be treated
/// as "is an API key" (see `TokenInfo::caller_kind`'s doc comment). Since #419 this is no longer
/// distinguishing behavior (every caller is served the same way regardless of the signal -- see
/// the test above), but it remains a useful pin on `TokenInfo::caller_kind`'s absence-is-unknown
/// contract.
#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_still_serves_caller_with_no_caller_kind_signal(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    let output = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "15000000"),
    )
    .await
    .expect("a caller with no caller-kind signal must not be refused");

    assert_eq!(output.status, "auto_approved");
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_returns_queued_requests(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B15).await;
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B30).await;

    let queued = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "30000000"),
    )
    .await
    .expect("exhausted-allowance refill must queue");
    assert_eq!(queued.status, "pending_review");

    let pending = list_pending(&procedures, &db, &ctx, list_pending_args(Some(&account_id)))
        .await
        .expect("listing the review queue must succeed");

    assert_eq!(pending.entries.len(), 1);
    assert_eq!(pending.entries[0].id, queued.id);
    assert_eq!(pending.entries[0].status, "pending_review");
    assert!(
        pending.nextCursor.is_none(),
        "a short (single-entry) page must report no further cursor"
    );

    let pending_global = list_pending(&procedures, &db, &ctx, list_pending_args(None))
        .await
        .expect("listing the whole queue must succeed");
    assert!(
        pending_global.entries.iter().any(|r| r.id == queued.id),
        "the global (unscoped) queue must include this account's pending request too"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn approve_grants_and_updates_status(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let reviewer_id = cuid2();
    insert_account(&pool, &reviewer_id).await;
    let (procedures, ctx, budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let reviewer_ctx = ctx_for(&reviewer_id).await;
    let db = lazy_cratestack_db();

    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B15).await;
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B30).await;

    let queued = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "30000000"),
    )
    .await
    .expect("exhausted-allowance refill must queue");
    assert_eq!(queued.status, "pending_review");

    let approved = approve(&procedures, &db, &reviewer_ctx, approve_args(&queued.id))
        .await
        .expect("approving a pending request must succeed");

    assert_eq!(approved.status, "approved");
    assert!(
        approved.grantId.is_some(),
        "an approval must carry the grant it produced"
    );
    assert_eq!(approved.reviewedBy.as_deref(), Some(reviewer_id.as_str()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn reject_without_a_reason_is_rejected_at_the_schema_or_procedure_layer(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let reviewer_id = cuid2();
    insert_account(&pool, &reviewer_id).await;
    let (procedures, ctx, budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let reviewer_ctx = ctx_for(&reviewer_id).await;
    let db = lazy_cratestack_db();

    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B15).await;
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B30).await;

    let queued = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "30000000"),
    )
    .await
    .expect("exhausted-allowance refill must queue");

    // The schema's `reason` field is non-optional, so a caller cannot omit it entirely through
    // the typed `Args` this direct-call test constructs -- a caller who did (e.g. a raw JSON
    // request missing the field) would be rejected by cratestack's own schema deserialization
    // before ever reaching this procedure. What this direct-call test CAN, and does, prove is the
    // procedure layer's own defense in depth: `ReviewService::reject` validates the reason is
    // non-empty (not just present) before touching the database at all, so an empty string --
    // which the schema type alone cannot rule out -- is still refused here.
    let result = reject(&procedures, &db, &reviewer_ctx, reject_args(&queued.id, "")).await;

    assert!(
        result.is_err(),
        "an empty rejection reason must be refused, not silently accepted: {result:?}"
    );

    let still_pending = list_pending(&procedures, &db, &ctx, list_pending_args(Some(&account_id)))
        .await
        .expect("listing the review queue must succeed");
    assert!(
        still_pending.entries.iter().any(|r| r.id == queued.id),
        "a rejected-at-validation reject call must not have changed the row's status"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn reject_with_a_reason_succeeds_and_records_it(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let reviewer_id = cuid2();
    insert_account(&pool, &reviewer_id).await;
    let (procedures, ctx, budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let reviewer_ctx = ctx_for(&reviewer_id).await;
    let db = lazy_cratestack_db();

    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B15).await;
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B30).await;

    let queued = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "30000000"),
    )
    .await
    .expect("exhausted-allowance refill must queue");

    let reason = "over the account's approved discretionary ceiling for this quarter";
    let rejected = reject(
        &procedures,
        &db,
        &reviewer_ctx,
        reject_args(&queued.id, reason),
    )
    .await
    .expect("rejecting with a non-empty reason must succeed");

    assert_eq!(rejected.status, "denied");
    assert_eq!(
        rejected.grantId, None,
        "a rejection must never carry a grant"
    );
    assert_eq!(rejected.rejectionReason.as_deref(), Some(reason));
    assert_eq!(rejected.reviewedBy.as_deref(), Some(reviewer_id.as_str()));
}

/// #296: `listPendingAugmentationRequests` pages oldest-first with a `created_at`-based `after`
/// cursor, and continues forward without repeating or skipping rows across pages -- the
/// procedure-layer proof on top of `augmentation_repo_tests.rs`'s own repo-level coverage of the
/// same behavior.
#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_augmentation_requests_paginates_oldest_first(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    // Exhaust the auto-approve allowance once, then every further call queues -- three distinct
    // pending rows for one account, oldest to newest in call order.
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B15).await;
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B30).await;

    let mut queued_ids = Vec::new();
    for _ in 0..3 {
        let queued = request_refill(
            &procedures,
            &db,
            &ctx,
            refill_args(&account_id, None, "30000000"),
        )
        .await
        .expect("an exhausted-allowance refill must still queue, not error");
        assert_eq!(queued.status, "pending_review");
        queued_ids.push(queued.id);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let page1 = list_pending(
        &procedures,
        &db,
        &ctx,
        list_pending_args_paged(Some(&account_id), None, Some(2)),
    )
    .await
    .expect("first page must succeed");
    assert_eq!(
        page1
            .entries
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>(),
        queued_ids[0..2],
        "the first page must be the two oldest pending requests, oldest first"
    );
    let cursor = page1
        .nextCursor
        .expect("a full page must carry a nextCursor -- there is a third, newer request");

    let page2 = list_pending(
        &procedures,
        &db,
        &ctx,
        list_pending_args_paged(Some(&account_id), Some(cursor), Some(2)),
    )
    .await
    .expect("second page must succeed");
    assert_eq!(
        page2
            .entries
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>(),
        vec![queued_ids[2].clone()],
        "the second page must return exactly the one remaining, newest request"
    );
    assert!(
        page2.nextCursor.is_none(),
        "a short page must report no further cursor"
    );
}

/// #295: `listMyAugmentationRequests` returns the caller's own history across every status --
/// not just `pending_review` -- newest-first.
#[sqlx::test(migrations = "../../migrations")]
async fn list_my_augmentation_requests_returns_own_history_across_statuses_newest_first(
    pool: PgPool,
) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    // The seeded default policy auto-approves the first two self-service refills per period, then
    // queues the third -- so three plain calls (no pre-seeded grants) produce two distinct
    // statuses without any direct repo access.
    let mut submitted = Vec::new();
    for _ in 0..3 {
        let created = request_refill(
            &procedures,
            &db,
            &ctx,
            refill_args(&account_id, None, "15000000"),
        )
        .await
        .expect("request must succeed (auto-approved or queued, never erroring)");
        submitted.push(created);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(submitted[0].status, "auto_approved");
    assert_eq!(submitted[1].status, "auto_approved");
    assert_eq!(
        submitted[2].status, "pending_review",
        "the third refill this period must exhaust the auto-approve allowance"
    );

    let history = list_my(&procedures, &db, &ctx, list_my_args(None, None))
        .await
        .expect("listing own history must succeed");

    assert_eq!(
        history.entries.len(),
        3,
        "every request must be returned regardless of status: {:?}",
        history.entries
    );
    assert_eq!(
        history
            .entries
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>(),
        vec![
            submitted[2].id.clone(),
            submitted[1].id.clone(),
            submitted[0].id.clone(),
        ],
        "must be newest-first"
    );
    assert_eq!(history.entries[0].status, "pending_review");
    assert_eq!(history.entries[1].status, "auto_approved");
}

/// The IDOR guard #295 explicitly calls for: `listMyAugmentationRequests` takes no target
/// account/subject field at all, so a second caller with their own (empty) history must never see
/// the first caller's requests -- proven here, not merely asserted from the schema shape.
#[sqlx::test(migrations = "../../migrations")]
async fn list_my_augmentation_requests_does_not_leak_another_callers_requests(pool: PgPool) {
    let owner_id = cuid2();
    let bystander_id = cuid2();
    insert_account(&pool, &owner_id).await;
    insert_account(&pool, &bystander_id).await;
    let (procedures, owner_ctx, _budget_repo) = procedures_and_ctx(pool, &owner_id).await;
    let bystander_ctx = ctx_for(&bystander_id).await;
    let db = lazy_cratestack_db();

    let created = request_refill(
        &procedures,
        &db,
        &owner_ctx,
        refill_args(&owner_id, None, "15000000"),
    )
    .await
    .expect("owner's own refill request must succeed");

    let owner_history = list_my(&procedures, &db, &owner_ctx, list_my_args(None, None))
        .await
        .expect("owner listing their own history must succeed");
    assert!(
        owner_history.entries.iter().any(|r| r.id == created.id),
        "the owner must see their own request"
    );

    let bystander_history = list_my(&procedures, &db, &bystander_ctx, list_my_args(None, None))
        .await
        .expect("bystander listing their own (empty) history must succeed");
    assert!(
        bystander_history.entries.is_empty(),
        "a caller with no requests of their own must never see another account's: {:?}",
        bystander_history.entries
    );
}

/// The read-only amount-picker companion (see `refill.rs`'s `RefillService::refill_status` doc
/// comment): a fresh account sees the active policy's offered amounts, and this preview must
/// agree with what a real `requestBudgetRefill` call actually accepts -- proven here by calling
/// both against the same account.
#[sqlx::test(migrations = "../../migrations")]
async fn get_my_budget_refill_ladder_returns_the_active_policys_offered_amounts(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    let status = get_ladder(&procedures, &db, &ctx, ladder_args())
        .await
        .expect("a fresh account's ladder status must succeed");

    assert_eq!(status.budgetAccountId, account_id);
    assert_eq!(status.period, PERIOD);
    assert_eq!(
        status.allowedAmountsMicros,
        vec!["6000000", "15000000", "30000000"]
    );

    let refill = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "30000000"),
    )
    .await
    .expect("an amount the preview reported as offered must be accepted by a real submission");
    assert_eq!(refill.requestedTier, "b-30");
}

/// #387's own regression guard: the pre-ADR-0015 `currentTier`/`currentTierAmountMicros`/
/// `nextTier`/`nextTierAmountMicros`/`ladder` fields (and the `BudgetLadderRung` type) must be
/// genuinely absent from the wire response, not merely unused in Rust -- serializes the real,
/// procedure-produced `Output` the same way the RPC codec would and inspects the actual bytes, so
/// a future re-introduction of any of these fields on the schema type would be caught even though
/// nothing in this test file references them by name as a struct field.
#[sqlx::test(migrations = "../../migrations")]
async fn get_my_budget_refill_ladder_response_never_serializes_the_removed_legacy_fields(
    pool: PgPool,
) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    let status = get_ladder(&procedures, &db, &ctx, ladder_args())
        .await
        .expect("a fresh account's ladder status must succeed");

    let wire = serde_json::to_string(&status).expect("the response type must serialize");

    for legacy_field in [
        "currentTier",
        "currentTierAmountMicros",
        "nextTier",
        "nextTierAmountMicros",
        "ladder",
        "amountMicros",
    ] {
        assert!(
            !wire.contains(legacy_field),
            "the wire response must never contain the removed field `{legacy_field}`: {wire}"
        );
    }
    assert!(
        wire.contains("allowedAmountsMicros"),
        "the wire response must still carry allowedAmountsMicros: {wire}"
    );
}

/// The self-scoping guarantee `getMyBudgetRefillLadder`'s schema doc comment claims: `budgetAccountId`
/// always reflects the authenticated caller, never a caller-supplied or shared value -- there is
/// no target field on the input to even attempt otherwise.
#[sqlx::test(migrations = "../../migrations")]
async fn get_my_budget_refill_ladder_is_scoped_to_the_callers_own_budget_account_id(pool: PgPool) {
    let owner_id = cuid2();
    let bystander_id = cuid2();
    insert_account(&pool, &owner_id).await;
    insert_account(&pool, &bystander_id).await;
    let (procedures, owner_ctx, _budget_repo) = procedures_and_ctx(pool, &owner_id).await;
    let bystander_ctx = ctx_for(&bystander_id).await;
    let db = lazy_cratestack_db();

    let owner_status = get_ladder(&procedures, &db, &owner_ctx, ladder_args())
        .await
        .expect("owner's own status must succeed");
    assert_eq!(owner_status.budgetAccountId, owner_id);

    let bystander_status = get_ladder(&procedures, &db, &bystander_ctx, ladder_args())
        .await
        .expect("bystander's own status must succeed");
    assert_eq!(bystander_status.budgetAccountId, bystander_id);
    assert_ne!(
        owner_status.budgetAccountId, bystander_status.budgetAccountId,
        "budgetAccountId must always reflect the authenticated caller, never a shared value"
    );
}

/// #646: `requestBudgetRefill` records the AUTHENTICATED CALLER as the requester -- not the
/// `budgetAccountId` the caller named, and not any client-supplied field (there is none, by
/// design). The context's subject is deliberately a different id from the account here, which is
/// the whole reason the field exists: the console's earlier "Requester" column was removed
/// precisely because it only ever duplicated the account.
#[sqlx::test(migrations = "../../migrations")]
async fn request_refill_records_the_caller_subject_as_the_requester(pool: PgPool) {
    let account_id = cuid2();
    let requester_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, _account_ctx, _budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let requester_ctx = ctx_for(&requester_id).await;
    let db = lazy_cratestack_db();

    let output = request_refill(
        &procedures,
        &db,
        &requester_ctx,
        refill_args(&account_id, None, "15000000"),
    )
    .await
    .expect("a fresh account's first refill must succeed");

    assert_eq!(
        output.requestedByUserId.as_deref(),
        Some(requester_id.as_str()),
        "the requester is the token subject, never the budget account"
    );
    assert_ne!(
        output.requestedByUserId.as_deref(),
        Some(account_id.as_str())
    );
    assert_eq!(
        output.reviewedBy, None,
        "requester and reviewer are separate fields: nothing has reviewed this yet"
    );
}

/// The field must survive the wire, not just the direct mutation response: both listings the
/// console renders (`listPendingAugmentationRequests`, the admin queue; and
/// `listMyAugmentationRequests`, the caller's own history) must carry it. Subject and
/// `budgetAccountId` coincide here because `listMyAugmentationRequests` derives its target from
/// the subject alone (#295's IDOR guard) -- the "requester is not the account" property is proven
/// by `request_refill_records_the_caller_subject_as_the_requester` above instead.
#[sqlx::test(migrations = "../../migrations")]
async fn the_requester_round_trips_through_both_augmentation_request_listings(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let (procedures, ctx, budget_repo) = procedures_and_ctx(pool, &account_id).await;
    let db = lazy_cratestack_db();

    // The seeded policy auto-approves only the first two self-service refills per period; seed
    // both so the request below lands in `pending_review` and therefore appears in the admin
    // queue as well as in the caller's own history.
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B15).await;
    seed_self_service_grant(&budget_repo, &account_id, BudgetTier::B30).await;

    let queued = request_refill(
        &procedures,
        &db,
        &ctx,
        refill_args(&account_id, None, "30000000"),
    )
    .await
    .expect("an exhausted-allowance refill must still succeed (queued)");
    assert_eq!(queued.status, "pending_review");

    let pending = list_pending(&procedures, &db, &ctx, list_pending_args(Some(&account_id)))
        .await
        .expect("the admin queue read must succeed");
    let queued_entry = pending
        .entries
        .iter()
        .find(|r| r.id == queued.id)
        .expect("the queued request must be in the admin queue");
    assert_eq!(
        queued_entry.requestedByUserId.as_deref(),
        Some(account_id.as_str())
    );

    let history = list_my(&procedures, &db, &ctx, list_my_args(None, None))
        .await
        .expect("the caller's own history read must succeed");
    let history_entry = history
        .entries
        .iter()
        .find(|r| r.id == queued.id)
        .expect("the queued request must be in the caller's own history");
    assert_eq!(
        history_entry.requestedByUserId.as_deref(),
        Some(account_id.as_str())
    );

    let wire = serde_json::to_string(&queued).expect("the response type must serialize");
    assert!(
        wire.contains("requestedByUserId"),
        "the field must be present on the actual wire bytes the console decodes: {wire}"
    );
}
