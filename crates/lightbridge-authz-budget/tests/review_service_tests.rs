#![cfg(feature = "it-tests")]

use std::sync::Arc;

use lightbridge_authz_budget::augmentation::{
    AugmentationRepo, AugmentationStatus, NewAugmentationRequest, RecordedDecision,
    UnapprovedDecision,
};
use lightbridge_authz_budget::decision::Effect;
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::refill::{RefillRequest, RefillService};
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::review::ReviewService;
use lightbridge_authz_budget::rule_data::{RuleDataEngine, default_rule_set_json};
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::{Spend, SpendReader};
use lightbridge_authz_budget::tier::BudgetTier;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

const PERIOD: &str = "2026-08";

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

fn db_pool(pool: &PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool.clone()))
}

fn review_service(pool: &PgPool) -> ReviewService {
    let db_pool = db_pool(pool);
    ReviewService::new(
        Arc::new(BudgetRepo::new(Arc::clone(&db_pool))),
        Arc::new(AugmentationRepo::new(Arc::clone(&db_pool))),
    )
}

/// Seeds a `pending_review` row directly through [`AugmentationRepo`], bypassing
/// [`RefillService`] entirely -- simpler and more targeted for tests that only care about the
/// review-queue behavior on top of an already-queued request.
async fn seed_pending_review(
    pool: &PgPool,
    account_id: &str,
    requested_amount_micros: i64,
) -> String {
    let db_pool = db_pool(pool);
    let repo = AugmentationRepo::new(db_pool);

    let created = repo
        .create(NewAugmentationRequest {
            budget_account_id: account_id.to_string(),
            account_id: account_id.to_string(),
            project_id: None,
            period: Period::parse(PERIOD).expect("valid period"),
            requested_tier: BudgetTier::B30,
            requested_amount_micros,
            idempotency_key: None,
            requested_by_user_id: None,
        })
        .await
        .expect("seeding a fresh request must succeed");

    repo.record_decision(
        &created.id,
        RecordedDecision::PendingReview(UnapprovedDecision {
            policy_effect: Effect::ManualReview,
            policy_reason_codes: vec!["over_unaided_rung_limit".to_string()],
            matched_rule_ids: vec!["rule-review".to_string()],
            policy_revision: "budget-policy-1".to_string(),
        }),
    )
    .await
    .expect("moving the seeded request to pending_review must succeed");

    created.id
}

async fn seed_grant(pool: &PgPool, account_id: &str, source: GrantSource, amount_micros: i64) {
    let db_pool = db_pool(pool);
    let budget_repo = BudgetRepo::new(db_pool);
    budget_repo
        .grant(GrantRequest {
            budget_account_id: account_id.to_string(),
            account_id: account_id.to_string(),
            project_id: None,
            period: Period::parse(PERIOD).expect("valid period"),
            amount_micros,
            source,
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

#[derive(Debug)]
struct FixedSpendReader;

#[lightbridge_authz_core::async_trait]
impl SpendReader for FixedSpendReader {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(Spend::Known(0))
    }
}

/// Drives a real request all the way to `pending_review` through [`RefillService`] -- proving
/// [`ReviewService`] genuinely composes with the orchestration a real self-service refill uses,
/// not just with hand-seeded rows. Mirrors
/// `refill_service_tests.rs::exhausting_unaided_allowance_routes_to_pending_review`.
async fn seed_pending_review_via_refill_service(pool: &PgPool, account_id: &str) -> String {
    seed_grant(
        pool,
        account_id,
        GrantSource::SelfService,
        BudgetTier::B15.amount().get(),
    )
    .await;
    seed_grant(
        pool,
        account_id,
        GrantSource::SelfService,
        BudgetTier::B30.amount().get(),
    )
    .await;

    let db_pool = db_pool(pool);
    let policy_engine: Arc<dyn lightbridge_authz_budget::decision::PolicyEngine> = Arc::new(
        RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid default rule set"),
    );
    let refill_service = RefillService::new(
        Arc::new(BudgetRepo::new(Arc::clone(&db_pool))),
        Arc::new(AugmentationRepo::new(Arc::clone(&db_pool))),
        policy_engine,
        Arc::new(FixedSpendReader),
    );

    let result = refill_service
        .request_refill(RefillRequest {
            budget_account_id: account_id.to_string(),
            account_id: account_id.to_string(),
            project_id: None,
            period: Period::parse(PERIOD).expect("valid period"),
            idempotency_key: None,
            as_of: chrono::Utc::now(),
            requested_amount_micros: 30_000_000,
            requested_by_user_id: None,
        })
        .await
        .expect("the exhausted-allowance refill must succeed, queued for review");

    assert_eq!(
        result.status,
        AugmentationStatus::PendingReview,
        "seeding via RefillService must actually land in pending_review, or this test proves nothing"
    );

    result.id
}

async fn count_manual_approval_grants(pool: &PgPool, account_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM budget_grants \
         WHERE budget_account_id = $1 AND period = $2 AND source = 'manual_approval'",
    )
    .bind(account_id)
    .bind(PERIOD)
    .fetch_one(pool)
    .await
    .expect("count query must succeed")
}

#[sqlx::test(migrations = "../../migrations")]
async fn approve_grants_the_requested_amount_and_records_the_grant_id(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let request_id = seed_pending_review_via_refill_service(&pool, &account_id).await;
    let service = review_service(&pool);

    let approved = service
        .approve(&request_id, "reviewer-1")
        .await
        .expect("approving a pending request must succeed");

    assert_eq!(approved.status, AugmentationStatus::Approved);
    let grant_id = approved
        .grant_id
        .clone()
        .expect("an approval must record the grant id it produced");

    let (amount_micros, source, actor_id): (i64, String, Option<String>) =
        sqlx::query_as("SELECT amount_micros, source, actor_id FROM budget_grants WHERE id = $1")
            .bind(&grant_id)
            .fetch_one(&pool)
            .await
            .expect("the grant row referenced by the approval must exist");

    assert_eq!(source, "manual_approval");
    assert_eq!(actor_id, Some("reviewer-1".to_string()));
    assert_eq!(amount_micros, approved.requested_amount_micros);
}

#[sqlx::test(migrations = "../../migrations")]
async fn reject_requires_a_non_empty_reason(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let request_id = seed_pending_review(&pool, &account_id, 30_000_000).await;

    let service = review_service(&pool);
    let result = service.reject(&request_id, "reviewer-1", "").await;

    assert!(
        matches!(result, Err(BudgetError::MissingRejectionReason)),
        "an empty rejection reason must be rejected as a caller error, got {result:?}"
    );

    let augmentation_repo = AugmentationRepo::new(db_pool(&pool));
    let unchanged = augmentation_repo
        .get(&request_id)
        .await
        .expect("the request must still exist");
    assert_eq!(
        unchanged.status,
        AugmentationStatus::PendingReview,
        "a rejected-for-empty-reason call must not have written anything"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn reject_records_the_reason_and_reviewer(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let request_id = seed_pending_review(&pool, &account_id, 30_000_000).await;

    let service = review_service(&pool);
    let rejected = service
        .reject(
            &request_id,
            "reviewer-2",
            "account already exceeded its unaided rungs this period",
        )
        .await
        .expect("a real rejection must succeed");

    assert_eq!(rejected.status, AugmentationStatus::Denied);
    assert_eq!(
        rejected.rejection_reason,
        Some("account already exceeded its unaided rungs this period".to_string())
    );
    assert_eq!(rejected.reviewed_by, Some("reviewer-2".to_string()));
    assert!(rejected.reviewed_at.is_some());
    assert_eq!(rejected.grant_id, None);

    assert_eq!(count_manual_approval_grants(&pool, &account_id).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn approving_an_already_resolved_request_is_a_clear_error(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let request_id = seed_pending_review(&pool, &account_id, 30_000_000).await;

    let service = review_service(&pool);
    service
        .approve(&request_id, "reviewer-1")
        .await
        .expect("the first approval must succeed");

    let second = service.approve(&request_id, "reviewer-2").await;
    assert!(
        matches!(second, Err(BudgetError::AlreadyReviewed(_))),
        "re-approving an already-resolved request must be a clear, typed error, got {second:?}"
    );

    let third = service.reject(&request_id, "reviewer-3", "too late").await;
    assert!(
        matches!(third, Err(BudgetError::AlreadyReviewed(_))),
        "rejecting an already-resolved request must be a clear, typed error, got {third:?}"
    );

    assert_eq!(
        count_manual_approval_grants(&pool, &account_id).await,
        1,
        "no second grant may result from the rejected re-review attempts"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_excludes_resolved_requests(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let first_id = seed_pending_review(&pool, &account_id, 30_000_000).await;
    let second_id = seed_pending_review(&pool, &account_id, 60_000_000).await;

    let service = review_service(&pool);
    service
        .approve(&first_id, "reviewer-1")
        .await
        .expect("resolving the first request must succeed");

    let pending = service
        .list_pending(None, None, 200)
        .await
        .expect("listing the queue must succeed");
    let pending_ids: Vec<&str> = pending.iter().map(|r| r.id.as_str()).collect();

    assert_eq!(pending_ids, vec![second_id.as_str()]);
    assert!(!pending_ids.contains(&first_id.as_str()));
}

/// The real concurrency proof: two genuinely concurrent tasks, one approving and one rejecting
/// the *same* pending request, racing each other -- not two `approve()` calls racing each other.
/// Proves the deterministic-idempotency-key design (see `review.rs`'s module doc) holds under a
/// timing race between two *different* actions, and that the row-status guard added to
/// `record_review` (see `augmentation.rs`) resolves the race to exactly one winner.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_approve_and_reject_of_the_same_request_produce_exactly_one_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let request_id = seed_pending_review(&pool, &account_id, 30_000_000).await;

    let service = review_service(&pool);
    let approve_service = service.clone();
    let reject_service = service.clone();
    let id_for_approve = request_id.clone();
    let id_for_reject = request_id.clone();

    let approve_task = tokio::spawn(async move {
        approve_service
            .approve(&id_for_approve, "reviewer-approve")
            .await
    });
    let reject_task = tokio::spawn(async move {
        reject_service
            .reject(&id_for_reject, "reviewer-reject", "racing rejection")
            .await
    });

    let (approve_result, reject_result) =
        tokio::try_join!(approve_task, reject_task).expect("neither task must panic");

    let approve_won = approve_result.is_ok();
    let reject_won = reject_result.is_ok();
    assert_ne!(
        approve_won, reject_won,
        "exactly one of the two racing actions must succeed, got approve={:?} reject={:?}",
        approve_result, reject_result
    );

    if let Err(err) = &approve_result {
        assert!(matches!(err, BudgetError::AlreadyReviewed(_)));
    }
    if let Err(err) = &reject_result {
        assert!(matches!(err, BudgetError::AlreadyReviewed(_)));
    }

    let grant_count = count_manual_approval_grants(&pool, &account_id).await;
    assert!(
        grant_count <= 1,
        "at most one manual_approval grant may ever result from this race, got {grant_count}"
    );
    if approve_won {
        assert_eq!(
            grant_count, 1,
            "the winning approval must have produced exactly one grant"
        );
    } else {
        assert_eq!(
            grant_count, 0,
            "a winning rejection must never have produced a grant"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_request_id_is_a_clear_error_for_both_approve_and_reject(pool: PgPool) {
    let service = review_service(&pool);

    let approve_result = service.approve("does-not-exist", "reviewer-1").await;
    assert!(
        matches!(approve_result, Err(BudgetError::NotFound(_))),
        "approving an unknown id must be a clear NotFound error, got {approve_result:?}"
    );

    let reject_result = service
        .reject("does-not-exist", "reviewer-1", "any reason")
        .await;
    assert!(
        matches!(reject_result, Err(BudgetError::NotFound(_))),
        "rejecting an unknown id must be a clear NotFound error, got {reject_result:?}"
    );
}
