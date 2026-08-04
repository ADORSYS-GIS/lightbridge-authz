#![cfg(feature = "it-tests")]

use std::sync::Arc;
use std::time::Duration;

use lightbridge_authz_budget::augmentation::{
    ApprovedDecision, AugmentationRepo, AugmentationStatus, NewAugmentationRequest,
    RecordedDecision, UnapprovedDecision,
};
use lightbridge_authz_budget::decision::Effect;
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::tier::BudgetTier;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

const PERIOD: &str = "2026-08";

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

async fn insert_grant(pool: &PgPool, account_id: &str) -> String {
    let id = cuid2();
    sqlx::query(
        "INSERT INTO budget_grants (id, budget_account_id, account_id, period, amount_micros, source) \
         VALUES ($1, $2, $2, $3, $4, 'self_service')",
    )
    .bind(&id)
    .bind(account_id)
    .bind(PERIOD)
    .bind(30_000_000_i64)
    .execute(pool)
    .await
    .expect("inserting a test grant must succeed");
    id
}

fn base_new_request(account_id: &str, amount_micros: i64) -> NewAugmentationRequest {
    NewAugmentationRequest {
        budget_account_id: account_id.to_string(),
        account_id: account_id.to_string(),
        project_id: None,
        period: Period::parse(PERIOD).expect("valid period"),
        requested_tier: BudgetTier::B30,
        requested_amount_micros: amount_micros,
        idempotency_key: None,
    }
}

fn pending_review_decision() -> RecordedDecision {
    RecordedDecision::PendingReview(UnapprovedDecision {
        policy_effect: Effect::ManualReview,
        policy_reason_codes: vec!["over_unaided_rung_limit".to_string()],
        matched_rule_ids: vec!["rule-review".to_string()],
        policy_revision: "budget-policy-1".to_string(),
    })
}

fn denied_decision() -> RecordedDecision {
    RecordedDecision::Denied(UnapprovedDecision {
        policy_effect: Effect::Deny,
        policy_reason_codes: vec!["top_rung_already".to_string()],
        matched_rule_ids: vec!["rule-deny".to_string()],
        policy_revision: "budget-policy-1".to_string(),
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_inserts_a_fresh_request(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));
    let request = base_new_request(&account_id, 30_000_000);

    let created = repo
        .create(request)
        .await
        .expect("creating a fresh request must succeed");

    assert_eq!(created.budget_account_id, account_id);
    assert_eq!(created.account_id, account_id);
    assert_eq!(created.project_id, None);
    assert_eq!(created.period, Period::parse(PERIOD).expect("valid period"));
    assert_eq!(created.requested_tier, BudgetTier::B30);
    assert_eq!(created.requested_amount_micros, 30_000_000);
    assert_eq!(created.status, AugmentationStatus::Created);
    assert_eq!(created.policy_effect, None);
    assert_eq!(created.grant_id, None);
    assert_eq!(created.reviewed_at, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_with_duplicate_idempotency_key_returns_the_original(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));
    let idempotency_key = cuid2();

    let mut first_request = base_new_request(&account_id, 15_000_000);
    first_request.idempotency_key = Some(idempotency_key.clone());

    let mut second_request = base_new_request(&account_id, 60_000_000);
    second_request.idempotency_key = Some(idempotency_key);

    let first = repo
        .create(first_request)
        .await
        .expect("first create must succeed");
    let second = repo
        .create(second_request)
        .await
        .expect("replayed create must succeed and return the original");

    assert_eq!(first.id, second.id);
    assert_eq!(
        second.requested_amount_micros, 15_000_000,
        "the replay must return the FIRST call's content, not the second call's input"
    );
    assert_eq!(second.requested_tier, first.requested_tier);
}

#[sqlx::test(migrations = "../../migrations")]
async fn record_decision_transitions_status_and_records_policy_fields(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let grant_id = insert_grant(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));
    let created = repo
        .create(base_new_request(&account_id, 30_000_000))
        .await
        .expect("create must succeed");

    let decision = RecordedDecision::AutoApproved(ApprovedDecision {
        policy_effect: Effect::AutoApprove,
        policy_reason_codes: vec!["under_unaided_rung_limit".to_string()],
        matched_rule_ids: vec!["rule-auto-approve".to_string()],
        policy_revision: "budget-policy-1".to_string(),
        approved_amount_micros: 30_000_000,
        grant_id: grant_id.clone(),
    });

    let updated = repo
        .record_decision(&created.id, decision)
        .await
        .expect("recording an auto-approved decision must succeed");

    assert_eq!(updated.status, AugmentationStatus::AutoApproved);
    assert_eq!(updated.policy_effect, Some(Effect::AutoApprove));
    assert_eq!(
        updated.policy_reason_codes,
        Some(vec!["under_unaided_rung_limit".to_string()])
    );
    assert_eq!(
        updated.matched_rule_ids,
        Some(vec!["rule-auto-approve".to_string()])
    );
    assert_eq!(updated.policy_revision, Some("budget-policy-1".to_string()));
    assert_eq!(updated.approved_amount_micros, Some(30_000_000));
    assert_eq!(updated.grant_id, Some(grant_id));
}

#[sqlx::test(migrations = "../../migrations")]
async fn record_review_requires_a_rejection_reason(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));
    let created = repo
        .create(base_new_request(&account_id, 30_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&created.id, pending_review_decision())
        .await
        .expect("moving the request to pending_review must succeed");

    let result = repo
        .record_review(&created.id, AugmentationStatus::Denied, "reviewer-1", None)
        .await;

    assert!(
        matches!(result, Err(BudgetError::MissingRejectionReason)),
        "a denial with no reason must be rejected as a caller error, got {result:?}"
    );

    let unchanged = repo
        .get(&created.id)
        .await
        .expect("the request must still exist");
    assert_eq!(
        unchanged.status,
        AugmentationStatus::PendingReview,
        "the failed validation must not have partially written the row"
    );
    assert_eq!(unchanged.reviewed_by, None);
    assert_eq!(unchanged.rejection_reason, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn record_review_succeeds_with_a_reason(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));
    let created = repo
        .create(base_new_request(&account_id, 30_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&created.id, pending_review_decision())
        .await
        .expect("moving the request to pending_review must succeed");

    let reviewed = repo
        .record_review(
            &created.id,
            AugmentationStatus::Denied,
            "reviewer-2",
            Some("account already exceeded its unaided rungs this period"),
        )
        .await
        .expect("a denial with a real reason must succeed");

    assert_eq!(reviewed.status, AugmentationStatus::Denied);
    assert_eq!(reviewed.reviewed_by, Some("reviewer-2".to_string()));
    assert_eq!(
        reviewed.rejection_reason,
        Some("account already exceeded its unaided rungs this period".to_string())
    );
    assert!(reviewed.reviewed_at.is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_review_returns_only_pending_requests_oldest_first(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let first = repo
        .create(base_new_request(&account_id, 30_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&first.id, pending_review_decision())
        .await
        .expect("must move to pending_review");

    tokio::time::sleep(Duration::from_millis(10)).await;

    let second = repo
        .create(base_new_request(&account_id, 60_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&second.id, pending_review_decision())
        .await
        .expect("must move to pending_review");

    let third = repo
        .create(base_new_request(&account_id, 120_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&third.id, denied_decision())
        .await
        .expect("must move to denied directly, never pending_review");

    let pending = repo
        .list_pending_review(None)
        .await
        .expect("listing the queue must succeed");

    let pending_ids: Vec<&str> = pending.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        pending_ids,
        vec![first.id.as_str(), second.id.as_str()],
        "must return only the still-pending requests, oldest first"
    );
    assert!(!pending_ids.contains(&third.id.as_str()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_review_scopes_to_one_account_when_given_an_id(pool: PgPool) {
    let account_a = cuid2();
    let account_b = cuid2();
    insert_account(&pool, &account_a).await;
    insert_account(&pool, &account_b).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let request_a = repo
        .create(base_new_request(&account_a, 30_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&request_a.id, pending_review_decision())
        .await
        .expect("must move to pending_review");

    let request_b = repo
        .create(base_new_request(&account_b, 30_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&request_b.id, pending_review_decision())
        .await
        .expect("must move to pending_review");

    let scoped = repo
        .list_pending_review(Some(&account_a))
        .await
        .expect("scoped listing must succeed");

    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].id, request_a.id);
    assert_eq!(scoped[0].budget_account_id, account_a);
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_of_unknown_id_is_a_loud_error(pool: PgPool) {
    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let result = repo.get("does-not-exist").await;

    assert!(matches!(result, Err(BudgetError::NotFound(_))));
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_by_idempotency_key_returns_none_when_nothing_matches(pool: PgPool) {
    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let found = repo
        .find_by_idempotency_key("does-not-exist")
        .await
        .expect("lookup must succeed");

    assert_eq!(found, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_by_idempotency_key_returns_the_matching_request(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));
    let idempotency_key = cuid2();

    let mut request = base_new_request(&account_id, 30_000_000);
    request.idempotency_key = Some(idempotency_key.clone());

    let created = repo
        .create(request)
        .await
        .expect("creating a fresh request must succeed");

    let found = repo
        .find_by_idempotency_key(&idempotency_key)
        .await
        .expect("lookup must succeed")
        .expect("the request must be found");

    assert_eq!(found.id, created.id);
    assert_eq!(found.idempotency_key, Some(idempotency_key));
}
