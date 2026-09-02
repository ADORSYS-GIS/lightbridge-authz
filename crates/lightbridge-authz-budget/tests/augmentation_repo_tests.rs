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
        requested_by_user_id: None,
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
        .record_review(
            &created.id,
            AugmentationStatus::Denied,
            "reviewer-1",
            None,
            None,
        )
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
            None,
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
    assert_eq!(reviewed.grant_id, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn record_review_approval_records_the_grant_id(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let grant_id = insert_grant(&pool, &account_id).await;

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
            AugmentationStatus::Approved,
            "reviewer-3",
            None,
            Some(&grant_id),
        )
        .await
        .expect("an approval with a grant id must succeed");

    assert_eq!(reviewed.status, AugmentationStatus::Approved);
    assert_eq!(reviewed.grant_id, Some(grant_id));
}

/// The concurrency fix at the heart of PR 3.3 (#191): [`REQUEST_UPDATE_REVIEW_SQL`]'s
/// `AND status = 'pending_review'` guard means that when two review actions race on the same
/// row, exactly one `UPDATE` matches and the other gets zero rows back -- surfaced here as
/// [`BudgetError::AlreadyReviewed`], never a silent double-write.
///
/// Proven by breaking it first: with the guard removed (see the comment this test's author left
/// in the PR description -- verified manually, not committed here since the fix must always be
/// in place on `main`), both concurrent calls succeed and the row silently reflects whichever
/// write happened to commit last. With the guard restored, exactly one call succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_review_of_the_same_request_results_in_exactly_one_outcome(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    // `grant_id` carries a real FK to `budget_grants(id)` -- the approving task must reference
    // an actual grant row, not an arbitrary string, or the FK violation would masquerade as the
    // very "already reviewed" error this test is trying to isolate.
    let grant_id = insert_grant(&pool, &account_id).await;

    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = AugmentationRepo::new(Arc::clone(&db_pool));
    let created = repo
        .create(base_new_request(&account_id, 30_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&created.id, pending_review_decision())
        .await
        .expect("moving the request to pending_review must succeed");

    let repo_approve = AugmentationRepo::new(Arc::clone(&db_pool));
    let repo_reject = AugmentationRepo::new(Arc::clone(&db_pool));
    let id_for_approve = created.id.clone();
    let id_for_reject = created.id.clone();

    let grant_id_for_assertion = grant_id.clone();
    let approve_task = tokio::spawn(async move {
        repo_approve
            .record_review(
                &id_for_approve,
                AugmentationStatus::Approved,
                "reviewer-approve",
                None,
                Some(&grant_id),
            )
            .await
    });
    let reject_task = tokio::spawn(async move {
        repo_reject
            .record_review(
                &id_for_reject,
                AugmentationStatus::Denied,
                "reviewer-reject",
                Some("racing rejection"),
                None,
            )
            .await
    });

    let (approve_result, reject_result) =
        tokio::try_join!(approve_task, reject_task).expect("neither task must panic");

    let outcomes = [approve_result.is_ok(), reject_result.is_ok()];
    assert_eq!(
        outcomes.iter().filter(|ok| **ok).count(),
        1,
        "exactly one of the two racing review actions must succeed, got approve={:?} reject={:?}",
        approve_result,
        reject_result
    );

    if let Err(err) = &approve_result {
        assert!(matches!(err, BudgetError::AlreadyReviewed(_)));
    }
    if let Err(err) = &reject_result {
        assert!(matches!(err, BudgetError::AlreadyReviewed(_)));
    }

    let final_row = repo.get(&created.id).await.expect("row must still exist");
    if approve_result.is_ok() {
        assert_eq!(final_row.status, AugmentationStatus::Approved);
        assert_eq!(final_row.grant_id, Some(grant_id_for_assertion));
    } else {
        assert_eq!(final_row.status, AugmentationStatus::Denied);
        assert_eq!(
            final_row.rejection_reason,
            Some("racing rejection".to_string())
        );
    }
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
        .list_pending_review(None, None, 200)
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
        .list_pending_review(Some(&account_a), None, 200)
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

/// #296: `list_pending_review` pages oldest-first (unchanged order) with a `created_at`-based
/// `after` cursor, and pages forward without repeating or skipping rows -- the exact bug a test
/// that never calls it a second time would miss, mirroring
/// `budget_repo_query_tests.rs::list_grants_pages_newest_first_by_created_at`'s own reasoning for
/// its DESC counterpart.
#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_review_pages_oldest_first_by_created_at(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let mut inserted_ids = Vec::new();
    for i in 0..5 {
        let created = repo
            .create(base_new_request(&account_id, 1_000_000 * (i + 1)))
            .await
            .expect("create must succeed");
        repo.record_decision(&created.id, pending_review_decision())
            .await
            .expect("must move to pending_review");
        inserted_ids.push(created.id);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Oldest-first means insertion order IS the expected page order (unlike the DESC ledger
    // query, no reversal needed here).
    let oldest_to_newest = inserted_ids;

    let page1 = repo
        .list_pending_review(None, None, 2)
        .await
        .expect("first page must succeed");
    assert_eq!(page1.len(), 2, "page size must be respected");
    assert_eq!(
        page1.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        oldest_to_newest[0..2],
        "the first page must be the two oldest pending requests, oldest first"
    );

    let cursor = page1[1].created_at;
    let page2 = repo
        .list_pending_review(None, Some(cursor), 2)
        .await
        .expect("second page must succeed");
    assert_eq!(
        page2.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        oldest_to_newest[2..4],
        "the second page must continue strictly after the cursor, not repeat or skip rows"
    );

    let cursor2 = page2[1].created_at;
    let page3 = repo
        .list_pending_review(None, Some(cursor2), 2)
        .await
        .expect("third page must succeed");
    assert_eq!(
        page3.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        oldest_to_newest[4..5],
        "the final page must return exactly the one remaining, newest request"
    );
}

/// #295: `list_by_budget_account` returns every request for one account regardless of status --
/// the gap `listPendingAugmentationRequests` (pending-only) leaves -- newest-first, paginated by
/// `created_at` with a `before` cursor, matching `BudgetRepo::list_grants`'s own convention.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_budget_account_returns_every_status_newest_first_and_paginates(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let first = repo
        .create(base_new_request(&account_id, 10_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&first.id, denied_decision())
        .await
        .expect("must move to denied");
    tokio::time::sleep(Duration::from_millis(10)).await;

    let second = repo
        .create(base_new_request(&account_id, 20_000_000))
        .await
        .expect("create must succeed");
    repo.record_decision(&second.id, pending_review_decision())
        .await
        .expect("must move to pending_review");
    tokio::time::sleep(Duration::from_millis(10)).await;

    let third = repo
        .create(base_new_request(&account_id, 30_000_000))
        .await
        .expect("create must succeed, left in `created` status");

    let page1 = repo
        .list_by_budget_account(&account_id, None, 2)
        .await
        .expect("first page must succeed");
    assert_eq!(page1.len(), 2, "page size must be respected");
    assert_eq!(
        page1.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        vec![third.id.clone(), second.id.clone()],
        "must return the two newest requests first, regardless of status: {page1:?}"
    );

    let cursor = page1[1].created_at;
    let page2 = repo
        .list_by_budget_account(&account_id, Some(cursor), 2)
        .await
        .expect("second page must succeed");
    assert_eq!(
        page2.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        vec![first.id.clone()],
        "the second page must return exactly the one remaining, oldest (denied) request"
    );
}

/// A caller with no requests at all -- or another account's own history alone -- must never leak
/// another account's requests. Proves `list_by_budget_account` scopes strictly by
/// `budget_account_id`, the same isolation `list_pending_review_scopes_to_one_account_when_given_an_id`
/// already proves for the admin queue's optional scoping.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_budget_account_does_not_leak_another_accounts_requests(pool: PgPool) {
    let account_a = cuid2();
    let account_b = cuid2();
    insert_account(&pool, &account_a).await;
    insert_account(&pool, &account_b).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let request_a = repo
        .create(base_new_request(&account_a, 30_000_000))
        .await
        .expect("create must succeed");

    repo.create(base_new_request(&account_b, 30_000_000))
        .await
        .expect("create must succeed");

    let scoped = repo
        .list_by_budget_account(&account_a, None, 200)
        .await
        .expect("scoped listing must succeed");

    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].id, request_a.id);
    assert_eq!(scoped[0].budget_account_id, account_a);
}

/// #646: the requester is persisted at creation and survives every later write to the row. The
/// second half matters as much as the first -- `record_decision`/`record_review` name their
/// columns explicitly (see `REQUEST_UPDATE_DECISION_SQL`/`REQUEST_UPDATE_REVIEW_SQL`), so a
/// requester that vanished on review would be a silent, invisible regression the queue itself
/// could never surface.
#[sqlx::test(migrations = "../../migrations")]
async fn the_requester_is_persisted_at_creation_and_survives_decision_and_review(pool: PgPool) {
    let account_id = cuid2();
    let requester_id = cuid2();
    let reviewer_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let created = repo
        .create(NewAugmentationRequest {
            requested_by_user_id: Some(requester_id.clone()),
            ..base_new_request(&account_id, 30_000_000)
        })
        .await
        .expect("create must succeed");

    assert_eq!(
        created.requested_by_user_id.as_deref(),
        Some(requester_id.as_str())
    );

    let fetched = repo.get(&created.id).await.expect("get must succeed");
    assert_eq!(
        fetched.requested_by_user_id.as_deref(),
        Some(requester_id.as_str()),
        "the requester must round-trip through a fresh read, not just the INSERT ... RETURNING"
    );

    let decided = repo
        .record_decision(&created.id, pending_review_decision())
        .await
        .expect("record_decision must succeed");
    assert_eq!(
        decided.requested_by_user_id.as_deref(),
        Some(requester_id.as_str()),
        "recording a policy decision must not drop the requester"
    );

    let reviewed = repo
        .record_review(
            &created.id,
            AugmentationStatus::Denied,
            &reviewer_id,
            Some("not this period"),
            None,
        )
        .await
        .expect("record_review must succeed");
    assert_eq!(
        reviewed.requested_by_user_id.as_deref(),
        Some(requester_id.as_str()),
        "the requester and the reviewer are two different people and two different columns"
    );
    assert_eq!(reviewed.reviewed_by.as_deref(), Some(reviewer_id.as_str()));
}

/// #646's "NULL means unknown, pre-migration" contract: a row that carries no requester -- which
/// is exactly the shape every row written before
/// `20260902000002_budget_augmentation_requests_add_requested_by.sql` has -- reads back as `None`
/// through the normal repository path, with no error and no invented placeholder. Written with
/// raw SQL that never names the new column, so it reproduces a pre-migration insert faithfully
/// rather than merely binding `NULL` to it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_written_without_a_requester_reads_back_as_none(pool: PgPool) {
    let account_id = cuid2();
    let request_id = cuid2();
    insert_account(&pool, &account_id).await;

    sqlx::query(
        "INSERT INTO budget_augmentation_requests \
         (id, budget_account_id, account_id, period, requested_tier, requested_amount_micros, status) \
         VALUES ($1, $2, $2, $3, 'b-30', $4, 'pending_review')",
    )
    .bind(&request_id)
    .bind(&account_id)
    .bind(PERIOD)
    .bind(30_000_000_i64)
    .execute(&pool)
    .await
    .expect("a pre-migration-shaped insert must still be a legal write");

    let repo = AugmentationRepo::new(Arc::new(DbPool::from_pool(pool)));

    let fetched = repo.get(&request_id).await.expect("get must succeed");
    assert_eq!(
        fetched.requested_by_user_id, None,
        "an unattributed row is unknown, not an error and not a stand-in id"
    );

    let queued = repo
        .list_pending_review(Some(&account_id), None, 200)
        .await
        .expect("listing the queue over an unattributed row must succeed");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].requested_by_user_id, None);
}
