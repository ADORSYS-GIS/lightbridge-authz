#![cfg(feature = "it-tests")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use chrono::Utc;
use lightbridge_authz_budget::augmentation::{AugmentationRepo, AugmentationStatus};
use lightbridge_authz_budget::decision::{Decision, Effect, Obligations, PolicyEngine};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::facts::Facts;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::refill::{RefillRequest, RefillService};
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
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

async fn count_budget_grants(pool: &PgPool, account_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM budget_grants WHERE budget_account_id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .expect("count query must succeed")
}

fn base_request(account_id: &str, idempotency_key: Option<String>) -> RefillRequest {
    RefillRequest {
        budget_account_id: account_id.to_string(),
        account_id: account_id.to_string(),
        project_id: None,
        period: Period::parse(PERIOD).expect("valid period"),
        idempotency_key,
        as_of: Utc::now(),
    }
}

fn seed_grant_request(account_id: &str, source: GrantSource, amount_micros: i64) -> GrantRequest {
    GrantRequest {
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
    }
}

fn refill_service(
    pool: &PgPool,
    policy_engine: Arc<dyn PolicyEngine>,
    spend_reader: Arc<dyn SpendReader>,
) -> RefillService {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    RefillService::new(
        Arc::new(BudgetRepo::new(Arc::clone(&db_pool))),
        Arc::new(AugmentationRepo::new(Arc::clone(&db_pool))),
        policy_engine,
        spend_reader,
    )
}

fn default_policy_engine() -> Arc<dyn PolicyEngine> {
    Arc::new(RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid default rule set"))
}

#[derive(Debug)]
struct FixedSpendReader {
    spend: Spend,
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for FixedSpendReader {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(self.spend)
    }
}

fn known_zero_spend_reader() -> Arc<dyn SpendReader> {
    Arc::new(FixedSpendReader {
        spend: Spend::Known(0),
    })
}

/// Proves "no policy engine call happened" for the already-at-top-rung case: a real
/// [`RuleDataEngine`] would just silently not care that it was skipped, so only a double that
/// hard-fails on `evaluate` makes that property a real test failure if violated.
#[derive(Debug)]
struct PanicIfCalledPolicyEngine;

#[lightbridge_authz_core::async_trait]
impl PolicyEngine for PanicIfCalledPolicyEngine {
    async fn evaluate(
        &self,
        _facts: &Facts,
        _requested_amount_micros: i64,
    ) -> Result<Decision, BudgetError> {
        panic!(
            "PolicyEngine::evaluate must not be called when the account is already at the top rung"
        );
    }
}

#[derive(Debug)]
struct AlwaysErrPolicyEngine;

#[lightbridge_authz_core::async_trait]
impl PolicyEngine for AlwaysErrPolicyEngine {
    async fn evaluate(
        &self,
        _facts: &Facts,
        _requested_amount_micros: i64,
    ) -> Result<Decision, BudgetError> {
        Err(BudgetError::StorageFailed(
            "simulated policy engine outage".to_string(),
        ))
    }
}

/// Counts `evaluate` calls so the idempotency short-circuit's real proof isn't just "the end
/// state looks the same" -- it is "the engine was invoked exactly once".
#[derive(Debug)]
struct CountingAutoApprovePolicyEngine {
    calls: AtomicUsize,
}

impl CountingAutoApprovePolicyEngine {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[lightbridge_authz_core::async_trait]
impl PolicyEngine for CountingAutoApprovePolicyEngine {
    async fn evaluate(
        &self,
        _facts: &Facts,
        requested_amount_micros: i64,
    ) -> Result<Decision, BudgetError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Decision {
            effect: Effect::AutoApprove,
            approved_amount_micros: requested_amount_micros,
            maximum_amount_micros: requested_amount_micros,
            reason_codes: vec!["counted".to_string()],
            matched_rule_ids: vec![],
            policy_revision: "counting-test-revision".to_string(),
            obligations: Obligations::default(),
        })
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_refill_grants_the_next_tier_and_records_auto_approved(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let service = refill_service(&pool, default_policy_engine(), known_zero_spend_reader());

    let result = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("a fresh account's first refill must succeed");

    assert_eq!(result.status, AugmentationStatus::AutoApproved);
    assert_eq!(
        result.requested_tier,
        BudgetTier::B30,
        "default-tier B15 -> next() is B30"
    );
    assert_eq!(result.approved_amount_micros, Some(30_000_000));
    let grant_id = result
        .grant_id
        .clone()
        .expect("an auto-approved refill must carry a grant id");

    let (amount_micros, source): (i64, String) =
        sqlx::query_as("SELECT amount_micros, source FROM budget_grants WHERE id = $1")
            .bind(&grant_id)
            .fetch_one(&pool)
            .await
            .expect("the grant row referenced by the augmentation request must exist");

    assert_eq!(amount_micros, 30_000_000);
    assert_eq!(source, "self_service");
}

#[sqlx::test(migrations = "../../migrations")]
async fn second_refill_same_period_grants_the_tier_after_that(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let service = refill_service(&pool, default_policy_engine(), known_zero_spend_reader());

    let first = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("first refill must succeed");
    assert_eq!(first.requested_tier, BudgetTier::B30);
    assert_eq!(first.status, AugmentationStatus::AutoApproved);

    tokio::time::sleep(Duration::from_millis(10)).await;

    let second = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("second refill must succeed");

    assert_eq!(
        second.requested_tier,
        BudgetTier::B60,
        "tier progression must read back what was actually granted (B30), not always start from B15"
    );
    assert_eq!(second.status, AugmentationStatus::AutoApproved);
    assert_eq!(second.approved_amount_micros, Some(60_000_000));
}

#[sqlx::test(migrations = "../../migrations")]
async fn exhausting_unaided_allowance_routes_to_pending_review(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = BudgetRepo::new(Arc::clone(&db_pool));

    budget_repo
        .grant(seed_grant_request(
            &account_id,
            GrantSource::SelfService,
            BudgetTier::B15.amount().get(),
        ))
        .await
        .expect("seed grant 1 must succeed");
    budget_repo
        .grant(seed_grant_request(
            &account_id,
            GrantSource::SelfService,
            BudgetTier::B30.amount().get(),
        ))
        .await
        .expect("seed grant 2 must succeed");

    let service = RefillService::new(
        Arc::new(budget_repo),
        Arc::new(AugmentationRepo::new(Arc::clone(&db_pool))),
        default_policy_engine(),
        known_zero_spend_reader(),
    );

    let before_count = count_budget_grants(&pool, &account_id).await;

    let result = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("an exhausted-allowance refill must still succeed (queued, not erroring)");

    assert_eq!(result.status, AugmentationStatus::PendingReview);
    assert_eq!(
        result.requested_tier,
        BudgetTier::B60,
        "resolves from the latest tier grant (B30) -> next is B60"
    );
    assert_eq!(result.grant_id, None);

    let after_count = count_budget_grants(&pool, &account_id).await;
    assert_eq!(
        after_count, before_count,
        "a pending_review outcome must not write a budget_grants row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn already_at_top_rung_is_refused_without_a_failed_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = BudgetRepo::new(Arc::clone(&db_pool));

    budget_repo
        .grant(seed_grant_request(
            &account_id,
            GrantSource::Admin,
            BudgetTier::B1000.amount().get(),
        ))
        .await
        .expect("seeding the top-rung grant must succeed");

    let service = RefillService::new(
        Arc::new(budget_repo),
        Arc::new(AugmentationRepo::new(Arc::clone(&db_pool))),
        Arc::new(PanicIfCalledPolicyEngine),
        known_zero_spend_reader(),
    );

    let result = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("a top-rung refill must still succeed (denied, not erroring)");

    assert_eq!(result.status, AugmentationStatus::Denied);
    assert_eq!(
        result.policy_reason_codes,
        Some(vec!["already_at_top_rung".to_string()])
    );
    assert_eq!(result.grant_id, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn policy_engine_unavailable_queues_rather_than_denies_or_grants(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let service = refill_service(
        &pool,
        Arc::new(AlwaysErrPolicyEngine),
        known_zero_spend_reader(),
    );

    let result = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("an unavailable policy engine must not propagate as a caller-facing error");

    assert_eq!(result.status, AugmentationStatus::PendingReview);
    assert_eq!(
        result.policy_reason_codes,
        Some(vec!["policy_engine_unavailable".to_string()]),
        "must be distinguishable from a policy-based pending_review by reason code"
    );
    assert_eq!(result.grant_id, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn duplicate_idempotency_key_returns_the_same_outcome_without_re_evaluating(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let counting_engine = Arc::new(CountingAutoApprovePolicyEngine::new());
    let service = refill_service(
        &pool,
        Arc::clone(&counting_engine) as Arc<dyn PolicyEngine>,
        known_zero_spend_reader(),
    );

    let idempotency_key = cuid2();

    let first = service
        .request_refill(base_request(&account_id, Some(idempotency_key.clone())))
        .await
        .expect("first call must succeed");
    let second = service
        .request_refill(base_request(&account_id, Some(idempotency_key)))
        .await
        .expect("second (duplicate) call must succeed");

    assert_eq!(
        first.id, second.id,
        "a duplicate idempotency key must return the same request, not create a second one"
    );
    assert_eq!(
        counting_engine.call_count(),
        1,
        "the policy engine must be evaluated exactly once across both submissions"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn manual_review_decision_records_reason_codes_and_matched_rule_ids_from_the_real_decision(
    pool: PgPool,
) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let rule_data = r#"{
      "policy_revision": "test-manual-review-policy",
      "rules": [
        {
          "id": "always-manual-review",
          "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
          "effect": "manual_review",
          "reason_code": "custom_manual_review_reason"
        }
      ],
      "default_effect": "deny",
      "default_reason_code": "unreachable_default"
    }"#;
    let engine: Arc<dyn PolicyEngine> =
        Arc::new(RuleDataEngine::new(rule_data, 1_000).expect("valid rule set"));

    let service = refill_service(&pool, engine, known_zero_spend_reader());

    let result = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("refill must succeed");

    assert_eq!(result.status, AugmentationStatus::PendingReview);
    assert_eq!(result.policy_effect, Some(Effect::ManualReview));
    assert_eq!(
        result.policy_reason_codes,
        Some(vec!["custom_manual_review_reason".to_string()]),
        "must carry the real decision's reason codes, not empty/default ones"
    );
    assert_eq!(
        result.matched_rule_ids,
        Some(vec!["always-manual-review".to_string()]),
        "must carry the real decision's matched rule ids, not empty/default ones"
    );
    assert_eq!(
        result.policy_revision,
        Some("test-manual-review-policy".to_string())
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn refill_status_for_a_fresh_account_starts_at_b15_with_b30_next(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let service = refill_service(
        &pool,
        Arc::new(PanicIfCalledPolicyEngine),
        known_zero_spend_reader(),
    );

    let status = service
        .refill_status(&account_id, &Period::parse(PERIOD).expect("valid period"))
        .await
        .expect("a fresh account's status must succeed");

    assert_eq!(
        status.current_tier,
        BudgetTier::B15,
        "no grants yet this period -> the same B15 default request_refill itself falls back to"
    );
    assert_eq!(status.next_tier, Some(BudgetTier::B30));
    assert_eq!(
        status.ladder.len(),
        7,
        "the full static ADR-0008 ladder, not just current/next"
    );
    assert_eq!(status.ladder[0].tier, BudgetTier::B15);
    assert_eq!(status.ladder[0].amount_micros, 15_000_000);
    assert_eq!(status.ladder[6].tier, BudgetTier::B1000);
    assert_eq!(status.ladder[6].amount_micros, 1_000_000_000);
}

#[sqlx::test(migrations = "../../migrations")]
async fn refill_status_resolves_current_tier_from_the_latest_tier_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = BudgetRepo::new(Arc::clone(&db_pool));
    budget_repo
        .grant(seed_grant_request(
            &account_id,
            GrantSource::SelfService,
            BudgetTier::B30.amount().get(),
        ))
        .await
        .expect("seed grant must succeed");

    let service = RefillService::new(
        Arc::new(budget_repo),
        Arc::new(AugmentationRepo::new(Arc::clone(&db_pool))),
        Arc::new(PanicIfCalledPolicyEngine),
        known_zero_spend_reader(),
    );

    let status = service
        .refill_status(&account_id, &Period::parse(PERIOD).expect("valid period"))
        .await
        .expect("status must succeed");

    assert_eq!(
        status.current_tier,
        BudgetTier::B30,
        "must read back the latest tier grant (B30), not always default to B15"
    );
    assert_eq!(status.next_tier, Some(BudgetTier::B60));
}

#[sqlx::test(migrations = "../../migrations")]
async fn refill_status_at_top_rung_has_no_next_tier(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = BudgetRepo::new(Arc::clone(&db_pool));
    budget_repo
        .grant(seed_grant_request(
            &account_id,
            GrantSource::Admin,
            BudgetTier::B1000.amount().get(),
        ))
        .await
        .expect("seeding the top-rung grant must succeed");

    let service = RefillService::new(
        Arc::new(budget_repo),
        Arc::new(AugmentationRepo::new(Arc::clone(&db_pool))),
        Arc::new(PanicIfCalledPolicyEngine),
        known_zero_spend_reader(),
    );

    let status = service
        .refill_status(&account_id, &Period::parse(PERIOD).expect("valid period"))
        .await
        .expect("status must succeed even at the top rung");

    assert_eq!(status.current_tier, BudgetTier::B1000);
    assert_eq!(
        status.next_tier, None,
        "top rung has nothing further, mirroring request_refill's already_at_top_rung case"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn refill_status_never_calls_the_policy_engine(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    // PanicIfCalledPolicyEngine::evaluate panics if invoked -- reaching a returned status at all
    // (rather than a panic) is the proof this read never touches policy evaluation.
    let service = refill_service(
        &pool,
        Arc::new(PanicIfCalledPolicyEngine),
        known_zero_spend_reader(),
    );

    let status = service
        .refill_status(&account_id, &Period::parse(PERIOD).expect("valid period"))
        .await
        .expect("status must succeed without ever calling the policy engine");

    assert_eq!(status.current_tier, BudgetTier::B15);
}

#[sqlx::test(migrations = "../../migrations")]
async fn refill_status_next_tier_agrees_with_what_request_refill_would_actually_request(
    pool: PgPool,
) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let service = refill_service(&pool, default_policy_engine(), known_zero_spend_reader());
    let period = Period::parse(PERIOD).expect("valid period");

    let status_before = service
        .refill_status(&account_id, &period)
        .await
        .expect("status before any refill must succeed");

    let request_result = service
        .request_refill(base_request(&account_id, None))
        .await
        .expect("refill must succeed");

    assert_eq!(
        status_before.next_tier,
        Some(request_result.requested_tier),
        "the ladder preview must never promise a rung that the real request path disagrees with"
    );
}
