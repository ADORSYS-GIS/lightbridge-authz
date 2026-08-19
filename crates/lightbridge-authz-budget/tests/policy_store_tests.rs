#![cfg(feature = "it-tests")]

use std::sync::Arc;

use lightbridge_authz_budget::decision::{Effect, PolicyEngine};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::facts::Facts;
use lightbridge_authz_budget::policy_store::PolicyStore;
use lightbridge_authz_budget::spend::Spend;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

const SEEDED_POLICY_SET_ID: &str = "budget-refill";
// ADR-0015: the seeded-active revision as of migration 20260819000001, which supersedes
// 20260804000001's original `budget-policy-v1`/`budget-refill-v1` seed (still present as an
// inactive row -- migrations are immutable, so the ADR-0015 migration inserts and activates a
// second revision rather than editing the first).
const SEEDED_POLICY_REVISION: &str = "budget-policy-v2-adr0015";
const SEEDED_REVISION_ID: &str = "budget-refill-v2-adr0015";
const EVALUATION_BUDGET: usize = 1_000;

/// Deliberately valid JSON *syntax* (so a JSONB column would happily store it) but invalid rule
/// data (a duplicate rule id) -- this is what actually exercises the "validate before writing"
/// ordering `PolicyStore::activate` promises. A syntactically-broken JSON string would never
/// reach `validate_rule_data` at all in either ordering, because a `::jsonb` cast rejects it at
/// the database level before any application code runs -- it would not distinguish a correct
/// implementation from a buggy one that writes before validating.
const MALFORMED_RULE_DATA: &str = r#"{
  "policy_revision": "budget-policy-malformed",
  "rules": [
    {
      "id": "dup",
      "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
      "effect": "auto_approve",
      "reason_code": "a"
    },
    {
      "id": "dup",
      "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
      "effect": "deny",
      "reason_code": "b"
    }
  ],
  "default_effect": "manual_review",
  "default_reason_code": "default_reason",
  "allowed_amounts_micros": [6000000, 15000000, 30000000],
  "starting_amount_micros": 15000000,
  "fail_closed_floor_micros": 6000000
}"#;

fn facts_with_grant_count(self_service_grant_count: i32) -> Facts {
    Facts {
        effective_balance_micros: 100_000_000,
        self_service_grant_count,
        spend_this_period: Spend::Known(0),
        spend_last_period: Spend::Known(0),
    }
}

fn valid_replacement_rule_data(policy_revision: &str, threshold: i64) -> String {
    format!(
        r#"{{
          "policy_revision": "{policy_revision}",
          "rules": [
            {{
              "id": "within-unaided-allowance",
              "condition": {{ "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": {threshold} }},
              "effect": "auto_approve",
              "reason_code": "within_unaided_allowance"
            }}
          ],
          "default_effect": "manual_review",
          "default_reason_code": "unaided_allowance_exhausted",
          "allowed_amounts_micros": [6000000, 15000000, 30000000],
          "starting_amount_micros": 15000000,
          "fail_closed_floor_micros": 6000000
        }}"#
    )
}

async fn active_revision_id(pool: &PgPool, policy_set_id: &str) -> Option<String> {
    let row: (Option<String>,) =
        sqlx::query_as("SELECT active_revision_id FROM budget_policy_sets WHERE id = $1")
            .bind(policy_set_id)
            .fetch_one(pool)
            .await
            .expect("policy set row must exist");
    row.0
}

async fn revision_count(pool: &PgPool, policy_set_id: &str) -> i64 {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM budget_policy_revisions WHERE policy_set_id = $1")
            .bind(policy_set_id)
            .fetch_one(pool)
            .await
            .expect("count query must succeed");
    row.0
}

#[sqlx::test(migrations = "../../migrations")]
async fn load_active_from_db_reflects_the_seeded_default_policy(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));

    let store = PolicyStore::load_active_from_db(db_pool, SEEDED_POLICY_SET_ID, EVALUATION_BUDGET)
        .await
        .expect("the migration seeds an active revision for budget-refill");

    assert_eq!(store.active_policy_revision(), SEEDED_POLICY_REVISION);

    let engine = store.engine();

    let within_allowance = engine
        .evaluate(&facts_with_grant_count(0), 5_000_000)
        .await
        .expect("evaluation succeeds");
    assert_eq!(within_allowance.effect, Effect::AutoApprove);
    assert_eq!(within_allowance.approved_amount_micros, 5_000_000);

    let beyond_allowance = engine
        .evaluate(&facts_with_grant_count(2), 5_000_000)
        .await
        .expect("evaluation succeeds");
    assert_eq!(beyond_allowance.effect, Effect::ManualReview);
}

#[sqlx::test(migrations = "../../migrations")]
async fn activate_with_valid_rule_data_persists_and_hot_swaps(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));

    let store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("seeded policy set loads");

    let new_revision_data = valid_replacement_rule_data("budget-policy-v2-test", 5);

    let returned_revision = store
        .activate(&new_revision_data, Some("tester"))
        .await
        .expect("valid rule data must activate");
    assert_eq!(returned_revision, "budget-policy-v2-test");

    assert_eq!(
        store.active_policy_revision(),
        "budget-policy-v2-test",
        "the live engine on the same store instance must reflect the new revision immediately"
    );

    let new_active_id = active_revision_id(&pool, SEEDED_POLICY_SET_ID)
        .await
        .expect("active_revision_id must be set");
    let (persisted_revision,): (String,) =
        sqlx::query_as("SELECT policy_revision FROM budget_policy_revisions WHERE id = $1")
            .bind(&new_active_id)
            .fetch_one(&pool)
            .await
            .expect("the newly activated revision row must exist");
    assert_eq!(persisted_revision, "budget-policy-v2-test");

    let restarted_store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("a fresh load simulating a restart must succeed");
    assert_eq!(
        restarted_store.active_policy_revision(),
        "budget-policy-v2-test",
        "a fresh PolicyStore built after activation must also see the new revision"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn activate_with_malformed_rule_data_leaves_everything_unchanged(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));

    let store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("seeded policy set loads");

    let count_before = revision_count(&pool, SEEDED_POLICY_SET_ID).await;
    let active_id_before = active_revision_id(&pool, SEEDED_POLICY_SET_ID).await;

    let result = store.activate(MALFORMED_RULE_DATA, None).await;
    assert!(
        matches!(result, Err(BudgetError::InvalidRuleData(_))),
        "malformed rule data must be rejected as InvalidRuleData: {result:?}"
    );

    assert_eq!(
        store.active_policy_revision(),
        SEEDED_POLICY_REVISION,
        "the live engine must be untouched by a rejected activation"
    );

    let count_after = revision_count(&pool, SEEDED_POLICY_SET_ID).await;
    assert_eq!(
        count_after, count_before,
        "a rejected activation must not insert any row, not even a rejected/failed one"
    );

    let active_id_after = active_revision_id(&pool, SEEDED_POLICY_SET_ID).await;
    assert_eq!(
        active_id_after, active_id_before,
        "a rejected activation must not repoint active_revision_id"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_policy_set_is_a_loud_error(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));

    let result = PolicyStore::load_active_from_db(
        db_pool,
        "some-id-that-was-never-seeded",
        EVALUATION_BUDGET,
    )
    .await;

    assert!(
        matches!(result, Err(BudgetError::StorageFailed(_))),
        "a policy set id that doesn't exist must be a clear, typed error, not a panic or a \
         silently-empty default engine: {result:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn activate_by_revision_id_rolls_back_to_an_existing_revision(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));

    let store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("seeded policy set loads");

    // Activate a brand-new revision first, so there is genuinely something to roll back FROM.
    let new_revision_data = valid_replacement_rule_data("budget-policy-v2-test", 5);
    store
        .activate(&new_revision_data, Some("tester"))
        .await
        .expect("valid rule data must activate");
    assert_eq!(store.active_policy_revision(), "budget-policy-v2-test");

    let count_before_rollback = revision_count(&pool, SEEDED_POLICY_SET_ID).await;

    // Roll back to the original seeded revision by id -- this must NOT insert a new row, unlike
    // resubmitting the same rule data through `activate` (which would collide with the
    // `UNIQUE (policy_set_id, policy_revision)` constraint).
    let reactivated_revision = store
        .activate_by_revision_id(SEEDED_REVISION_ID)
        .await
        .expect("rolling back to an existing revision id must succeed");
    assert_eq!(reactivated_revision, SEEDED_POLICY_REVISION);

    assert_eq!(
        store.active_policy_revision(),
        SEEDED_POLICY_REVISION,
        "the live engine on the same store instance must reflect the reactivated revision \
         immediately"
    );

    let count_after_rollback = revision_count(&pool, SEEDED_POLICY_SET_ID).await;
    assert_eq!(
        count_after_rollback, count_before_rollback,
        "rollback-by-id must never insert a new revision row -- it only re-points \
         active_revision_id at the one that already exists"
    );

    let active_id = active_revision_id(&pool, SEEDED_POLICY_SET_ID)
        .await
        .expect("active_revision_id must be set");
    assert_eq!(
        active_id, SEEDED_REVISION_ID,
        "active_revision_id must point back at the original seeded revision row"
    );

    let restarted_store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("a fresh load simulating a restart must succeed");
    assert_eq!(
        restarted_store.active_policy_revision(),
        SEEDED_POLICY_REVISION,
        "a fresh PolicyStore built after the rollback must also see the original revision"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn activate_by_revision_id_rejects_an_unknown_revision(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));

    let store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("seeded policy set loads");

    let active_id_before = active_revision_id(&pool, SEEDED_POLICY_SET_ID).await;

    let result = store
        .activate_by_revision_id("some-revision-id-that-was-never-created")
        .await;

    assert!(
        matches!(result, Err(BudgetError::StorageFailed(_))),
        "rolling back to a nonexistent revision id must be a clear, typed error, not a panic or \
         a silent no-op: {result:?}"
    );

    assert_eq!(
        store.active_policy_revision(),
        SEEDED_POLICY_REVISION,
        "the live engine must be untouched by a rejected rollback"
    );

    let active_id_after = active_revision_id(&pool, SEEDED_POLICY_SET_ID).await;
    assert_eq!(
        active_id_after, active_id_before,
        "a rejected rollback must not repoint active_revision_id"
    );
}

/// `budget:policy-write`'s domain method: a new revision is inserted, but the previously active
/// revision is untouched -- both by id (`active_revision_id` unchanged) and by what the live
/// engine actually serves. This is the "a bad revision never displaces a good one" property
/// applied to the write path: even a genuinely valid new revision must not go live just because
/// it was authored.
#[sqlx::test(migrations = "../../migrations")]
async fn create_revision_inserts_without_activating(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));

    let store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("seeded policy set loads");

    let active_id_before = active_revision_id(&pool, SEEDED_POLICY_SET_ID)
        .await
        .expect("active_revision_id must be set");
    let count_before = revision_count(&pool, SEEDED_POLICY_SET_ID).await;

    let candidate_data = valid_replacement_rule_data("budget-policy-authored-not-activated", 7);
    let new_revision = store
        .create_revision(&candidate_data, Some("policy-author"))
        .await
        .expect("valid rule data must be writable as a new revision");

    assert_eq!(
        new_revision.policy_revision,
        "budget-policy-authored-not-activated"
    );

    // The row genuinely exists...
    let (persisted_revision,): (String,) =
        sqlx::query_as("SELECT policy_revision FROM budget_policy_revisions WHERE id = $1")
            .bind(&new_revision.id)
            .fetch_one(&pool)
            .await
            .expect("the newly written revision row must exist");
    assert_eq!(persisted_revision, "budget-policy-authored-not-activated");
    let count_after = revision_count(&pool, SEEDED_POLICY_SET_ID).await;
    assert_eq!(
        count_after,
        count_before + 1,
        "exactly one new revision row must be inserted"
    );

    // ...but nothing about what's active changed, at either layer.
    assert_eq!(
        store.active_policy_revision(),
        SEEDED_POLICY_REVISION,
        "the live engine on the same store instance must still serve the original revision"
    );
    let active_id_after = active_revision_id(&pool, SEEDED_POLICY_SET_ID)
        .await
        .expect("active_revision_id must still be set");
    assert_eq!(
        active_id_after, active_id_before,
        "create_revision must never repoint active_revision_id"
    );

    // A separate activate_by_revision_id call is what would later make it serve -- proving the
    // row really is a legitimate, activatable revision, not a malformed write that merely looks
    // like one.
    let activated = store
        .activate_by_revision_id(&new_revision.id)
        .await
        .expect("the written-but-not-yet-active revision must be activatable by id");
    assert_eq!(activated, "budget-policy-authored-not-activated");
    assert_eq!(
        store.active_policy_revision(),
        "budget-policy-authored-not-activated"
    );
}

/// Mirrors `activate_with_malformed_rule_data_leaves_everything_unchanged`: `create_revision`
/// validates BEFORE writing, so a rejected candidate leaves no trace in
/// `budget_policy_revisions` at all -- not even a "rejected" row.
#[sqlx::test(migrations = "../../migrations")]
async fn create_revision_with_malformed_rule_data_writes_nothing(pool: PgPool) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));

    let store = PolicyStore::load_active_from_db(
        Arc::clone(&db_pool),
        SEEDED_POLICY_SET_ID,
        EVALUATION_BUDGET,
    )
    .await
    .expect("seeded policy set loads");

    let count_before = revision_count(&pool, SEEDED_POLICY_SET_ID).await;

    let result = store.create_revision(MALFORMED_RULE_DATA, None).await;
    assert!(
        matches!(result, Err(BudgetError::InvalidRuleData(_))),
        "malformed rule data must be rejected as InvalidRuleData: {result:?}"
    );

    let count_after = revision_count(&pool, SEEDED_POLICY_SET_ID).await;
    assert_eq!(
        count_after, count_before,
        "a rejected create_revision call must not insert any row, not even a rejected one"
    );
    assert_eq!(
        store.active_policy_revision(),
        SEEDED_POLICY_REVISION,
        "the live engine must be completely untouched by a rejected write"
    );
}
