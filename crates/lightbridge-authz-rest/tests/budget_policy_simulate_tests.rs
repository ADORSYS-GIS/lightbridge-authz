// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Direct-call coverage for `simulateBudgetPolicy` (#190, ADR-0007;
//! `Procedures::simulate_budget_policy`), the last piece of the budget-policy RPC surface.
//!
//! #190's acceptance criteria for this endpoint: "Given the simulation endpoint and a proposed
//! change, when it is run, then it reports what would happen -- without granting anything," and
//! "Simulation has no side effects -- asserted by a test, not by inspection." This file's second
//! test (`simulation_writes_nothing_to_the_ledger_or_policy_tables`) is that assertion: it
//! snapshots real row counts across the three tables a careless implementation could plausibly
//! touch and proves they are exactly unchanged after a simulation run, against a real, migrated
//! Postgres database -- not reasoning about the code, demonstrating it.
//!
//! Same rationale as `budget_policy_procedure_tests.rs` for calling `Procedures` methods directly
//! rather than standing up the full HTTP router: it keeps this file independent of Redis (needed
//! only by the rate-limiting middleware `rpc_it_tests.rs` exercises) while still proving the real
//! `Procedures` -> `RuleDataEngine` code path a genuine RPC call would take past `rpc_authorize`
//! and cratestack's own dispatch.
#![cfg(feature = "it-tests")]

use std::sync::Arc;

use cratestack::{CratestackContext, CratestackError, Value};
use lightbridge_authz_api::schema;
use lightbridge_authz_api::schema::procedures::ProcedureRegistry;
use lightbridge_authz_budget::PolicyStore;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::Procedures;
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;

const SEEDED_POLICY_SET_ID: &str = "budget-refill";
// ADR-0015: the seeded-active revision as of migration 20260819000001 -- see the identical
// comment in `lightbridge-authz-budget`'s own `policy_store_tests.rs`.
const SEEDED_POLICY_REVISION: &str = "budget-policy-v2-adr0015";
const EVALUATION_BUDGET: usize = 10_000;

/// A proposed policy that genuinely differs from the seeded active one
/// (`SEEDED_POLICY_REVISION`, `self_service_grant_count lt 2`): raises the unaided-rung threshold
/// to `10`. Paired with `SCENARIO_GRANT_COUNT_5_JSON` below, this auto-approves under the
/// proposed policy but would NOT auto-approve under the currently active one (`5` is not `lt 2`).
fn proposed_rule_data_json(policy_revision: &str) -> String {
    format!(
        r#"{{
          "policy_revision": "{policy_revision}",
          "rules": [
            {{
              "id": "within-unaided-allowance",
              "condition": {{ "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": 10 }},
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

/// Syntactically valid JSON, but invalid rule data (a duplicate rule id) -- same reasoning as the
/// identical constant in `budget_policy_procedure_tests.rs`.
const MALFORMED_RULE_DATA: &str = r#"{
  "policy_revision": "budget-policy-malformed-sim",
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

/// A scenario (`Facts`, see `crates/lightbridge-authz-budget/src/facts.rs`) with
/// `self_service_grant_count: 5` -- within `proposed_rule_data_json`'s `lt 10` threshold but
/// beyond the seeded active policy's `lt 2` threshold. Field names/`Spend` shape match the
/// `Serialize`/`Deserialize` derives added to `Facts`/`Spend` in this same PR.
const SCENARIO_GRANT_COUNT_5_JSON: &str = r#"{
  "effective_balance_micros": 100000000,
  "self_service_grant_count": 5,
  "spend_this_period": { "status": "known", "amount_micros": 0 },
  "spend_last_period": { "status": "known", "amount_micros": 0 }
}"#;

const MALFORMED_SCENARIO_JSON: &str = "{ this is not valid json";

/// A `schema::Cratestack` lazily wired to an unreachable address -- `simulate_budget_policy`
/// takes `_db: &schema::Cratestack` but never uses it (it never touches `PolicyStore` or any
/// repository), so this is never actually queried, matching the pattern already used for the
/// same purpose in `budget_policy_procedure_tests.rs`.
fn lazy_cratestack_db() -> schema::Cratestack {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy cratestack pool should be constructible");
    schema::Cratestack::builder(pool).build()
}

/// Builds a real `Procedures` instance against `pool` (a genuinely migrated, seeded database),
/// with a bearer subject sealed into the `CratestackContext` the way `CratestackAuthProvider` would for
/// a real authenticated request. `simulate_budget_policy` itself never touches `PolicyStore`, but
/// `Procedures::new` still requires one to construct -- same reasoning as
/// `budget_policy_procedure_tests.rs`.
async fn procedures_and_ctx(pool: PgPool, subject: &str) -> (Procedures, CratestackContext) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    let issuer = Arc::new(AuthzStoreImpl::with_pool(db_pool.clone()));
    let policy_store = Arc::new(
        PolicyStore::load_active_from_db(db_pool.clone(), SEEDED_POLICY_SET_ID, EVALUATION_BUDGET)
            .await
            .expect("migrations seed an active budget-refill revision"),
    );
    // `simulate_budget_policy` itself never touches `refill_service`/`review_service` either (see
    // the module doc), but `Procedures::new` still requires both to construct -- same reasoning
    // as `budget_policy_procedure_tests.rs`.
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        db_pool.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(db_pool));
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
    let procedures = Procedures::new(
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
    );
    let ctx =
        CratestackContext::authenticated([("id".to_owned(), Value::String(subject.to_owned()))]);
    (procedures, ctx)
}

/// Thin `invoke_with_db` wrapper (cratestack#512: `ProcedureRegistry` methods now require an
/// `Authorized` witness only `authorize_with_db`/`invoke_with_db` can produce). `simulateBudgetPolicy`
/// declares only `@allow(auth() != null)`, so this runs that check before invoking the registry
/// method, matching what the generated RPC dispatch handler does for a real request -- see
/// `budget_policy_procedure_tests.rs`'s identical pattern.
async fn simulate(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::simulate_budget_policy::Args,
) -> Result<schema::procedures::simulate_budget_policy::Output, CratestackError> {
    let call_args = args.clone();
    schema::procedures::simulate_budget_policy::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .simulate_budget_policy(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

/// Same wrapper as [`simulate`], for `getBudgetPolicyStatus` (also `@allow(auth() != null)`),
/// used by this file's "simulation writes nothing" test to read status before/after simulating.
async fn get_status(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CratestackContext,
    args: schema::procedures::get_budget_policy_status::Args,
) -> Result<schema::procedures::get_budget_policy_status::Output, CratestackError> {
    let call_args = args.clone();
    schema::procedures::get_budget_policy_status::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .get_budget_policy_status(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

fn simulate_args(
    rule_data_json: &str,
    scenario_json: &str,
    requested_amount_micros: &str,
) -> schema::procedures::simulate_budget_policy::Args {
    schema::procedures::simulate_budget_policy::Args {
        args: schema::SimulateBudgetPolicyInput {
            ruleDataJson: rule_data_json.to_string(),
            scenarioJson: scenario_json.to_string(),
            requestedAmountMicros: requested_amount_micros.to_string(),
        },
    }
}

fn status_args(policy_set_id: &str) -> schema::procedures::get_budget_policy_status::Args {
    schema::procedures::get_budget_policy_status::Args {
        args: schema::GetBudgetPolicyStatusInput {
            policySetId: policy_set_id.to_string(),
        },
    }
}

/// Row counts across every table a careless `simulateBudgetPolicy` implementation could
/// plausibly touch. Three separate `'static` query literals (rather than one dynamic-SQL helper
/// parameterized on table name) so `sqlx::query_scalar`'s `SqlSafeStr` bound is satisfied without
/// an `AssertSqlSafe` escape hatch for what would otherwise be a compiler-flagged dynamic string.
async fn ledger_and_policy_row_counts(pool: &PgPool) -> (i64, i64, i64) {
    let budget_grants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM budget_grants")
        .fetch_one(pool)
        .await
        .expect("counting rows in budget_grants should succeed");
    let budget_balances: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM budget_balances")
        .fetch_one(pool)
        .await
        .expect("counting rows in budget_balances should succeed");
    let budget_policy_revisions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM budget_policy_revisions")
            .fetch_one(pool)
            .await
            .expect("counting rows in budget_policy_revisions should succeed");
    (budget_grants, budget_balances, budget_policy_revisions)
}

#[sqlx::test(migrations = "../../migrations")]
async fn simulation_reports_the_decision_a_proposed_policy_would_make(pool: PgPool) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-simulate-decision").await;
    let db = lazy_cratestack_db();

    let proposed_revision = "budget-policy-simulated-v1";
    let decision = simulate(
        &procedures,
        &db,
        &ctx,
        simulate_args(
            &proposed_rule_data_json(proposed_revision),
            SCENARIO_GRANT_COUNT_5_JSON,
            "5000000",
        ),
    )
    .await
    .expect("a valid simulation must succeed");

    assert_eq!(
        decision.effect, "auto_approve",
        "the proposed policy's lt-10 threshold must auto-approve a grant_count-5 scenario, \
         which the currently active lt-2 policy would NOT: {decision:?}"
    );
    assert_eq!(decision.approvedAmountMicros, "5000000");
    assert_eq!(decision.policyRevision, proposed_revision);
    assert_eq!(decision.matchedRuleIds, vec!["within-unaided-allowance"]);
}

/// The load-bearing test for this PR (#190: "Simulation has no side effects -- asserted by a
/// test, not by inspection"). Uses rule data/a scenario that, if `simulateBudgetPolicy` actually
/// activated the proposed policy (the exact bug a careless implementation could introduce), would
/// insert a new row into `budget_policy_revisions` -- proving the row counts are unchanged proves
/// that did not happen, rather than merely reasoning that the code has no write path.
///
/// Verified to actually catch that bug: temporarily changed `Procedures::simulate_budget_policy`
/// to call `self.policy_store.activate(&rule_data_json, ...)` before evaluating, reran this test,
/// and confirmed the `budget_policy_revisions` count assertion failed (revealing the row the
/// buggy version persisted) before reverting to the real, non-persisting implementation.
#[sqlx::test(migrations = "../../migrations")]
async fn simulation_writes_nothing_to_the_ledger_or_policy_tables(pool: PgPool) {
    let before = ledger_and_policy_row_counts(&pool).await;

    let (procedures, ctx) = procedures_and_ctx(pool.clone(), "tester-simulate-no-write").await;
    let db = lazy_cratestack_db();

    let decision = simulate(
        &procedures,
        &db,
        &ctx,
        simulate_args(
            &proposed_rule_data_json("budget-policy-simulated-would-persist"),
            SCENARIO_GRANT_COUNT_5_JSON,
            "5000000",
        ),
    )
    .await
    .expect("a valid simulation must succeed");
    assert_eq!(
        decision.effect, "auto_approve",
        "sanity check that the simulated policy really would have produced a grant-worthy \
         decision, which is exactly the case a persisting bug would have written a real \
         revision/grant for"
    );

    let after = ledger_and_policy_row_counts(&pool).await;
    assert_eq!(
        before, after,
        "(budget_grants, budget_balances, budget_policy_revisions) row counts must be \
         byte-for-byte unchanged by a simulation run"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_budget_policy_status_is_unaffected_by_a_simulation_run(pool: PgPool) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-simulate-status").await;
    let db = lazy_cratestack_db();

    let status_before = get_status(&procedures, &db, &ctx, status_args(SEEDED_POLICY_SET_ID))
        .await
        .expect("status read must succeed");
    assert_eq!(status_before.activePolicyRevision, SEEDED_POLICY_REVISION);

    // A different `policy_revision` than what's active, so a leak would be unmissable.
    simulate(
        &procedures,
        &db,
        &ctx,
        simulate_args(
            &proposed_rule_data_json("budget-policy-simulated-should-not-leak"),
            SCENARIO_GRANT_COUNT_5_JSON,
            "5000000",
        ),
    )
    .await
    .expect("a valid simulation must succeed");

    let status_after = get_status(&procedures, &db, &ctx, status_args(SEEDED_POLICY_SET_ID))
        .await
        .expect("status read must succeed");
    assert_eq!(
        status_after.activePolicyRevision, SEEDED_POLICY_REVISION,
        "a simulation run must not even LOOK like it changed the active policy from a caller's \
         perspective, not just at the row-count level"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn malformed_scenario_json_is_rejected(pool: PgPool) {
    let before = ledger_and_policy_row_counts(&pool).await;
    let (procedures, ctx) = procedures_and_ctx(pool.clone(), "tester-simulate-bad-scenario").await;
    let db = lazy_cratestack_db();

    let result = simulate(
        &procedures,
        &db,
        &ctx,
        simulate_args(
            &proposed_rule_data_json("budget-policy-simulated-bad-scenario"),
            MALFORMED_SCENARIO_JSON,
            "5000000",
        ),
    )
    .await;

    match result {
        Err(cratestack::CratestackError::BadRequest(_)) => {}
        other => panic!("malformed scenarioJson must be rejected as BadRequest, got: {other:?}"),
    }

    let after = ledger_and_policy_row_counts(&pool).await;
    assert_eq!(
        before, after,
        "a rejected simulation must not write anything either"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn malformed_rule_data_is_rejected(pool: PgPool) {
    let before = ledger_and_policy_row_counts(&pool).await;
    let (procedures, ctx) = procedures_and_ctx(pool.clone(), "tester-simulate-bad-ruledata").await;
    let db = lazy_cratestack_db();

    let result = simulate(
        &procedures,
        &db,
        &ctx,
        simulate_args(MALFORMED_RULE_DATA, SCENARIO_GRANT_COUNT_5_JSON, "5000000"),
    )
    .await;

    match result {
        Err(cratestack::CratestackError::BadRequest(_)) => {}
        other => panic!("malformed ruleDataJson must be rejected as BadRequest, got: {other:?}"),
    }

    let after = ledger_and_policy_row_counts(&pool).await;
    assert_eq!(
        before, after,
        "a rejected simulation must not write anything either"
    );
}
