// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Direct-call coverage for the budget policy lifecycle procedures (ADR-0007;
//! `Procedures::activate_budget_policy` / `Procedures::get_budget_policy_status`, backed by
//! `lightbridge_authz_budget::PolicyStore`).
//!
//! This exercises the real wiring (`Procedures` -> `PolicyStore` -> `RuleDataEngine` -> DB) by
//! calling the two `ProcedureRegistry` methods **directly** against a real, migrated Postgres
//! database, rather than standing up the full HTTP router -- that keeps this file independent of
//! Redis (which the rest of the `it-tests` surface, `rpc_it_tests.rs`, needs for rate limiting)
//! while still proving the actual code path a real RPC call would take once past `rpc_authorize`
//! and cratestack's own dispatch. See the PR description for whether HTTP-level coverage through
//! the full router was added on top of this as a stretch goal.
#![cfg(feature = "it-tests")]

use std::sync::Arc;

use cratestack::{CoolContext, CoolError, Value};
use lightbridge_authz_api::schema;
use lightbridge_authz_api::schema::procedures::ProcedureRegistry;
use lightbridge_authz_budget::PolicyStore;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::Procedures;
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;

const SEEDED_POLICY_SET_ID: &str = "budget-refill";
const SEEDED_POLICY_REVISION: &str = "budget-policy-v1";
const SEEDED_REVISION_ID: &str = "budget-refill-v1";
const EVALUATION_BUDGET: usize = 10_000;

/// Syntactically valid JSON, but invalid rule data (a duplicate rule id) -- exercises the real
/// "validate before writing, and leave the previous revision serving on rejection" path, same
/// reasoning as the identical constant in `lightbridge-authz-budget`'s own `policy_store_tests.rs`.
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
  "default_reason_code": "default_reason"
}"#;

fn valid_replacement_rule_data(policy_revision: &str) -> String {
    format!(
        r#"{{
          "policy_revision": "{policy_revision}",
          "rules": [
            {{
              "id": "within-unaided-allowance",
              "condition": {{ "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": 5 }},
              "effect": "auto_approve",
              "reason_code": "within_unaided_allowance"
            }}
          ],
          "default_effect": "manual_review",
          "default_reason_code": "unaided_allowance_exhausted"
        }}"#
    )
}

/// A `schema::Cratestack` lazily wired to an unreachable address -- the two procedures under test
/// take `_db: &schema::Cratestack` but never use it (they delegate entirely to `PolicyStore`), so
/// this is never actually queried, matching the pattern already used for the same purpose in
/// `rpc_router_tests.rs`/`lib_tests.rs`.
fn lazy_cratestack_db() -> schema::Cratestack {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy cratestack pool should be constructible");
    schema::Cratestack::builder(pool).build()
}

/// Builds a real `Procedures` instance against `pool` (a genuinely migrated, seeded database --
/// see the module doc), with a bearer subject sealed into the `CoolContext` the way
/// `CratestackAuthProvider` would for a real authenticated request.
async fn procedures_and_ctx(pool: PgPool, subject: &str) -> (Procedures, CoolContext) {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    let issuer = Arc::new(AuthzStoreImpl::with_pool(db_pool.clone()));
    let policy_store = Arc::new(
        PolicyStore::load_active_from_db(db_pool.clone(), SEEDED_POLICY_SET_ID, EVALUATION_BUDGET)
            .await
            .expect("migrations seed an active budget-refill revision"),
    );
    // This file only exercises `activate_budget_policy`/`get_budget_policy_status`, neither of
    // which touches `refill_service`/`review_service` -- but `Procedures::new` requires both to
    // construct. Real repos against the same live `db_pool`, `UnavailableSpendReader` since no
    // test here reaches a spend-dependent policy fact.
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
    let ctx = CoolContext::authenticated([("id".to_owned(), Value::String(subject.to_owned()))]);
    (procedures, ctx)
}

/// Thin `invoke_with_db` wrapper (cratestack#512: `ProcedureRegistry` methods now require an
/// `Authorized` witness only `authorize_with_db`/`invoke_with_db` can produce, closing the exact
/// direct-call bypass this file's module doc describes). Runs the real `@allow(auth() != null)`
/// check `activateBudgetPolicy` declares before invoking the registry method, matching what the
/// generated RPC dispatch handler does for a real request.
async fn activate(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CoolContext,
    args: schema::procedures::activate_budget_policy::Args,
) -> Result<schema::procedures::activate_budget_policy::Output, CoolError> {
    let call_args = args.clone();
    schema::procedures::activate_budget_policy::invoke_with_db(
        db,
        &args,
        ctx,
        |authorized| async move {
            procedures
                .activate_budget_policy(db, ctx, call_args, authorized)
                .await
        },
    )
    .await
}

/// Same wrapper as [`activate`], for `getBudgetPolicyStatus` (also `@allow(auth() != null)`).
async fn get_status(
    procedures: &Procedures,
    db: &schema::Cratestack,
    ctx: &CoolContext,
    args: schema::procedures::get_budget_policy_status::Args,
) -> Result<schema::procedures::get_budget_policy_status::Output, CoolError> {
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

fn activate_args(
    policy_set_id: &str,
    rule_data_json: Option<String>,
    revision_id: Option<String>,
) -> schema::procedures::activate_budget_policy::Args {
    schema::procedures::activate_budget_policy::Args {
        args: schema::ActivateBudgetPolicyInput {
            policySetId: policy_set_id.to_string(),
            ruleDataJson: rule_data_json,
            revisionId: revision_id,
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

#[sqlx::test(migrations = "../../migrations")]
async fn activating_new_rule_data_is_immediately_reflected_by_status(pool: PgPool) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-activate").await;
    let db = lazy_cratestack_db();

    let new_rule_data = valid_replacement_rule_data("budget-policy-v2-it");
    let activate_output = activate(
        &procedures,
        &db,
        &ctx,
        activate_args(SEEDED_POLICY_SET_ID, Some(new_rule_data), None),
    )
    .await
    .expect("valid rule data must activate");

    assert_eq!(activate_output.policySetId, SEEDED_POLICY_SET_ID);
    assert_eq!(activate_output.activePolicyRevision, "budget-policy-v2-it");

    let status = get_status(&procedures, &db, &ctx, status_args(SEEDED_POLICY_SET_ID))
        .await
        .expect("status read must succeed");
    assert_eq!(
        status.activePolicyRevision, "budget-policy-v2-it",
        "status must reflect the just-activated revision with no restart needed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn malformed_rule_data_is_rejected_and_status_still_reports_the_original_revision(
    pool: PgPool,
) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-malformed").await;
    let db = lazy_cratestack_db();

    let result = activate(
        &procedures,
        &db,
        &ctx,
        activate_args(
            SEEDED_POLICY_SET_ID,
            Some(MALFORMED_RULE_DATA.to_string()),
            None,
        ),
    )
    .await;
    assert!(
        result.is_err(),
        "malformed rule data must be rejected, not silently activated: {result:?}"
    );

    let status = get_status(&procedures, &db, &ctx, status_args(SEEDED_POLICY_SET_ID))
        .await
        .expect("status read must succeed");
    assert_eq!(
        status.activePolicyRevision, SEEDED_POLICY_REVISION,
        "a failed load must leave the previous revision serving, and status reporting must say so"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn rollback_via_revision_id_works_and_status_reflects_it(pool: PgPool) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-rollback").await;
    let db = lazy_cratestack_db();

    // Activate a new revision first, so there is genuinely something to roll back FROM.
    let new_rule_data = valid_replacement_rule_data("budget-policy-v3-it");
    activate(
        &procedures,
        &db,
        &ctx,
        activate_args(SEEDED_POLICY_SET_ID, Some(new_rule_data), None),
    )
    .await
    .expect("valid rule data must activate");

    // Roll back to the originally seeded revision by id (the runbook's rollback flow).
    let rollback_output = activate(
        &procedures,
        &db,
        &ctx,
        activate_args(
            SEEDED_POLICY_SET_ID,
            None,
            Some(SEEDED_REVISION_ID.to_string()),
        ),
    )
    .await
    .expect("rolling back to an existing revision id must succeed");
    assert_eq!(rollback_output.activePolicyRevision, SEEDED_POLICY_REVISION);

    let status = get_status(&procedures, &db, &ctx, status_args(SEEDED_POLICY_SET_ID))
        .await
        .expect("status read must succeed");
    assert_eq!(
        status.activePolicyRevision, SEEDED_POLICY_REVISION,
        "status must reflect the rolled-back revision immediately"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn supplying_both_rule_data_and_revision_id_is_rejected(pool: PgPool) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-both").await;
    let db = lazy_cratestack_db();

    let result = activate(
        &procedures,
        &db,
        &ctx,
        activate_args(
            SEEDED_POLICY_SET_ID,
            Some(valid_replacement_rule_data("budget-policy-both")),
            Some(SEEDED_REVISION_ID.to_string()),
        ),
    )
    .await;
    assert!(
        result.is_err(),
        "supplying both ruleDataJson and revisionId must be rejected: {result:?}"
    );

    let status = get_status(&procedures, &db, &ctx, status_args(SEEDED_POLICY_SET_ID))
        .await
        .expect("status read must succeed");
    assert_eq!(
        status.activePolicyRevision, SEEDED_POLICY_REVISION,
        "a rejected activation must not change what's serving"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn supplying_neither_rule_data_nor_revision_id_is_rejected(pool: PgPool) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-neither").await;
    let db = lazy_cratestack_db();

    let result = activate(
        &procedures,
        &db,
        &ctx,
        activate_args(SEEDED_POLICY_SET_ID, None, None),
    )
    .await;
    assert!(
        result.is_err(),
        "supplying neither ruleDataJson nor revisionId must be rejected: {result:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_policy_set_id_is_rejected_by_both_procedures(pool: PgPool) {
    let (procedures, ctx) = procedures_and_ctx(pool, "tester-unknown-set").await;
    let db = lazy_cratestack_db();

    let activate_result = activate(
        &procedures,
        &db,
        &ctx,
        activate_args(
            "not-a-real-policy-set",
            Some(valid_replacement_rule_data("budget-policy-unreachable")),
            None,
        ),
    )
    .await;
    assert!(
        activate_result.is_err(),
        "an unknown policySetId must be rejected, not silently redirected to the real set: \
         {activate_result:?}"
    );

    let status_result =
        get_status(&procedures, &db, &ctx, status_args("not-a-real-policy-set")).await;
    assert!(
        status_result.is_err(),
        "an unknown policySetId must be rejected on the read path too: {status_result:?}"
    );
}
