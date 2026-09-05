//! DB-backed tests for the starting grant a new account is funded with (#697).
//!
//! Real ephemeral Postgres (`sqlx::test`) with the real migrations, for the same reason
//! `reset_schedule_tests` does it: the behaviour is about SQL. The amount comes out of a
//! precedence query over `budget_reset_schedules ⋈ accounts ⋈ projects ⋈ api_keys`, the
//! no-double-grant property is `budget_grants`' partial unique index on `idempotency_key`, and
//! "the next schedule run is a no-op" is `delta = target − remaining` arithmetic against a real
//! ledger. None of that survives a mock.
//!
//! The migrations seed the `"budget-refill"` policy set with ADR-0015's real document, whose
//! `starting_amount_micros` is $15 — so the policy-fallback test asserts against the shipped
//! default rather than a fixture, which is the number production would actually use.

#![cfg(feature = "it-tests")]
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::BudgetRepo;
use lightbridge_authz_budget::reset_schedule::{ResetMode, ScheduleScopeKind};
use lightbridge_authz_budget::reset_scheduler::ResetScheduler;
use lightbridge_authz_budget::snapshot::BudgetSnapshotReader;
use lightbridge_authz_budget::snapshot_store::SnapshotStore;
use lightbridge_authz_budget::spend::{Spend, SpendReader};
use lightbridge_authz_budget::starting_grant::StartingGrantService;
use lightbridge_authz_budget::starting_grant_amount::{
    StartingAmount, starting_grant_idempotency_key,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

/// The policy set the migrations seed and every server activates against.
const POLICY_SET_ID: &str = "budget-refill";
const EVALUATION_BUDGET: usize = 10_000;

/// ADR-0015's shipped `starting_amount_micros`, seeded by
/// `migrations/20260819000001_budget_policy_adr0015_amounts.sql`.
const POLICY_STARTING_AMOUNT_MICROS: i64 = 15_000_000;

/// The live free-plan schedule's target on 2026-09-04 (`docs/budget-cli.md`, "The $8-vs-$15
/// rule"). Deliberately different from the policy default, so a test that reads the wrong one
/// cannot pass by coincidence.
const SCHEDULE_AMOUNT_MICROS: i64 = 8_000_000;

fn at(day: u32, hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, day, hour, 0, 0)
        .single()
        .expect("valid UTC instant")
}

#[derive(Debug, Default)]
struct MapSpendReader {
    known: HashMap<String, i64>,
}

impl MapSpendReader {
    fn with(mut self, account_id: &str, spent_micros: i64) -> Self {
        self.known.insert(account_id.to_string(), spent_micros);
        self
    }
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for MapSpendReader {
    async fn spend_for_account(
        &self,
        account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(match self.known.get(account_id) {
            Some(spent) => Spend::Known(*spent),
            None => Spend::Unavailable,
        })
    }
}

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

async fn insert_project(pool: &PgPool, account_id: &str, billing_plan: &str) {
    sqlx::query(
        "INSERT INTO projects (id, account_id, name, billing_plan, billing_identity) \
         VALUES ($1, $2, 'proj', $3, $4)",
    )
    .bind(cuid2())
    .bind(account_id)
    .bind(billing_plan)
    .bind(format!("bill-{}", cuid2()))
    .execute(pool)
    .await
    .expect("inserting a test project must succeed");
}

async fn seed_schedule(
    pool: &PgPool,
    name: &str,
    scope_kind: ScheduleScopeKind,
    scope_id: Option<&str>,
    amount_micros: i64,
    next_run_at: DateTime<Utc>,
) -> String {
    let id = cuid2();
    sqlx::query(
        "INSERT INTO budget_reset_schedules \
         (id, name, scope_kind, scope_id, cadence, anchor, run_at_utc, amount_micros, mode, \
          enabled, next_run_at) \
         VALUES ($1, $2, $3, $4, 'weekly', 1, '00:00', $5, $6, true, $7)",
    )
    .bind(&id)
    .bind(name)
    .bind(scope_kind.to_string())
    .bind(scope_id)
    .bind(amount_micros)
    .bind(ResetMode::Reset.to_string())
    .bind(next_run_at)
    .execute(pool)
    .await
    .expect("seeding a schedule must succeed");
    id
}

async fn grants_for(pool: &PgPool, account_id: &str) -> Vec<(i64, String, Option<String>)> {
    sqlx::query_as(
        "SELECT amount_micros, source, idempotency_key FROM budget_grants \
         WHERE budget_account_id = $1 ORDER BY created_at ASC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
    .expect("reading grants must succeed")
}

fn service(pool: &PgPool) -> (Arc<dyn DbPoolTrait>, StartingGrantService) {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let service = StartingGrantService::new(core.clone(), POLICY_SET_ID, EVALUATION_BUDGET);
    (core, service)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_new_account_is_granted_the_effective_schedules_target(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    insert_project(&pool, &account_id, "free").await;
    seed_schedule(
        &pool,
        "Refill $8",
        ScheduleScopeKind::BillingPlan,
        Some("free"),
        SCHEDULE_AMOUNT_MICROS,
        at(7, 0),
    )
    .await;

    let (_core, service) = service(&pool);
    let grant = service.book(&account_id, at(4, 12)).await.unwrap();

    assert_eq!(grant.amount_micros, SCHEDULE_AMOUNT_MICROS);
    assert_eq!(grant.source.to_string(), "automatic");
    assert_eq!(grant.period.to_string(), "2026-09");
    assert_eq!(
        grant.idempotency_key.as_deref(),
        Some(
            starting_grant_idempotency_key(&Period::parse("2026-09").unwrap(), &account_id)
                .as_str()
        )
    );
    // The amount is the schedule's, not the policy's -- the whole point of the $8-vs-$15 rule.
    assert_ne!(grant.amount_micros, POLICY_STARTING_AMOUNT_MICROS);
}

#[sqlx::test(migrations = "../../migrations")]
async fn booking_twice_never_double_grants(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    insert_project(&pool, &account_id, "free").await;
    seed_schedule(
        &pool,
        "Refill $8",
        ScheduleScopeKind::BillingPlan,
        Some("free"),
        SCHEDULE_AMOUNT_MICROS,
        at(7, 0),
    )
    .await;

    let (core, service) = service(&pool);
    let first = service.book(&account_id, at(4, 12)).await.unwrap();
    let second = service.book(&account_id, at(4, 13)).await.unwrap();

    assert_eq!(
        first.id, second.id,
        "a retry must resolve to the same grant"
    );
    assert_eq!(grants_for(&pool, &account_id).await.len(), 1);

    let repo = BudgetRepo::new(core);
    let balance = repo
        .effective_balance(&account_id, &Period::parse("2026-09").unwrap(), at(4, 14))
        .await
        .unwrap();
    assert_eq!(balance, SCHEDULE_AMOUNT_MICROS);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_no_schedule_covers_falls_back_to_the_policy_amount(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let (_core, service) = service(&pool);
    let amount = service.resolve_amount(&account_id).await.unwrap();
    assert_eq!(
        amount,
        StartingAmount::PolicyDefault {
            amount_micros: POLICY_STARTING_AMOUNT_MICROS
        }
    );

    let grant = service.book(&account_id, at(4, 12)).await.unwrap();
    assert_eq!(grant.amount_micros, POLICY_STARTING_AMOUNT_MICROS);
}

/// A `billing_plan`-scoped schedule cannot match an account with no project yet -- the fact the
/// module doc warns about, pinned so a future change to the plan derivation is a visible test
/// failure rather than a silent change in what a new account is granted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_plan_schedule_does_not_cover_an_account_with_no_project(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    seed_schedule(
        &pool,
        "Refill $8",
        ScheduleScopeKind::BillingPlan,
        Some("free"),
        SCHEDULE_AMOUNT_MICROS,
        at(7, 0),
    )
    .await;

    let (_core, service) = service(&pool);
    assert_eq!(
        service.resolve_amount(&account_id).await.unwrap(),
        StartingAmount::PolicyDefault {
            amount_micros: POLICY_STARTING_AMOUNT_MICROS
        }
    );
}

/// A `global` schedule, by contrast, covers an account from its first second.
#[sqlx::test(migrations = "../../migrations")]
async fn a_global_schedule_covers_an_account_with_no_project(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let schedule_id = seed_schedule(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        SCHEDULE_AMOUNT_MICROS,
        at(7, 0),
    )
    .await;

    let (_core, service) = service(&pool);
    assert_eq!(
        service.resolve_amount(&account_id).await.unwrap(),
        StartingAmount::Schedule {
            schedule_id,
            schedule_name: "Everyone $8".to_string(),
            amount_micros: SCHEDULE_AMOUNT_MICROS,
        }
    );
}

/// The acceptance criterion the whole amount rule exists for: after a starting grant, the very
/// schedule that produced its amount has nothing left to do this window. `delta = 8 − 8 = 0`, so
/// no row at all -- and in particular no negative `correction`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_next_schedule_run_is_a_no_op_after_a_starting_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    insert_project(&pool, &account_id, "free").await;
    let schedule_id = seed_schedule(
        &pool,
        "Refill $8",
        ScheduleScopeKind::BillingPlan,
        Some("free"),
        SCHEDULE_AMOUNT_MICROS,
        at(7, 0),
    )
    .await;

    let (core, service) = service(&pool);
    service.book(&account_id, at(4, 12)).await.unwrap();

    let budget_repo = Arc::new(BudgetRepo::new(core.clone()));
    let scheduler = ResetScheduler::new(
        core,
        budget_repo,
        // The account has spent nothing: it was created three days ago and has no API key.
        Arc::new(MapSpendReader::default().with(&account_id, 0)),
    );
    let outcome = scheduler
        .run_now(&schedule_id, at(7, 0), false)
        .await
        .unwrap();

    assert!(
        outcome.planned.is_empty(),
        "the window must plan nothing for an account already on target, got {:?}",
        outcome.planned
    );
    let grants = grants_for(&pool, &account_id).await;
    assert_eq!(grants.len(), 1, "no correction row may follow: {grants:?}");
    assert_eq!(grants[0].0, SCHEDULE_AMOUNT_MICROS);
    assert_eq!(grants[0].1, "automatic");
}

/// A $15 starting grant against an $8 schedule is the failure mode the rule exists to prevent.
/// Asserting it here means the rule is pinned by a test that would go red if the amount
/// resolution ever regressed to the policy default while a schedule matched.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mismatched_starting_amount_would_draw_a_correction(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    insert_project(&pool, &account_id, "free").await;
    let schedule_id = seed_schedule(
        &pool,
        "Refill $8",
        ScheduleScopeKind::BillingPlan,
        Some("free"),
        SCHEDULE_AMOUNT_MICROS,
        at(7, 0),
    )
    .await;

    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = Arc::new(BudgetRepo::new(core.clone()));
    // Deliberately the WRONG amount: the policy default, as a pre-#697 backfill would have used.
    budget_repo
        .grant(lightbridge_authz_budget::repo::GrantRequest {
            budget_account_id: account_id.clone(),
            account_id: account_id.clone(),
            project_id: None,
            period: Period::parse("2026-09").unwrap(),
            amount_micros: POLICY_STARTING_AMOUNT_MICROS,
            source: lightbridge_authz_budget::source::GrantSource::Automatic,
            actor_id: None,
            reason: None,
            policy_revision: None,
            matched_rule_ids: None,
            idempotency_key: None,
            trigger_key: None,
            expires_at: None,
        })
        .await
        .unwrap();

    let scheduler = ResetScheduler::new(
        core,
        budget_repo,
        Arc::new(MapSpendReader::default().with(&account_id, 0)),
    );
    scheduler
        .run_now(&schedule_id, at(7, 0), false)
        .await
        .unwrap();

    let grants = grants_for(&pool, &account_id).await;
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[1].1, "correction");
    assert_eq!(
        grants[1].0,
        SCHEDULE_AMOUNT_MICROS - POLICY_STARTING_AMOUNT_MICROS
    );
}

/// ADR-0034 §15/§15.6: the account must be in the snapshot working set straight away, so the
/// refresher fills its reading on the next tick instead of the account waiting for its own first
/// metered request to create the row.
#[sqlx::test(migrations = "../../migrations")]
async fn booking_puts_the_account_in_the_snapshot_working_set(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let (core, service) = service(&pool);
    assert!(
        SnapshotStore::new(core.clone())
            .read(&account_id)
            .await
            .unwrap()
            .is_none(),
        "a fresh account has no snapshot row before its starting grant"
    );

    service.book(&account_id, at(4, 12)).await.unwrap();

    let snapshot = SnapshotStore::new(core)
        .read(&account_id)
        .await
        .unwrap()
        .expect("the starting grant must create the snapshot row");
    assert_eq!(snapshot.budget_account_id, account_id);
    // No reading yet -- the refresher writes it on its next tick, which is exactly the "within one
    // tick" contract. What matters here is that the row exists to be picked up at all.
    assert!(snapshot.remaining_micros.is_none());
}
