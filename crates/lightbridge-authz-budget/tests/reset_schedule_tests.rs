//! DB-backed tests for budget reset schedules and their scheduler (ADR-0032, story #651).
//!
//! Every test here runs against a real ephemeral Postgres (`sqlx::test`) with the real migrations,
//! because the behaviour under test is almost entirely about SQL: the `FOR UPDATE SKIP LOCKED`
//! claim, the `budget_grants_trigger_key_uidx` idempotency, the `budget_grants_amount_sign_chk`
//! constraint that forces a reset-down to be booked as a `correction`, and the account enumeration
//! joins. A mocked repository would prove none of it.
//!
//! The clock is always supplied explicitly (`tick(now)` / `run_now(id, now, ..)`), so nothing here
//! is timing-dependent -- see `reset_schedule.rs`'s "Clock discipline" note.

#![cfg(feature = "it-tests")]
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::reset_schedule::{
    BudgetResetScheduleUpdate, Cadence, NewBudgetResetSchedule, ResetMode, ResetScheduleRepo,
    ScheduleScopeKind,
};
use lightbridge_authz_budget::reset_scheduler::ResetScheduler;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::{Spend, SpendReader};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

/// Every test pins "now" inside this calendar month, so `Period::current(now)` is stable and the
/// ledger assertions can name the period literally.
const PERIOD: &str = "2026-09";

fn at(day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, day, hour, minute, 0)
        .single()
        .expect("valid UTC instant")
}

fn midnight_time() -> chrono::NaiveTime {
    chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap()
}

/// A [`SpendReader`] whose answers are fixed per account: present in the map means
/// [`Spend::Known`], absent means [`Spend::Unavailable`]. Deliberately NOT a mock framework -- the
/// only behaviour that matters is which of the two variants comes back, and conflating "no entry"
/// with "unavailable" is exactly the distinction `spend.rs` exists to preserve.
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
    // The `accounts_set_user` trigger (20260825000001, amended by 20260830000003) provisions the
    // owning `users` row for a bare insert, which is what the scheduler's `JOIN users` relies on.
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

async fn insert_project(pool: &PgPool, account_id: &str, billing_plan: &str) -> String {
    let project_id = cuid2();
    sqlx::query(
        "INSERT INTO projects (id, account_id, name, billing_plan, billing_identity) \
         VALUES ($1, $2, 'proj', $3, $4)",
    )
    .bind(&project_id)
    .bind(account_id)
    .bind(billing_plan)
    .bind(format!("bill-{}", cuid2()))
    .execute(pool)
    .await
    .expect("inserting a test project must succeed");
    project_id
}

/// Seeds a schedule directly, so a test can pin `next_run_at` into the past and flip `enabled` --
/// neither of which `ResetScheduleRepo::create` allows a caller to do, by design (a create is
/// always disabled with a future window). `create`'s own guarantees are asserted separately in
/// `create_is_always_disabled_with_a_future_window`.
#[allow(clippy::too_many_arguments)]
async fn seed_schedule(
    pool: &PgPool,
    name: &str,
    scope_kind: ScheduleScopeKind,
    scope_id: Option<&str>,
    mode: ResetMode,
    amount_micros: i64,
    next_run_at: DateTime<Utc>,
    enabled: bool,
) -> String {
    let id = cuid2();
    sqlx::query(
        "INSERT INTO budget_reset_schedules \
         (id, name, scope_kind, scope_id, cadence, anchor, run_at_utc, amount_micros, mode, \
          enabled, next_run_at) \
         VALUES ($1, $2, $3, $4, 'daily', NULL, '00:00', $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(name)
    .bind(scope_kind.to_string())
    .bind(scope_id)
    .bind(amount_micros)
    .bind(mode.to_string())
    .bind(enabled)
    .bind(next_run_at)
    .execute(pool)
    .await
    .expect("seeding a schedule must succeed");
    id
}

async fn grants_for(pool: &PgPool, account_id: &str) -> Vec<(i64, String, Option<String>)> {
    sqlx::query_as(
        "SELECT amount_micros, source, trigger_key FROM budget_grants \
         WHERE budget_account_id = $1 ORDER BY created_at ASC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
    .expect("reading grants must succeed")
}

async fn grant_count(pool: &PgPool) -> i64 {
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM budget_grants")
        .fetch_one(pool)
        .await
        .expect("counting grants must succeed");
    count
}

async fn schedule_timing(pool: &PgPool, id: &str) -> (DateTime<Utc>, Option<DateTime<Utc>>) {
    sqlx::query_as("SELECT next_run_at, last_run_at FROM budget_reset_schedules WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("reading schedule timing must succeed")
}

async fn seed_base_grant(repo: &BudgetRepo, account_id: &str, amount_micros: i64) {
    repo.grant(GrantRequest {
        budget_account_id: account_id.to_string(),
        account_id: account_id.to_string(),
        project_id: None,
        period: Period::parse(PERIOD).unwrap(),
        amount_micros,
        source: GrantSource::Base,
        actor_id: None,
        reason: None,
        policy_revision: None,
        matched_rule_ids: None,
        idempotency_key: None,
        trigger_key: None,
        expires_at: None,
    })
    .await
    .expect("seeding a base grant must succeed");
}

fn scheduler(
    pool: &PgPool,
    spend: MapSpendReader,
) -> (Arc<dyn DbPoolTrait>, Arc<BudgetRepo>, ResetScheduler) {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = Arc::new(BudgetRepo::new(core.clone()));
    let scheduler = ResetScheduler::new(core.clone(), budget_repo.clone(), Arc::new(spend));
    (core, budget_repo, scheduler)
}

// ---------------------------------------------------------------------------------------------
// Mode semantics: top_up, reset up, reset down (the owner's "clamps both ways" ruling).
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn top_up_writes_one_positive_automatic_grant(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());
    let schedule = seed_schedule(
        &pool,
        "daily top-up",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::TopUp,
        5_000_000,
        at(2, 0, 0),
        true,
    )
    .await;

    let report = scheduler.tick(at(2, 0, 30)).await.unwrap();
    assert_eq!(report.claimed_schedule_ids, vec![schedule]);
    assert_eq!(report.grants_written, 1);

    let grants = grants_for(&pool, &account).await;
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].0, 5_000_000);
    assert_eq!(grants[0].1, "automatic");
    assert!(
        grants[0].2.is_some(),
        "a scheduled grant carries a trigger key"
    );
}

/// `reset` up: remaining ($1.00) is BELOW the $2.00 target, so the grant is exactly the shortfall
/// and remaining lands on the target to the micro-dollar.
#[sqlx::test(migrations = "../../migrations")]
async fn reset_below_target_grants_the_exact_shortfall(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, repo, scheduler) =
        scheduler(&pool, MapSpendReader::default().with(&account, 9_000_000));
    seed_base_grant(&repo, &account, 10_000_000).await;
    seed_schedule(
        &pool,
        "reset to $2",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::Reset,
        2_000_000,
        at(2, 0, 0),
        true,
    )
    .await;

    scheduler.tick(at(2, 0, 30)).await.unwrap();

    let grants = grants_for(&pool, &account).await;
    assert_eq!(grants.len(), 2, "the base grant plus one scheduled grant");
    assert_eq!(grants[1].0, 1_000_000);
    assert_eq!(grants[1].1, "automatic");

    let effective = repo
        .effective_balance(&account, &Period::parse(PERIOD).unwrap(), at(2, 1, 0))
        .await
        .unwrap();
    assert_eq!(
        effective - 9_000_000,
        2_000_000,
        "remaining is exactly the target"
    );
}

/// `reset` DOWN, the owner's binding ruling: remaining ($9.00) is ABOVE the $2.00 target, so the
/// excess is booked as a NEGATIVE `source = 'correction'` row -- the only source
/// `budget_grants_amount_sign_chk` permits to be negative -- and remaining is clamped to exactly
/// the target without any row being mutated or deleted (ADR-0009).
#[sqlx::test(migrations = "../../migrations")]
async fn reset_above_target_books_a_negative_refund_type_correction(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, repo, scheduler) =
        scheduler(&pool, MapSpendReader::default().with(&account, 1_000_000));
    seed_base_grant(&repo, &account, 10_000_000).await;
    seed_schedule(
        &pool,
        "reset to $2",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::Reset,
        2_000_000,
        at(2, 0, 0),
        true,
    )
    .await;

    scheduler.tick(at(2, 0, 30)).await.unwrap();

    let grants = grants_for(&pool, &account).await;
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[1].0, -7_000_000, "the excess, negated");
    assert_eq!(
        grants[1].1, "correction",
        "a negative delta is the compensating correction row, never a mutated grant"
    );

    let effective = repo
        .effective_balance(&account, &Period::parse(PERIOD).unwrap(), at(2, 1, 0))
        .await
        .unwrap();
    assert_eq!(effective, 3_000_000);
    assert_eq!(
        effective - 1_000_000,
        2_000_000,
        "remaining is exactly the target"
    );

    // The materialized projection agrees with a full replay of the ledger -- ADR-0009's own
    // invariant, re-checked here because this test writes the first NEGATIVE row the scheduler can
    // produce.
    let derived = repo.rebuild_all_balances().await.unwrap();
    let stored = repo
        .get_balance(&account, &Period::parse(PERIOD).unwrap())
        .await
        .unwrap()
        .unwrap();
    let derived = derived
        .into_iter()
        .find(|row| row.budget_account_id == account)
        .expect("a derived row for this account");
    assert_eq!(
        derived.effective_budget_micros,
        stored.effective_budget_micros
    );
    assert_eq!(derived.base_total_micros, 10_000_000);
    assert_eq!(
        derived.automatic_total_micros, 0,
        "a correction adjusts the effective budget only, not the automatic bucket"
    );
}

// ---------------------------------------------------------------------------------------------
// Idempotency, fail-closed spend, precedence, drift.
// ---------------------------------------------------------------------------------------------

/// The same window processed twice writes ONE grant. Reprocessing is not hypothetical: the tick
/// commits its `next_run_at` advance only on success, so a crash mid-pass leaves the window due
/// and the next tick reclaims it -- simulated here by putting `next_run_at` back.
#[sqlx::test(migrations = "../../migrations")]
async fn the_same_window_processed_twice_writes_one_grant(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());
    let schedule = seed_schedule(
        &pool,
        "daily top-up",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::TopUp,
        5_000_000,
        at(2, 0, 0),
        true,
    )
    .await;

    scheduler.tick(at(2, 0, 30)).await.unwrap();
    assert_eq!(grant_count(&pool).await, 1);

    sqlx::query("UPDATE budget_reset_schedules SET next_run_at = $2 WHERE id = $1")
        .bind(&schedule)
        .bind(at(2, 0, 0))
        .execute(&pool)
        .await
        .unwrap();

    let report = scheduler.tick(at(2, 0, 45)).await.unwrap();
    assert_eq!(
        report.claimed_schedule_ids.len(),
        1,
        "the window was reclaimed"
    );
    assert_eq!(
        grant_count(&pool).await,
        1,
        "the replayed window resolves to the already-committed grant, not a second one"
    );
}

/// Fail-closed spend: an account whose spend is `Unavailable` gets NO grant, every other account
/// in the same window still processes, the window stays due, and the retry lands the grant once
/// spend is readable -- without duplicating the account that already succeeded.
#[sqlx::test(migrations = "../../migrations")]
async fn unavailable_spend_skips_that_account_and_others_still_process(pool: PgPool) {
    let known = cuid2();
    let unknown = cuid2();
    insert_account(&pool, &known).await;
    insert_account(&pool, &unknown).await;

    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = Arc::new(BudgetRepo::new(core.clone()));
    seed_base_grant(&budget_repo, &known, 10_000_000).await;
    seed_base_grant(&budget_repo, &unknown, 10_000_000).await;

    let schedule = seed_schedule(
        &pool,
        "estate reset",
        ScheduleScopeKind::Global,
        None,
        ResetMode::Reset,
        2_000_000,
        at(2, 0, 0),
        true,
    )
    .await;

    let partial = ResetScheduler::new(
        core.clone(),
        budget_repo.clone(),
        Arc::new(MapSpendReader::default().with(&known, 9_000_000)),
    );
    partial.tick(at(2, 0, 30)).await.unwrap();

    assert_eq!(grants_for(&pool, &known).await.len(), 2);
    assert_eq!(
        grants_for(&pool, &unknown).await.len(),
        1,
        "only the seeded base grant -- never grant on unknown spend"
    );
    let (next_run_at, last_run_at) = schedule_timing(&pool, &schedule).await;
    assert_eq!(
        next_run_at,
        at(2, 0, 0),
        "the window stays due so the next tick retries the deferred account"
    );
    assert_eq!(last_run_at, Some(at(2, 0, 30)));

    // Next tick, spend is readable for both.
    let full = ResetScheduler::new(
        core,
        budget_repo,
        Arc::new(
            MapSpendReader::default()
                .with(&known, 9_000_000)
                .with(&unknown, 5_000_000),
        ),
    );
    full.tick(at(2, 1, 0)).await.unwrap();

    assert_eq!(
        grants_for(&pool, &known).await.len(),
        2,
        "the account that already succeeded is not granted twice (trigger_key)"
    );
    let unknown_grants = grants_for(&pool, &unknown).await;
    assert_eq!(unknown_grants.len(), 2);
    assert_eq!(unknown_grants[1].0, -3_000_000);
    let (next_run_at, _) = schedule_timing(&pool, &schedule).await;
    assert_eq!(next_run_at, at(3, 0, 0), "the completed window advances");
}

/// Precedence: account > billing_plan > global. All three schedules are due in the same tick, and
/// each account is touched by exactly one of them.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_most_specific_schedule_fires_for_an_account(pool: PgPool) {
    let targeted = cuid2();
    let on_free = cuid2();
    let on_pro = cuid2();
    for account in [&targeted, &on_free, &on_pro] {
        insert_account(&pool, account).await;
    }
    insert_project(&pool, &targeted, "free").await;
    insert_project(&pool, &on_free, "free").await;
    insert_project(&pool, &on_pro, "pro").await;

    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());
    seed_schedule(
        &pool,
        "global",
        ScheduleScopeKind::Global,
        None,
        ResetMode::TopUp,
        1_000_000,
        at(2, 0, 0),
        true,
    )
    .await;
    seed_schedule(
        &pool,
        "free plan",
        ScheduleScopeKind::BillingPlan,
        Some("free"),
        ResetMode::TopUp,
        2_000_000,
        at(2, 0, 0),
        true,
    )
    .await;
    seed_schedule(
        &pool,
        "one account",
        ScheduleScopeKind::Account,
        Some(&targeted),
        ResetMode::TopUp,
        3_000_000,
        at(2, 0, 0),
        true,
    )
    .await;

    scheduler.tick(at(2, 0, 30)).await.unwrap();

    let targeted_grants = grants_for(&pool, &targeted).await;
    assert_eq!(
        targeted_grants.len(),
        1,
        "the account schedule fired, alone"
    );
    assert_eq!(targeted_grants[0].0, 3_000_000);

    let free_grants = grants_for(&pool, &on_free).await;
    assert_eq!(free_grants.len(), 1);
    assert_eq!(free_grants[0].0, 2_000_000);

    let pro_grants = grants_for(&pool, &on_pro).await;
    assert_eq!(pro_grants.len(), 1);
    assert_eq!(pro_grants[0].0, 1_000_000);
}

/// The anti-drift criterion: `next_run_at` is `previous window + one cadence step`, NOT
/// `now + one step`. The tick here wakes up 9h17m late on a window that is already a day stale, and
/// the schedule still lands on the next midnight -- once, not once per missed window.
#[sqlx::test(migrations = "../../migrations")]
async fn next_run_at_advances_from_the_schedule_not_from_now(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());
    let schedule = seed_schedule(
        &pool,
        "daily top-up",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::TopUp,
        5_000_000,
        at(1, 0, 0),
        true,
    )
    .await;

    scheduler.tick(at(2, 9, 17)).await.unwrap();

    let (next_run_at, last_run_at) = schedule_timing(&pool, &schedule).await;
    assert_eq!(next_run_at, at(3, 0, 0));
    assert_eq!(last_run_at, Some(at(2, 9, 17)));
    assert_eq!(
        grant_count(&pool).await,
        1,
        "a missed window is caught up to, not replayed once per window"
    );
}

// ---------------------------------------------------------------------------------------------
// Dry run, manual fire, effective-schedule resolution, CRUD guarantees.
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_returns_the_plan_and_writes_nothing(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, repo, scheduler) =
        scheduler(&pool, MapSpendReader::default().with(&account, 1_000_000));
    seed_base_grant(&repo, &account, 10_000_000).await;
    let schedule = seed_schedule(
        &pool,
        "reset to $2",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::Reset,
        2_000_000,
        at(2, 0, 0),
        true,
    )
    .await;
    let before = grant_count(&pool).await;

    let outcome = scheduler
        .run_now(&schedule, at(2, 0, 30), true)
        .await
        .unwrap();

    assert_eq!(outcome.planned.len(), 1);
    assert_eq!(outcome.planned[0].budget_account_id, account);
    assert_eq!(outcome.planned[0].remaining_micros, 9_000_000);
    assert_eq!(outcome.planned[0].delta_micros, -7_000_000);

    assert_eq!(
        grant_count(&pool).await,
        before,
        "a dry run writes no grant"
    );
    let (next_run_at, last_run_at) = schedule_timing(&pool, &schedule).await;
    assert_eq!(
        next_run_at,
        at(2, 0, 0),
        "a dry run does not advance the window"
    );
    assert_eq!(last_run_at, None, "a dry run does not stamp last_run_at");
}

/// `runBudgetResetScheduleNow` with `dryRun: false` fires the schedule's pending window with the
/// SAME `trigger_key` the tick would have used, so a manual fire followed by the scheduled tick
/// cannot double-grant.
#[sqlx::test(migrations = "../../migrations")]
async fn a_manual_run_and_the_tick_cannot_double_grant_the_same_window(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());
    let schedule = seed_schedule(
        &pool,
        "daily top-up",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::TopUp,
        5_000_000,
        at(2, 0, 0),
        true,
    )
    .await;

    let outcome = scheduler
        .run_now(&schedule, at(1, 12, 0), false)
        .await
        .unwrap();
    assert_eq!(outcome.planned.len(), 1);
    assert_eq!(grant_count(&pool).await, 1);

    // Put the window back (as a crashed advance would) and let the scheduled tick reclaim it.
    sqlx::query("UPDATE budget_reset_schedules SET next_run_at = $2 WHERE id = $1")
        .bind(&schedule)
        .bind(at(2, 0, 0))
        .execute(&pool)
        .await
        .unwrap();
    scheduler.tick(at(2, 0, 30)).await.unwrap();

    assert_eq!(grant_count(&pool).await, 1);
}

/// Replica safety: two ticks running concurrently over the same due set claim DISJOINT schedules
/// (`FOR UPDATE SKIP LOCKED`), so every schedule fires exactly once.
#[sqlx::test(migrations = "../../migrations")]
async fn two_concurrent_ticks_claim_each_schedule_exactly_once(pool: PgPool) {
    let mut accounts = Vec::new();
    for _ in 0..4 {
        let account = cuid2();
        insert_account(&pool, &account).await;
        seed_schedule(
            &pool,
            "daily top-up",
            ScheduleScopeKind::Account,
            Some(&account),
            ResetMode::TopUp,
            5_000_000,
            at(2, 0, 0),
            true,
        )
        .await;
        accounts.push(account);
    }

    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let budget_repo = Arc::new(BudgetRepo::new(core.clone()));
    let replica_a = ResetScheduler::new(
        core.clone(),
        budget_repo.clone(),
        Arc::new(MapSpendReader::default()),
    );
    let replica_b = ResetScheduler::new(core, budget_repo, Arc::new(MapSpendReader::default()));

    let (a, b) = tokio::join!(replica_a.tick(at(2, 0, 30)), replica_b.tick(at(2, 0, 30)));
    let a = a.unwrap();
    let b = b.unwrap();

    for id in &a.claimed_schedule_ids {
        assert!(
            !b.claimed_schedule_ids.contains(id),
            "schedule {id} was claimed by BOTH replicas -- SKIP LOCKED did not hold"
        );
    }
    assert_eq!(
        a.claimed_schedule_ids.len() + b.claimed_schedule_ids.len(),
        4,
        "every due schedule is claimed exactly once across the two replicas"
    );

    for account in &accounts {
        assert_eq!(
            grants_for(&pool, account).await.len(),
            1,
            "each account received exactly one grant"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_effective_schedule_is_the_most_specific_enabled_one(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    insert_project(&pool, &account, "free").await;
    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());

    assert!(
        scheduler
            .effective_schedule(&account)
            .await
            .unwrap()
            .is_none(),
        "no schedules at all resolves to none"
    );

    seed_schedule(
        &pool,
        "global",
        ScheduleScopeKind::Global,
        None,
        ResetMode::TopUp,
        1_000_000,
        at(3, 0, 0),
        true,
    )
    .await;
    let plan_schedule = seed_schedule(
        &pool,
        "free plan",
        ScheduleScopeKind::BillingPlan,
        Some("free"),
        ResetMode::Reset,
        2_000_000,
        at(4, 0, 0),
        true,
    )
    .await;
    // Disabled, and therefore invisible to precedence even though it is the most specific.
    seed_schedule(
        &pool,
        "disabled account override",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::TopUp,
        9_000_000,
        at(5, 0, 0),
        false,
    )
    .await;

    let effective = scheduler
        .effective_schedule(&account)
        .await
        .unwrap()
        .expect("a winner");
    assert_eq!(effective.schedule.id, plan_schedule);
    assert_eq!(effective.next_run_at, at(4, 0, 0));
    assert_eq!(effective.schedule.amount_micros, 2_000_000);
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_is_always_disabled_with_a_future_window(pool: PgPool) {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = ResetScheduleRepo::new(core);
    let now = at(2, 6, 0);

    let created = repo
        .create(
            NewBudgetResetSchedule {
                name: "reset to $2 daily".to_string(),
                scope_kind: ScheduleScopeKind::Global,
                scope_id: None,
                cadence: Cadence::Daily,
                anchor: None,
                run_at_utc: midnight_time(),
                amount_micros: 2_000_000,
                mode: ResetMode::Reset,
                next_run_at: None,
            },
            Some("admin-subject"),
            now,
        )
        .await
        .unwrap();

    assert!(!created.enabled, "a new schedule is never live on creation");
    assert_eq!(created.next_run_at, at(3, 0, 0));
    assert_eq!(created.created_by.as_deref(), Some("admin-subject"));

    let enabled = repo
        .update(
            &created.id,
            BudgetResetScheduleUpdate {
                enabled: Some(true),
                ..Default::default()
            },
            now,
        )
        .await
        .unwrap();
    assert!(enabled.enabled);
    assert_eq!(
        enabled.next_run_at, created.next_run_at,
        "flipping `enabled` alone must not re-seed the window"
    );

    repo.delete(&created.id).await.unwrap();
    assert!(matches!(
        repo.get(&created.id).await,
        Err(BudgetError::NotFound(_))
    ));
    assert!(matches!(
        repo.delete(&created.id).await,
        Err(BudgetError::NotFound(_))
    ));
}

/// The DB is the authority on the closed domains, and the repo turns each violation into a legible
/// `InvalidSchedule` (a 400) rather than letting a raw constraint violation surface as a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn create_rejects_a_schedule_the_scheduler_could_never_execute(pool: PgPool) {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = ResetScheduleRepo::new(core);
    let now = at(2, 6, 0);

    let base = NewBudgetResetSchedule {
        name: "bad".to_string(),
        scope_kind: ScheduleScopeKind::Global,
        scope_id: None,
        cadence: Cadence::Daily,
        anchor: None,
        run_at_utc: midnight_time(),
        amount_micros: 2_000_000,
        mode: ResetMode::Reset,
        next_run_at: None,
    };

    // A global schedule may not carry a target.
    let mut bad = base.clone();
    bad.scope_id = Some("acc-1".to_string());
    assert!(matches!(
        repo.create(bad, None, now).await,
        Err(BudgetError::InvalidSchedule(_))
    ));

    // A weekly schedule needs a weekday anchor.
    let mut bad = base.clone();
    bad.cadence = Cadence::Weekly;
    assert!(matches!(
        repo.create(bad, None, now).await,
        Err(BudgetError::InvalidSchedule(_))
    ));

    // A top-up of zero would violate `budget_grants_amount_sign_chk` at fire time.
    let mut bad = base.clone();
    bad.mode = ResetMode::TopUp;
    bad.amount_micros = 0;
    assert!(matches!(
        repo.create(bad, None, now).await,
        Err(BudgetError::InvalidSchedule(_))
    ));

    // A reset to zero, by contrast, is legitimate ("cut everyone off at midnight").
    let mut ok = base;
    ok.amount_micros = 0;
    assert!(repo.create(ok, None, now).await.is_ok());
}

/// A disabled schedule is never claimed, however overdue it is.
#[sqlx::test(migrations = "../../migrations")]
async fn a_disabled_schedule_is_never_claimed(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());
    seed_schedule(
        &pool,
        "daily top-up",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::TopUp,
        5_000_000,
        at(1, 0, 0),
        false,
    )
    .await;

    let report = scheduler.tick(at(9, 0, 0)).await.unwrap();
    assert!(report.claimed_schedule_ids.is_empty());
    assert_eq!(grant_count(&pool).await, 0);
}

// ---------------------------------------------------------------------------------------------
// Forcing the next execution onto a specific date (the ADR-0032 "forced next execution"
// amendment). A forced window is a one-off: it fires once, then the schedule is back on its own
// cadence grid at its own `run_at_utc`.
// ---------------------------------------------------------------------------------------------

/// A caller-supplied `next_run_at` is stored verbatim instead of the cadence's own first window,
/// and the row is STILL created disabled — forcing a date does not skip the dry-run gate.
#[sqlx::test(migrations = "../../migrations")]
async fn create_honours_a_forced_next_run_at(pool: PgPool) {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = ResetScheduleRepo::new(core);
    let now = at(2, 6, 0);
    let forced = at(15, 9, 30);

    let created = repo
        .create(
            NewBudgetResetSchedule {
                name: "reset to $2 daily, first run on the 15th".to_string(),
                scope_kind: ScheduleScopeKind::Global,
                scope_id: None,
                cadence: Cadence::Daily,
                anchor: None,
                run_at_utc: midnight_time(),
                amount_micros: 2_000_000,
                mode: ResetMode::Reset,
                next_run_at: Some(forced),
            },
            Some("admin-subject"),
            now,
        )
        .await
        .unwrap();

    assert_eq!(
        created.next_run_at, forced,
        "a forced window is stored verbatim, not rounded onto the cadence grid"
    );
    assert!(
        !created.enabled,
        "forcing a date must not bypass the create-disabled rule (ADR-0032 D8)"
    );
}

/// A backdated window would fire on the very next 60-second tick, across the whole estate, before
/// anyone had dry-run it. Both `create` and `update` refuse it with a legible message (a 400).
#[sqlx::test(migrations = "../../migrations")]
async fn a_next_run_at_in_the_past_is_refused(pool: PgPool) {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = ResetScheduleRepo::new(core);
    let now = at(10, 6, 0);

    let base = NewBudgetResetSchedule {
        name: "backdated".to_string(),
        scope_kind: ScheduleScopeKind::Global,
        scope_id: None,
        cadence: Cadence::Daily,
        anchor: None,
        run_at_utc: midnight_time(),
        amount_micros: 2_000_000,
        mode: ResetMode::Reset,
        next_run_at: Some(at(1, 0, 0)),
    };

    let err = repo.create(base.clone(), None, now).await.unwrap_err();
    assert!(
        matches!(&err, BudgetError::InvalidSchedule(m) if m.contains("must be in the future")),
        "expected a legible InvalidSchedule, got: {err}"
    );

    // `now` itself is not the future either.
    let mut exactly_now = base.clone();
    exactly_now.next_run_at = Some(now);
    assert!(matches!(
        repo.create(exactly_now, None, now).await,
        Err(BudgetError::InvalidSchedule(_))
    ));

    // The same guard on the update path.
    let mut ok = base;
    ok.next_run_at = None;
    let created = repo.create(ok, None, now).await.unwrap();
    let err = repo
        .update(
            &created.id,
            BudgetResetScheduleUpdate {
                next_run_at: Some(at(1, 0, 0)),
                ..Default::default()
            },
            now,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BudgetError::InvalidSchedule(_)));
    assert_eq!(
        repo.get(&created.id).await.unwrap().next_run_at,
        created.next_run_at,
        "a refused update must not have moved the window"
    );
}

/// An update that omits `next_run_at` leaves the column alone — including a forced one. Only a
/// cadence/anchor/run-time change re-seeds it, exactly as before this amendment.
#[sqlx::test(migrations = "../../migrations")]
async fn an_update_without_next_run_at_leaves_a_forced_window_alone(pool: PgPool) {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = ResetScheduleRepo::new(core);
    let now = at(2, 6, 0);
    let forced = at(15, 9, 30);

    let created = repo
        .create(
            NewBudgetResetSchedule {
                name: "forced".to_string(),
                scope_kind: ScheduleScopeKind::Global,
                scope_id: None,
                cadence: Cadence::Daily,
                anchor: None,
                run_at_utc: midnight_time(),
                amount_micros: 2_000_000,
                mode: ResetMode::Reset,
                next_run_at: Some(forced),
            },
            None,
            now,
        )
        .await
        .unwrap();

    // Renaming, re-pricing and enabling all leave the forced window untouched.
    let updated = repo
        .update(
            &created.id,
            BudgetResetScheduleUpdate {
                name: Some("forced, renamed".to_string()),
                amount_micros: Some(3_000_000),
                enabled: Some(true),
                ..Default::default()
            },
            now,
        )
        .await
        .unwrap();
    assert_eq!(updated.next_run_at, forced);

    // Changing the cadence DOES re-seed it, per ADR-0032 — a forced daily window must not survive
    // into a weekly schedule.
    let reseeded = repo
        .update(
            &created.id,
            BudgetResetScheduleUpdate {
                cadence: Some(Cadence::Weekly),
                anchor: Some(Some(1)),
                ..Default::default()
            },
            now,
        )
        .await
        .unwrap();
    assert_ne!(reseeded.next_run_at, forced);
    assert_eq!(
        reseeded.next_run_at,
        at(7, 0, 0),
        "the next Monday at 00:00"
    );
}

/// The advance-after-a-forced-run contract: a daily schedule forced onto 2026-09-15 fires there
/// once, then next fires on 09-16 at its own `run_at_utc` (00:00) — NOT 24 hours after the forced
/// instant's time of day.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forced_window_fires_once_then_returns_to_the_cadence_grid(pool: PgPool) {
    let account = cuid2();
    insert_account(&pool, &account).await;
    let (_core, _repo, scheduler) = scheduler(&pool, MapSpendReader::default());

    // `seed_schedule` writes a daily/00:00 schedule; force its window onto the 15th at 09:30.
    let forced = at(15, 9, 30);
    let schedule_id = seed_schedule(
        &pool,
        "daily top-up, forced onto the 15th",
        ScheduleScopeKind::Account,
        Some(&account),
        ResetMode::TopUp,
        5_000_000,
        forced,
        true,
    )
    .await;

    // Not due yet: a tick before the forced instant claims nothing.
    let report = scheduler.tick(at(15, 9, 0)).await.unwrap();
    assert!(report.claimed_schedule_ids.is_empty());
    assert_eq!(grant_count(&pool).await, 0);

    // The tick that wakes just after the forced instant fires it once...
    let report = scheduler
        .tick(forced + chrono::Duration::seconds(10))
        .await
        .unwrap();
    assert_eq!(report.claimed_schedule_ids, vec![schedule_id.clone()]);
    assert_eq!(grant_count(&pool).await, 1);

    // ...and the schedule is back on its own grid: 09-16 at 00:00, its `run_at_utc`.
    let (next_run_at, last_run_at) = schedule_timing(&pool, &schedule_id).await;
    assert_eq!(next_run_at, at(16, 0, 0));
    assert!(last_run_at.is_some());

    // And it keeps stepping on the grid from there.
    let report = scheduler.tick(at(16, 0, 30)).await.unwrap();
    assert_eq!(report.claimed_schedule_ids, vec![schedule_id.clone()]);
    let (next_run_at, _) = schedule_timing(&pool, &schedule_id).await;
    assert_eq!(next_run_at, at(17, 0, 0));
}
