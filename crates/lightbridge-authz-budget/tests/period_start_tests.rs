//! DB-backed tests for the month-start pass: every real account holds its starting grant for the
//! CURRENT period, so the gateway's ceiling is not `0` for everyone at 00:00 UTC on the 1st.
//!
//! Real ephemeral Postgres (`sqlx::test`) with the real migrations, for the reason
//! `starting_grant_tests` gives: the behaviour is SQL. The "who is missing" answer is an anti-join
//! on `budget_grants.idempotency_key`, the no-double-grant property is that key's partial unique
//! index, and the same-tick case is `delta = target − remaining` arithmetic against a real ledger.
//!
//! The clock is always supplied (`run(now)` / `tick(now)`), so nothing here is timing-dependent.
//! The migrations seed the `"budget-refill"` policy set, whose `starting_amount_micros` is $15.

#![cfg(feature = "it-tests")]

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Datelike, TimeZone, Utc, Weekday};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::remaining::{Remaining, RemainingReader, RemainingService};
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::reset_schedule::{ResetMode, ScheduleScopeKind};
use lightbridge_authz_budget::reset_scheduler::ResetScheduler;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::{Spend, SpendObservation, SpendReader};
use lightbridge_authz_budget::starting_grant::StartingGrantService;
use lightbridge_authz_budget::starting_grant_amount::starting_grant_idempotency_key;
use lightbridge_authz_budget::{BudgetTicker, PeriodStartGrants};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

const POLICY_SET_ID: &str = "budget-refill";
const EVALUATION_BUDGET: usize = 10_000;

/// ADR-0015's shipped `starting_amount_micros`, seeded by the migrations.
const POLICY_STARTING_AMOUNT_MICROS: i64 = 15_000_000;
const TARGET_MICROS: i64 = 8_000_000;

fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .expect("valid UTC instant")
}

fn period(s: &str) -> Period {
    Period::parse(s).expect("valid period")
}

/// Per-account spend: present means [`Spend::Known`], absent means [`Spend::Unavailable`] — the
/// distinction `spend.rs` exists to preserve. `observe_*` reports the usage store's honest answer
/// for a new month, "answered, holds nothing", which is what the gateway-side read sees.
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

    async fn observe_spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        Ok(SpendObservation::Empty)
    }
}

async fn insert_account(pool: &PgPool) -> String {
    let account_id = cuid2();
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(&account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
    account_id
}

async fn seed_weekly_monday(
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

/// `(amount_micros, source, idempotency_key, reason)`, oldest first.
async fn ledger(
    pool: &PgPool,
    account_id: &str,
    period: &str,
) -> Vec<(i64, String, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT amount_micros, source, idempotency_key, reason FROM budget_grants \
         WHERE budget_account_id = $1 AND period = $2 ORDER BY created_at ASC",
    )
    .bind(account_id)
    .bind(period)
    .fetch_all(pool)
    .await
    .expect("reading the ledger must succeed")
}

struct Graph {
    core: Arc<dyn DbPoolTrait>,
    starting: StartingGrantService,
    pass: PeriodStartGrants,
}

fn graph(pool: &PgPool) -> Graph {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let starting = StartingGrantService::new(core.clone(), POLICY_SET_ID, EVALUATION_BUDGET);
    let pass = PeriodStartGrants::new(core.clone(), starting.clone());
    Graph {
        core,
        starting,
        pass,
    }
}

async fn ceiling(graph: &Graph, account_id: &str, period_s: &str, at: DateTime<Utc>) -> i64 {
    BudgetRepo::new(graph.core.clone())
        .effective_balance(account_id, &period(period_s), at)
        .await
        .expect("reading the ceiling must succeed")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_first_pass_of_a_month_funds_every_account_at_the_schedule_target(pool: PgPool) {
    let funded_in_september = insert_account(&pool).await;
    let never_funded = insert_account(&pool).await;
    seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);

    let end_of_september = utc(2026, 9, 30, 23, 59, 0);
    g.starting
        .book(&funded_in_september, end_of_september)
        .await
        .expect("booking the september grant must succeed");
    assert_eq!(
        ceiling(&g, &funded_in_september, "2026-09", end_of_september).await,
        TARGET_MICROS,
        "precondition: the account is funded for the month that is ending"
    );

    let midnight = utc(2026, 10, 1, 0, 0, 0);
    assert_eq!(
        ceiling(&g, &funded_in_september, "2026-10", midnight).await,
        0,
        "the defect: a funded account has a ceiling of zero the moment the month turns"
    );

    let report = g.pass.run(utc(2026, 10, 1, 0, 0, 15)).await.expect("pass");

    assert_eq!((report.missing, report.funded, report.failed), (2, 2, 0));
    for account_id in [&funded_in_september, &never_funded] {
        assert_eq!(
            ceiling(&g, account_id, "2026-10", midnight).await,
            TARGET_MICROS
        );
    }

    let spend: Arc<dyn SpendReader> = Arc::new(MapSpendReader::default());
    let repo = Arc::new(BudgetRepo::new(g.core.clone()));
    let scheduler = Arc::new(ResetScheduler::new(
        g.core.clone(),
        repo.clone(),
        spend.clone(),
    ));
    let remaining = RemainingService::new(repo, spend, scheduler)
        .remaining_for_account(&funded_in_september, &period("2026-10"), midnight)
        .await
        .expect("the ledger is readable");
    let Remaining::Known(known) = remaining else {
        panic!("expected a known remaining balance, got {remaining:?}");
    };
    assert_eq!(known.ceiling_micros, TARGET_MICROS);
    assert!(
        known.remaining_micros > 0,
        "the gateway must see budget left on the 1st, got {}",
        known.remaining_micros
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_pass_books_nothing(pool: PgPool) {
    let first = insert_account(&pool).await;
    let second = insert_account(&pool).await;
    seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);

    let first_pass = g.pass.run(utc(2026, 10, 1, 0, 0, 15)).await.expect("pass");
    let second_pass = g.pass.run(utc(2026, 10, 1, 0, 1, 15)).await.expect("pass");

    assert_eq!((first_pass.missing, first_pass.funded), (2, 2));
    assert_eq!(
        (second_pass.missing, second_pass.funded, second_pass.failed),
        (0, 0, 0),
        "steady state: nothing is missing, so nothing is booked"
    );
    for account_id in [&first, &second] {
        assert_eq!(ledger(&pool, account_id, "2026-10").await.len(), 1);
    }
}

/// Production was bridged for 2026-10 by a Job that booked these rows by hand under the key
/// `StartingGrantService::book` uses. The pass must read them as already booked.
#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_an_operator_booked_under_the_key_is_not_repeated(pool: PgPool) {
    let bridged = insert_account(&pool).await;
    let unbridged = insert_account(&pool).await;
    seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);
    let key = starting_grant_idempotency_key(&period("2026-10"), &bridged);
    BudgetRepo::new(g.core.clone())
        .grant(GrantRequest {
            budget_account_id: bridged.clone(),
            account_id: bridged.clone(),
            project_id: None,
            period: period("2026-10"),
            amount_micros: TARGET_MICROS,
            source: GrantSource::Automatic,
            actor_id: None,
            reason: Some("manual month-start bridge".to_string()),
            policy_revision: None,
            matched_rule_ids: None,
            idempotency_key: Some(key.clone()),
            trigger_key: None,
            expires_at: None,
        })
        .await
        .expect("the operator's grant must book");

    let report = g.pass.run(utc(2026, 10, 1, 0, 0, 15)).await.expect("pass");

    assert_eq!(
        (report.missing, report.funded),
        (1, 1),
        "only the unbridged"
    );
    let rows = ledger(&pool, &bridged, "2026-10").await;
    assert_eq!(rows.len(), 1, "no second grant on top of the operator's");
    assert_eq!(rows[0].2.as_deref(), Some(key.as_str()));
    assert_eq!(rows[0].3.as_deref(), Some("manual month-start bridge"));
    assert_eq!(
        ceiling(&g, &bridged, "2026-10", utc(2026, 10, 2, 0, 0, 0)).await,
        TARGET_MICROS
    );
    assert_eq!(ledger(&pool, &unbridged, "2026-10").await.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_created_mid_month_is_not_granted_twice(pool: PgPool) {
    let account_id = insert_account(&pool).await;
    let schedule_id = seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 10, 19, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);

    g.starting
        .book(&account_id, utc(2026, 10, 14, 9, 0, 0))
        .await
        .expect("the creation-time grant must book");
    let report = g.pass.run(utc(2026, 10, 14, 9, 1, 0)).await.expect("pass");

    assert_eq!(report.missing, 0);
    let rows = ledger(&pool, &account_id, "2026-10").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].3.as_deref(),
        Some(
            format!(
                "starting grant at account creation, matching reset schedule 'Everyone $8' \
                 ({schedule_id})"
            )
            .as_str()
        ),
        "the creation-time reason must be unchanged"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_month_start_reason_does_not_claim_the_account_was_just_created(pool: PgPool) {
    let account_id = insert_account(&pool).await;
    let schedule_id = seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);

    g.pass.run(utc(2026, 10, 1, 0, 0, 15)).await.expect("pass");

    let rows = ledger(&pool, &account_id, "2026-10").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "automatic");
    assert_eq!(
        rows[0].3.as_deref(),
        Some(
            format!(
                "month-start grant for 2026-10, matching reset schedule 'Everyone $8' \
                 ({schedule_id})"
            )
            .as_str()
        )
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_schedule_beats_the_global_one_and_the_rest_follow_global(pool: PgPool) {
    let special = insert_account(&pool).await;
    let ordinary = insert_account(&pool).await;
    seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    seed_weekly_monday(
        &pool,
        "Special $5",
        ScheduleScopeKind::Account,
        Some(&special),
        5_000_000,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);

    g.pass.run(utc(2026, 10, 1, 0, 0, 15)).await.expect("pass");

    let at = utc(2026, 10, 1, 0, 1, 0);
    assert_eq!(ceiling(&g, &special, "2026-10", at).await, 5_000_000);
    assert_eq!(ceiling(&g, &ordinary, "2026-10", at).await, TARGET_MICROS);
}

#[sqlx::test(migrations = "../../migrations")]
async fn with_no_schedule_at_all_the_policy_starting_amount_applies(pool: PgPool) {
    let account_id = insert_account(&pool).await;
    let g = graph(&pool);

    g.pass.run(utc(2026, 10, 1, 0, 0, 15)).await.expect("pass");

    let rows = ledger(&pool, &account_id, "2026-10").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, POLICY_STARTING_AMOUNT_MICROS);
    assert!(
        rows[0]
            .3
            .as_deref()
            .is_some_and(|reason| reason
                .starts_with("month-start grant for 2026-10, from the active policy")),
        "got {:?}",
        rows[0].3
    );
}

/// The creation-time reason is part of the ledger and must stay byte-identical for the policy
/// fallback too: only the month-start grant is allowed to say anything new.
#[sqlx::test(migrations = "../../migrations")]
async fn the_creation_reason_for_the_policy_fallback_is_unchanged(pool: PgPool) {
    let account_id = insert_account(&pool).await;
    let g = graph(&pool);

    let grant = g
        .starting
        .book(&account_id, utc(2026, 10, 14, 9, 0, 0))
        .await
        .expect("the creation-time grant must book");

    assert_eq!(
        grant.reason.as_deref(),
        Some(
            "starting grant at account creation, from the active policy's \
             starting_amount_micros (no reset schedule covers this account)"
        )
    );
}

/// Monday 2026-06-01: the schedule window and the new period begin in the same wake. The pass
/// funds first, so the reset finds the account already on target — one grant, no correction.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reset_window_that_opens_with_the_month_finds_a_funded_ceiling(pool: PgPool) {
    assert_eq!(utc(2026, 6, 1, 0, 0, 0).weekday(), Weekday::Mon);
    let account_id = insert_account(&pool).await;
    let schedule_id = seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 6, 1, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);
    g.starting
        .book(&account_id, utc(2026, 5, 31, 23, 59, 0))
        .await
        .expect("the may grant must book");

    let spend: Arc<dyn SpendReader> = Arc::new(MapSpendReader::default().with(&account_id, 0));
    let scheduler = Arc::new(ResetScheduler::new(
        g.core.clone(),
        Arc::new(BudgetRepo::new(g.core.clone())),
        spend,
    ));
    let ticker = BudgetTicker::new(g.pass.clone(), scheduler);

    let now = utc(2026, 6, 1, 0, 0, 15);
    let report = ticker.tick(now).await;

    let pass = report.period_start.expect("the pass must succeed");
    let reset = report.reset.expect("the reset tick must succeed");
    assert_eq!(pass.funded, 1);
    assert_eq!(reset.claimed_schedule_ids, vec![schedule_id]);
    assert_eq!(
        reset.grants_written, 0,
        "delta = target - remaining = 0: the reset has nothing left to book"
    );
    let rows = ledger(&pool, &account_id, "2026-06").await;
    assert_eq!(rows.len(), 1, "one grant, no correction: {rows:?}");
    assert_eq!(rows[0].0, TARGET_MICROS);
    assert_eq!(
        ceiling(&g, &account_id, "2026-06", now).await,
        TARGET_MICROS
    );
}

/// The production shape. A reset in `mode: reset` defers an account whose spend is unavailable
/// (`Spend::Unavailable`, unchanged here), and at the start of a month every account has no spend
/// rows — so the reset alone funds no one. The pass is what keeps those accounts off `402`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_pass_funds_an_account_whose_reset_is_deferred_for_unavailable_spend(pool: PgPool) {
    let account_id = insert_account(&pool).await;
    seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 6, 1, 0, 0, 0),
    )
    .await;
    let g = graph(&pool);
    let spend: Arc<dyn SpendReader> = Arc::new(MapSpendReader::default());
    let scheduler = Arc::new(ResetScheduler::new(
        g.core.clone(),
        Arc::new(BudgetRepo::new(g.core.clone())),
        spend,
    ));
    let ticker = BudgetTicker::new(g.pass.clone(), scheduler);

    let now = utc(2026, 6, 1, 0, 0, 15);
    let report = ticker.tick(now).await;

    assert_eq!(
        report.reset.expect("reset").grants_written,
        0,
        "deferred, as before"
    );
    assert_eq!(
        ceiling(&g, &account_id, "2026-06", now).await,
        TARGET_MICROS
    );
}

/// One account that cannot be funded must not leave every account behind it at a zero ceiling, and
/// the one it could not fund must stay at zero rather than being granted something it was not owed.
#[sqlx::test(migrations = "../../migrations")]
async fn one_account_failing_does_not_stop_the_others_and_never_over_grants(pool: PgPool) {
    let covered = insert_account(&pool).await;
    let uncovered = insert_account(&pool).await;
    seed_weekly_monday(
        &pool,
        "Covered $5",
        ScheduleScopeKind::Account,
        Some(&covered),
        5_000_000,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    sqlx::query("UPDATE budget_policy_sets SET active_revision_id = NULL WHERE id = $1")
        .bind(POLICY_SET_ID)
        .execute(&pool)
        .await
        .expect("deactivating the policy must succeed");
    let g = graph(&pool);

    let now = utc(2026, 10, 1, 0, 0, 15);
    let report = g.pass.run(now).await.expect("enumeration still succeeds");

    assert_eq!((report.missing, report.funded, report.failed), (2, 1, 1));
    assert!(report.first_error.is_some());
    assert_eq!(ceiling(&g, &covered, "2026-10", now).await, 5_000_000);
    assert_eq!(
        ceiling(&g, &uncovered, "2026-10", now).await,
        0,
        "an account that could not be resolved stays closed"
    );
    assert!(ledger(&pool, &uncovered, "2026-10").await.is_empty());
}

/// Replicas wake independently and can pick the same accounts. Both runs must succeed and the
/// ledger must hold exactly one grant per account: a unique-violation race is not an error.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_passes_book_each_account_exactly_once(pool: PgPool) {
    let mut accounts = Vec::new();
    for _ in 0..12 {
        accounts.push(insert_account(&pool).await);
    }
    seed_weekly_monday(
        &pool,
        "Everyone $8",
        ScheduleScopeKind::Global,
        None,
        TARGET_MICROS,
        utc(2026, 10, 5, 0, 0, 0),
    )
    .await;
    let now = utc(2026, 10, 1, 0, 0, 15);
    let handles: Vec<_> = (0..3)
        .map(|_| {
            let pass = graph(&pool).pass;
            tokio::spawn(async move { pass.run(now).await })
        })
        .collect();
    for handle in handles {
        let report = handle
            .await
            .expect("task")
            .expect("a race must not surface as an error");
        assert_eq!(report.failed, 0);
        assert_eq!(report.funded, report.missing);
    }

    for account_id in &accounts {
        assert_eq!(ledger(&pool, account_id, "2026-10").await.len(), 1);
    }
}
