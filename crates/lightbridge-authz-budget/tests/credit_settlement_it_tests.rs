#![cfg(feature = "it-tests")]
#![allow(clippy::unwrap_used)]
//! ADR-0035 end to end against Postgres: funding, reversal, settlement in spending order, debt,
//! expiry, the pool-scoped reset, and the pool-aware snapshot.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::reset_scheduler::ResetScheduler;
use lightbridge_authz_budget::snapshot::BudgetSnapshotReader;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::{Spend, SpendObservation, SpendReader};
use lightbridge_authz_budget::{
    CreditRepo, FundRequest, SettleOutcome, Settlement, SnapshotRefreshConfig, SnapshotRefresher,
    SnapshotStore,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

const USD: i64 = 1_000_000;

/// Answers each ingested-window query with the next queued amount (then zero), and every monthly
/// query with `month`. `unreachable` makes every query fail, as a down usage service would.
#[derive(Debug, Default)]
struct WindowSpend {
    queue: Mutex<Vec<i64>>,
    month: i64,
    unreachable: bool,
}

impl WindowSpend {
    fn answering(amounts: &[i64]) -> Self {
        Self {
            queue: Mutex::new(amounts.iter().rev().copied().collect()),
            ..Self::default()
        }
    }
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for WindowSpend {
    async fn spend_for_account(&self, _: &str, _: &Period) -> Result<Spend, BudgetError> {
        Ok(Spend::Known(self.month))
    }
    async fn observe_spend_ingested(
        &self,
        _: &str,
        _: DateTime<Utc>,
        _: DateTime<Utc>,
    ) -> Result<SpendObservation, BudgetError> {
        if self.unreachable {
            return Ok(SpendObservation::Unreachable);
        }
        Ok(SpendObservation::Answered(
            self.queue.lock().unwrap().pop().unwrap_or(0),
        ))
    }
}

struct Fixture {
    core: Arc<dyn DbPoolTrait>,
    repo: Arc<BudgetRepo>,
    credit: CreditRepo,
    settlement: Arc<Settlement>,
    account: String,
    now: DateTime<Utc>,
}

async fn fixture(pool: &PgPool, spend: WindowSpend) -> Fixture {
    let account = cuid2();
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(&account)
        .execute(pool)
        .await
        .unwrap();
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let settlement = Arc::new(Settlement::new(
        core.clone(),
        Arc::new(spend),
        Duration::from_secs(60),
        Duration::from_secs(86_400),
    ));
    Fixture {
        repo: Arc::new(BudgetRepo::new(core.clone())),
        credit: CreditRepo::new(core.clone()),
        settlement,
        core,
        account,
        now: Utc::now(),
    }
}

impl Fixture {
    async fn allowance(&self, amount: i64) {
        self.repo
            .grant(GrantRequest {
                budget_account_id: self.account.clone(),
                account_id: self.account.clone(),
                project_id: None,
                period: Period::current(self.now),
                amount_micros: amount,
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
            .unwrap();
    }

    fn fund_request(&self, source: GrantSource, amount: i64, key: &str) -> FundRequest {
        FundRequest {
            budget_account_id: self.account.clone(),
            source,
            amount_micros: amount,
            idempotency_key: key.to_string(),
            external_ref: Some(format!("pi_{key}")),
            reverses_idempotency_key: None,
            expires_at: None,
            actor_id: Some("svc:commerce".to_string()),
            reason: None,
        }
    }

    async fn lot_remaining(&self, pool: &PgPool, lot_id: &str) -> i64 {
        sqlx::query_scalar("SELECT remaining_micros FROM credit_lots WHERE lot_id = $1")
            .bind(lot_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn balances(&self) -> lightbridge_authz_budget::SettledBalances {
        self.settlement
            .settled_balances(&self.account, &Period::current(self.now), self.now)
            .await
            .unwrap()
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_purchase_opens_a_lot_and_a_replay_returns_it(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::default()).await;
    let first = f
        .credit
        .fund(f.fund_request(GrantSource::Purchase, 20 * USD, "ord-1"))
        .await
        .unwrap();
    assert!(!first.replayed);
    assert_eq!(first.lot_id, first.grant_id, "a credit row is its own lot");
    assert_eq!(f.lot_remaining(&pool, &first.lot_id).await, 20 * USD);

    let replay = f
        .credit
        .fund(f.fund_request(GrantSource::Purchase, 20 * USD, "ord-1"))
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.grant_id, first.grant_id);
    assert_eq!(
        f.balances().await.paid_micros,
        20 * USD,
        "the replay booked nothing"
    );

    let conflict = f
        .credit
        .fund(f.fund_request(GrantSource::Purchase, 21 * USD, "ord-1"))
        .await;
    assert!(matches!(conflict, Err(BudgetError::IdempotencyConflict(_))));

    let mut unknown = f.fund_request(GrantSource::Purchase, USD, "ord-2");
    unknown.budget_account_id = cuid2();
    assert!(matches!(
        f.credit.fund(unknown).await,
        Err(BudgetError::NotFound(_))
    ));
    let refused = f
        .credit
        .fund(f.fund_request(GrantSource::Admin, USD, "ord-3"))
        .await;
    assert!(matches!(refused, Err(BudgetError::FundingRefused(_))));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reversal_is_capped_at_what_is_left_of_the_purchase(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::default()).await;
    let purchase = f
        .credit
        .fund(f.fund_request(GrantSource::Purchase, 20 * USD, "ord-1"))
        .await
        .unwrap();
    let mut reversal = f.fund_request(GrantSource::PurchaseReversal, 5 * USD, "refund-1");
    reversal.reverses_idempotency_key = Some("ord-1".to_string());
    let reversed = f.credit.fund(reversal.clone()).await.unwrap();
    assert_eq!(reversed.amount_micros, -5 * USD);
    assert_eq!(f.lot_remaining(&pool, &purchase.lot_id).await, 15 * USD);

    let mut too_much = reversal;
    too_much.idempotency_key = "refund-2".to_string();
    too_much.amount_micros = 16 * USD;
    assert!(matches!(
        f.credit.fund(too_much).await,
        Err(BudgetError::ReversalExceedsLot { requested, remaining })
            if requested == 16 * USD && remaining == 15 * USD
    ));
}

/// The ADR's Monday example: $8 allowance, $5 promotion, $20 purchase, $10 spent, then a reset to
/// $8. Today that reset books −$15; under ADR-0035 the purchase is untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn settlement_spends_in_order_and_a_reset_never_touches_paid_credit(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::answering(&[10 * USD])).await;
    f.allowance(8 * USD).await;
    let mut promo = f.fund_request(GrantSource::Promotion, 5 * USD, "promo-1");
    promo.expires_at = Some(f.now + chrono::Duration::days(30));
    let promo = f.credit.fund(promo).await.unwrap();
    let purchase = f
        .credit
        .fund(f.fund_request(GrantSource::Purchase, 20 * USD, "ord-1"))
        .await
        .unwrap();

    let SettleOutcome::Settled(booked) = f
        .settlement
        .settle_account(&f.account, f.now)
        .await
        .unwrap()
    else {
        panic!("the window must settle");
    };
    assert_eq!(booked.consumption_rows, 2, "allowance, then the promotion");
    assert_eq!(f.lot_remaining(&pool, &promo.lot_id).await, 3 * USD);
    assert_eq!(f.lot_remaining(&pool, &purchase.lot_id).await, 20 * USD);
    let settled = f.balances().await;
    assert_eq!((settled.allowance_micros, settled.debt_micros), (0, 0));

    let scheduler = ResetScheduler::new(
        f.core.clone(),
        f.repo.clone(),
        Arc::new(WindowSpend::default()),
    )
    .with_settlement(f.settlement.clone());
    let schedule = cuid2();
    sqlx::query(
        "INSERT INTO budget_reset_schedules (id, name, scope_kind, scope_id, cadence, run_at_utc, \
         amount_micros, mode, enabled, next_run_at) \
         VALUES ($1, 'reset to $8', 'account', $2, 'daily', '00:00', $3, 'reset', true, $4)",
    )
    .bind(&schedule)
    .bind(&f.account)
    .bind(8 * USD)
    .bind(f.now)
    .execute(&pool)
    .await
    .unwrap();
    let outcome = scheduler.run_now(&schedule, f.now, false).await.unwrap();
    assert_eq!(
        outcome.planned[0].delta_micros,
        8 * USD,
        "allowance was $0, so +$8"
    );

    let after = f.balances().await;
    assert_eq!(after.allowance_micros, 8 * USD);
    assert_eq!(after.granted_micros, 3 * USD);
    assert_eq!(
        after.paid_micros,
        20 * USD,
        "the reset never read the purchase"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reset_down_books_expiry_not_correction(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::default()).await;
    f.allowance(10 * USD).await;
    let scheduler = ResetScheduler::new(
        f.core.clone(),
        f.repo.clone(),
        Arc::new(WindowSpend::default()),
    )
    .with_settlement(f.settlement.clone());
    let schedule = cuid2();
    sqlx::query(
        "INSERT INTO budget_reset_schedules (id, name, scope_kind, scope_id, cadence, run_at_utc, \
         amount_micros, mode, enabled, next_run_at) \
         VALUES ($1, 'reset to $2', 'account', $2, 'daily', '00:00', $3, 'reset', true, $4)",
    )
    .bind(&schedule)
    .bind(&f.account)
    .bind(2 * USD)
    .bind(f.now)
    .execute(&pool)
    .await
    .unwrap();
    scheduler.run_now(&schedule, f.now, false).await.unwrap();
    let source: String = sqlx::query_scalar(
        "SELECT source FROM budget_grants WHERE budget_account_id = $1 AND amount_micros < 0",
    )
    .bind(&f.account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(source, "expiry");
    assert_eq!(f.balances().await.allowance_micros, 2 * USD);
}

#[sqlx::test(migrations = "../../migrations")]
async fn spend_past_all_credit_is_debt_and_a_purchase_repays_it_first(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::answering(&[3 * USD])).await;
    f.allowance(USD).await;
    f.settlement
        .settle_account(&f.account, f.now)
        .await
        .unwrap();
    assert_eq!(f.balances().await.debt_micros, 2 * USD);

    let purchase = f
        .credit
        .fund(f.fund_request(GrantSource::Purchase, 10 * USD, "ord-1"))
        .await
        .unwrap();
    let later = f.now + chrono::Duration::minutes(5);
    f.settlement
        .settle_account(&f.account, later)
        .await
        .unwrap();
    assert_eq!(
        f.lot_remaining(&pool, &purchase.lot_id).await,
        8 * USD,
        "debt paid first"
    );
    assert_eq!(f.balances().await.debt_micros, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_granted_lot_is_booked_as_expiry(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::default()).await;
    let mut promo = f.fund_request(GrantSource::Promotion, 5 * USD, "promo-1");
    promo.expires_at = Some(f.now + chrono::Duration::hours(1));
    let promo = f.credit.fund(promo).await.unwrap();
    let after_expiry = f.now + chrono::Duration::hours(2);
    let SettleOutcome::Settled(booked) = f
        .settlement
        .settle_account(&f.account, after_expiry)
        .await
        .unwrap()
    else {
        panic!("must settle");
    };
    assert_eq!(booked.expired_lots, 1);
    assert_eq!(f.lot_remaining(&pool, &promo.lot_id).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_window_is_settled_once_and_unknown_spend_writes_nothing(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::answering(&[2 * USD])).await;
    f.allowance(5 * USD).await;
    f.settlement
        .settle_account(&f.account, f.now)
        .await
        .unwrap();
    f.settlement
        .settle_account(&f.account, f.now)
        .await
        .unwrap();
    assert_eq!(
        f.balances().await.allowance_micros,
        3 * USD,
        "the second run booked nothing"
    );

    let down = fixture(
        &pool,
        WindowSpend {
            unreachable: true,
            ..WindowSpend::default()
        },
    )
    .await;
    down.allowance(5 * USD).await;
    let outcome = down
        .settlement
        .settle_account(&down.account, down.now)
        .await
        .unwrap();
    assert_eq!(outcome, SettleOutcome::Deferred);
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM settlement_state WHERE budget_account_id = $1")
            .bind(&down.account)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 0, "no watermark is written on unknown spend");
}

/// ADR-0035 *Rollout*: for an account with no granted or paid credit the pool-aware snapshot reads
/// exactly what the ADR-0034 refresher did. A purchase then moves it on the very next read.
#[sqlx::test(migrations = "../../migrations")]
async fn the_pool_aware_snapshot_equals_todays_number_then_adds_a_purchase(pool: PgPool) {
    let f = fixture(&pool, WindowSpend::answering(&[3 * USD, 3 * USD])).await;
    f.allowance(10 * USD).await;
    let store = SnapshotStore::new(f.core.clone());
    store.touch(&f.account).await.unwrap();
    let scheduler = Arc::new(
        ResetScheduler::new(
            f.core.clone(),
            f.repo.clone(),
            Arc::new(WindowSpend::default()),
        )
        .with_settlement(f.settlement.clone()),
    );
    let refresher = SnapshotRefresher::new(
        store.clone(),
        f.repo.clone(),
        Arc::new(WindowSpend::default()),
        scheduler,
        SnapshotRefreshConfig::default(),
    );
    refresher.tick(f.now).await.unwrap();
    let snapshot = store.read(&f.account).await.unwrap().unwrap();
    assert_eq!(
        snapshot.remaining_micros,
        Some(7 * USD),
        "10 granted − 3 spent, as today"
    );

    f.credit
        .fund(f.fund_request(GrantSource::Purchase, 20 * USD, "ord-1"))
        .await
        .unwrap();
    let snapshot = store.read(&f.account).await.unwrap().unwrap();
    assert_eq!(
        snapshot.remaining_micros,
        Some(27 * USD),
        "visible before any refresh"
    );

    let paid: Option<i64> = sqlx::query_scalar(
        "SELECT paid_remaining_micros FROM budget_remaining_snapshots WHERE budget_account_id = $1",
    )
    .bind(&f.account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(paid, Some(20 * USD));
}

/// ADR-0035 D9 for the live `/budget/v1/remaining` read: with settlement on it must count paid
/// credit exactly as the snapshot does. The ADR-0034 formula (allowance minus this month's spend)
/// would answer 10 − 3 = 7 here and silently drop the $20 purchase.
#[sqlx::test(migrations = "../../migrations")]
async fn the_live_remaining_read_counts_purchased_credit_under_settlement(pool: PgPool) {
    use lightbridge_authz_budget::{Remaining, RemainingReader, RemainingService};

    let f = fixture(&pool, WindowSpend::answering(&[3 * USD])).await;
    f.allowance(10 * USD).await;
    f.credit
        .fund(f.fund_request(GrantSource::Purchase, 20 * USD, "ord-1"))
        .await
        .unwrap();
    let scheduler = Arc::new(
        ResetScheduler::new(
            f.core.clone(),
            f.repo.clone(),
            Arc::new(WindowSpend::default()),
        )
        .with_settlement(f.settlement.clone()),
    );
    let service =
        RemainingService::new(f.repo.clone(), Arc::new(WindowSpend::default()), scheduler);
    let Remaining::Known(remaining) = service
        .remaining_for_account(&f.account, &Period::current(f.now), f.now)
        .await
        .unwrap()
    else {
        panic!("a known account with a readable spend source must answer Known");
    };
    assert_eq!(
        remaining.ceiling_micros,
        30 * USD,
        "allowance + the purchase"
    );
    assert_eq!(remaining.spent_micros, 3 * USD, "the unsettled tail");
    assert_eq!(remaining.remaining_micros, 27 * USD);
}
