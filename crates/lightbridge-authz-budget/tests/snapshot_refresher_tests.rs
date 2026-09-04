#![cfg(feature = "it-tests")]
//! [`SnapshotRefresher`] against a real Postgres — ADR-0034 §15.
//!
//! Covers the four properties the module doc claims: the active-set selection, the batch bound,
//! the fail-soft keep on an unreachable spend source, and the advisory lock that stops a second
//! replica recomputing the same rows.

use std::sync::Arc;

use chrono::Utc;
use lightbridge_authz_budget::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::BudgetRepo;
use lightbridge_authz_budget::reset_scheduler::ResetScheduler;
use lightbridge_authz_budget::snapshot::{BudgetSnapshotReader, SnapshotRefreshConfig};
use lightbridge_authz_budget::snapshot_refresher::SnapshotRefresher;
use lightbridge_authz_budget::snapshot_store::SnapshotStore;
use lightbridge_authz_budget::spend::{Spend, SpendObservation, SpendReader};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

fn period() -> Period {
    Period::current(Utc::now())
}

async fn account(pool: &PgPool) -> String {
    let id = cuid2();
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(&id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
    id
}

fn build(
    pool: &PgPool,
    spend: Arc<dyn SpendReader>,
    config: SnapshotRefreshConfig,
) -> (SnapshotStore, SnapshotRefresher) {
    let db = Arc::new(DbPool::from_pool(pool.clone()));
    let store = SnapshotStore::new(db.clone());
    let repo = Arc::new(BudgetRepo::new(db.clone()));
    let scheduler = Arc::new(ResetScheduler::new(db, repo.clone(), spend.clone()));
    (
        store.clone(),
        SnapshotRefresher::new(store, repo, spend, scheduler, config),
    )
}

fn config() -> SnapshotRefreshConfig {
    SnapshotRefreshConfig {
        active_window: std::time::Duration::from_secs(600),
        ..SnapshotRefreshConfig::default()
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_tick_computes_a_reading_for_every_active_account(pool: PgPool) {
    let id = account(&pool).await;
    let (store, refresher) = build(&pool, Arc::new(FixedSpend(7_000_000)), config());
    store.touch(&id).await.expect("touch");

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert!(report.ran);
    assert_eq!((report.considered, report.refreshed), (1, 1));

    let snapshot = store
        .read(&id)
        .await
        .expect("read")
        .expect("the tick must have written a row");
    assert_eq!(
        snapshot.remaining_for(&period()),
        Some(-7_000_000),
        "no grants yet, so the ceiling is zero and the account is already overspent -- signed and \
         unclamped, exactly as the ledger says"
    );
    assert!(snapshot.age_seconds(Utc::now()).is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_outside_the_active_window_is_not_refreshed(pool: PgPool) {
    let id = account(&pool).await;
    let (store, refresher) = build(&pool, Arc::new(FixedSpend(1)), config());
    store.touch(&id).await.expect("touch");
    sqlx::query("UPDATE budget_remaining_snapshots SET last_seen_at = now() - interval '1 hour'")
        .execute(&pool)
        .await
        .expect("backdating last_seen_at must succeed");

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert_eq!((report.considered, report.refreshed), (0, 0));
    assert_eq!(
        store
            .read(&id)
            .await
            .expect("read")
            .expect("row")
            .remaining_micros,
        None,
        "cost scales with concurrently-active accounts, not with the size of the estate"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unreachable_spend_source_keeps_the_previous_reading(pool: PgPool) {
    let id = account(&pool).await;
    let (store, refresher) = build(&pool, Arc::new(UnreachableSpend), config());
    store.touch(&id).await.expect("touch");
    store
        .store_reading(&id, &period(), 24_000_000, 4_000_000, Utc::now())
        .await
        .expect("storing a reading must succeed");

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert_eq!((report.refreshed, report.kept_stale), (0, 1));

    let snapshot = store.read(&id).await.expect("read").expect("row");
    assert_eq!(
        snapshot.remaining_for(&period()),
        Some(20_000_000),
        "fail-soft: an authz-usage outage must not turn a known balance into a fleet-wide 503"
    );
    assert!(snapshot.stale_since.is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_that_has_never_had_a_readable_spend_stays_unknown(pool: PgPool) {
    let id = account(&pool).await;
    let (store, refresher) = build(&pool, Arc::new(UnreachableSpend), config());
    store.touch(&id).await.expect("touch");

    refresher.tick(Utc::now()).await.expect("tick must succeed");

    assert_eq!(
        store
            .read(&id)
            .await
            .expect("read")
            .expect("row")
            .remaining_micros,
        None,
        "unknown is never zero: the introspection omits the field and the gateway reads 503"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_replicas_tick_is_a_no_op_while_the_first_holds_the_lock(pool: PgPool) {
    let id = account(&pool).await;
    let (store, first) = build(&pool, Arc::new(FixedSpend(1)), config());
    let (_, second) = build(&pool, Arc::new(FixedSpend(1)), config());
    store.touch(&id).await.expect("touch");

    // A session-scoped advisory lock taken by hand on a connection we keep open stands in for the
    // other replica: it is the same lock, taken the same way, from a different session.
    let mut held = pool.acquire().await.expect("acquire");
    let (taken,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
        .bind(0x4255_4447_5F53_4E50_i64)
        .fetch_one(&mut *held)
        .await
        .expect("taking the lock by hand must succeed");
    assert!(taken);

    let blocked = second.tick(Utc::now()).await.expect("tick must succeed");
    assert!(
        !blocked.ran,
        "a replica that cannot take the lock must return immediately, not recompute the same rows"
    );

    let (_,): (bool,) = sqlx::query_as("SELECT pg_advisory_unlock($1)")
        .bind(0x4255_4447_5F53_4E50_i64)
        .fetch_one(&mut *held)
        .await
        .expect("releasing the lock must succeed");
    drop(held);

    assert!(
        first.tick(Utc::now()).await.expect("tick").ran,
        "once the lock is free the next tick runs normally"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_batch_bound_caps_one_ticks_work(pool: PgPool) {
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(account(&pool).await);
    }
    let (store, refresher) = build(
        &pool,
        Arc::new(FixedSpend(1)),
        SnapshotRefreshConfig {
            batch: 2,
            ..config()
        },
    );
    for id in &ids {
        store.touch(id).await.expect("touch");
    }

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert_eq!(
        (report.considered, report.refreshed),
        (2, 2),
        "a tick refreshes at most `batch` accounts; the rest wait for the next one"
    );
}

/// Answers a fixed spend, as `authz-usage` would.
#[derive(Debug)]
struct FixedSpend(i64);

#[lightbridge_authz_core::async_trait]
impl SpendReader for FixedSpend {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(Spend::Known(self.0))
    }

    async fn observe_spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        Ok(SpendObservation::Answered(self.0))
    }
}

/// Stands in for an `authz-usage` that cannot be reached at all.
#[derive(Debug)]
struct UnreachableSpend;

#[lightbridge_authz_core::async_trait]
impl SpendReader for UnreachableSpend {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(Spend::Unavailable)
    }
}
