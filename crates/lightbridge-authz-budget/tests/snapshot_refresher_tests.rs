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

    // A transaction-scoped advisory lock taken by hand stands in for the other replica: it is the
    // same lock, taken the same way, from a different session.
    let mut held = pool.begin().await.expect("begin");
    let (taken,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1)")
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

    // Ending the transaction releases it -- which is the property this whole design rests on.
    held.rollback().await.expect("rollback must succeed");

    assert!(
        first.tick(Utc::now()).await.expect("tick").ran,
        "once the lock is free the next tick runs normally"
    );
}

/// The reason the lock is transaction-scoped: a tick that is CANCELLED mid-flight must still leave
/// the lock free **to another session**. A cancelled task and a panicking one drop the future at
/// exactly the same place, and neither runs the explicit unlock that a session-scoped lock needs.
///
/// Two details make this a real test rather than a shape:
///
/// - The tick is made slow on purpose (`SlowSpend`), and the test waits until another session can
///   *observe* the lock held before cancelling. Cancelling earlier would abort before the lock was
///   ever taken and prove nothing — the first version of this test did exactly that and passed
///   against the broken implementation.
/// - The final assertion comes from a SEPARATE session. Postgres advisory locks are re-entrant
///   within one session, and a dropped `PoolConnection` goes straight back to the pool, so with a
///   session-scoped lock the very next tick can be handed the same connection and re-acquire its
///   own leaked lock — passing while every OTHER replica is wedged.
///
/// **What this does and does not discriminate — measured, 2026-09-04.** Under *cancellation* the
/// aborted task's connection is destroyed rather than returned to the pool, and destroying the
/// session releases a session-scoped advisory lock too. So both scopes end up free here; they
/// differ only in how fast (xact 1-6 ms, session 21-23 ms, measured locally). A ~20 ms margin is
/// not something a loaded CI runner respects, and asserting it *instantly* — as this test did until
/// lightbridge-authz#695's `test` job went red — was asserting the scheduler, not the lock.
///
/// The cancellation half is therefore bounded-poll only: it pins "a cancelled tick does not wedge
/// the lock", which is the property an operator cares about, and would still catch a leak measured
/// in seconds. The **deterministic** scope check is the second half below, on a tick that runs to
/// completion: there is no teardown to mask anything, so a session-scoped lock whose explicit
/// unlock was skipped stays held and the assertion fails every time. Verified by hand both ways.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cancelled_tick_leaves_the_lock_free_for_other_replicas(pool: PgPool) {
    let id = account(&pool).await;
    let (store, refresher) = build(&pool, Arc::new(SlowSpend), config());
    store.touch(&id).await.expect("touch");

    let refresher = Arc::new(refresher);
    let running = tokio::spawn({
        let refresher = refresher.clone();
        async move { refresher.tick(Utc::now()).await }
    });

    // Wait until the lock is genuinely held, from another session's point of view. Without this the
    // cancellation below can land before `tick` ever reaches the lock.
    let mut held = false;
    for _ in 0..100 {
        if !lock_is_free(&pool).await {
            held = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        held,
        "the tick must have taken the lock before it can be cancelled mid-flight"
    );

    running.abort();
    let _ = running.await;

    assert!(
        lock_becomes_free(&pool).await,
        "a cancelled tick must not leave the advisory lock held -- a session-scoped lock returned \
         to the pool still held would silently stop every OTHER replica's refresher until that \
         connection happened to be recycled"
    );

    // The deterministic half. This tick runs to COMPLETION, so its connection goes back to the
    // pool healthy and no teardown can mask a leak: the lock is free here only because `tick` took
    // it with `pg_try_advisory_xact_lock` and its own rollback released it. Probed instantly and
    // without a poll, on purpose -- there is no race left to tolerate.
    let (_, quick) = build(&pool, Arc::new(FixedSpend(1)), config());
    quick
        .tick(Utc::now())
        .await
        .expect("a completed tick must succeed");
    assert!(
        lock_is_free(&pool).await,
        "a COMPLETED tick must leave the advisory lock free with no explicit unlock -- this is the \
         assertion that fails outright if the lock is ever made session-scoped again"
    );
}

/// Polls [`lock_is_free`] for up to two seconds.
///
/// The wait is not slack in the property; it is what makes the property observable at all.
/// `sqlx::Transaction::drop` does **not** issue `ROLLBACK` synchronously — it marks the connection
/// so the rollback runs before that connection is used again. So between `abort()` returning and
/// the queued rollback actually executing there is a window, and a probe on a *different* pool
/// connection can land inside it and see the lock still held. Asserting instantly therefore tested
/// the scheduler's timing as much as the lock's scope, and went red on a loaded CI runner
/// (lightbridge-authz#695's `test` job) while passing 15/15 locally.
///
/// What is being asserted is unchanged: the lock is released **promptly and without anyone calling
/// `pg_advisory_unlock`**. The negative control still fails exactly as the doc comment above
/// claims — a session-scoped `pg_try_advisory_lock` whose explicit unlock was skipped stays held
/// for as long as that connection sits in the pool, which is far longer than this bound.
/// Polls [`lock_is_free`] for up to two seconds.
///
/// The wait is not slack in the property, it is what makes the property observable at all.
/// `sqlx::Transaction::drop` does **not** issue `ROLLBACK` synchronously -- it marks the connection
/// so the rollback runs before that connection is used again. Between `abort()` returning and that
/// queued work executing there is a window, and a probe on a *different* pool connection can land
/// inside it. Two seconds is far above the 1-6 ms this takes in practice and far below any leak
/// worth calling a leak.
async fn lock_becomes_free(pool: &PgPool) -> bool {
    for _ in 0..100 {
        if lock_is_free(pool).await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    false
}

/// `true` when nobody holds the refresher's advisory lock, read from `pg_locks`.
///
/// **This must not acquire the lock to find out.** The previous version asked with
/// `pg_try_advisory_xact_lock` and rolled back, which made the observer a *competitor*: the
/// observation loop below probes ~50 times a second, `SnapshotRefresher::tick` makes exactly ONE
/// `try` attempt and gives up for the whole tick if it loses, so a probe landing on the same
/// instant made the tick return `ran: false` and the lock was then never held at all. That is the
/// mechanism behind both halves of this test going red intermittently (2 of 25 local runs, and
/// lightbridge-authz#695's `test` job on a loaded runner).
///
/// Reading `pg_locks` takes no lock and cannot perturb what it measures. A 64-bit advisory key is
/// split across two columns: `classid` is the high 32 bits, `objid` the low 32 — the same split
/// the `budget-remaining-snapshot` runbook's diagnostic query uses.
async fn lock_is_free(pool: &PgPool) -> bool {
    const LOCK_CLASSID: i32 = 1_112_884_295;
    const LOCK_OBJID: i32 = 1_599_295_056;
    let (held,): (i64,) = sqlx::query_as(
        "SELECT count(*)::bigint FROM pg_locks \
         WHERE locktype = 'advisory' AND classid = $1 AND objid = $2 AND granted",
    )
    .bind(LOCK_CLASSID)
    .bind(LOCK_OBJID)
    .fetch_one(pool)
    .await
    .expect("reading pg_locks must succeed");
    held == 0
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

/// A spend reader slow enough that a tick can be observed mid-flight and cancelled there.
#[derive(Debug)]
struct SlowSpend;

#[lightbridge_authz_core::async_trait]
impl SpendReader for SlowSpend {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        Ok(Spend::Known(1))
    }

    async fn observe_spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        Ok(SpendObservation::Answered(1))
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
