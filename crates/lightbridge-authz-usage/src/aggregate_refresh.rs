//! The KPI aggregate-refresh background loop (#587).
//!
//! The named KPI aggregates are plain-Postgres materialized views (one per KPI measure, each on
//! exactly one grain table -- see `migrations-usage/20260918000001_usage_kpi_aggregates.sql`).
//! This module refreshes them on a schedule with `REFRESH MATERIALIZED VIEW CONCURRENTLY` (which
//! needs the per-view unique index the migration creates) and records the last successful refresh
//! in `usage_aggregate_refresh_state`, so a test or operator can prove the refresh has run -- the
//! ticket's "refresh policies ... have demonstrably run" acceptance criterion, on plain Postgres.
//!
//! This is Option A from the #587 discussion: the refresh is driven by the usage service's own
//! background loop, mirroring the existing `retention_loop` (which refreshes `usage_events_daily`).
//! It needs no TimescaleDB and no `pg_cron`/`pg_ivm` extension, so the whole feature stays in this
//! repo and is fully testable in CI on plain Postgres.

use lightbridge_authz_core::{Error, Result};
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgConnection;
use sqlx::{PgPool, Postgres};
use std::sync::Arc;
use tracing::{info, warn};

use crate::aggregate_refresh_config::AggregateRefreshConfig;

/// Advisory-lock key for the aggregate refresh job. A fixed, arbitrary constant: Postgres advisory
/// locks are a flat `bigint` namespace shared cluster-wide, so the only requirement is that nothing
/// else in this estate picks the same number.
const REFRESH_ADVISORY_LOCK_KEY: i64 = 587_000_001;

/// The named KPI aggregates, in dependency-free order (each is independent, built on one grain
/// table). This list is the single source of truth for what the refresh job refreshes and what the
/// existence/refresh tests assert -- keep it in lockstep with the migration's materialized views.
///
/// Only the day/seat grains are aggregate-backed: the day-facts and seat query endpoints route to
/// these views, while the execution/model-call endpoints span grains and stay raw (see the
/// migration header). There is deliberately no hourly aggregate here -- a refreshed-but-never-read
/// view is dead weight (the #587 review's P2).
pub const AGGREGATE_VIEWS: &[&str] = &[
    "mv_day_facts_active_users_daily",
    "mv_day_facts_acceptances_daily",
    "mv_day_facts_spend_daily",
    "mv_seat_snapshots_active_daily",
];

/// The day-facts grain's aggregates, for the routing check. Kept separate from
/// [`SEAT_AGGREGATE_VIEWS`] so the day-facts and seat query paths degrade independently: a partial
/// migration or a manual `DROP` of one grain's views must not force the other grain off its own
/// healthy aggregates (the #587 review's P3).
pub const DAY_FACTS_AGGREGATE_VIEWS: &[&str] = &[
    "mv_day_facts_active_users_daily",
    "mv_day_facts_acceptances_daily",
    "mv_day_facts_spend_daily",
];

/// The seat grain's aggregate, for the routing check. See [`DAY_FACTS_AGGREGATE_VIEWS`].
pub const SEAT_AGGREGATE_VIEWS: &[&str] = &["mv_seat_snapshots_active_daily"];

/// Runs the aggregate-refresh background loop forever: every `config.interval_seconds`, refreshes
/// every named KPI aggregate with `REFRESH MATERIALIZED VIEW CONCURRENTLY`. A failed run is logged
/// and the loop continues -- a refresh hiccup must not take the server down, and the next run
/// retries. The first tick fires immediately, so the first refresh happens at startup.
pub async fn run_aggregate_refresh_loop(pool: Arc<PgPool>, config: AggregateRefreshConfig) {
    if !config.enabled {
        info!("usage KPI aggregate refresh disabled by config");
        return;
    }
    info!(
        "usage KPI aggregate refresh enabled: {} aggregates, interval={}s",
        AGGREGATE_VIEWS.len(),
        config.interval_seconds
    );
    // `tokio::time::interval` (not a bare `sleep` loop) so the cadence does not drift by however
    // long each run takes, and `MissedTickBehavior::Skip` so a run that overruns the interval does
    // not queue a burst of catch-up ticks.
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        config.interval_seconds.max(1),
    ));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        match refresh_all_aggregates(&pool).await {
            Ok(true) => {
                // A refresh actually ran; record it so a test or operator can prove it.
                if let Err(e) = record_last_refresh(&pool).await {
                    warn!("usage aggregate refresh: failed to record last refresh: {e}");
                }
            }
            Ok(false) => {
                // Skipped because another replica holds the refresh lock; nothing was refreshed, so
                // we deliberately do NOT record a last_refreshed_at for a run that refreshed
                // nothing (the #587 review's P2: a silent skip must not masquerade as a refresh).
            }
            Err(e) => warn!("usage aggregate refresh run failed: {e}"),
        }
    }
}

/// Refreshes every named KPI aggregate with `REFRESH MATERIALIZED VIEW CONCURRENTLY`, under a
/// session-level advisory lock so concurrent replicas do not refresh the same view at once. Each
/// view is refreshed in its own statement; a failure aborts the run (the loop logs and retries next
/// tick).
///
/// Returns `Ok(true)` when a refresh actually ran, `Ok(false)` when this run was skipped because
/// another replica holds the refresh lock (the caller must NOT record a `last_refreshed_at` for a
/// run that refreshed nothing), and `Err` on a real failure.
pub async fn refresh_all_aggregates(pool: &PgPool) -> Result<bool> {
    let mut conn = pool.acquire().await?;

    // Exclusive advisory lock for the refresh job, so two replicas never run `REFRESH ...
    // CONCURRENTLY` on the same view at the same time (which Postgres would refuse with "cannot
    // refresh materialized view concurrently"). This MUST be a session-level lock
    // (`pg_try_advisory_lock`), not a transaction-scoped one (`pg_try_advisory_xact_lock`): each
    // `REFRESH` below runs in its own implicit transaction, so a transaction-scoped lock would be
    // released before the first refresh and would not serialize anything. The session lock is held
    // on this connection until it is released, and is released automatically if the
    // connection/session ends.
    let lock_acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(REFRESH_ADVISORY_LOCK_KEY)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| Error::Database(format!("usage aggregate refresh lock failed: {e}")))?;

    if !lock_acquired {
        // Another replica is currently refreshing; skip this run. Log it (a silent skip would
        // masquerade as a refresh -- the #587 review's P2) and report that nothing was refreshed.
        warn!("usage aggregate refresh: another replica holds the refresh lock; skipping this run");
        return Ok(false);
    }

    // From here the session lock is held. Hand it to a guard so it is released even if this future
    // is cancelled or panics mid-refresh -- see [`RefreshLockGuard`].
    let mut guard = RefreshLockGuard::new(conn, REFRESH_ADVISORY_LOCK_KEY);

    let result = async {
        for view in AGGREGATE_VIEWS {
            // `view` comes from the hardcoded static allowlist `AGGREGATE_VIEWS` (never user input),
            // so wrapping the interpolated statement in `AssertSqlSafe` is the documented safe use
            // of the escape hatch -- the names are compile-time constants, not request data.
            let sql = format!("REFRESH MATERIALIZED VIEW CONCURRENTLY {view}");
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(guard.conn_mut())
                .await
                .map_err(|e| {
                    Error::Database(format!("usage aggregate refresh of {view} failed: {e}"))
                })?;
        }
        Ok::<(), Error>(())
    }
    .await;

    // Always release the session lock, whether the refresh succeeded or failed, so a failed run
    // does not leave the lock held on a pooled connection. If the unlock itself fails, log it (a
    // held lock on a pooled connection would block future refreshes) but do NOT let it mask the
    // refresh result -- the refresh error, if any, is the more important signal (the #587 review's
    // P2: an unlock failure must not overwrite a refresh failure).
    guard.release().await;

    result.map(|()| true)
}

/// Guards the session-scoped advisory lock for the aggregate refresh.
///
/// `REFRESH MATERIALIZED VIEW CONCURRENTLY` cannot run inside an explicit transaction, so the
/// refresh lock must be session-scoped (`pg_try_advisory_lock`), not transaction-scoped like the
/// budget refresher's (`pg_try_advisory_xact_lock`, which releases on rollback -- including the
/// rollback `sqlx::Transaction`'s `Drop` issues on cancellation or panic). A session lock is
/// released only by `pg_advisory_unlock` on the SAME session or by that session ending. If the
/// refresh future were cancelled or panicked before the explicit unlock, the pooled connection
/// would return to the pool with the lock still held on its session -- silently freezing every
/// replica's refresh (the exact bug class `snapshot_refresher.rs` fixed with a transaction-scoped
/// lock). This guard guarantees the unlock runs on drop, even on cancellation or panic.
///
/// The normal path calls [`RefreshLockGuard::release`], which runs the unlock and consumes the
/// connection so `Drop` does nothing. The abnormal path (cancellation/panic) drops the guard with
/// the connection still held, and `Drop` releases the lock on a dedicated thread with its own
/// runtime -- robust even if the current runtime is shutting down.
pub struct RefreshLockGuard {
    conn: Option<PoolConnection<Postgres>>,
    key: i64,
}

impl RefreshLockGuard {
    pub fn new(conn: PoolConnection<Postgres>, key: i64) -> Self {
        Self {
            conn: Some(conn),
            key,
        }
    }

    /// The connection the refresh runs on. Always present until [`RefreshLockGuard::release`] or
    /// `Drop` takes it.
    fn conn_mut(&mut self) -> &mut PgConnection {
        self.conn
            .as_mut()
            .expect("refresh lock guard connection present")
    }

    /// Releases the session lock on the normal path, consuming the connection so `Drop` does
    /// nothing. Logs (does not propagate) an unlock failure -- a held lock on a pooled connection
    /// would block future refreshes, but the refresh result is the more important signal.
    async fn release(mut self) {
        if let Some(mut conn) = self.conn.take()
            && let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.key)
                .execute(&mut *conn)
                .await
        {
            warn!("usage aggregate refresh: failed to release advisory lock: {e}");
        }
    }
}

impl Drop for RefreshLockGuard {
    fn drop(&mut self) {
        // Abnormal path: the refresh future was cancelled or panicked before `release` ran. The
        // connection is still here, so release the lock on a dedicated thread with its own runtime
        // before the connection returns to the pool. This is robust even during runtime shutdown
        // (the pool teardown would also close the session, but we do not rely on that).
        if let Some(conn) = self.conn.take() {
            let key = self.key;
            std::thread::spawn(move || {
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(e) => {
                        warn!(
                            "usage aggregate refresh: failed to build runtime to release advisory \
                             lock on drop: {e}"
                        );
                        return;
                    }
                };
                rt.block_on(async move {
                    let mut conn = conn;
                    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
                        .bind(key)
                        .execute(&mut *conn)
                        .await
                    {
                        warn!(
                            "usage aggregate refresh: failed to release advisory lock on drop: {e}"
                        );
                    }
                });
            });
        }
    }
}

/// Records the last successful refresh into `usage_aggregate_refresh_state`, so a test or operator
/// can prove the refresh has run. Uses the database clock so it matches what the refresh actually
/// did regardless of app/DB clock skew.
pub async fn record_last_refresh(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "INSERT INTO usage_aggregate_refresh_state (id, last_refreshed_at)
         VALUES (TRUE, now())
         ON CONFLICT (id) DO UPDATE
           SET last_refreshed_at = EXCLUDED.last_refreshed_at, updated_at = now()",
    )
    .execute(pool)
    .await
    .map_err(|e| Error::Database(format!("usage aggregate refresh state write failed: {e}")))?;

    Ok(())
}
