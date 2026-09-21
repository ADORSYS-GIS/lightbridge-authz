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
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};

use crate::aggregate_refresh_config::AggregateRefreshConfig;

/// The named KPI aggregates, in dependency-free order (each is independent, built on one grain
/// table). This list is the single source of truth for what the refresh job refreshes and what the
/// existence/refresh tests assert -- keep it in lockstep with the migration's materialized views.
pub const AGGREGATE_VIEWS: &[&str] = &[
    "mv_executions_spend_hourly",
    "mv_executions_requests_hourly",
    "mv_executions_latency_hourly",
    "mv_model_calls_tokens_hourly",
    "mv_model_calls_spend_hourly",
    "mv_model_calls_requests_hourly",
    "mv_day_facts_active_users_daily",
    "mv_day_facts_acceptances_daily",
    "mv_day_facts_spend_daily",
    "mv_seat_snapshots_active_daily",
];

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
            Ok(()) => {
                if let Err(e) = record_last_refresh(&pool).await {
                    warn!("usage aggregate refresh: failed to record last refresh: {e}");
                }
            }
            Err(e) => warn!("usage aggregate refresh run failed: {e}"),
        }
    }
}

/// Refreshes every named KPI aggregate with `REFRESH MATERIALIZED VIEW CONCURRENTLY`, under a
/// session-level advisory lock so concurrent replicas do not refresh the same view at once. Each
/// view is refreshed in its own statement; a failure aborts the run (the loop logs and retries next
/// tick).
pub async fn refresh_all_aggregates(pool: &PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;

    // Exclusive advisory lock for the refresh job, so two replicas never run `REFRESH ...
    // CONCURRENTLY` on the same view at the same time (which Postgres would refuse with "cannot
    // refresh materialized view concurrently"). This MUST be a session-level lock
    // (`pg_try_advisory_lock`), not a transaction-scoped one (`pg_try_advisory_xact_lock`): each
    // `REFRESH` below runs in its own implicit transaction, so a transaction-scoped lock would be
    // released before the first refresh and would not serialize anything. The session lock is held
    // on this connection until we explicitly release it below, and is released automatically if the
    // connection/session ends.
    let lock_acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock(587000001)")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| Error::Database(format!("usage aggregate refresh lock failed: {e}")))?;

    if !lock_acquired {
        // Another replica is currently refreshing; skip this run gracefully.
        return Ok(());
    }

    let result = async {
        for view in AGGREGATE_VIEWS {
            // `view` comes from the hardcoded static allowlist `AGGREGATE_VIEWS` (never user input),
            // so wrapping the interpolated statement in `AssertSqlSafe` is the documented safe use
            // of the escape hatch -- the names are compile-time constants, not request data.
            let sql = format!("REFRESH MATERIALIZED VIEW CONCURRENTLY {view}");
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    Error::Database(format!("usage aggregate refresh of {view} failed: {e}"))
                })?;
        }
        Ok::<(), Error>(())
    }
    .await;

    // Always release the session lock, whether the refresh succeeded or failed, so a failed run
    // does not leave the lock held on a pooled connection.
    sqlx::query("SELECT pg_advisory_unlock(587000001)")
        .execute(&mut *conn)
        .await
        .map_err(|e| Error::Database(format!("usage aggregate refresh unlock failed: {e}")))?;

    result
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
