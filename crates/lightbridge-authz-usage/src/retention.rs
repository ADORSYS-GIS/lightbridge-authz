//! Retention/rollup for `usage_events` (#549 AC2).
//!
//! `usage_events` grows ~100 MB/day with no retention. This module runs a background job that
//! rolls rows older than a retention window into the `usage_events_daily` aggregate table and
//! deletes them from the raw table, in one transaction per batch (see [`rollup_and_purge`]). The
//! rollup table is itself bounded by `rollup_days`, so the long-term store does not grow without
//! bound either.
//!
//! ## Cutover against a pre-existing backlog has no grace period
//!
//! The steady-state picture above -- a day spends `rollup_days - raw_days` visible in the rollup
//! before being purged -- assumes the job has been running since the data was ingested. It does
//! NOT hold for a fresh cutover against a backlog older than `rollup_days`: the first run rolls up
//! everything older than `raw_days` (including rows far older than `rollup_days`) and then, in the
//! same run, purges any rollup row older than `rollup_days`. That slice is rolled up and deleted
//! in the same run, with zero grace period and no way to inspect or export it first. See
//! [`RetentionConfig::enabled`] and `docs/runbooks/reclaim-usage-events-space.md` for the operator
//! warning.
//!
//! ## Why only COMPLETE days are rolled up
//!
//! The cutoff is `date_trunc('day', now() - raw_days)` -- the start of the day that is `raw_days`
//! old. Rows strictly older than that cutoff come from days that are fully in the past, so every
//! day is rolled up exactly once, as a whole day. The transaction's atomicity (rollup + delete
//! commit together) makes a re-run idempotent: a committed run leaves no raw rows for the days it
//! rolled up, and a rolled-back run leaves no rollup rows at all.
//!
//! ## The rollup and the purge are ONE statement (no READ COMMITTED race)
//!
//! The rollup and the raw purge are a single `DELETE ... RETURNING` feeding an `INSERT ... ON
//! CONFLICT DO UPDATE` (see [`ROLLUP_AND_PURGE_SQL`]). Under READ COMMITTED each *statement* takes
//! one snapshot, so a single statement can never delete a row it did not also roll up. If the two
//! were separate statements, a backdated row committed by ingest between them -- a replayed OTLP
//! export, a slow exporter flush -- would satisfy `observed_at < cutoff`, be invisible to the
//! INSERT, and be deleted by the DELETE: billable spend gone, permanently, silently. The
//! one-statement form closes that window: whatever the DELETE sees, the INSERT rolls up, and a row
//! committed mid-statement is invisible to both and simply stays raw for the next run.
//!
//! ## Late-arriving data is FOLDED IN, never dropped
//!
//! The rollup INSERT carries `ON CONFLICT DO UPDATE`, so a late-arriving raw event -- one whose
//! `observed_at` falls in a day a previous run already rolled up (a replayed export, or clock
//! skew) -- is added to the existing rollup row rather than dropped. Without it, that event's
//! `(bucket_start, dimensions)` group would already exist in `usage_events_daily` (the unique index
//! treats NULLs as equal), the INSERT would either raise a unique violation (wedging the job) or,
//! with `DO NOTHING`, silently discard the late event's cost. `DO UPDATE` folds the late cost in
//! with a NULL-safe `COALESCE` add, so spend for a closed historical period is stable: it never
//! jumps up while the late row is still raw and then collapses when the row is purged.
//!
//! ## The retention window vs. the dashboard
//!
//! The dashboard's max range is 90 days, and `raw_days` defaults to 90. Because the cutoff is
//! rounded DOWN to the day boundary, raw keeps slightly MORE than `raw_days` (up to the start of
//! the boundary day), so the full 90-day dashboard window is always served from raw -- which is
//! what keeps latency percentiles exact (the rollup does not carry them). Budget spend reads the
//! current billing period, which is always within the raw window, so it is never truncated.
//!
//! ## Bucketing is pinned to UTC
//!
//! `date_trunc('day', <timestamptz>)` truncates in the database session's `TimeZone`, so the day
//! boundary -- and therefore the cutoff -- would shift with the session's zone. The transaction
//! runs `SET LOCAL TimeZone = 'UTC'` as its first statement, pinning every day boundary in this
//! transaction to UTC regardless of the session's configured zone.

use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Error, Result};
use sqlx::{Connection, PgConnection, PgPool};
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::RetentionConfig;
// The rollup/purge SQL statements live in `rollup_sql` (split out by the LoC gate); re-export them
// here so `retention.rs`'s existing callers and the module's public surface are unchanged.
pub use crate::rollup_sql::{ROLLUP_AND_PURGE_SQL, ROLLUP_PURGE_SQL};

/// Outcome of a retention/rollup run.
#[derive(Debug, Clone, Copy)]
pub struct RetentionRun {
    /// Number of raw rows rolled up and purged.
    pub purged: u64,
    /// Whether the run drained the raw table to the cutoff (reached an empty batch). `false` when
    /// the run was cut short by losing the advisory lock to a concurrent replica -- partial
    /// progress only, older rows still raw.
    pub completed: bool,
}

/// Runs the retention/rollup background loop forever: every `config.interval_seconds`, rolls rows
/// older than `config.raw_days` into `usage_events_daily` and deletes them from `usage_events`,
/// and deletes rollup rows older than `config.rollup_days`. A failed run is logged and the loop
/// continues -- a retention hiccup must not take the server down, and the next run retries.
pub async fn run_retention_loop(pool: Arc<PgPool>, config: RetentionConfig) {
    if !config.enabled {
        info!("usage retention/rollup disabled by config");
        return;
    }
    info!(
        "usage retention/rollup enabled: raw_days={}, rollup_days={}, interval={}s",
        config.raw_days, config.rollup_days, config.interval_seconds
    );
    // `tokio::time::interval` (not a bare `sleep` loop) so the cadence does not drift by however
    // long each run takes, and `MissedTickBehavior::Skip` so a run that overruns the interval
    // does not queue a burst of catch-up ticks. The first tick fires immediately, so the first
    // run happens at startup and then every `interval_seconds`.
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        config.interval_seconds.max(1),
    ));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        match rollup_and_purge(&pool, config.raw_days, config.rollup_days).await {
            Ok(run) => {
                record_cutoff_if_completed(&pool, config.raw_days, &run).await;
                if run.purged > 0 {
                    info!(
                        "usage retention: rolled up and purged {} raw rows",
                        run.purged
                    );
                }
            }
            Err(e) => warn!("usage retention/rollup run failed: {e}"),
        }
    }
}

/// Records the purge cutoff after a run, but ONLY when the run completed a full drain. A run cut
/// short by advisory-lock contention (`completed == false`) has NOT purged everything older than
/// the cutoff, so recording it would over-report `truncated` for ranges whose rows are still raw
/// (P2). A stale (older) cutoff errs toward a false positive, never a false negative.
pub async fn record_cutoff_if_completed(pool: &PgPool, raw_days: i64, run: &RetentionRun) {
    if !run.completed {
        warn!(
            "usage retention: run cut short by advisory lock contention ({} rows purged); not recording purge cutoff",
            run.purged
        );
        return;
    }
    if let Err(e) = record_last_purge_cutoff(pool, raw_days).await {
        warn!("usage retention: failed to record last purge cutoff: {e}");
    }
}

/// Records the day-truncated purge cutoff of a successful run into `usage_retention_state`, so
/// `/usage/v1/usage/query` can report `truncated` from what the job actually purged (P2) rather
/// than from the wall clock at query time. The cutoff is read from the database clock -- the same
/// `date_trunc('day', now() - raw_days)` the rollup SQL uses -- so it matches what the run purged
/// regardless of app/DB clock skew.
pub async fn record_last_purge_cutoff(pool: &PgPool, raw_days: i64) -> Result<()> {
    let cutoff: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('day', now() - ($1 * interval '1 day'))")
            .bind(raw_days)
            .fetch_one(pool)
            .await
            .map_err(|e| Error::Database(format!("usage retention cutoff read failed: {e}")))?;

    sqlx::query(
        "INSERT INTO usage_retention_state (id, last_purge_cutoff) VALUES (TRUE, $1)
         ON CONFLICT (id) DO UPDATE
           SET last_purge_cutoff = EXCLUDED.last_purge_cutoff, updated_at = now()",
    )
    .bind(cutoff)
    .execute(pool)
    .await
    .map_err(|e| Error::Database(format!("usage retention state write failed: {e}")))?;

    Ok(())
}

/// Rolls `usage_events` rows older than `raw_days` (rounded down to the day boundary, so only
/// complete days) into `usage_events_daily`, deletes them from `usage_events`, and deletes rollup
/// rows older than `rollup_days`. Returns the run's outcome -- how many raw rows were purged and
/// whether the run completed a full drain (see [`RetentionRun`]).
///
/// The rollup+purge runs in bounded batches ([`BATCH_SIZE`] rows per statement), and **each batch
/// commits in its own transaction**, so the FIRST run against a large pre-existing backlog does
/// not aggregate and delete the whole table in one unbounded statement -- which would hold one
/// advisory-locked transaction (and one pool connection) for the whole table, spike WAL, and burst
/// dead tuples right before the #549 AC5 reclaim. Committing per batch bounds the advisory-lock
/// and transaction lifetime to a single batch rather than the whole run, and makes a crash mid-way
/// leave partial progress that the next run continues. Each batch is idempotent (`ON CONFLICT DO
/// UPDATE`), so a batch re-run after a crash, or a concurrent run on another replica, folds in
/// rather than double-counts.
pub async fn rollup_and_purge(
    pool: &PgPool,
    raw_days: i64,
    rollup_days: i64,
) -> Result<RetentionRun> {
    let mut conn = pool.acquire().await?;
    rollup_and_purge_on(&mut conn, raw_days, rollup_days).await
}

/// The connection-pinned core of [`rollup_and_purge`]: runs the whole rollup+purge loop on the
/// given connection. Exposed separately so a test can pin the session's `TimeZone` on the SAME
/// connection the rollup runs on -- otherwise a `SET TimeZone` issued against a pool applies to
/// whichever pooled connection is handed out and the test can pass vacuously without exercising
/// the transaction's `SET LOCAL TimeZone = 'UTC'` at all.
pub async fn rollup_and_purge_on(
    conn: &mut PgConnection,
    raw_days: i64,
    rollup_days: i64,
) -> Result<RetentionRun> {
    let mut total_purged: u64 = 0;
    loop {
        let mut tx = conn.begin().await?;

        // Pin day boundaries to UTC for this batch's transaction (see module docs). Must be the
        // first statement so both the rollup cutoff and the rollup-purge cutoff agree on the same
        // zone.
        sqlx::query("SET LOCAL TimeZone = 'UTC'")
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(format!("usage retention timezone pin failed: {e}")))?;

        // Acquire an exclusive advisory lock for the retention job to prevent concurrent rollups
        // across multiple replicas. The lock is tied to the transaction and released on commit.
        let lock_acquired =
            sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(549000001)")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Error::Database(format!("usage retention lock failed: {e}")))?;

        if !lock_acquired {
            // Another replica is currently running the rollup, gracefully skip this run. The run is
            // NOT complete: it may have purged some batches before losing the lock, but older rows
            // are still raw, so the caller must not record a purge cutoff (P2).
            return Ok(RetentionRun {
                purged: total_purged,
                completed: false,
            });
        }

        // One statement per batch: DELETE ... RETURNING feeds the INSERT, so the rollup and the raw
        // purge share a single snapshot and can never drift (see module docs). Returns the number of
        // raw rows deleted in this batch (the `deleted` CTE is materialised and counted). Loop until
        // a batch deletes nothing, bounding the work per statement.
        let batch: i64 = sqlx::query_scalar(ROLLUP_AND_PURGE_SQL)
            .bind(raw_days)
            .bind(BATCH_SIZE)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| Error::Database(format!("usage retention rollup failed: {e}")))?;

        if batch <= 0 {
            // No more raw rows to roll up; run the rollup purge in this same transaction and finish.
            sqlx::query(ROLLUP_PURGE_SQL)
                .bind(rollup_days)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    Error::Database(format!("usage retention rollup purge failed: {e}"))
                })?;
            tx.commit()
                .await
                .map_err(|e| Error::Database(format!("usage retention commit failed: {e}")))?;
            break;
        }

        total_purged += batch as u64;
        tx.commit()
            .await
            .map_err(|e| Error::Database(format!("usage retention commit failed: {e}")))?;
    }

    Ok(RetentionRun {
        purged: total_purged,
        completed: true,
    })
}

/// Maximum number of raw rows rolled up and purged per statement, bounding the first run against a
/// large backlog (see [`rollup_and_purge`]).
const BATCH_SIZE: i64 = 50_000;
