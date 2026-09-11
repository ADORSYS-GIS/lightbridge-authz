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

use lightbridge_authz_core::{Error, Result};
use sqlx::{Connection, PgConnection, PgPool};

// The rollup/purge SQL statements live in `rollup_sql` (split out by the LoC gate); re-export them
// here so `retention.rs`'s existing callers and the module's public surface are unchanged.
pub use crate::rollup_sql::{ROLLUP_AND_PURGE_SQL, ROLLUP_PURGE_SQL};

// The background-loop driver and the P2 purge-cutoff bookkeeping live in `retention_loop` (split
// out by the LoC gate, lightbridge-governance#172): they are a self-contained unit built ON TOP OF
// `rollup_and_purge` below, not part of the rollup/purge core itself. Re-exported here so every
// existing `retention::{run_retention_loop, record_cutoff_if_completed, record_last_purge_cutoff}`
// path -- `lib.rs`, `tests/retention_it_tests.rs` -- still resolves unchanged, and the pairing
// (`retention_loop` calls straight back into `rollup_and_purge`/`RetentionRun` here) is unchanged.
pub use crate::retention_loop::{
    record_cutoff_if_completed, record_last_purge_cutoff, run_retention_loop,
};

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
