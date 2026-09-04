//! Retention/rollup for `usage_events` (#549 AC2).
//!
//! `usage_events` grows ~100 MB/day with no retention. This module runs a background job that
//! rolls rows older than a retention window into the `usage_events_daily` aggregate table and
//! deletes them from the raw table, in one transaction. The rollup table is itself bounded by
//! `rollup_days`, so the long-term store does not grow without bound either.
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
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::RetentionConfig;

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
    let interval = std::time::Duration::from_secs(config.interval_seconds.max(1));
    loop {
        tokio::time::sleep(interval).await;
        match rollup_and_purge(&pool, config.raw_days, config.rollup_days).await {
            Ok(purged) => {
                if purged > 0 {
                    info!("usage retention: rolled up and purged {purged} raw rows");
                }
            }
            Err(e) => warn!("usage retention/rollup run failed: {e}"),
        }
    }
}

/// Rolls `usage_events` rows older than `raw_days` (rounded down to the day boundary, so only
/// complete days) into `usage_events_daily`, deletes them from `usage_events`, and deletes rollup
/// rows older than `rollup_days` -- one transaction. Returns the number of raw rows purged.
///
/// The rollup+purge runs in bounded batches ([`BATCH_SIZE`] rows per statement) so the FIRST run
/// against a large pre-existing backlog does not aggregate and delete the whole table in one
/// unbounded statement -- which would hold one advisory-locked transaction (and one pool
/// connection) for the whole table, spike WAL, and burst dead tuples right before the #549 AC5
/// reclaim. Each batch is idempotent (`ON CONFLICT DO UPDATE`), so a crash mid-way leaves partial
/// progress that the next run continues.
pub async fn rollup_and_purge(pool: &PgPool, raw_days: i64, rollup_days: i64) -> Result<u64> {
    let mut tx = pool.begin().await?;

    // Pin day boundaries to UTC for the whole transaction (see module docs). Must be the first
    // statement so both the rollup cutoff and the rollup-purge cutoff agree on the same zone.
    sqlx::query("SET LOCAL TimeZone = 'UTC'")
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::Database(format!("usage retention timezone pin failed: {e}")))?;

    // Acquire an exclusive advisory lock for the retention job to prevent concurrent rollups
    // across multiple replicas. The lock is tied to the transaction and released on commit/rollback.
    let lock_acquired =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(549000001)")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| Error::Database(format!("usage retention lock failed: {e}")))?;

    if !lock_acquired {
        // Another replica is currently running the rollup, gracefully skip this run.
        return Ok(0);
    }

    // One statement per batch: DELETE ... RETURNING feeds the INSERT, so the rollup and the raw
    // purge share a single snapshot and can never drift (see module docs). Returns the number of
    // raw rows deleted in this batch (the `deleted` CTE is materialised and counted). Loop until a
    // batch deletes nothing, bounding the work per statement.
    let mut total_purged: u64 = 0;
    loop {
        let batch: i64 = sqlx::query_scalar(ROLLUP_AND_PURGE_SQL)
            .bind(raw_days)
            .bind(BATCH_SIZE)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| Error::Database(format!("usage retention rollup failed: {e}")))?;
        if batch <= 0 {
            break;
        }
        total_purged += batch as u64;
    }

    sqlx::query(ROLLUP_PURGE_SQL)
        .bind(rollup_days)
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::Database(format!("usage retention rollup purge failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| Error::Database(format!("usage retention commit failed: {e}")))?;

    Ok(total_purged)
}

/// Maximum number of raw rows rolled up and purged per statement, bounding the first run against a
/// large backlog (see [`rollup_and_purge`]).
const BATCH_SIZE: i64 = 50_000;

/// Rolls raw rows older than the cutoff into `usage_events_daily` and deletes them from
/// `usage_events`, in ONE statement. The cutoff is computed in SQL from the database clock
/// (`now()`), so it stays consistent with the data regardless of any clock skew between the app
/// and the database. `date_trunc('day', observed_at)` is the bucket key, matching the cutoff's day
/// boundary; both are pinned to UTC by the transaction's `SET LOCAL TimeZone = 'UTC'`. `$2` bounds
/// the batch (see [`BATCH_SIZE`]) so a large backlog is processed in bounded chunks.
///
/// The `DELETE ... RETURNING` and the `INSERT ... SELECT` share one statement snapshot, so a row
/// is never deleted without being rolled up (no READ COMMITTED race). `ON CONFLICT DO UPDATE`
/// folds a late-arriving row for an already-rolled-up day into the existing rollup row with a
/// NULL-safe `COALESCE` add, so spend for a closed period is stable. The trailing `SELECT COUNT(*)`
/// returns the number of raw rows deleted.
const ROLLUP_AND_PURGE_SQL: &str = r#"
WITH deleted AS (
    DELETE FROM usage_events
    WHERE ctid IN (
        SELECT ctid FROM usage_events
        WHERE observed_at < date_trunc('day', now() - ($1 * interval '1 day'))
        LIMIT $2
    )
    RETURNING *
),
rolled AS (
    INSERT INTO usage_events_daily (
        bucket_start, account_id, project_id, api_key_id, user_id, user_name, model, metric_name,
        signal_type, azp, operation, billing_plan, requests, usage_value, prompt_tokens,
        completion_tokens, total_tokens, total_cost, latency_samples
    )
    SELECT
        date_trunc('day', observed_at) AS bucket_start,
        account_id, project_id, api_key_id, user_id, user_name, model, metric_name, signal_type,
        azp, operation, billing_plan,
        SUM(request_count)::bigint AS requests,
        SUM(usage_value)::double precision AS usage_value,
        SUM(prompt_tokens)::bigint AS prompt_tokens,
        SUM(completion_tokens)::bigint AS completion_tokens,
        SUM(total_tokens)::bigint AS total_tokens,
        SUM(total_cost)::double precision AS total_cost,
        COUNT(latency_ms)::bigint AS latency_samples
    FROM deleted
    GROUP BY bucket_start, account_id, project_id, api_key_id, user_id, user_name, model, metric_name,
             signal_type, azp, operation, billing_plan
    ON CONFLICT (bucket_start, account_id, project_id, api_key_id, user_id, user_name, model, metric_name,
                 signal_type, azp, operation, billing_plan)
    DO UPDATE SET
        requests = usage_events_daily.requests + EXCLUDED.requests,
        usage_value = usage_events_daily.usage_value + EXCLUDED.usage_value,
        prompt_tokens = usage_events_daily.prompt_tokens + EXCLUDED.prompt_tokens,
        completion_tokens = usage_events_daily.completion_tokens + EXCLUDED.completion_tokens,
        total_tokens = usage_events_daily.total_tokens + EXCLUDED.total_tokens,
        total_cost = COALESCE(usage_events_daily.total_cost, 0) + COALESCE(EXCLUDED.total_cost, 0),
        latency_samples = usage_events_daily.latency_samples + EXCLUDED.latency_samples
)
SELECT COUNT(*) FROM deleted
"#;

/// Deletes rollup rows older than `rollup_days`, bounding the long-term store so it does not grow
/// without bound. Same day-boundary cutoff shape as [`ROLLUP_AND_PURGE_SQL`], and pinned to UTC by
/// the transaction's `SET LOCAL TimeZone = 'UTC'`.
const ROLLUP_PURGE_SQL: &str = r#"
DELETE FROM usage_events_daily
WHERE bucket_start < date_trunc('day', now() - ($1 * interval '1 day'))
"#;
