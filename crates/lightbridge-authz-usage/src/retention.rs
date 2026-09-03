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
//! Rolling up only complete days also sidesteps the NULL-money trap: `total_cost` is nullable
//! (`SUM` over all-NULL rows is NULL, "unknown", never 0), and because a day is aggregated in one
//! shot there is never a partial-day `ON CONFLICT DO UPDATE` that would have to combine a NULL
//! with a value.
//!
//! ## Late-arriving data and `ON CONFLICT DO NOTHING`
//!
//! The rollup INSERT carries `ON CONFLICT DO NOTHING` so a late-arriving raw event -- one whose
//! `observed_at` falls in a day that a previous run already rolled up (a replayed export, or clock
//! skew) -- cannot wedge the job. Without it, that event's `(bucket_start, dimensions)` group would
//! already exist in `usage_events_daily` (the unique index treats NULLs as equal), the INSERT would
//! raise a unique violation, the whole transaction would roll back, and the loop would log-and-retry
//! forever without ever purging -- raw growth would resume. With `DO NOTHING`, the duplicate group
//! is skipped, the purge still deletes the late raw row (its day is already represented in the
//! rollup), and the job stays healthy. The late event's cost is not folded back into the rollup --
//! an acceptable, deliberate trade for a day already past the retention window.
//!
//! ## The retention window vs. the dashboard
//!
//! The dashboard's max range is 90 days, and `raw_days` defaults to 90. Because the cutoff is
//! rounded DOWN to the day boundary, raw keeps slightly MORE than `raw_days` (up to the start of
//! the boundary day), so the full 90-day dashboard window is always served from raw -- which is
//! what keeps latency percentiles exact (the rollup does not carry them). Budget spend reads the
//! current billing period, which is always within the raw window, so it is never truncated.

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
pub async fn rollup_and_purge(pool: &PgPool, raw_days: i64, rollup_days: i64) -> Result<u64> {
    let mut tx = pool.begin().await?;

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

    let inserted = sqlx::query(ROLLUP_SQL)
        .bind(raw_days)
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::Database(format!("usage retention rollup failed: {e}")))?;

    let purged = sqlx::query(PURGE_SQL)
        .bind(raw_days)
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::Database(format!("usage retention purge failed: {e}")))?;

    sqlx::query(ROLLUP_PURGE_SQL)
        .bind(rollup_days)
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::Database(format!("usage retention rollup purge failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| Error::Database(format!("usage retention commit failed: {e}")))?;

    debug_assert!(
        inserted.rows_affected() <= purged.rows_affected() || purged.rows_affected() == 0,
        "rollup rows ({}) should not exceed purged raw rows ({})",
        inserted.rows_affected(),
        purged.rows_affected()
    );

    Ok(purged.rows_affected())
}

/// Aggregates raw rows older than the cutoff into `usage_events_daily`. The cutoff is computed in
/// SQL from the database clock (`now()`), so it stays consistent with the data regardless of any
/// clock skew between the app and the database. `date_trunc('day', observed_at)` is the bucket
/// key, matching the cutoff's day boundary.
const ROLLUP_SQL: &str = r#"
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
FROM usage_events
WHERE observed_at < date_trunc('day', now() - ($1 * interval '1 day'))
GROUP BY bucket_start, account_id, project_id, api_key_id, user_id, user_name, model, metric_name,
         signal_type, azp, operation, billing_plan
ON CONFLICT DO NOTHING
"#;

/// Deletes the raw rows that were just rolled up. Same cutoff expression as [`ROLLUP_SQL`], so the
/// two can never drift apart.
const PURGE_SQL: &str = r#"
DELETE FROM usage_events
WHERE observed_at < date_trunc('day', now() - ($1 * interval '1 day'))
"#;

/// Deletes rollup rows older than `rollup_days`, bounding the long-term store so it does not grow
/// without bound. Same day-boundary cutoff shape as [`ROLLUP_SQL`]/[`PURGE_SQL`].
const ROLLUP_PURGE_SQL: &str = r#"
DELETE FROM usage_events_daily
WHERE bucket_start < date_trunc('day', now() - ($1 * interval '1 day'))
"#;
