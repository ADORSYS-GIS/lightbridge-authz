//! The retention background-loop driver and the P2 purge-cutoff bookkeeping.
//!
//! Split out of `retention.rs` by the LoC gate (`.github/actions/loc-gate`,
//! lightbridge-governance#172): this is a self-contained unit built ON TOP OF
//! `retention::rollup_and_purge`/`RetentionRun`, not part of the rollup/purge core itself. The
//! pairing is unchanged -- `retention.rs` re-exports everything here so every existing
//! `retention::{run_retention_loop, record_cutoff_if_completed, record_last_purge_cutoff}` path
//! still resolves, and the loop still calls straight back into `rollup_and_purge` on every tick.

use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Error, Result};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::RetentionConfig;
use crate::retention::{RetentionRun, rollup_and_purge};

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
