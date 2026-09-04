//! The refresher's timer loop and its per-tick log line — ADR-0034 §15/§15.6.
//!
//! Split from [`crate::snapshot_refresher`] under this repo's 200-LoC gate once §15.6 gave the
//! tick a coverage census to report; code moved, not rewritten, except that the tick line moved
//! from `debug` to `info` (see [`log_tick`]).

use std::sync::Arc;

use chrono::Utc;

use crate::snapshot::RefreshReport;
use crate::snapshot_refresher::SnapshotRefresher;

impl SnapshotRefresher {
    /// Drives [`Self::tick`] forever on the configured interval. Spawned, never awaited, by
    /// `authz-budget`: a refresher failure must not take the RPC surface down, and a failed tick
    /// retries on the next interval with nothing lost. `MissedTickBehavior::Delay`, like the reset
    /// scheduler's loop: an overrunning tick must not queue a backlog of catch-up ticks behind it.
    ///
    /// The first tick fires immediately (`tokio::time::interval`'s first tick completes at once),
    /// so the §15.6 seed runs at startup without a separate code path — a replica that has just
    /// rolled seeds before it serves its first refresh, rather than one interval later.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.config.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match self.tick(Utc::now()).await {
                    Ok(report) => log_tick(&report),
                    Err(err) => tracing::error!(
                        error = %err,
                        "budget snapshot refresh tick failed; retrying on the next interval"
                    ),
                }
            }
        })
    }
}

/// One structured line per tick, at `info` — not `debug` like §15's, because the coverage figures
/// are what the gateway runbook cites when it decides whether Stage 2 may start, and a number
/// nobody can read in production is not evidence. The field names are the metric names.
fn log_tick(report: &RefreshReport) {
    if !report.ran {
        return;
    }
    tracing::info!(
        budget_snapshot_accounts_total = report.coverage.accounts_total,
        budget_snapshot_known_total = report.coverage.known_total,
        budget_snapshot_stale_total = report.coverage.stale_total,
        budget_snapshot_uncovered_total = report.coverage.uncovered_total,
        seeded = report.seeded,
        considered = report.considered,
        refreshed = report.refreshed,
        kept_stale = report.kept_stale,
        failed = report.failed,
        "budget remaining snapshot refresh tick"
    );
}
