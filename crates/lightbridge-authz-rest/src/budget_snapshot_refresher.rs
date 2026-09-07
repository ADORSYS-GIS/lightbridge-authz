//! Starting ADR-0034 §15/§15.6's remaining-snapshot refresher — the one piece of the budget
//! service graph that runs only on `authz-budget`.
//!
//! Split from [`crate::budget_services`] under this repo's 200-LoC ceiling once §15.6 added the
//! seed and slow-lane knobs (and the validation that refuses a zero-length lane boundary); code
//! moved, not rewritten.

use std::sync::Arc;

use lightbridge_authz_core::{Error, Result};

use crate::budget_services::BudgetServices;

/// Starts ADR-0034 §15's snapshot refresher on the `authz-budget` process, and only there.
///
/// Spawned, never awaited, like the reset scheduler's tick loop next to it: a refresher failure
/// must not stop the RPC surface from serving. `authz-api`/`lightbridge-mcp` share the graph and
/// do NOT call this.
pub fn spawn_snapshot_refresher(
    services: &BudgetServices,
    budget: &lightbridge_authz_core::config::BudgetServer,
) -> Result<()> {
    if budget.snapshot_refresh_seconds == 0 {
        return Err(Error::Server(
            "server.budget.snapshot_refresh_seconds must be greater than zero -- a zero-second \
             interval is a busy loop against the database, not a configuration"
                .to_string(),
        ));
    }
    if budget.snapshot_slow_lane_minutes == 0 {
        return Err(Error::Server(
            "server.budget.snapshot_slow_lane_minutes must be greater than zero -- it is both the \
             boundary between the refresher's two lanes and the slow lane's cadence, so zero \
             would put every account in the fast lane permanently (ADR-0034 section 15.6)"
                .to_string(),
        ));
    }
    let config = lightbridge_authz_budget::SnapshotRefreshConfig {
        interval: std::time::Duration::from_secs(budget.snapshot_refresh_seconds),
        active_window: std::time::Duration::from_secs(budget.snapshot_active_window_minutes * 60),
        slow_lane_interval: std::time::Duration::from_secs(budget.snapshot_slow_lane_minutes * 60),
        seed_lookback_days: budget.snapshot_seed_lookback_days,
        batch: i64::from(budget.snapshot_batch),
        concurrency: usize::from(budget.snapshot_concurrency),
    };
    tracing::info!(?config, "starting the budget remaining-snapshot refresher");
    Arc::new(lightbridge_authz_budget::SnapshotRefresher::new(
        (*services.snapshots).clone(),
        services.budget_repo.clone(),
        services.spend_reader.clone(),
        services.reset_scheduler.clone(),
        config,
    ))
    .spawn();
    Ok(())
}
