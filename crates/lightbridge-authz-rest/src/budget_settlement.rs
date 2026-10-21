//! ADR-0035 wiring: when `server.budget.settlement_seconds > 0`, build the settlement loop, hand
//! it to the reset scheduler (so resets settle first and clamp allowance only, D8, and the
//! snapshot refresher -- which reaches settlement through the scheduler -- turns pool-aware, D9),
//! and start it. With the setting at its default `0`, nothing changes.

use std::sync::Arc;
use std::time::Duration;

use lightbridge_authz_budget::Settlement;
use lightbridge_authz_core::config::BudgetServer;
use lightbridge_authz_core::db::DbPoolTrait;

use crate::budget_services::BudgetServices;

pub(crate) fn enable_settlement(
    services: &mut BudgetServices,
    pool: Arc<dyn DbPoolTrait>,
    budget: &BudgetServer,
) -> Option<Arc<Settlement>> {
    if budget.settlement_seconds == 0 {
        tracing::info!("ADR-0035 settlement is off (server.budget.settlement_seconds = 0)");
        return None;
    }
    let settlement = Arc::new(Settlement::new(
        pool,
        services.spend_reader.clone(),
        Duration::from_secs(budget.settlement_seconds),
        Duration::from_secs(budget.snapshot_active_window_minutes * 60),
    ));
    services.reset_scheduler = Arc::new(
        (*services.reset_scheduler)
            .clone()
            .with_settlement(settlement.clone()),
    );
    tracing::info!(
        interval_seconds = budget.settlement_seconds,
        "ADR-0035 settlement is on: resets clamp the allowance pool, the snapshot is pool-aware"
    );
    settlement.clone().spawn();
    Some(settlement)
}
