//! ADR-0035 D9: the pool-aware snapshot refresh. The ceiling is all SETTLED credit (allowance +
//! open granted and paid lots), the spend is the debt plus the UNSETTLED tail -- spend ingested
//! after the settlement watermark -- and `remaining = ceiling − spend`, the formula the gateway
//! already reads, so ADR-0034's contract does not change. The per-pool columns are estimates
//! between settlements: the tail is charged to them in spending order. The total is exact.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::period::Period;
use crate::remaining::next_period_start_utc;
use crate::reset_scheduler::ResetScheduler;
use crate::settlement::Settlement;
use crate::settlement_alloc::remaining_after;
use crate::snapshot_store::SnapshotStore;
use crate::snapshot_store_pools::PoolReading;
use crate::spend::SpendObservation;

pub(crate) async fn refresh_pools(
    store: SnapshotStore,
    settlement: Arc<Settlement>,
    reset_scheduler: Arc<ResetScheduler>,
    account_id: String,
    period: Period,
    now: DateTime<Utc>,
) -> Result<bool, BudgetError> {
    let settled = settlement
        .settled_balances(&account_id, &period, now)
        .await?;
    let tail_micros = match settlement
        .spend_reader()
        .observe_spend_ingested(&account_id, settled.settled_through, now)
        .await?
    {
        SpendObservation::Answered(micros) => micros,
        SpendObservation::Empty => 0,
        // Fail-soft, exactly like the ADR-0034 refresher: keep the previous reading, mark it
        // stale, never invent a zero.
        SpendObservation::Unreachable => {
            store.mark_stale(&account_id).await?;
            return Ok(false);
        }
    };

    let spent_micros = settled.debt_micros.saturating_add(tail_micros);
    let (allowance, granted, paid) = remaining_after(
        spent_micros,
        settled.allowance_micros,
        settled.granted_micros,
        settled.paid_micros,
    );
    let next_reset_at = match reset_scheduler.effective_schedule(&account_id).await? {
        Some(effective) => effective.next_run_at,
        None => next_period_start_utc(&period),
    };

    store
        .store_pool_reading(
            &account_id,
            &period,
            &PoolReading {
                ceiling_micros: settled.settled_total(),
                spent_micros,
                next_reset_at,
                allowance_remaining_micros: allowance,
                granted_remaining_micros: granted,
                paid_remaining_micros: paid,
                debt_micros: settled.debt_micros,
            },
        )
        .await?;
    Ok(true)
}
