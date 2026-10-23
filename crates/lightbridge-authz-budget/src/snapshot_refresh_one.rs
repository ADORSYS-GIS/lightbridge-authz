//! One account's snapshot refresh — the unit of work [`crate::snapshot_refresher`] runs
//! concurrently, extracted so the loop module stays about pacing and locking and this one stays
//! about the reading itself (ADR-0034 §15).
//!
//! Split under this repo's 200-LoC gate; code moved, not rewritten.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::period::Period;
use crate::remaining::next_period_start_utc;
use crate::repo::BudgetRepo;
use crate::reset_scheduler::ResetScheduler;
use crate::snapshot_store::SnapshotStore;
use crate::spend::{SpendObservation, SpendReader};

/// Recomputes one account's snapshot and writes it.
///
/// `Ok(true)` wrote a fresh reading. `Ok(false)` could not read spend, so the PREVIOUS reading was
/// kept and `stale_since` stamped — fail-soft, never an erased balance.
///
/// Takes owned handles rather than `&self` so the returned future is `'static` and a whole chunk of
/// these can be driven concurrently by a `JoinSet`.
pub(crate) async fn refresh_one_account(
    store: SnapshotStore,
    repo: Arc<BudgetRepo>,
    spend_reader: Arc<dyn SpendReader>,
    reset_scheduler: Arc<ResetScheduler>,
    account_id: String,
    period: Period,
    now: DateTime<Utc>,
) -> Result<bool, BudgetError> {
    let spent_micros = match spend_reader
        .observe_spend_for_account(&account_id, &period)
        .await?
    {
        SpendObservation::Answered(micros) => micros,
        // The usage store answered and holds nothing this period. That is the state of
        // EVERY account at 00:00 UTC on the 1st until its first request completes; it
        // counts as zero spend, and the ceiling alone decides. See `SpendObservation`.
        SpendObservation::Empty => 0,
        SpendObservation::Unreachable => {
            store.mark_stale(&account_id).await?;
            return Ok(false);
        }
    };

    let ceiling_micros = repo.effective_balance(&account_id, &period, now).await?;
    let next_reset_at = match reset_scheduler.effective_schedule(&account_id).await? {
        Some(effective) => effective.next_run_at,
        None => next_period_start_utc(&period),
    };

    store
        .store_reading(
            &account_id,
            &period,
            ceiling_micros,
            spent_micros,
            next_reset_at,
        )
        .await?;
    Ok(true)
}
