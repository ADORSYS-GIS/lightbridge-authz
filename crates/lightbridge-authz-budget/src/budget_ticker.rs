//! One wake of `authz-budget`'s schedule driver: the month-start pass, THEN the reset tick.
//!
//! ## Why the pass runs before the reset tick, in the same wake
//!
//! A reset in `mode: reset` books `delta = target − remaining`
//! ([`crate::reset_scheduler::ResetScheduler`]). On a Monday-the-1st the schedule window and the new
//! period begin together. Funding first means the reset computes its delta against a funded ceiling
//! and finds `0` — one grant, no spurious correction. The other order lets the reset fund the
//! account from `0` and the pass then add the starting grant on top of it: the account holds the
//! target twice. Both steps are handed the SAME `now`, so they cannot disagree about the month.
//!
//! The pass is a separate step, not a schedule: a schedule fires on its own cadence and cannot be
//! "the first tick of every month" for every account, which is exactly the gap being closed. In the
//! last hour of a month the pass also books the NEXT month ([`crate::period_start`]), so a funded
//! ceiling is already there when the snapshot refresher rolls into it at 00:00 UTC; the reset tick
//! then finds it funded on the Monday-the-1st just the same.
//!
//! ## A failed pass does not stop the reset tick
//!
//! The pass returns `Err` only when it cannot enumerate the accounts missing a grant (the database
//! is unreachable, and the reset tick fails with it), and counts a per-account failure rather than
//! raising it. Holding every reset back for one persistently failing account would be a larger,
//! quieter outage than the one it guards against, so a failure is logged at `error` and retried on
//! the next wake while the reset runs. The ceiling it leaves behind is `0`, never a larger one.
//!
//! ## Replicas
//!
//! Every `authz-budget` replica runs this loop. The reset tick is safe because it claims due
//! schedules with `FOR UPDATE SKIP LOCKED`; the pass is safe because its writes are idempotent on
//! the starting-grant key (see [`crate::period_start`]).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::period_start::{PeriodReport, PeriodStartGrants, PeriodStartReport};
use crate::reset_scheduler::{ResetScheduler, TickReport};

/// What one wake did: both steps' outcomes, so neither hides the other's failure.
#[derive(Debug)]
pub struct BudgetTickReport {
    pub period_start: Result<PeriodStartReport, BudgetError>,
    pub reset: Result<TickReport, BudgetError>,
}

/// Drives the month-start pass and the reset scheduler, in that order.
#[derive(Debug)]
pub struct BudgetTicker {
    period_start: PeriodStartGrants,
    reset: Arc<ResetScheduler>,
}

impl BudgetTicker {
    pub fn new(period_start: PeriodStartGrants, reset: Arc<ResetScheduler>) -> Self {
        Self {
            period_start,
            reset,
        }
    }

    /// One wake at `now`. The order is the point — see the module docs.
    pub async fn tick(&self, now: DateTime<Utc>) -> BudgetTickReport {
        let period_start = self.period_start.run(now).await;
        let reset = self.reset.tick(now).await;
        BudgetTickReport {
            period_start,
            reset,
        }
    }

    /// Runs [`Self::tick`] forever on `interval`. Spawned, never awaited, by `authz-budget`: a
    /// failure here must never stop the RPC surface from serving, and a failed wake retries on the
    /// next one — the reset tick's claim transaction only commits a window's advance on success, so
    /// a failed window stays due rather than being skipped. `Delay`, not the default `Burst`: a
    /// wake that overruns the interval (a global schedule over a large estate) must not queue a
    /// backlog of immediate catch-up wakes behind it. The first wake is immediate (the first
    /// `interval` tick completes at once), so a replica that has just started funds the current
    /// month straight away instead of one interval later.
    pub fn spawn(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                log_tick(&self.tick(Utc::now()).await);
            }
        })
    }
}

/// Silent in steady state: a wake that found nothing to fund and nothing due writes no line.
fn log_tick(report: &BudgetTickReport) {
    match &report.period_start {
        Ok(pass) => {
            log_period(&pass.current);
            if let Some(ahead) = &pass.ahead {
                log_period(ahead);
            }
        }
        Err(err) => tracing::error!(
            error = %err,
            "month-start pass failed; retrying on the next interval"
        ),
    }
    match &report.reset {
        Ok(reset) if reset.claimed_schedule_ids.is_empty() => {}
        Ok(reset) => tracing::info!(
            claimed = reset.claimed_schedule_ids.len(),
            grants_written = reset.grants_written,
            "budget reset scheduler tick"
        ),
        Err(err) => tracing::error!(
            error = %err,
            "budget reset scheduler tick failed; retrying on the next interval"
        ),
    }
}

fn log_period(pass: &PeriodReport) {
    if pass.is_incomplete() {
        tracing::error!(
            period = %pass.period,
            missing = pass.missing,
            funded = pass.funded,
            failed = pass.failed,
            first_error = pass.first_error.as_deref().unwrap_or_default(),
            "month-start grants incomplete; the unfunded accounts stay at a zero ceiling until the \
             next tick retries them"
        );
    } else if pass.missing > 0 {
        tracing::info!(
            period = %pass.period,
            missing = pass.missing,
            funded = pass.funded,
            "booked month-start grants"
        );
    }
}
