//! [`RemainingService`] — the concrete [`crate::remaining::RemainingReader`], and the bounded
//! last-known-good cache that is ADR-0034's *fail-closed with cached grace*.
//!
//! Split out of `remaining.rs` verbatim (code moved, not rewritten) because that file exceeded the
//! LoC-gate ceiling. The pairing is unchanged: the types and the trait live next door and this
//! module is re-exported from there, so `lightbridge_authz_budget::RemainingService` and
//! `crate::remaining::RemainingService` both still resolve.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};

use crate::error::BudgetError;
use crate::period::Period;
use crate::remaining::{BudgetRemaining, Remaining, RemainingReader, next_period_start_utc};
use crate::remaining_cache::SpendCache;
use crate::repo::BudgetRepo;
use crate::reset_scheduler::ResetScheduler;
use crate::spend::{SpendObservation, SpendReader};

/// Answers [`Remaining`] for one account, over the same repo/spend-reader/scheduler graph every
/// other budget service shares (`lightbridge-authz-rest`'s `budget_services`), so this endpoint
/// can never disagree with what a refill decision or a reset tick would compute from the same
/// state.
#[derive(Debug)]
pub struct RemainingService {
    repo: Arc<BudgetRepo>,
    spend_reader: Arc<dyn SpendReader>,
    reset_scheduler: Arc<ResetScheduler>,
    /// Bounds the *fail-closed with cached grace* half of ADR-0034: how long a last-known-good
    /// spend reading may still be served after the spend source stops answering, and the readings
    /// themselves. See [`crate::remaining_cache::SpendCache`].
    spend_cache: SpendCache,
}

impl RemainingService {
    /// A service with no grace window: an unreachable spend source is immediately
    /// [`Remaining::Unavailable`].
    pub fn new(
        repo: Arc<BudgetRepo>,
        spend_reader: Arc<dyn SpendReader>,
        reset_scheduler: Arc<ResetScheduler>,
    ) -> Self {
        Self::with_grace(repo, spend_reader, reset_scheduler, Duration::zero())
    }

    /// A service that may serve a last-known-good spend reading for up to `grace` after the spend
    /// source stops answering, stamping the reading's age into
    /// [`BudgetRemaining::source_lag_seconds`].
    ///
    /// This is the *fail-closed with cached grace* half of ADR-0034, and it is deliberately
    /// bounded rather than open-ended: past `grace` the answer becomes `Unavailable` again, so a
    /// long usage-service outage ends in a visible `503`/`budget_unavailable` at the gateway
    /// rather than in an indefinitely stale allowance nobody notices. `grace` of zero disables
    /// stale serving entirely.
    ///
    /// The cache is per-process, so N replicas hold N independent caches — which only means a
    /// request may or may not find a warm entry during an outage, never that two replicas disagree
    /// about a *fresh* reading. Deduplicating it into Redis was considered and rejected: it would
    /// put a second network dependency inside the one code path whose entire job is to survive a
    /// network dependency being down.
    pub fn with_grace(
        repo: Arc<BudgetRepo>,
        spend_reader: Arc<dyn SpendReader>,
        reset_scheduler: Arc<ResetScheduler>,
        grace: Duration,
    ) -> Self {
        Self {
            repo,
            spend_reader,
            reset_scheduler,
            spend_cache: SpendCache::new(grace),
        }
    }
}

#[lightbridge_authz_core::async_trait]
impl RemainingReader for RemainingService {
    /// `ceiling − spend` for `(budget_account_id, period)`, or [`Remaining::Unavailable`] when the
    /// spend source could not be asked.
    ///
    /// `now` is passed in rather than read here, matching this crate's clock-free discipline
    /// (`period.rs`, ADR-0007) — it is only used to expire grants at the ledger boundary.
    async fn remaining_for_account(
        &self,
        budget_account_id: &str,
        period: &Period,
        now: DateTime<Utc>,
    ) -> Result<Remaining, BudgetError> {
        // FIRST, before the ceiling and before the spend read. `COALESCE(SUM(...), 0)` cannot tell
        // a row-less account from a non-existent one, so without this probe an id nothing has ever
        // heard of reports a perfectly ordinary zero balance and reaches the gateway as
        // `402 budget_exhausted` for a phantom account (owner directive, 2026-09-03).
        //
        // Ordering matters in one direction only: an unknown id must answer `404` even while the
        // usage service is down, so the existence check cannot sit behind the spend read. It sits
        // in front of it, and its own failure is an `Err` -> `503`, never a `false` -> `404`.
        if !crate::known_account::budget_account_exists(&self.repo, budget_account_id).await? {
            tracing::warn!(
                budget_account_id = %budget_account_id,
                period = %period,
                "remaining was asked for a budget account that does not exist; answering \
                 unknown_account rather than a zero balance"
            );
            return Ok(Remaining::UnknownAccount);
        }

        let ceiling_micros = self
            .repo
            .effective_balance(budget_account_id, period, now)
            .await?;

        let cache_key = (budget_account_id.to_string(), period.clone());
        let (spent_micros, source_lag_seconds) = match self
            .spend_reader
            .observe_spend_for_account(budget_account_id, period)
            .await?
        {
            SpendObservation::Answered(micros) => {
                self.spend_cache.remember(cache_key, micros, now);
                (micros, None)
            }
            // The usage store answered and holds nothing for this account this period. That is
            // the state of EVERY account at 00:00 UTC on the 1st until its first request
            // completes -- treating it as "unknown" here would 503 the whole fleet at every month
            // boundary. It counts as zero spend, and the ceiling alone decides.
            SpendObservation::Empty => {
                self.spend_cache.remember(cache_key, 0, now);
                (0, None)
            }
            SpendObservation::Unreachable => match self.spend_cache.recall(&cache_key, now) {
                Some((micros, age)) => {
                    tracing::warn!(
                        budget_account_id = %budget_account_id,
                        period = %period,
                        age_seconds = age.num_seconds(),
                        "spend source unreachable; serving the last known reading within the \
                         grace window"
                    );
                    // `max(0)` because `Duration::num_seconds` truncates toward zero and the age
                    // is already non-negative -- this is a cast guard, not a clamp.
                    (micros, Some(age.num_seconds().max(0) as u64))
                }
                // No cached reading, or one older than the grace window: back to "we don't know",
                // which the HTTP edge renders as a 503 and never as a zero balance.
                None => return Ok(Remaining::Unavailable),
            },
        };

        let next_reset_at = match self
            .reset_scheduler
            .effective_schedule(budget_account_id)
            .await?
        {
            Some(effective) => effective.next_run_at,
            None => next_period_start_utc(period),
        };

        Ok(Remaining::Known(Box::new(BudgetRemaining {
            budget_account_id: budget_account_id.to_string(),
            period: period.clone(),
            ceiling_micros,
            spent_micros,
            remaining_micros: ceiling_micros.saturating_sub(spent_micros),
            next_reset_at,
            source_lag_seconds,
            // Computed live, from the ledger and the spend source, for this call.
            snapshot_age_seconds: None,
        })))
    }
}
