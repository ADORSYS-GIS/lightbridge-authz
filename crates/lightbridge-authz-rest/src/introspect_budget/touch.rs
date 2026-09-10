//! The `last_seen_at` write-behind and its throttle — ADR-0034 §15/§15.6.
//!
//! Split from [`super`] under this repo's 200-LoC gate. The throttle is the same per-process map
//! §15 shipped; what §15.6 adds is that a failed write no longer disappears — see [`Dropped`].

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};
use std::time::{Duration, Instant};

use super::BudgetIntrospection;
use crate::OpaRepoTrait;

/// How often one account's `last_seen_at` is refreshed from this process. Well below the
/// refresher's fast-lane boundary (10 minutes by default), so an account in continuous use never
/// falls out of the fast lane, and far above the request rate, so the write is amortised to
/// nothing.
pub(crate) const TOUCH_INTERVAL: Duration = Duration::from_secs(30);

/// How long the spawned write may take before it is abandoned and counted.
///
/// Bounded rather than open-ended because the pool this borrows from is the same one serving
/// introspection reads: a touch that sits in `acquire_timeout` for 30 s is holding a slot the
/// request path needs, to buy a `last_seen_at` that is only useful to the *next* refresher tick.
/// Two seconds is far above a healthy write (~1 ms) and far below the pool's own timeout.
pub(crate) const TOUCH_TIMEOUT: Duration = Duration::from_secs(2);

impl BudgetIntrospection {
    /// Fires the `last_seen_at` write in the background when this account is due one.
    ///
    /// Deliberately not awaited by the caller: it is on the critical path of every metered model
    /// request, and the value of this write is entirely to the *next* refresher tick. But it is not
    /// unbounded and not silent — a failure or a timeout releases the throttle claim so the very
    /// next request retries, and increments `budget_snapshot_touch_dropped_total`.
    pub(crate) fn schedule_touch(&self, repo: &Arc<dyn OpaRepoTrait>, budget_account_id: &str) {
        if !self.claim_touch(budget_account_id) {
            return;
        }
        let repo = repo.clone();
        let account_id = budget_account_id.to_string();
        let touched = Arc::clone(&self.touched);
        let dropped = Arc::clone(&self.dropped);
        tokio::spawn(async move {
            let outcome = tokio::time::timeout(
                TOUCH_TIMEOUT,
                repo.touch_budget_remaining_snapshot(&account_id),
            )
            .await;
            let reason = match outcome {
                Ok(Ok(())) => return,
                Ok(Err(err)) => err.to_string(),
                Err(_) => format!("timed out after {}s", TOUCH_TIMEOUT.as_secs()),
            };
            let total = dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if let Ok(mut guard) = touched.lock() {
                guard.remove(&account_id);
            }
            tracing::warn!(
                budget_account_id = %account_id,
                error = %reason,
                budget_snapshot_touch_dropped_total = total,
                "failed to touch the budget snapshot's last_seen_at; the claim was released so the \
                 next request retries immediately (ADR-0034 §15.6)"
            );
        });
    }

    /// `true` when this process has not touched `budget_account_id` within [`TOUCH_INTERVAL`],
    /// recording the claim as it goes. Entries older than the interval are dropped on the same
    /// pass — the only eviction this map has, and enough: an entry past the interval can never
    /// suppress a touch again, so keeping it would be pure leak.
    fn claim_touch(&self, budget_account_id: &str) -> bool {
        let now = Instant::now();
        let mut touched = self.lock();
        touched.retain(|_, at| now.duration_since(*at) < TOUCH_INTERVAL);
        if touched.contains_key(budget_account_id) {
            return false;
        }
        touched.insert(budget_account_id.to_string(), now);
        true
    }

    /// A poisoned mutex here means a previous caller panicked holding a map of ids and instants —
    /// there is no invariant to have been broken, so the guard is recovered rather than propagated
    /// as a panic that would take introspection down for every later request.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Instant>> {
        self.touched
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
