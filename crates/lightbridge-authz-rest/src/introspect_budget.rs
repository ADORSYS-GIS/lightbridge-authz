//! The budget half of `POST /v1/authorino/validate/introspect` — ADR-0034 §15's single-call
//! design (owner directive, 2026-09-04).
//!
//! ## What changed, and why it is one call now
//!
//! The gateway used to make **two** Authorino metadata calls for a metered model request: this
//! introspection into `authz-opa`, and a separate `GET /budget/v1/remaining` into `authz-budget`
//! that itself fanned out to `authz-usage` for the spend `SUM`. The owner's directive is one call
//! per request. So the introspection response now carries the balance too — and it can, because
//! answering "what is left" costs exactly one primary-key probe of a table `authz-opa`'s own
//! connection already reaches (`budget_remaining_snapshots`, filled off the request path by
//! `authz-budget`'s refresher).
//!
//! ## The two rules this module keeps
//!
//! - **Nothing is fabricated.** No row, no reading, or a reading describing a period that has
//!   since rolled over ⇒ the three `budget_*` fields are **omitted** from the response. The
//!   AuthConfig then publishes `known: false`, and the gateway's Lua refuses with `503
//!   budget_unavailable` — never `402 budget_exhausted`, which would bill a user for our own
//!   latency. A `0` here would be exactly that bug.
//! - **The hot path stays read-mostly.** The account's `last_seen_at` has to move so the refresher
//!   keeps its reading warm, but a write per request would put WAL on the critical path of every
//!   model call. So the touch is *write-behind*: fire-and-forget, and at most once per account per
//!   [`TOUCH_INTERVAL`] in this process. A missed touch costs one refresh cycle of freshness and
//!   can never cost correctness.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::Utc;
use lightbridge_authz_budget::Period;

use crate::OpaRepoTrait;

/// How often one account's `last_seen_at` is refreshed from this process. Well below the
/// refresher's own active window (10 minutes by default), so an account in continuous use never
/// falls out of the work list, and far above the request rate, so the write is amortised to
/// nothing.
const TOUCH_INTERVAL: Duration = Duration::from_secs(30);

/// The three fields an introspection response gains when the balance is known. Absent as a whole
/// (`None` from [`BudgetIntrospection::read_and_touch`]) whenever it is not — see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetFields {
    pub remaining_micros: i64,
    pub next_reset_at: Option<chrono::DateTime<Utc>>,
    /// How stale the figure is, in seconds. Published so the gateway (and anyone reading a trace)
    /// can see the window the decision was made inside rather than assuming freshness the
    /// single-call design deliberately trades away.
    pub snapshot_age_seconds: u64,
}

/// Reads the snapshot for an introspection, and keeps the account in the refresher's work list.
///
/// Holds only the touch throttle: the read itself goes through the [`OpaRepoTrait`] the handler
/// already has, so `authz-opa` opens no second connection and no second service graph exists to
/// disagree with the first.
#[derive(Debug, Default)]
pub struct BudgetIntrospection {
    /// Last time this process touched each account, so the write-behind can be throttled without a
    /// round trip. Per-process by design: N replicas each touch at most once per interval, which
    /// is N writes per interval per hot account — negligible, and it needs no coordination.
    touched: Mutex<HashMap<String, Instant>>,
}

impl BudgetIntrospection {
    /// The budget fields for `budget_account_id`, or `None` when the balance is not knowable
    /// right now. Also schedules the write-behind touch.
    ///
    /// Never returns an error: a snapshot read that fails is logged and answers `None`, because
    /// this is a *decoration* on an introspection whose primary job — is this credential valid? —
    /// must not start failing because a budget table did. That is the same instinct as
    /// `Remaining::Unavailable` not being `Err`, applied one layer out.
    pub async fn read_and_touch(
        &self,
        repo: &Arc<dyn OpaRepoTrait>,
        budget_account_id: &str,
    ) -> Option<BudgetFields> {
        self.schedule_touch(repo, budget_account_id);

        let now = Utc::now();
        let snapshot = match repo.budget_remaining_snapshot(budget_account_id).await {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return None,
            Err(err) => {
                tracing::warn!(
                    budget_account_id = %budget_account_id,
                    error = %err,
                    "budget snapshot read failed during introspection; omitting the budget fields \
                     (the gateway reads this as unknown, never as an exhausted balance)"
                );
                return None;
            }
        };

        // The period check is what makes a month boundary safe: at 00:00 UTC on the 1st every
        // stored reading instantly describes LAST month, and serving it would hand the fleet a
        // balance it has already spent.
        let remaining_micros = snapshot.remaining_for(&Period::current(now))?;

        Some(BudgetFields {
            remaining_micros,
            next_reset_at: snapshot.next_reset_at,
            // `unwrap_or_default` is unreachable in practice: a row carrying `remaining_micros`
            // was written by the refresher, which always stamps `refreshed_at` in the same
            // statement.
            snapshot_age_seconds: snapshot.age_seconds(now).unwrap_or_default(),
        })
    }

    /// Fires the `last_seen_at` write in the background when this account is due one.
    ///
    /// Deliberately not awaited: the caller is on the critical path of every metered model
    /// request, and the value of this write is entirely to the *next* refresher tick.
    fn schedule_touch(&self, repo: &Arc<dyn OpaRepoTrait>, budget_account_id: &str) {
        if !self.claim_touch(budget_account_id) {
            return;
        }
        let repo = repo.clone();
        let account_id = budget_account_id.to_string();
        tokio::spawn(async move {
            if let Err(err) = repo.touch_budget_remaining_snapshot(&account_id).await {
                tracing::warn!(
                    budget_account_id = %account_id,
                    error = %err,
                    "failed to touch the budget snapshot's last_seen_at; this account may fall \
                     out of the refresher's active set"
                );
            }
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
    /// there is no invariant to have been broken, so the guard is recovered rather than
    /// propagated as a panic that would take introspection down for every later request.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Instant>> {
        self.touched
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
