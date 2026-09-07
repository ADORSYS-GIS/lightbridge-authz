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
//!   keeps its reading in the fast lane, but a write per request would put WAL on the critical path
//!   of every model call. So the touch stays off the response: spawned, bounded by a timeout, and
//!   at most once per account per touch interval in this process.
//!
//! ## What §15.6 changed here
//!
//! §15's touch was fire-and-forget in the strong sense: the throttle claim was taken *before* the
//! write, so a write that failed suppressed the next attempt for a full interval and vanished
//! without a trace. Two consequences the Stage 1b coverage watch had to rule out by hand — a
//! systematically failing write looked identical to an account that was simply not sending traffic,
//! and a bounded pool under load could drop the very touches that matter most. The write is now
//! bounded by [`touch::TOUCH_TIMEOUT`], and a failure or timeout **releases the claim** (so the very
//! next request retries instead of waiting out the interval) and is counted into
//! `budget_snapshot_touch_dropped_total`. Nothing is silently lost.
//!
//! Row *existence* no longer depends on this write at all: `authz-budget`'s refresher seeds a row
//! for every account that can send traffic (ADR-0034 §15.6, `crate::snapshot_seed` in the budget
//! crate), so the touch's only job is keeping a busy account in the fast lane.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chrono::Utc;
use lightbridge_authz_budget::Period;

use crate::OpaRepoTrait;

pub mod touch;

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
    /// Last time this process touched each account, so the throttle needs no round trip.
    /// Per-process by design: N replicas each touch at most once per interval, which is N writes
    /// per interval per hot account — negligible, and it needs no coordination.
    /// `Arc` so the spawned write can hold it for the release-on-failure path without borrowing
    /// `self` into a `'static` task.
    pub(crate) touched: Arc<Mutex<HashMap<String, Instant>>>,
    /// `budget_snapshot_touch_dropped_total` for this process: touches that failed or timed out.
    /// Steady state is zero; a climbing value means `last_seen_at` is not moving for some accounts
    /// and the refresher's fast lane is working from stale recency (ADR-0034 §15.6).
    pub(crate) dropped: Arc<std::sync::atomic::AtomicU64>,
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

    /// `budget_snapshot_touch_dropped_total` for this process — see [`Self::dropped`]. Exposed so a
    /// test can assert the counter moves, and so an operator reading a heap dump or a future
    /// metrics surface has one place to read it from.
    pub fn dropped_touches(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}
