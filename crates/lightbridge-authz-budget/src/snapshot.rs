//! The precomputed remaining balance the request path reads — ADR-0034 §15 (the single-call
//! design, owner directive 2026-09-04, lightbridge-authz#658).
//!
//! ## The problem this solves
//!
//! [`crate::remaining::RemainingService`] answers `ceiling − spend` correctly, and it costs an
//! indexed `SUM` over `budget_grants` plus an HTTPS round trip to `authz-usage` for the spend
//! `SUM`. That is a fine price for an operator's read. It is the wrong price for the data plane:
//! the owner's directive is **one call per request**, which means the answer has to be reachable
//! from the introspection `authz-opa` already serves, in the database connection it already holds,
//! without a second service in the path.
//!
//! So the expensive computation moves **off** the request path entirely. A background loop in
//! `authz-budget` ([`crate::snapshot_refresher`]) recomputes one row per active account every few
//! seconds; the request path reads that row by primary key and reports how old it is. Nothing on
//! the request path talks to `authz-usage`, and nothing on it sums a ledger.
//!
//! ## The two rules this type exists to enforce
//!
//! - **Unknown is never zero.** Every money field is `Option`. A row with `remaining_micros:
//!   None` is "seen, not yet computed", and it must render as an ABSENT introspection field, which
//!   the gateway's Lua reads as `known: false` → `503 budget_unavailable`. It must never render as
//!   `0`, which is `402 budget_exhausted` — a bill for our own latency.
//! - **A stale reading says how stale it is.** [`BudgetSnapshot::age_seconds`] is derived from
//!   `refreshed_at` and travels with the number, so a consumer acting on it can see the window it
//!   is acting inside instead of assuming the figure is current.
//!
//! ## What "forgiven overspend" means here (owner ruling, 2026-09-04)
//!
//! The snapshot is by construction behind reality by `refresh interval + ingest lag + one
//! in-flight request`. The owner accepted that window explicitly: over-consumption is forgiven,
//! and the guarantee that matters is per-request latency. This module therefore optimises for a
//! cheap, always-answerable read rather than for a fresh one — and says so in the payload, via
//! [`BudgetSnapshot::age_seconds`], instead of implying a freshness it does not have.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::period::Period;

/// One account's precomputed balance, exactly as `budget_remaining_snapshots` stores it.
///
/// Every money field is `Option` and every `None` means **unknown** — see the module doc. The
/// struct is deliberately flat and `Clone`: it crosses a service boundary as three JSON fields on
/// an introspection response, and there is no invariant between the fields worth an accessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub budget_account_id: String,
    /// Which period the money fields describe. `None` until the first successful refresh. A reader
    /// whose current period differs treats the whole snapshot as absent: a rolled-over balance is
    /// a different quantity, not a stale approximation of this one.
    pub period: Option<Period>,
    pub ceiling_micros: Option<i64>,
    pub spent_micros: Option<i64>,
    /// `ceiling − spent`, signed and unclamped. Negative means the account overshot.
    pub remaining_micros: Option<i64>,
    pub next_reset_at: Option<DateTime<Utc>>,
    /// When the money fields were last recomputed. `None` until the first successful refresh.
    pub refreshed_at: Option<DateTime<Utc>>,
    /// Non-`None` while the spend source has been unreadable since that instant, with the previous
    /// reading still served. Fail-soft: an outage must not erase a known balance.
    pub stale_since: Option<DateTime<Utc>>,
    pub last_seen_at: DateTime<Utc>,
}

impl BudgetSnapshot {
    /// How old the reading is, in whole seconds, or `None` when there is no reading yet.
    ///
    /// Clamped at zero rather than allowed to go negative: `refreshed_at` is written by the
    /// database's clock and read against the caller's, so a few milliseconds of skew is ordinary
    /// and a negative age would be nonsense on the wire. It is **a lower bound** on staleness —
    /// the OTLP ingest lag sits on top of it and nothing in this process can measure that (see
    /// `BudgetRemaining::source_lag_seconds`).
    pub fn age_seconds(&self, now: DateTime<Utc>) -> Option<u64> {
        let refreshed_at = self.refreshed_at?;
        Some(now.signed_duration_since(refreshed_at).num_seconds().max(0) as u64)
    }

    /// The remaining balance **only if it is usable for `period`** — i.e. the row carries a
    /// reading and that reading describes the period being asked about.
    ///
    /// The period check is the whole point: at 00:00 UTC on the 1st every stored snapshot
    /// instantly describes last month. Serving it would hand the fleet a balance that was already
    /// spent, which is the one direction this domain refuses to be wrong in.
    pub fn remaining_for(&self, period: &Period) -> Option<i64> {
        if self.period.as_ref() != Some(period) {
            return None;
        }
        self.remaining_micros
    }
}

/// Reads one account's snapshot. A trait, not just the concrete store, so `authz-opa`'s
/// introspection handler can be exercised against every outcome — a hit, a miss, and a row that
/// exists with no reading yet — without a live Postgres. Those are exactly the paths whose wrong
/// answer would be a `402` for an account that has money.
#[lightbridge_authz_core::async_trait]
pub trait BudgetSnapshotReader: Send + Sync + std::fmt::Debug {
    /// The snapshot for `budget_account_id`, or `None` when no row exists.
    ///
    /// A storage failure is an `Err`, never `Ok(None)`: "the database did not answer" must not
    /// render as "this account has no budget", for the same reason `Remaining::Unavailable` is not
    /// `remaining = 0`.
    async fn read(&self, budget_account_id: &str) -> Result<Option<BudgetSnapshot>, BudgetError>;

    /// Records that the request path just asked about this account, so the refresher keeps its
    /// reading warm. Creates the row (with no reading) when there is none.
    ///
    /// Write-behind by contract: callers must not await this on the hot path. Its failure is
    /// logged and swallowed by the caller — a missed touch costs one refresh cycle of freshness,
    /// never a wrong answer.
    async fn touch(&self, budget_account_id: &str) -> Result<(), BudgetError>;
}

/// How the loop is paced and bounded. Every field is operator-tunable config
/// (`server.budget.snapshot_*`); the defaults are the values ADR-0034 §15 argues for.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotRefreshConfig {
    /// Time between ticks. The dominant term of the snapshot's staleness, and therefore of the
    /// forgiven-overspend window.
    pub interval: Duration,
    /// How recently an account must have been seen to be worth refreshing.
    pub active_window: Duration,
    /// Most accounts one tick will refresh. Bounds a tick's wall time so a large active set cannot
    /// make ticks overlap; the remainder is picked up next tick, oldest-reading-first.
    pub batch: i64,
    /// Most spend reads in flight at once. The spend read is an HTTPS round trip to `authz-usage`,
    /// so this is the knob that decides whether the refresher is a polite background job or a
    /// thundering herd against a service that is also serving the console.
    pub concurrency: usize,
}

impl Default for SnapshotRefreshConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            active_window: Duration::from_secs(600),
            batch: 500,
            concurrency: 8,
        }
    }
}

/// What one tick did. Returned rather than only logged so a test can assert on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RefreshReport {
    /// `false` when another replica held the advisory lock; every other count is then zero.
    pub ran: bool,
    pub considered: usize,
    pub refreshed: usize,
    /// Accounts whose spend source could not be asked — previous reading kept, `stale_since`
    /// stamped.
    pub kept_stale: usize,
    pub failed: usize,
}
