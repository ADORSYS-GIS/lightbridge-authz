//! How the snapshot refresher is paced, and what one pass reports — ADR-0034 §15/§15.6.
//!
//! Split out of [`crate::snapshot`] (which is about the row and its two rules) so that file stays
//! under this repo's 200-LoC ceiling once §15.6's seeding and slow lane are configurable. Both
//! types are re-exported from `crate::snapshot`, so every existing `use` path still resolves.

use std::time::Duration;

/// How the loop is paced and bounded. Every field is operator-tunable config
/// (`server.budget.snapshot_*`); the defaults are the values ADR-0034 §15/§15.6 argue for.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotRefreshConfig {
    /// Time between ticks, and the cadence of the FAST lane. The dominant term of the snapshot's
    /// staleness for an account in active use, and therefore of the forgiven-overspend window.
    pub interval: Duration,
    /// The outer bound: past this much time since [`crate::snapshot::BudgetSnapshot::last_seen_at`]
    /// an account stops being refreshed altogether.
    ///
    /// §15.6 raised this from ten minutes to a day. Ten minutes made the loop cheap and made
    /// coverage a lie: an account that paused for a coffee break kept a reading frozen at the
    /// moment it went quiet, and at the next UTC month boundary that reading became
    /// period-mismatched — i.e. ABSENT — for every such account at once. A day, with the slow lane
    /// below carrying most of it, costs one spend query per idle account per
    /// [`Self::slow_lane_interval`] and keeps the reading true.
    pub active_window: Duration,
    /// The boundary between the two lanes, and the cadence of the slow one.
    ///
    /// One value doing two jobs, deliberately: an account seen within this window is HOT and is
    /// recomputed every [`Self::interval`]; an account seen longer ago than this (but inside
    /// [`Self::active_window`]) is WARM and is recomputed only once per this interval. Two knobs
    /// would let an operator configure a gap in which an account is in neither lane.
    pub slow_lane_interval: Duration,
    /// How far back the seed looks for evidence that an account can send traffic — a booked grant
    /// or an active API key that has been used. See [`crate::snapshot_seed`].
    pub seed_lookback_days: u32,
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
            active_window: Duration::from_secs(24 * 60 * 60),
            slow_lane_interval: Duration::from_secs(600),
            seed_lookback_days: 30,
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
    /// Rows the seed created this tick, plus rows it re-armed back into the active window. Zero on
    /// a steady-state tick — the seed is idempotent, so a non-zero value means the estate gained
    /// an account, or an idle one aged out and was put back.
    pub seeded: u64,
    pub considered: usize,
    pub refreshed: usize,
    /// Accounts whose spend source could not be asked — previous reading kept, `stale_since`
    /// stamped.
    pub kept_stale: usize,
    pub failed: usize,
    /// The coverage census taken at the end of the tick. See [`CoverageCounts`].
    pub coverage: CoverageCounts,
}

/// The coverage census — the numbers ADR-0034 §15.6 exists to make citable, counted once per tick
/// straight from the table rather than inferred from the work the tick happened to do.
///
/// The question these answer is the one the Stage 1b watch could not: *of the accounts that can
/// send traffic, how many would the gateway read as `known`?* A refresher can report a perfectly
/// healthy tick while half the estate has no row at all — that was exactly the ~50 % coverage the
/// rollout found, and no per-tick counter above would have shown it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CoverageCounts {
    /// `budget_snapshot_accounts_total` — rows in `budget_remaining_snapshots`.
    pub accounts_total: i64,
    /// `budget_snapshot_known_total` — rows carrying a reading for the CURRENT period, i.e. rows
    /// the introspection would answer `known: true` from right now.
    pub known_total: i64,
    /// `budget_snapshot_stale_total` — rows whose `stale_since` is stamped (the spend source has
    /// been unreadable for them since that instant, previous reading kept).
    pub stale_total: i64,
    /// `budget_snapshot_uncovered_total` — accounts the seed predicate says CAN send traffic and
    /// which the gateway would nonetheless read as unknown: no row, no reading, or a reading for a
    /// period that has rolled over. **This is the number that must be zero**; every unit of it is
    /// an account that fails open under enforcement and pollutes the decision table under shadow.
    pub uncovered_total: i64,
}
