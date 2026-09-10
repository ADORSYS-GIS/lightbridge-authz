//! `authz-budget`'s server block, and the knobs that pace ADR-0034 §15's snapshot refresher.
//!
//! Split out of `config/mod.rs` (which sits on its LoC-gate ceiling) the same way
//! `budget_internal.rs` and `claim_mapper.rs` beside it were: [`BudgetServer`] is re-exported from
//! `crate::config`, so every existing `use` path still resolves.

use serde::Deserialize;

use super::Tls;

/// `authz-budget`'s server block. Shaped like [`super::IdpServer`] (address/port/TLS, no
/// `basic_auth`): every route this server mounts is behind the same bearer-JWT `rpc_authorize`
/// gate `authz-api` already uses, not Basic auth like [`super::OpaServer`]. Unlike `idp`, this
/// server's RPC surface is mounted under a fixed `/budget` path prefix (`build_budget_router`)
/// rather than at the configurable root `authz-api` uses — there is no `rpc_base_path` field here
/// because the prefix is not optional, it is what makes the service reachable behind a shared
/// gateway origin alongside `authz-api` (see `docs/architecture/budget.md`).
///
/// The six `snapshot_*` fields below pace the background loop that precomputes
/// `budget_remaining_snapshots`. They live on THIS block rather than on
/// [`super::BudgetInternalServer`] deliberately: the snapshot is read by `authz-opa`'s
/// introspection, which is served whether or not this deployment configures the internal listener
/// at all, so the refresher must run for every `authz-budget` — not only for one that publishes
/// `GET /budget/v1/remaining`.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
    /// Seconds between snapshot refresh ticks. **This is the dominant term of ADR-0034 §15's
    /// forgiven-overspend window**: an account's enforced balance is at worst this stale, plus the
    /// OTLP ingest lag, plus one in-flight request.
    ///
    /// Lower is fresher and costs one spend query per active account per tick against
    /// `authz-usage`; higher is cheaper and forgives more overspend. The owner's ruling
    /// (2026-09-04) is that per-request latency wins and over-consumption is forgiven, which is
    /// why the default is a compromise rather than the smallest value that works. Zero is rejected
    /// at startup — a zero-second interval is a busy loop against the database, not a
    /// configuration.
    #[serde(default = "default_snapshot_refresh_seconds")]
    pub snapshot_refresh_seconds: u64,
    /// How many minutes an account stays in the refresher's work list after the request path last
    /// asked about it — the OUTER bound, past which it is not refreshed at all.
    ///
    /// **Raised from 10 minutes to 24 hours by ADR-0034 §15.6.** Ten minutes was chosen to make
    /// the loop's cost scale with concurrently-active accounts; what it actually did was freeze
    /// every idle account's balance ten minutes after its last request, so at the next UTC month
    /// boundary all of them became period-mismatched — i.e. `known: false` — at once. Idle
    /// accounts are now demoted to the slow lane below instead of being dropped, which costs one
    /// spend query per idle account per `snapshot_slow_lane_minutes` and keeps the reading true.
    #[serde(default = "default_snapshot_active_window_minutes")]
    pub snapshot_active_window_minutes: u64,
    /// ADR-0034 §15.6. The boundary between the refresher's two lanes, in minutes, and the cadence
    /// of the slow one: an account seen within this window is recomputed every
    /// `snapshot_refresh_seconds`; one seen longer ago than this (but inside
    /// `snapshot_active_window_minutes`) is recomputed once per this interval.
    ///
    /// One key for both jobs deliberately — two would let an operator configure a band in which an
    /// account belongs to neither lane and is silently dropped, which is the bug §15.6 removes.
    #[serde(default = "default_snapshot_slow_lane_minutes")]
    pub snapshot_slow_lane_minutes: u64,
    /// ADR-0034 §15.6. How many days back the refresher's seed looks for evidence that an account
    /// can send metered traffic — a booked budget grant, or an active API key that has been used.
    /// Every such account gets a snapshot row whether or not it is sending traffic right now, so
    /// coverage is a property of the estate rather than of who happened to make a request since
    /// the table was created (the Stage 1b watch measured ~50 % before this existed).
    ///
    /// Raising it covers accounts that go quiet for longer, at one row and one slow-lane spend
    /// query each. Lowering it narrows the population the coverage census reports on — it does not
    /// delete rows already seeded.
    #[serde(default = "default_snapshot_seed_lookback_days")]
    pub snapshot_seed_lookback_days: u32,
    /// Most accounts one tick refreshes, so a large active set cannot make ticks overlap. The
    /// remainder is picked up on the next tick, oldest reading first, so nothing is starved.
    #[serde(default = "default_snapshot_batch")]
    pub snapshot_batch: u32,
    /// Most spend reads in flight at once. Each is an HTTPS round trip to `authz-usage`, which is
    /// also serving the console — this is the knob that decides whether the refresher is a polite
    /// background job or a thundering herd.
    #[serde(default = "default_snapshot_concurrency")]
    pub snapshot_concurrency: u16,
}

/// Fifteen seconds. See [`BudgetServer::snapshot_refresh_seconds`].
fn default_snapshot_refresh_seconds() -> u64 {
    15
}

/// Twenty-four hours. See [`BudgetServer::snapshot_active_window_minutes`].
fn default_snapshot_active_window_minutes() -> u64 {
    24 * 60
}

/// Ten minutes. See [`BudgetServer::snapshot_slow_lane_minutes`].
fn default_snapshot_slow_lane_minutes() -> u64 {
    10
}

/// Thirty days. See [`BudgetServer::snapshot_seed_lookback_days`].
fn default_snapshot_seed_lookback_days() -> u32 {
    30
}

/// See [`BudgetServer::snapshot_batch`].
fn default_snapshot_batch() -> u32 {
    500
}

/// See [`BudgetServer::snapshot_concurrency`].
fn default_snapshot_concurrency() -> u16 {
    8
}
