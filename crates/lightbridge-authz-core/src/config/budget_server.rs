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
/// The four `snapshot_*` fields below pace the background loop that precomputes
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
    /// asked about it. This is what makes the loop's cost scale with *concurrently active*
    /// accounts rather than with the size of the estate.
    ///
    /// Too short and a bursty account's snapshot goes cold between bursts, so its next request
    /// pays the full live read (correct, just slower). Too long and the loop refreshes accounts
    /// nobody is using. Ten minutes covers a coffee break without covering a working day.
    #[serde(default = "default_snapshot_active_window_minutes")]
    pub snapshot_active_window_minutes: u64,
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

/// Ten minutes. See [`BudgetServer::snapshot_active_window_minutes`].
fn default_snapshot_active_window_minutes() -> u64 {
    10
}

/// See [`BudgetServer::snapshot_batch`].
fn default_snapshot_batch() -> u32 {
    500
}

/// See [`BudgetServer::snapshot_concurrency`].
fn default_snapshot_concurrency() -> u16 {
    8
}
