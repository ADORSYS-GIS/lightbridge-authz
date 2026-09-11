//! Retention/rollup configuration for `usage_events` (#549 AC2).
//!
//! Split out of `config.rs` by the LoC gate (`.github/actions/loc-gate`): the retention config is
//! a self-contained unit that does not belong to the server-group/scope-authority config, and
//! keeping it here lets `config.rs` stay under its ceiling. The pairing is unchanged -- `config.rs`
//! re-exports [`RetentionConfig`] so every existing `use` path still resolves, and the two files
//! move together.

use serde::Deserialize;

/// Retention/rollup configuration for `usage_events` (#549 AC2).
///
/// `usage_events` grows ~100 MB/day with no retention. This config drives a background job in the
/// usage service that rolls rows older than `raw_days` into the `usage_events_daily` aggregate and
/// deletes them from the raw table, in one transaction. The dashboard's max range is 90 days, so
/// `raw_days` MUST be >= 90 to keep the full dashboard window queryable from raw (which is what
/// keeps latency percentiles exact -- the rollup does not carry them). Budget spend reads the
/// current billing period, which is always within the raw window, so it is never truncated.
///
/// The rollup table itself is also bounded: `rollup_days` (default 365) is how long a rolled-up day
/// is kept before it too is deleted, so the long-term store does not grow without bound. Nothing
/// reads the rollup today (the dashboard's 90-day window is served from raw, and budget spend reads
/// the current period), so this bound is what keeps `usage_events_daily` from becoming the next
/// write-only, unbounded table -- the exact anti-pattern #549 exists to remove.
#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    /// Whether the retention/rollup background job runs. Default `false`.
    ///
    /// The job MOVES rows out of `usage_events` into `usage_events_daily` and deletes them -- a
    /// destructive, irreversible data migration. The N-1 binary's `spend_for_account` reads
    /// `usage_events` only (the `UNION ALL` rollup arm exists only in the binary that ships this
    /// config), so once a run commits, a rollback to the previous image silently under-reports
    /// spend for every aged window -- the permissive direction for `authz-budget`'s refill and
    /// remaining-balance decisions. Per ADR-0031's expand/contract rule, the job therefore
    /// defaults to OFF: an operator must explicitly opt in (and accept that enabling it makes the
    /// release non-revertible for aged data) before the destructive loop runs.
    ///
    /// There is **no grace period for a pre-existing backlog**. The first run rolls up EVERYTHING
    /// older than `raw_days` -- including rows far older than `rollup_days` -- and then, in the
    /// same run, purges any rollup row older than `rollup_days`. So on a fresh cutover against a
    /// service that has been running unretained for longer than `rollup_days`, the slice of the
    /// backlog older than `rollup_days` is rolled up and immediately deleted in that same first
    /// run: gone for good, with no window to inspect or export it first. If you need that history,
    /// export it BEFORE enabling the job.
    #[serde(default = "default_retention_enabled")]
    pub enabled: bool,
    /// Days of raw `usage_events` to keep before rolling up + deleting. Must be >= the dashboard's
    /// max range (90 days). Default `90`.
    #[serde(default = "default_retention_raw_days")]
    pub raw_days: i64,
    /// How long a rolled-up day is kept in `usage_events_daily` before it too is deleted. Must be
    /// >= 1. Default `365` (one year of long-term retention).
    #[serde(default = "default_retention_rollup_days")]
    pub rollup_days: i64,
    /// How often the retention/rollup job runs, in seconds. Default `3600` (hourly).
    #[serde(default = "default_retention_interval_seconds")]
    pub interval_seconds: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            enabled: default_retention_enabled(),
            raw_days: default_retention_raw_days(),
            rollup_days: default_retention_rollup_days(),
            interval_seconds: default_retention_interval_seconds(),
        }
    }
}

fn default_retention_enabled() -> bool {
    false
}

fn default_retention_raw_days() -> i64 {
    90
}

fn default_retention_rollup_days() -> i64 {
    365
}

fn default_retention_interval_seconds() -> u64 {
    3600
}
