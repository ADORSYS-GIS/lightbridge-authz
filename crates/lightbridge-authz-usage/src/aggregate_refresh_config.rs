//! Configuration for the KPI aggregate-refresh background job (#587).
//!
//! Split out of `config.rs` by the LoC gate (`.github/actions/loc-gate`): the aggregate-refresh
//! config is a self-contained unit that does not belong to the server-group/scope-authority
//! config, and keeping it here lets `config.rs` stay under its ceiling. The pairing is unchanged
//! -- `config.rs` re-exports [`AggregateRefreshConfig`] so every existing `use` path still
//! resolves, and the two files move together.

use serde::Deserialize;

/// Configuration for the KPI aggregate-refresh background job (#587).
///
/// The named KPI aggregates (`mv_*` materialized views, `migrations-usage/
/// 20260918000001_usage_kpi_aggregates.sql`) are refreshed by a background job in the usage
/// service, mirroring the `retention_loop` pattern (Option A -- plain Postgres, no TimescaleDB).
/// Unlike retention, refreshing a materialized view is **non-destructive and idempotent**
/// (`REFRESH MATERIALIZED VIEW CONCURRENTLY`), so this job defaults to ON: the whole point of the
/// aggregates is that the KPI read path hits them, and a stale aggregate silently serves stale
/// KPIs. There is no rollback-safety reason to default it off the way retention defaults off.
#[derive(Debug, Clone, Deserialize)]
pub struct AggregateRefreshConfig {
    /// Whether the aggregate-refresh background job runs. Default `true`.
    #[serde(default = "default_aggregate_refresh_enabled")]
    pub enabled: bool,
    /// How often the job refreshes the KPI aggregates, in seconds. Default `3600` (hourly).
    #[serde(default = "default_aggregate_refresh_interval_seconds")]
    pub interval_seconds: u64,
}

impl Default for AggregateRefreshConfig {
    fn default() -> Self {
        Self {
            enabled: default_aggregate_refresh_enabled(),
            interval_seconds: default_aggregate_refresh_interval_seconds(),
        }
    }
}

fn default_aggregate_refresh_enabled() -> bool {
    true
}

fn default_aggregate_refresh_interval_seconds() -> u64 {
    3600
}
