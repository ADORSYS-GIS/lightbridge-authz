//! Query series point, extracted to keep models within its existing size ceiling.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct UsageSeriesPoint {
    pub bucket_start: DateTime<Utc>,
    pub account_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub model: Option<String>,
    pub metric_name: Option<String>,
    pub signal_type: Option<String>,
    /// The emitter this bucket's telemetry came from (`usage_events.source`). Present when
    /// `group_by` includes `source`, `null` otherwise.
    pub source: Option<String>,
    /// The OAuth client the requests in this bucket arrived on. Present when `group_by` includes
    /// `azp`, `null` otherwise -- exactly like every other dimension echo here (#648).
    pub azp: Option<String>,
    /// Which API surface was called, from the closed [`crate::models::USAGE_OPERATIONS`] vocabulary. Present when
    /// `group_by` includes `operation`, `null` otherwise. A `null` here when `operation` IS
    /// grouped is a real value: those rows carried no request path at all (#648).
    pub operation: Option<String>,
    /// The billing plan stamped on the requests in this bucket. Present when `group_by` includes
    /// `billing_plan`, `null` otherwise (#648).
    pub billing_plan: Option<String>,
    pub requests: i64,
    pub usage_value: f64,
    pub total_cost: Option<f64>,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    /// Subsets of input/output respectively, summed over the events that report input (cached) or
    /// output (reasoning) tokens. None if one of those events lacks the count; an event with no
    /// token usage at all, such as a refused request, does not count against it.
    pub cached_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    /// How many rows in this bucket actually carried a latency measurement. A percentile computed
    /// over a handful of samples is noise, and `p99` needs ~100 samples before it means anything,
    /// so this count is returned alongside the percentiles rather than left for the caller to
    /// guess. `0` means no row in this bucket reported latency at all -- which is a legitimate,
    /// per-series outcome (see `UsageEvent::latency_ms`), not an error.
    pub latency_samples: i64,
    /// Median request latency in milliseconds, `percentile_cont(0.5)` over the bucket's
    /// `latency_ms` values. `None` exactly when `latency_samples == 0` -- never collapsed to `0.0`,
    /// because "no latency was reported" and "every request took 0 ms" are different facts and the
    /// console has to be able to say which one it is.
    pub latency_p50_ms: Option<f64>,
    /// 95th-percentile request latency in milliseconds. `None` when `latency_samples == 0`.
    pub latency_p95_ms: Option<f64>,
    /// 99th-percentile request latency in milliseconds. `None` when `latency_samples == 0`.
    /// Meaningful only once `latency_samples` is large (~100+); below that it degenerates towards
    /// the bucket maximum.
    pub latency_p99_ms: Option<f64>,
}
