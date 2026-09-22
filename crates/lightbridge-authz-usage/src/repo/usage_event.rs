//! Request-grain row, split from repo.rs to keep its existing size ceiling.
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct UsageEvent {
    /// Scoped natural request key; NULL for legacy rows/signals without a stable key.
    pub dedup_key: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub signal_type: String,
    pub source: Option<String>,
    pub account_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub model: Option<String>,
    pub metric_name: Option<String>,
    /// The OAuth client (`azp`) this request arrived on -- "which channel" (#648). Promoted out of
    /// the `attributes` blob so it can be grouped and filtered; `None` when the signal carried
    /// none of `AZP_KEYS`.
    pub azp: Option<String>,
    /// Which API surface was called, derived from the request path at ingest
    /// (`handlers::ingest::operation_from_path`) and drawn from the closed
    /// [`crate::models::USAGE_OPERATIONS`] vocabulary (#648). `None` means the signal carried no
    /// path key at all -- which is NOT `Some("other")`: "we do not know which surface" and "a
    /// surface we do not have a name for" are different facts.
    pub operation: Option<String>,
    /// The billing plan Authorino stamped on the request (#648). `None` when the signal carried
    /// none of `BILLING_PLAN_KEYS` -- unknown, never a default plan name.
    pub billing_plan: Option<String>,
    pub usage_value: f64,
    pub request_count: i64,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub total_cost: Option<f64>,
    /// Wall-clock duration of the single request this event describes, in milliseconds.
    ///
    /// `None` is a first-class, honest outcome, not a failure: it means this signal genuinely
    /// carries no per-request duration. Aggregate metric points (histogram / exponential-histogram
    /// / summary) are the standing example -- a bucketed distribution is not one observation, and
    /// synthesising `sum / count` into this column would feed a fabricated value into
    /// `percentile_cont`. Query results surface that as `latency_samples == 0` for the affected
    /// series rather than as a zero.
    pub latency_ms: Option<f64>,
}
