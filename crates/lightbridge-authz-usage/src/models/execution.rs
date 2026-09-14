//! Wire types for the execution-grain query endpoint (#726):
//! `POST /usage/v1/usage/executions/query`.
//!
//! The execution grain is `usage_executions` joined with its children `usage_model_calls` and
//! `usage_tool_calls` (#582). This endpoint aggregates executions into time buckets, optionally
//! grouped by `source` / `model` / `provider`, with bucket-scoped truncation (the #578
//! `dense_rank()` pattern) and the shared ownership gate (Ticket A, #725).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::UsageScope;

/// Request body for `POST /usage/v1/usage/executions/query`.
///
/// `scope` is restricted to `user` (self-ownership via the JWT subject, resolved through
/// `usage_identities`) and `all` (`usage:read-all`); `account`/`project`/`api_key` are rejected
/// with `400` because the execution grain has no per-account/per-project/per-key ownership
/// authority (see `GrainScope::Execution`).
///
/// There is deliberately no `metrics` field: the execution grain does not yet compute latency
/// percentiles on `duration_ms` (the ticket defers them), so the response carries no percentile
/// columns to select.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecutionQueryRequest {
    pub scope: UsageScope,
    pub scope_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    #[serde(default)]
    pub filters: ExecutionQueryFilters,
    #[serde(default)]
    pub group_by: Vec<ExecutionGroupBy>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

/// Equality filters for the execution grain. `source`/`provider` live on `usage_executions`;
/// `model` lives on the child `usage_model_calls`, so filtering by it joins the child at row
/// level (the Option A fan-out semantics -- see `ExecutionSeriesPoint`'s doc comment).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ExecutionQueryFilters {
    pub source: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
}

/// The dimensions the execution grain can be grouped by. `source` and `provider` live on
/// `usage_executions`; `model` lives on the child `usage_model_calls`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionGroupBy {
    Source,
    Model,
    Provider,
}

/// One aggregated time bucket of the execution grain.
///
/// `source`/`model`/`provider` are `Some` when the corresponding dimension is in `group_by`,
/// `null` otherwise -- exactly like every dimension echo on the legacy `UsageSeriesPoint`.
///
/// ## The `model` fan-out (Option A)
///
/// `model` is a real dimension on the child `usage_model_calls`, so grouping (or filtering) by it
/// joins the child at row level. An execution with N distinct models therefore contributes to N
/// groups: `executions_count`, `total_duration_ms` and `total_cost` are **not partition-disjoint
/// across `model` groups** -- a multi-model execution is counted once per model it touched. This
/// is the honest meaning of "executions touching this model" and is the one place the aggregates
/// are not additive across groups.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct ExecutionSeriesPoint {
    pub bucket_start: DateTime<Utc>,
    pub source: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub executions_count: i64,
    pub total_duration_ms: i64,
    /// Sum of `usage_executions.estimated_cost_micro_usd` (integer micro-USD). `None` when no
    /// execution in the bucket carried a cost -- never `0` (governance#188: unknown is not free).
    pub total_cost: Option<i64>,
    pub total_input_tokens: i64,
    pub total_output_tokens: i64,
    pub tool_call_count: i64,
}

/// Response body for `POST /usage/v1/usage/executions/query`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ExecutionQueryResponse {
    pub points: Vec<ExecutionSeriesPoint>,
    /// #578: `true` when more than `limit` DISTINCT `bucket_start` values matched and the OLDEST
    /// one was dropped WHOLE to fit. `limit` bounds bucket count, not `points.len()`.
    pub truncated: bool,
}

fn default_bucket() -> String {
    "1 hour".to_string()
}

fn default_limit() -> u32 {
    1_000
}
