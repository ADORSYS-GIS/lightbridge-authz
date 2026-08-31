use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct IngestResponse {
    pub accepted_events: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UsageErrorResponse {
    pub error: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UsageQueryRequest {
    pub scope: UsageScope,
    pub scope_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    #[serde(default)]
    pub filters: UsageQueryFilters,
    #[serde(default)]
    pub group_by: Vec<UsageGroupBy>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageScope {
    User,
    ApiKey,
    Project,
    Account,
    /// Estate-wide query: no `account_id`/`project_id`/`user_id`/`api_key_id` filter is added at
    /// all (`repo::push_scope_filters`'s `All` arm), so the query spans every account. Requires
    /// the caller's validated bearer token to hold `Permission::UsageReadAll`
    /// (`handlers::query::query_usage`) -- there is no per-row ownership predicate for "all", by
    /// definition, so this is gated on a coarse RBAC permission instead of `ScopeAuthority`.
    /// `scope_id` is still a required wire field (see `UsageQueryRequest::scope_id`) but is
    /// ignored for this scope; callers should send `""`.
    All,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UsageGroupBy {
    AccountId,
    ProjectId,
    ApiKeyId,
    UserId,
    UserName,
    Model,
    MetricName,
    SignalType,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UsageQueryFilters {
    pub account_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub model: Option<String>,
    pub metric_name: Option<String>,
    pub signal_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UsageQueryResponse {
    pub points: Vec<UsageSeriesPoint>,
    /// #578: `true` when more than `limit` DISTINCT `bucket_start` values matched the query and
    /// the OLDEST one was dropped WHOLE to fit. `limit` bounds bucket count, not `points.len()`
    /// (a row count) -- with a non-empty `group_by`, `points` can hold more entries than `limit`
    /// (one per series per surviving bucket), still in the same ascending `bucket_start` order as
    /// before this field existed, and every surviving bucket keeps its FULL series set, never an
    /// arbitrary subset while a sibling bucket keeps all of its own. `false` means every matching
    /// bucket is present. See `StoreRepo::query_usage`'s doc comment for why truncation drops the
    /// oldest bucket, not the newest, why it must be bucket-scoped rather than row-scoped, and for
    /// the known mid-bucket-cut caveat tracked as #586.
    pub truncated: bool,
}

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
    pub requests: i64,
    pub usage_value: f64,
    pub total_cost: f64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
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

fn default_bucket() -> String {
    "1 hour".to_string()
}

fn default_limit() -> u32 {
    1_000
}

/// Request body for the internal, mTLS-protected `/usage/v1/spend/query` endpoint (the query
/// listener requires and verifies a client certificate -- see `UsageServerGroup::query`'s doc
/// comment; this route carries no Basic-auth or bearer check of its own). Answers
/// exactly the question `lightbridge-authz-budget`'s `SpendReader` asks: the summed
/// `usage_events.total_cost` for one account over a half-open `[start, end)` interval. Deliberately
/// takes explicit `start`/`end` bounds rather than a `Period` -- period-to-bounds conversion
/// (`period_bounds_utc`) stays a budget-domain concern; this endpoint only ever runs the SQL.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SpendQueryRequest {
    pub account_id: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Response body for `/usage/v1/spend/query`. `total_cost` is the raw, nullable
/// `SUM(total_cost)::double precision` result -- `None` when no `usage_events` rows matched
/// (account_id + half-open interval), `Some` (including `Some(0.0)`) when at least one row
/// matched. Deliberately preserved as `Option<f64>` rather than collapsed to `0.0`: the caller
/// (`lightbridge-authz-budget`'s `UsageServiceSpendReader`) depends on this exact SQL-NULL-vs-zero
/// distinction to keep `Spend::Unavailable` distinct from `Spend::Known(0)`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SpendQueryResponse {
    pub total_cost: Option<f64>,
}
