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

#[derive(Debug, Serialize, ToSchema)]
pub struct UsageQueryResponse {
    pub points: Vec<UsageSeriesPoint>,
}

#[derive(Debug, Serialize, ToSchema, Clone)]
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
}

fn default_bucket() -> String {
    "1 hour".to_string()
}

fn default_limit() -> u32 {
    1_000
}

/// Request body for the internal, Basic-auth-protected `/usage/v1/spend/query` endpoint. Answers
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
