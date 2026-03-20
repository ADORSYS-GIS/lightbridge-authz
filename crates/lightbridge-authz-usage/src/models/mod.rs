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
    Project,
    Account,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UsageGroupBy {
    AccountId,
    ProjectId,
    UserId,
    Model,
    MetricName,
    SignalType,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UsageQueryFilters {
    pub account_id: Option<String>,
    pub project_id: Option<String>,
    pub user_id: Option<String>,
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
    pub user_id: Option<String>,
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
