//! Wire types for the day-facts grain query endpoint (#727):
//! `POST /usage/v1/usage/facts/query`.
//!
//! The day grain is `usage_day_facts` (#583): one row per `(source, day, subject_kind,
//! subject_id)`, a generalized daily aggregate from every source (GitHub Copilot org/user/repo
//! dailies today; Cursor, JetBrains, M365 tomorrow). This endpoint aggregates facts into time
//! buckets, optionally grouped by `source` / `subject_kind` / `subject_id`, with bucket-scoped
//! truncation (the #578 `dense_rank()` pattern) and the shared ownership gate
//! (`GrainScope::DaySeat`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::UsageScope;
use super::day_seat::SubjectKind;

/// Request body for `POST /usage/v1/usage/facts/query`.
///
/// `scope` is restricted to `user` (self-ownership via the JWT subject, matched on
/// `usage_day_facts.provider_user_id`) and `all` (`usage:read-all`); `account`/`project`/`api_key`
/// are rejected with `400` because the day grain has no per-account/per-project/per-key ownership
/// authority (see `GrainScope::DaySeat`).
///
/// There is deliberately no `metrics` field: the day grain has no latency column, so there is no
/// optional metric family to select.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DayFactQueryRequest {
    pub scope: UsageScope,
    pub scope_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    #[serde(default)]
    pub filters: DayFactQueryFilters,
    #[serde(default)]
    pub group_by: Vec<DayFactGroupBy>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

/// Equality filters for the day grain. All live on `usage_day_facts`; `subject_kind` is bound to
/// the closed [`SubjectKind`] vocabulary so an unknown value is refused at deserialization, never
/// silently matched against nothing.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DayFactQueryFilters {
    pub source: Option<String>,
    pub subject_kind: Option<SubjectKind>,
    pub is_aggregate_only: Option<bool>,
    pub language: Option<String>,
    pub editor: Option<String>,
    pub model: Option<String>,
}

/// The dimensions the day grain can be grouped by. All three live on `usage_day_facts`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DayFactGroupBy {
    Source,
    SubjectKind,
    SubjectId,
}

/// One aggregated time bucket of the day grain.
///
/// `source`/`subject_kind`/`subject_id` are `Some` when the corresponding dimension is in
/// `group_by`, `null` otherwise -- exactly like every dimension echo on the legacy
/// `UsageSeriesPoint`.
///
/// `is_aggregate_only` is always present and is a real group key: aggregate-only rows (e.g. a
/// GitHub Copilot org daily, which is the aggregate over its member user dailies) and per-entity
/// rows are overlapping populations, so they are never summed into one bucket. A caller who wants
/// the total across both must add the two points themselves.
///
/// Every measure is `Option<i64>`: `NULL` = unknown, never `0` (governance#188). A source that
/// does not report a measure leaves it `null`, and a bucket whose rows all carry `NULL` cost
/// reports `cost_micro_usd: null`, never `0`. `total_active_users` is a per-day distinct count, so
/// it is reported as the peak daily active users in the bucket (`MAX`), never summed across days.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct DayFactSeriesPoint {
    pub bucket_start: DateTime<Utc>,
    pub source: Option<String>,
    pub subject_kind: Option<String>,
    pub subject_id: Option<String>,
    pub is_aggregate_only: bool,
    pub total_suggestions: Option<i64>,
    pub total_acceptances: Option<i64>,
    pub total_lines_suggested: Option<i64>,
    pub total_lines_accepted: Option<i64>,
    pub total_active_users: Option<i64>,
    pub cost_micro_usd: Option<i64>,
}

/// Response body for `POST /usage/v1/usage/facts/query`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DayFactQueryResponse {
    pub points: Vec<DayFactSeriesPoint>,
    /// #578: `true` when more than `limit` DISTINCT `bucket_start` values matched and the OLDEST
    /// one was dropped WHOLE to fit. `limit` bounds bucket count, not `points.len()`.
    pub truncated: bool,
}

fn default_bucket() -> String {
    "1 day".to_string()
}

fn default_limit() -> u32 {
    1_000
}
