//! Wire types for the seat-grain query endpoint (#728):
//! `POST /usage/v1/usage/seats/query`.
//!
//! The seat grain is `usage_seat_snapshots` (#583): one row per
//! `(source, snapshot_day, subject_kind, subject_id, provider_user_id)` — a generalized daily
//! seat snapshot from every source (GitHub Copilot seat assignments today; Cursor, JetBrains
//! tomorrow). This endpoint aggregates snapshots into time buckets, optionally grouped by
//! `source` / `subject_kind` / `subject_id` / `seat_state`, with bucket-scoped truncation (the
//! #578 `dense_rank()` pattern) and the shared ownership gate (`GrainScope::DaySeat`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::UsageScope;
use super::day_seat::SubjectKind;

/// Request body for `POST /usage/v1/usage/seats/query`.
///
/// `scope` is restricted to `user` (self-ownership via the JWT subject, matched on
/// `usage_seat_snapshots.provider_user_id`) and `all` (`usage:read-all`); `account`/`project`/
/// `api_key` are rejected with `400` because the seat grain has no per-account/per-project/
/// per-key ownership authority (see `GrainScope::DaySeat`).
///
/// There is deliberately no `metrics` field: the seat grain has no latency column, so there is no
/// optional metric family to select.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SeatSnapshotQueryRequest {
    pub scope: UsageScope,
    pub scope_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    #[serde(default)]
    pub filters: SeatSnapshotQueryFilters,
    #[serde(default)]
    pub group_by: Vec<SeatGroupBy>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

/// Equality filters for the seat grain. All live on `usage_seat_snapshots`; `subject_kind` is
/// bound to the closed [`SubjectKind`] vocabulary so an unknown value is refused at
/// deserialization, never silently matched against nothing. `seat_state` is deliberately a free
/// `Option<String>`: the migration stores it verbatim as the provider's own opaque token (never
/// CHECKed — "closed at the normalizer, not here"), so a closed enum here would be a lie about
/// the schema.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SeatSnapshotQueryFilters {
    pub source: Option<String>,
    pub subject_kind: Option<SubjectKind>,
    pub seat_state: Option<String>,
    pub assignee_team: Option<String>,
    pub plan_type: Option<String>,
}

/// The dimensions the seat grain can be grouped by. All four live on `usage_seat_snapshots`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SeatGroupBy {
    Source,
    SubjectKind,
    SubjectId,
    SeatState,
}

/// One aggregated time bucket of the seat grain.
///
/// `source`/`subject_kind`/`subject_id`/`seat_state` are `Some` when the corresponding dimension
/// is in `group_by`, `null` otherwise — exactly like every dimension echo on the legacy
/// `UsageSeriesPoint`.
///
/// The three counts are seat-days (`COUNT(*)` over the daily snapshot rows in the bucket), not
/// distinct people. Each row is one seat on one day in exactly one state (`pending_cancellation_date`
/// is either `NULL` or not), so the counts are partition-disjoint and additive:
/// `active_count + pending_cancellation_count = seat_count`. "Active" is derived from
/// `pending_cancellation_date IS NULL`, never from the opaque `seat_state` token — hard-coding a
/// provider vocabulary would be fragile across sources (see `SeatSnapshotQueryFilters::seat_state`).
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SeatSnapshotSeriesPoint {
    pub bucket_start: DateTime<Utc>,
    pub source: Option<String>,
    pub subject_kind: Option<String>,
    pub subject_id: Option<String>,
    pub seat_state: Option<String>,
    pub seat_count: i64,
    pub active_count: i64,
    pub pending_cancellation_count: i64,
}

/// Response body for `POST /usage/v1/usage/seats/query`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SeatSnapshotQueryResponse {
    pub points: Vec<SeatSnapshotSeriesPoint>,
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
