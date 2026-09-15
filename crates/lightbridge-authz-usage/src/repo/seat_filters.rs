//! Scope/time/filter predicates for the seat-grain query (#728). Split out of
//! `repo/seat_query.rs` to satisfy the LoC gate (lightbridge-governance#172).

use crate::models::UsageScope;
use crate::models::seat::SeatSnapshotQueryRequest;
use sqlx::{Postgres, QueryBuilder};

/// Appends the time-range/scope/filter predicates for the seat-grain query.
///
/// `scope=user` matches `ss.provider_user_id = $scope_id` — self-ownership via the JWT subject.
/// Unlike day facts, `provider_user_id` is `NOT NULL` on the seat table, so `scope=user` always
/// matches real rows (there is no org/repo-level NULL-identity case to exclude). `scope=all` adds
/// no entity filter. The `account`/`project`/`api_key` arms are rejected with `400` at the handler
/// before this is ever called, but are fail-closed here (`AND false`) so a future caller that
/// bypasses the gate can never widen the query.
///
/// `snapshot_day` is a `DATE` column, so the request's `DateTime<Utc>` bounds are converted to
/// `NaiveDate` for the half-open `[start, end)` range.
pub(super) fn push_seat_scope_filters(
    builder: &mut QueryBuilder<Postgres>,
    input: &SeatSnapshotQueryRequest,
) {
    builder.push("ss.snapshot_day >= ");
    builder.push_bind(input.start_time.date_naive());
    builder.push(" AND ss.snapshot_day < ");
    builder.push_bind(input.end_time.date_naive());

    match input.scope {
        UsageScope::User => {
            builder.push(" AND ss.provider_user_id = ");
            builder.push_bind(&input.scope_id);
        }
        UsageScope::All => {}
        _ => {
            builder.push(" AND false");
        }
    }

    if let Some(source) = &input.filters.source {
        builder.push(" AND ss.source = ");
        builder.push_bind(source);
    }
    if let Some(subject_kind) = &input.filters.subject_kind {
        builder.push(" AND ss.subject_kind = ");
        builder.push_bind(subject_kind.as_str());
    }
    if let Some(seat_state) = &input.filters.seat_state {
        builder.push(" AND ss.seat_state = ");
        builder.push_bind(seat_state);
    }
    if let Some(assignee_team) = &input.filters.assignee_team {
        builder.push(" AND ss.assignee_team = ");
        builder.push_bind(assignee_team);
    }
    if let Some(plan_type) = &input.filters.plan_type {
        builder.push(" AND ss.plan_type = ");
        builder.push_bind(plan_type);
    }
}
