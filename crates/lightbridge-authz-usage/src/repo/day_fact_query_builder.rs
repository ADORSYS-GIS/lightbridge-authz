//! The day-facts KPI query builder (#587).
//!
//! Split out of `day_fact_query.rs` by the LoC gate: this module owns the single SQL statement
//! `StoreRepo::query_day_facts` runs, including the #587 routing between the KPI aggregates and the
//! raw `usage_day_facts` grain table.

use crate::models::day_fact::{DayFactGroupBy, DayFactQueryRequest};
use sqlx::{Postgres, QueryBuilder};
use std::collections::HashSet;

use super::day_fact_filters;

/// Builds the single statement [`super::day_fact_query::StoreRepo::query_day_facts`] runs: the
/// grouped aggregation, the bucket-scoped truncation, and the `truncated` flag, in one pass over
/// the day grain.
///
/// Mirrors `build_execution_query`'s nested-subquery + `dense_rank()` shape (one `FROM`, bucket-
/// scoped, newest-kept). `day` is a `DATE` column, so it is cast to `timestamptz` for `date_bin`
/// bucketing via `(df.day::timestamp AT TIME ZONE 'UTC')` -- the explicit `AT TIME ZONE 'UTC'`
/// pins the cast so it does not depend on the database session's `TimeZone` (the same class
/// `retention.rs` already fixed).
///
/// When `use_aggregate` is true the query reads the #587 KPI aggregates
/// (`mv_day_facts_acceptances_daily` FULL OUTER JOIN `mv_day_facts_active_users_daily` FULL OUTER
/// JOIN `mv_day_facts_spend_daily`, all on the `usage_day_facts` grain -- a same-grain join, which
/// the "no aggregate spans grains" rule allows). Each aggregate carries the full dimension set and
/// its pre-computed measures, so the join is 1:1 on the natural key and the routing is semantically
/// equivalent to reading `usage_day_facts` raw. The join is FULL OUTER (not INNER) because the
/// three views are refreshed independently and can hold different key sets at any instant -- an
/// INNER join would silently drop a row present in one view but missing from another. Otherwise it
/// reads the raw table and computes the measures.
///
/// `subject_kind` and `is_aggregate_only` are ALWAYS group keys (see the inline comments):
/// `usage_day_facts` holds overlapping populations at different hierarchy levels (an org row is
/// the aggregate over its member repo/user rows), so rows at different `subject_kind` levels or
/// with different `is_aggregate_only` flags must never be summed into one bucket.
pub(super) fn build_day_fact_query(
    input: &DayFactQueryRequest,
    use_aggregate: bool,
) -> QueryBuilder<Postgres> {
    let group_set: HashSet<DayFactGroupBy> = input.group_by.iter().cloned().collect();
    let limit = i64::from(input.limit);

    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT counted.bucket_start, counted.source, counted.subject_kind, counted.subject_id, counted.is_aggregate_only, counted.total_suggestions, counted.total_acceptances, counted.total_lines_suggested, counted.total_lines_accepted, counted.total_active_users, counted.cost_micro_usd, counted.bucket_count > ",
    );
    builder.push_bind(limit);
    builder.push(
        " AS truncated FROM (SELECT ranked.*, max(ranked.bucket_rank) OVER () AS bucket_count FROM (SELECT agg.*, dense_rank() OVER (ORDER BY agg.bucket_start DESC) AS bucket_rank FROM (SELECT date_bin(CAST(",
    );
    builder.push_bind(&input.bucket).push(
        " AS interval), (df.day::timestamp AT TIME ZONE 'UTC'), TIMESTAMPTZ '1970-01-01 00:00:00+00') AS bucket_start",
    );

    if group_set.contains(&DayFactGroupBy::Source) {
        builder.push(", df.source");
    } else {
        builder.push(", NULL::text AS source");
    }
    // `subject_kind` is ALWAYS a group key, not a conditional dimension: the CHECK vocabulary is
    // org/user/repo/user_team, and repo- and team-level rows are aggregate-only rollups that
    // overlap their parent org's total (the same 5-seat-floor API shape as the org row itself).
    // Summing an org row with its member repo rows would double-count the org's own total, one
    // `subject_kind` layer over the org/user case. Partitioning by `subject_kind` keeps each
    // hierarchy level in its own point, so the default (no filter, no group_by) never silently
    // adds overlapping populations together.
    builder.push(", df.subject_kind");
    if group_set.contains(&DayFactGroupBy::SubjectId) {
        builder.push(", df.subject_id");
    } else {
        builder.push(", NULL::text AS subject_id");
    }
    // `is_aggregate_only` is ALWAYS a group key, not a conditional dimension: an org-level
    // aggregate row and the per-user rows it aggregates are overlapping populations (the org row
    // IS the sum over its members), so summing them into one bucket would double-count measures
    // and cost. Partitioning by the flag keeps aggregate-only rows and per-entity rows in separate
    // points, so the default (no filter, no group_by) never silently adds them together.
    builder.push(", df.is_aggregate_only");

    if use_aggregate {
        // The aggregates already carry the pre-computed measures per (day, dims); summing/maxing
        // them across the bucket's days and any ungrouped dimensions reproduces the raw result.
        builder.push(", SUM(df.suggestions)::bigint AS total_suggestions");
        builder.push(", SUM(df.acceptances)::bigint AS total_acceptances");
        builder.push(", SUM(df.lines_suggested)::bigint AS total_lines_suggested");
        builder.push(", SUM(df.lines_accepted)::bigint AS total_lines_accepted");
        builder.push(", MAX(df.active_users)::bigint AS total_active_users");
        builder.push(", SUM(df.cost_micro_usd)::bigint AS cost_micro_usd");
    } else {
        builder.push(", SUM(df.total_suggestions_count)::bigint AS total_suggestions");
        builder.push(", SUM(df.total_acceptances_count)::bigint AS total_acceptances");
        builder.push(", SUM(df.total_lines_suggested)::bigint AS total_lines_suggested");
        builder.push(", SUM(df.total_lines_accepted)::bigint AS total_lines_accepted");
        // `total_active_users` is a per-day DISTINCT count, not additive: summing it across a
        // multi-day bucket would multiply it by the number of days. MAX reports the peak daily
        // active users in the bucket -- the honest, bounded reading of a distinct count we cannot
        // re-derive from daily aggregates.
        builder.push(", MAX(df.total_active_users)::bigint AS total_active_users");
        builder.push(", SUM(df.cost_micro_usd)::bigint AS cost_micro_usd");
    }

    if use_aggregate {
        // FULL OUTER JOIN, not INNER JOIN: the three per-measure aggregates are refreshed by
        // `refresh_all_aggregates` as SEPARATE `REFRESH MATERIALIZED VIEW CONCURRENTLY` statements
        // (aggregate_refresh.rs), so at any instant they can hold DIFFERENT key sets -- a row
        // ingested between two refreshes, or one view's refresh failing while the others succeed.
        // An INNER JOIN would silently drop any (day, dims) row present in one view but missing
        // from another, losing that row's suggestions/acceptances/lines/cost with no error and no
        // `truncated` flag. FULL OUTER JOIN keeps every row from every view: the dimension columns
        // are COALESCEd to one merged value, and a measure is NULL exactly when its owning view
        // lacks the row (SUM/MAX ignore NULLs, matching the raw path). Each view is unique on the
        // natural key, so the join is at most 1:1 -- no row is multiplied.
        builder.push(
            " FROM (SELECT COALESCE(a.day, u.day, s.day) AS day, \
                    COALESCE(a.source, u.source, s.source) AS source, \
                    COALESCE(a.subject_kind, u.subject_kind, s.subject_kind) AS subject_kind, \
                    COALESCE(a.subject_id, u.subject_id, s.subject_id) AS subject_id, \
                    COALESCE(a.is_aggregate_only, u.is_aggregate_only, s.is_aggregate_only) AS is_aggregate_only, \
                    COALESCE(a.language, u.language, s.language) AS language, \
                    COALESCE(a.editor, u.editor, s.editor) AS editor, \
                    COALESCE(a.model, u.model, s.model) AS model, \
                    COALESCE(a.provider_user_id, u.provider_user_id, s.provider_user_id) AS provider_user_id, \
                    a.acceptances, a.suggestions, a.lines_suggested, a.lines_accepted, \
                    u.active_users, s.cost_micro_usd \
                    FROM mv_day_facts_acceptances_daily a \
                    FULL OUTER JOIN mv_day_facts_active_users_daily u \
                      ON a.day = u.day AND a.source = u.source AND a.subject_kind = u.subject_kind \
                     AND a.subject_id = u.subject_id AND a.is_aggregate_only = u.is_aggregate_only \
                     AND a.language IS NOT DISTINCT FROM u.language AND a.editor IS NOT DISTINCT FROM u.editor \
                     AND a.model IS NOT DISTINCT FROM u.model AND a.provider_user_id IS NOT DISTINCT FROM u.provider_user_id \
                    FULL OUTER JOIN mv_day_facts_spend_daily s \
                      ON COALESCE(a.day, u.day) = s.day AND COALESCE(a.source, u.source) = s.source \
                     AND COALESCE(a.subject_kind, u.subject_kind) = s.subject_kind \
                     AND COALESCE(a.subject_id, u.subject_id) = s.subject_id \
                     AND COALESCE(a.is_aggregate_only, u.is_aggregate_only) = s.is_aggregate_only \
                     AND COALESCE(a.language, u.language) IS NOT DISTINCT FROM s.language \
                     AND COALESCE(a.editor, u.editor) IS NOT DISTINCT FROM s.editor \
                     AND COALESCE(a.model, u.model) IS NOT DISTINCT FROM s.model \
                     AND COALESCE(a.provider_user_id, u.provider_user_id) IS NOT DISTINCT FROM s.provider_user_id) df WHERE ",
        );
    } else {
        builder.push(" FROM usage_day_facts df WHERE ");
    }
    day_fact_filters::push_day_fact_scope_filters(&mut builder, input);

    builder.push(" GROUP BY bucket_start");
    if group_set.contains(&DayFactGroupBy::Source) {
        builder.push(", df.source");
    }
    builder.push(", df.subject_kind");
    if group_set.contains(&DayFactGroupBy::SubjectId) {
        builder.push(", df.subject_id");
    }
    builder.push(", df.is_aggregate_only");

    builder.push(") agg) ranked) counted WHERE counted.bucket_rank <= ");
    builder.push_bind(limit);

    // Deterministic tiebreaker: every dimension column, grouped or not. An ungrouped one is a
    // constant `NULL` across every row, so ordering by it is free and changes nothing.
    builder.push(
        " ORDER BY counted.bucket_start ASC, counted.source, counted.subject_kind, counted.subject_id, counted.is_aggregate_only",
    );

    builder
}
