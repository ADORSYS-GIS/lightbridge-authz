//! Day-facts grain query builder and repository method (#727): aggregates `usage_day_facts` into
//! time buckets, with bucket-scoped truncation (the #578 `dense_rank()` pattern) and the shared
//! ownership gate's `scope=user`/`scope=all` filter.

use crate::models::day_fact::{DayFactGroupBy, DayFactQueryRequest, DayFactSeriesPoint};
use crate::repo::StoreRepo;
use chrono::{DateTime, Utc};
use lightbridge_authz_core::Result;
use sqlx::{FromRow, Postgres, QueryBuilder};
use std::collections::HashSet;
use tracing::{debug, instrument};

#[derive(Debug, FromRow)]
struct DayFactQueryRow {
    bucket_start: DateTime<Utc>,
    source: Option<String>,
    subject_kind: Option<String>,
    subject_id: Option<String>,
    is_aggregate_only: bool,
    total_suggestions: Option<i64>,
    total_acceptances: Option<i64>,
    total_lines_suggested: Option<i64>,
    total_lines_accepted: Option<i64>,
    total_active_users: Option<i64>,
    cost_micro_usd: Option<i64>,
    /// Whole-result-set fact, not a per-row one: `true` when more DISTINCT `bucket_start` values
    /// matched than `input.limit` allowed and the oldest were dropped whole. Computed once by a
    /// window function over the distinct bucket list and repeated on every row.
    truncated: bool,
}

impl StoreRepo {
    /// Returns up to `input.limit` WHOLE buckets of the day grain plus whether more existed
    /// (#578). `truncated` is derived from the count of DISTINCT `bucket_start` values, never from
    /// row count. `Vec<DayFactSeriesPoint>` comes back in ascending `bucket_start` order.
    // `skip_all`: `input` carries `scope_id` and the whole `filters` set. `handlers::day_fact::
    // query_day_facts` already refuses to put those in ITS span for exactly that reason, and this
    // span re-adding them would have undone that.
    #[instrument(skip_all)]
    pub async fn query_day_facts(
        &self,
        input: &DayFactQueryRequest,
    ) -> Result<(Vec<DayFactSeriesPoint>, bool)> {
        debug!(
            "querying day facts with scope={:?}, scope_id={}, bucket={}, limit={}",
            input.scope, input.scope_id, input.bucket, input.limit
        );
        super::bucket::validate_bucket_interval(&input.bucket)?;

        let mut builder = build_day_fact_query(input);
        let rows: Vec<DayFactQueryRow> = builder.build_query_as().fetch_all(self.pool()).await?;

        let truncated = rows.first().is_some_and(|row| row.truncated);

        let points = rows
            .into_iter()
            .map(|row| DayFactSeriesPoint {
                bucket_start: row.bucket_start,
                source: row.source,
                subject_kind: row.subject_kind,
                subject_id: row.subject_id,
                is_aggregate_only: row.is_aggregate_only,
                total_suggestions: row.total_suggestions,
                total_acceptances: row.total_acceptances,
                total_lines_suggested: row.total_lines_suggested,
                total_lines_accepted: row.total_lines_accepted,
                total_active_users: row.total_active_users,
                cost_micro_usd: row.cost_micro_usd,
            })
            .collect();

        Ok((points, truncated))
    }
}

/// Builds the single statement [`StoreRepo::query_day_facts`] runs: the grouped aggregation, the
/// bucket-scoped truncation, and the `truncated` flag, in one pass over `usage_day_facts`.
///
/// Mirrors `build_execution_query`'s nested-subquery + `dense_rank()` shape (one `FROM
/// usage_day_facts`, bucket-scoped, newest-kept). `day` is a `DATE` column, so it is cast to
/// `timestamptz` for `date_bin` bucketing via `(df.day::timestamp AT TIME ZONE 'UTC')` -- the
/// explicit `AT TIME ZONE 'UTC'` pins the cast so it does not depend on the database session's
/// `TimeZone` (the same class `retention.rs` already fixed).
///
/// `is_aggregate_only` is ALWAYS a group key (see the inline comment): aggregate-only rows and
/// per-entity rows are overlapping populations and must never be summed into one bucket.
fn build_day_fact_query(input: &DayFactQueryRequest) -> QueryBuilder<Postgres> {
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
    if group_set.contains(&DayFactGroupBy::SubjectKind) {
        builder.push(", df.subject_kind");
    } else {
        builder.push(", NULL::text AS subject_kind");
    }
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

    builder.push(", SUM(df.total_suggestions_count)::bigint AS total_suggestions");
    builder.push(", SUM(df.total_acceptances_count)::bigint AS total_acceptances");
    builder.push(", SUM(df.total_lines_suggested)::bigint AS total_lines_suggested");
    builder.push(", SUM(df.total_lines_accepted)::bigint AS total_lines_accepted");
    // `total_active_users` is a per-day DISTINCT count, not additive: summing it across a
    // multi-day bucket would multiply it by the number of days. MAX reports the peak daily active
    // users in the bucket -- the honest, bounded reading of a distinct count we cannot re-derive
    // from daily aggregates.
    builder.push(", MAX(df.total_active_users)::bigint AS total_active_users");
    builder.push(", SUM(df.cost_micro_usd)::bigint AS cost_micro_usd");

    builder.push(" FROM usage_day_facts df WHERE ");
    super::day_fact_filters::push_day_fact_scope_filters(&mut builder, input);

    builder.push(" GROUP BY bucket_start");
    if group_set.contains(&DayFactGroupBy::Source) {
        builder.push(", df.source");
    }
    if group_set.contains(&DayFactGroupBy::SubjectKind) {
        builder.push(", df.subject_kind");
    }
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
