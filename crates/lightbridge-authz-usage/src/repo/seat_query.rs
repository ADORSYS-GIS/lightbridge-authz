//! Seat-grain query builder and repository method (#728): aggregates `usage_seat_snapshots` into
//! time buckets, with bucket-scoped truncation (the #578 `dense_rank()` pattern) and the shared
//! ownership gate's `scope=user`/`scope=all` filter.

use crate::models::seat::{SeatGroupBy, SeatSnapshotQueryRequest, SeatSnapshotSeriesPoint};
use crate::repo::StoreRepo;
use chrono::{DateTime, Utc};
use lightbridge_authz_core::Result;
use sqlx::{FromRow, Postgres, QueryBuilder};
use std::collections::HashSet;
use tracing::{debug, instrument};

#[derive(Debug, FromRow)]
struct SeatSnapshotQueryRow {
    bucket_start: DateTime<Utc>,
    source: Option<String>,
    subject_kind: Option<String>,
    subject_id: Option<String>,
    seat_state: Option<String>,
    seat_count: i64,
    active_count: i64,
    pending_cancellation_count: i64,
    /// Whole-result-set fact, not a per-row one: `true` when more DISTINCT `bucket_start` values
    /// matched than `input.limit` allowed and the oldest were dropped whole. Computed once by a
    /// window function over the distinct bucket list and repeated on every row.
    truncated: bool,
}

impl StoreRepo {
    /// Returns up to `input.limit` WHOLE buckets of the seat grain plus whether more existed
    /// (#578). `truncated` is derived from the count of DISTINCT `bucket_start` values, never from
    /// row count. `Vec<SeatSnapshotSeriesPoint>` comes back in ascending `bucket_start` order.
    // `skip_all`: `input` carries `scope_id` and the whole `filters` set. `handlers::seat::
    // query_seat_snapshots` already refuses to put those in ITS span for exactly that reason, and
    // this span re-adding them would have undone that.
    #[instrument(skip_all)]
    pub async fn query_seat_snapshots(
        &self,
        input: &SeatSnapshotQueryRequest,
    ) -> Result<(Vec<SeatSnapshotSeriesPoint>, bool)> {
        debug!(
            "querying seat snapshots with scope={:?}, scope_id={}, bucket={}, limit={}",
            input.scope, input.scope_id, input.bucket, input.limit
        );
        super::bucket::validate_bucket_interval(&input.bucket)?;
        // The seat grain is daily (`usage_seat_snapshots.snapshot_day` is a `DATE`); a sub-day
        // bucket would collapse every row into the midnight bucket -- degenerate and misleading.
        super::bucket::validate_day_grain_bucket(&input.bucket)?;

        // #587: route to the KPI aggregate when it exists, else fall back to the raw grain table.
        // The seat aggregate preserves every dimension the query can filter/group on and carries
        // the three pre-computed counts, so the routing is semantically equivalent at any bucket
        // granularity (seat data is daily; the aggregate is daily). The existence decision is
        // TTL-cached (`aggregate_views_available`) so it does not probe the DB on every request.
        let use_aggregate = self.aggregate_views_available().await?;
        let mut builder = build_seat_snapshot_query(input, use_aggregate);
        let rows: Vec<SeatSnapshotQueryRow> =
            builder.build_query_as().fetch_all(self.pool()).await?;

        let truncated = rows.first().is_some_and(|row| row.truncated);

        let points = rows
            .into_iter()
            .map(|row| SeatSnapshotSeriesPoint {
                bucket_start: row.bucket_start,
                source: row.source,
                subject_kind: row.subject_kind,
                subject_id: row.subject_id,
                seat_state: row.seat_state,
                seat_count: row.seat_count,
                active_count: row.active_count,
                pending_cancellation_count: row.pending_cancellation_count,
            })
            .collect();

        Ok((points, truncated))
    }
}

/// Builds the single statement [`StoreRepo::query_seat_snapshots`] runs: the grouped aggregation,
/// the bucket-scoped truncation, and the `truncated` flag, in one pass over the seat grain.
///
/// Mirrors `build_day_fact_query`'s nested-subquery + `dense_rank()` shape (one `FROM`, bucket-
/// scoped, newest-kept). `snapshot_day` is a `DATE` column, so it is cast to `timestamptz` for
/// `date_bin` bucketing -- pinned to UTC via `(snapshot_day::timestamp AT TIME ZONE 'UTC')` so the
/// bucket boundary is independent of the database session's `TimeZone` (the #733 review's P2 on the
/// day-facts grain, applied here too).
///
/// When `use_aggregate` is true the query reads the #587 KPI aggregate
/// `mv_seat_snapshots_active_daily` (which carries the same dimensions and the three pre-computed
/// counts, so the routing is semantically equivalent); otherwise it reads `usage_seat_snapshots`
/// raw and computes the counts. The three counts are seat-days, partition-disjoint and additive:
/// `active_count + pending_cancellation_count = seat_count`. "Active" is
/// `pending_cancellation_date IS NULL` -- never the opaque `seat_state` token (see
/// `SeatSnapshotSeriesPoint`'s doc comment).
fn build_seat_snapshot_query(
    input: &SeatSnapshotQueryRequest,
    use_aggregate: bool,
) -> QueryBuilder<Postgres> {
    let group_set: HashSet<SeatGroupBy> = input.group_by.iter().cloned().collect();
    let limit = i64::from(input.limit);

    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT counted.bucket_start, counted.source, counted.subject_kind, counted.subject_id, counted.seat_state, counted.seat_count, counted.active_count, counted.pending_cancellation_count, counted.bucket_count > ",
    );
    builder.push_bind(limit);
    builder.push(
        " AS truncated FROM (SELECT ranked.*, max(ranked.bucket_rank) OVER () AS bucket_count FROM (SELECT agg.*, dense_rank() OVER (ORDER BY agg.bucket_start DESC) AS bucket_rank FROM (SELECT date_bin(CAST(",
    );
    builder.push_bind(&input.bucket).push(
        " AS interval), (ss.snapshot_day::timestamp AT TIME ZONE 'UTC'), TIMESTAMPTZ '1970-01-01 00:00:00+00') AS bucket_start",
    );

    if group_set.contains(&SeatGroupBy::Source) {
        builder.push(", ss.source");
    } else {
        builder.push(", NULL::text AS source");
    }
    if group_set.contains(&SeatGroupBy::SubjectKind) {
        builder.push(", ss.subject_kind");
    } else {
        builder.push(", NULL::text AS subject_kind");
    }
    if group_set.contains(&SeatGroupBy::SubjectId) {
        builder.push(", ss.subject_id");
    } else {
        builder.push(", NULL::text AS subject_id");
    }
    if group_set.contains(&SeatGroupBy::SeatState) {
        builder.push(", ss.seat_state");
    } else {
        builder.push(", NULL::text AS seat_state");
    }

    if use_aggregate {
        // The aggregate already carries the three counts per (snapshot_day, dims); summing them
        // across the bucket's days and any ungrouped dimensions reproduces the raw COUNT(*) result.
        builder.push(", SUM(ss.seat_count)::bigint AS seat_count");
        builder.push(", SUM(ss.active_count)::bigint AS active_count");
        builder.push(", SUM(ss.pending_cancellation_count)::bigint AS pending_cancellation_count");
    } else {
        builder.push(", COUNT(*)::bigint AS seat_count");
        builder.push(
            ", COUNT(*) FILTER (WHERE ss.pending_cancellation_date IS NULL)::bigint AS active_count",
        );
        builder.push(", COUNT(*) FILTER (WHERE ss.pending_cancellation_date IS NOT NULL)::bigint AS pending_cancellation_count");
    }

    if use_aggregate {
        builder.push(" FROM mv_seat_snapshots_active_daily ss WHERE ");
    } else {
        builder.push(" FROM usage_seat_snapshots ss WHERE ");
    }
    super::seat_filters::push_seat_scope_filters(&mut builder, input);

    builder.push(" GROUP BY bucket_start");
    if group_set.contains(&SeatGroupBy::Source) {
        builder.push(", ss.source");
    }
    if group_set.contains(&SeatGroupBy::SubjectKind) {
        builder.push(", ss.subject_kind");
    }
    if group_set.contains(&SeatGroupBy::SubjectId) {
        builder.push(", ss.subject_id");
    }
    if group_set.contains(&SeatGroupBy::SeatState) {
        builder.push(", ss.seat_state");
    }

    builder.push(") agg) ranked) counted WHERE counted.bucket_rank <= ");
    builder.push_bind(limit);

    // Deterministic tiebreaker: every dimension column, grouped or not. An ungrouped one is a
    // constant `NULL` across every row, so ordering by it is free and changes nothing.
    builder.push(
        " ORDER BY counted.bucket_start ASC, counted.source, counted.subject_kind, counted.subject_id, counted.seat_state",
    );

    builder
}
