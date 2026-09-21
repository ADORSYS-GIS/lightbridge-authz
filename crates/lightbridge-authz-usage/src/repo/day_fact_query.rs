//! Day-facts grain query builder and repository method (#727): aggregates `usage_day_facts` into
//! time buckets, with bucket-scoped truncation (the #578 `dense_rank()` pattern) and the shared
//! ownership gate's `scope=user`/`scope=all` filter.

use crate::models::day_fact::{DayFactQueryRequest, DayFactSeriesPoint};
use crate::repo::StoreRepo;
use chrono::{DateTime, Utc};
use lightbridge_authz_core::Result;
use sqlx::FromRow;
use tracing::{debug, instrument, warn};

use super::day_fact_query_builder::build_day_fact_query;

#[derive(Debug, FromRow)]
struct DayFactQueryRow {
    bucket_start: DateTime<Utc>,
    source: Option<String>,
    subject_kind: String,
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
        // The day grain is daily (`usage_day_facts.day` is a `DATE`); a sub-day bucket would
        // collapse every row into the midnight bucket -- degenerate and misleading.
        super::bucket::validate_day_grain_bucket(&input.bucket)?;

        // #587: route to the KPI aggregates when they ALL exist, else fall back to the raw grain
        // table. The day-facts aggregates carry the full dimension set and pre-computed measures,
        // so the routing is semantically equivalent (see `build_day_fact_query`). ALL THREE must
        // exist: the aggregate path joins them, so a missing one would be a hard 500, not a
        // graceful degradation to the raw table.
        let use_aggregate = self
            .aggregates_exist(&[
                "mv_day_facts_acceptances_daily",
                "mv_day_facts_active_users_daily",
                "mv_day_facts_spend_daily",
            ])
            .await?;
        let mut builder = build_day_fact_query(input, use_aggregate);
        let rows: Vec<DayFactQueryRow> = builder.build_query_as().fetch_all(self.pool()).await?;

        let truncated = rows.first().is_some_and(|row| row.truncated);

        let points: Vec<DayFactSeriesPoint> = rows
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

        // #727 review: `scope=user` matches `provider_user_id = scope_id` on the assumption that
        // `provider_user_id` is written in the SAME namespace as the JWT subject. That assumption
        // is unverified (there is no day-facts ingest yet). A wrong namespace fails SAFE (returns
        // empty, never another tenant's data), but silently -- so surface it: an empty self-scope
        // result is exactly the symptom of a namespace mismatch, and an operator should see it.
        if matches!(input.scope, crate::models::UsageScope::User) && points.is_empty() {
            warn!(
                "scope=user day-facts query for subject {} returned no rows; if this subject has \
                 data, provider_user_id may not be written in the JWT-subject namespace (see \
                 day_fact_filters.rs)",
                input.scope_id
            );
        }

        Ok((points, truncated))
    }
}
