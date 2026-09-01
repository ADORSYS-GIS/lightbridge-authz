use crate::models::{UsageGroupBy, UsageQueryRequest, UsageScope, UsageSeriesPoint};
use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::{Error, Result};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, QueryBuilder};
use std::collections::HashSet;
use std::sync::{Arc, LazyLock};
use tracing::{debug, instrument};

#[derive(Debug, Clone)]
pub struct UsageEvent {
    pub observed_at: DateTime<Utc>,
    pub signal_type: String,
    pub account_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub model: Option<String>,
    pub metric_name: Option<String>,
    pub usage_value: f64,
    pub request_count: i64,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub total_cost: Option<f64>,
    /// Wall-clock duration of the single request this event describes, in milliseconds.
    ///
    /// `None` is a first-class, honest outcome, not a failure: it means this signal genuinely
    /// carries no per-request duration. Aggregate metric points (histogram / exponential-histogram
    /// / summary) are the standing example -- a bucketed distribution is not one observation, and
    /// synthesising `sum / count` into this column would feed a fabricated value into
    /// `percentile_cont`. Query results surface that as `latency_samples == 0` for the affected
    /// series rather than as a zero.
    pub latency_ms: Option<f64>,
    pub attributes: Value,
}

#[derive(Debug, Clone)]
pub struct StoreRepo {
    pool: Arc<dyn DbPoolTrait>,
}

#[derive(Debug, FromRow)]
struct UsageQueryRow {
    bucket_start: DateTime<Utc>,
    account_id: Option<String>,
    project_id: Option<String>,
    api_key_id: Option<String>,
    user_id: Option<String>,
    user_name: Option<String>,
    model: Option<String>,
    metric_name: Option<String>,
    signal_type: Option<String>,
    requests: Option<i64>,
    usage_value: Option<f64>,
    prompt_tokens: Option<i64>,
    completion_tokens: Option<i64>,
    total_tokens: Option<i64>,
    total_cost: Option<f64>,
    latency_samples: Option<i64>,
    latency_p50_ms: Option<f64>,
    latency_p95_ms: Option<f64>,
    latency_p99_ms: Option<f64>,
}

impl StoreRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    #[instrument(skip(self))]
    pub async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize> {
        debug!("inserting {} usage events", events.len());
        if events.is_empty() {
            return Ok(0);
        }

        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO usage_events (observed_at, signal_type, account_id, project_id, api_key_id, user_id, user_name, model, metric_name, usage_value, request_count, prompt_tokens, completion_tokens, total_tokens, total_cost, latency_ms, attributes) ",
        );

        builder.push_values(events, |mut row, event| {
            debug!("inserting event {:?}", event);
            row.push_bind(event.observed_at)
                .push_bind(&event.signal_type)
                .push_bind(&event.account_id)
                .push_bind(&event.project_id)
                .push_bind(&event.api_key_id)
                .push_bind(&event.user_id)
                .push_bind(&event.user_name)
                .push_bind(&event.model)
                .push_bind(&event.metric_name)
                .push_bind(event.usage_value)
                .push_bind(event.request_count)
                .push_bind(event.prompt_tokens)
                .push_bind(event.completion_tokens)
                .push_bind(event.total_tokens)
                .push_bind(event.total_cost.unwrap_or(0.0))
                .push_bind(event.latency_ms)
                .push_bind(&event.attributes);
        });

        let result = builder.build().execute(self.pool()).await?;
        usize::try_from(result.rows_affected())
            .map_err(|_| Error::Database("rows_affected overflowed usize".to_string()))
    }

    /// Sums `usage_events.total_cost` for one account over a half-open `[start, end)` interval.
    /// This is the exact query `lightbridge-authz-budget`'s (now-removed) `TimescaleSpendReader`
    /// ran directly against this same table before the spend-query dependency was inverted onto
    /// this HTTP endpoint -- see `crates/lightbridge-authz-budget/src/spend.rs`. `None` means SQL
    /// `SUM` over zero matching rows (`NULL`), never collapsed to `0.0` here: that distinction is
    /// load-bearing for the budget domain's `Spend::Known`/`Spend::Unavailable` split.
    #[instrument(skip(self))]
    pub async fn spend_for_account(
        &self,
        account_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Option<f64>> {
        debug!(
            "querying spend for account_id={} start={} end={}",
            account_id, start, end
        );
        let total_cost: Option<f64> = sqlx::query_scalar::<_, Option<f64>>(
            "SELECT SUM(total_cost)::double precision FROM usage_events \
             WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3",
        )
        .bind(account_id)
        .bind(start)
        .bind(end)
        .fetch_one(self.pool())
        .await?;

        Ok(total_cost)
    }

    /// Returns up to `input.limit` WHOLE buckets plus whether more existed (#578). `truncated` is
    /// derived from the count of DISTINCT `bucket_start` values that matched, never from row
    /// count -- see this method's own doc comment below for why that distinction is load-bearing
    /// whenever `group_by` is non-empty. `Vec<UsageSeriesPoint>` comes back in the same
    /// ascending-`bucket_start` order this method has always returned.
    ///
    /// ## #578 (and its own bucket-scoping correction): truncation is BUCKET-scoped, not row-scoped
    ///
    /// The query used to `ORDER BY bucket_start ASC LIMIT $n` directly -- for a series with more
    /// than `$n` buckets, an ascending sort followed by `LIMIT` keeps the buckets from the START
    /// of the time range and silently drops everything after, which is backwards for a
    /// monitoring/dashboard query: a caller hitting the limit lost their most RECENT data while
    /// keeping the oldest.
    ///
    /// The first fix for this applied `LIMIT` to ROWS, not distinct buckets -- correct only when
    /// `group_by` is empty (one row per bucket). With a non-empty `group_by` (one row per
    /// `(bucket, series)` pair), that is wrong in three independent ways: (1) `LIMIT`ing rows
    /// counts each bucket once per series, so N series x M buckets can trip `truncated: true` at
    /// a row count that is really only M whole buckets -- spurious truncation; (2) the boundary
    /// bucket -- whichever one lands astride the row-count cutoff -- gets an ARBITRARY SUBSET of
    /// its series while every OTHER bucket keeps its full set, presented as an ordinary point with
    /// no signal that its per-series sums are understated relative to its siblings -- exactly the
    /// silent-undercount dishonesty this whole epic exists to eliminate; (3) with no deterministic
    /// tiebreaker on which rows survive at that cutoff, WHICH series got dropped from the boundary
    /// bucket was nondeterministic across otherwise-identical runs.
    ///
    /// The actual fix: two queries, both scoped to distinct `bucket_start` values, never to rows.
    /// [`Self::select_kept_buckets`] runs first and returns the newest `limit + 1` DISTINCT
    /// `bucket_start` values (fetching one extra is what turns "were there more buckets" into an
    /// observable fact); this method drops the single oldest one when more than `limit` came back
    /// (`truncated: true`), then runs the full grouped aggregation FILTERED to exactly the kept
    /// `bucket_start` values (`= ANY($kept_buckets)`) -- every bucket in the result set is
    /// therefore either fully present (every series that has any row in it) or fully absent, never
    /// partially present. The aggregation query's `ORDER BY` also names every dimension column
    /// (grouped or constant-`NULL`) as an explicit tiebreaker after `bucket_start`, so which row
    /// comes first within a bucket is deterministic run to run, not an artifact of Postgres' free
    /// choice among ties.
    ///
    /// Known caveat (#586): a bucket that straddles the truncation boundary is dropped or kept as
    /// a whole bucket, not split -- this fix does not attempt partial-bucket truncation, only
    /// which whole buckets survive.
    #[instrument(skip(self))]
    pub async fn query_usage(
        &self,
        input: &UsageQueryRequest,
    ) -> Result<(Vec<UsageSeriesPoint>, bool)> {
        debug!(
            "querying usage with scope={:?}, scope_id={}, bucket={}, limit={}",
            input.scope, input.scope_id, input.bucket, input.limit
        );
        validate_bucket_interval(&input.bucket)?;

        let (kept_buckets, truncated) = self.select_kept_buckets(input).await?;
        if kept_buckets.is_empty() {
            return Ok((Vec::new(), truncated));
        }

        let mut group_set = HashSet::new();
        for group in &input.group_by {
            group_set.insert(group.clone());
        }

        let mut builder = QueryBuilder::<Postgres>::new("SELECT date_bin(CAST(");
        builder.push_bind(&input.bucket).push(
            " AS interval), observed_at, TIMESTAMPTZ '1970-01-01 00:00:00+00') AS bucket_start",
        );

        let mut grouped_columns: Vec<&'static str> = Vec::new();
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::AccountId,
            "account_id",
        );
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::ProjectId,
            "project_id",
        );
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::ApiKeyId,
            "api_key_id",
        );
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::UserId,
            "user_id",
        );
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::UserName,
            "user_name",
        );
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::Model,
            "model",
        );
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::MetricName,
            "metric_name",
        );
        append_dimension(
            &mut builder,
            &mut grouped_columns,
            &group_set,
            UsageGroupBy::SignalType,
            "signal_type",
        );

        builder.push(", SUM(request_count)::bigint AS requests");
        builder.push(", SUM(usage_value)::double precision AS usage_value");
        builder.push(", SUM(prompt_tokens)::bigint AS prompt_tokens");
        builder.push(", SUM(completion_tokens)::bigint AS completion_tokens");
        builder.push(", SUM(total_tokens)::bigint AS total_tokens");
        builder.push(", SUM(total_cost)::double precision AS total_cost");
        builder.push(", COUNT(latency_ms)::bigint AS latency_samples");
        builder.push(
            ", percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms)::double precision AS latency_p50_ms",
        );
        builder.push(
            ", percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::double precision AS latency_p95_ms",
        );
        builder.push(
            ", percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms)::double precision AS latency_p99_ms",
        );

        builder.push(" FROM usage_events WHERE ");
        push_scope_filters(&mut builder, input);

        // Bucket-scoped limit (#578 correction): restrict to exactly the buckets
        // `select_kept_buckets` chose, so a bucket is either fully represented (every series with
        // any matching row) or fully absent -- never a partial row subset.
        builder.push(" AND date_bin(CAST(");
        builder
            .push_bind(&input.bucket)
            .push(" AS interval), observed_at, TIMESTAMPTZ '1970-01-01 00:00:00+00') = ANY(");
        builder.push_bind(kept_buckets);
        builder.push(")");

        builder.push(" GROUP BY bucket_start");
        for col in grouped_columns {
            builder.push(", ");
            builder.push(col);
        }

        // Deterministic tiebreaker: every dimension column, grouped or not (an ungrouped column is
        // a `NULL` constant across every row, so ordering by it is free and changes nothing when
        // it isn't grouped -- but it means the ORDER BY clause's shape never depends on `group_by`
        // and a grouped dimension always gets a real, stable sort key).
        builder.push(
            " ORDER BY bucket_start ASC, account_id, project_id, api_key_id, user_id, user_name, model, metric_name, signal_type",
        );

        let rows: Vec<UsageQueryRow> = builder.build_query_as().fetch_all(self.pool()).await?;

        let points = rows
            .into_iter()
            .map(|row| UsageSeriesPoint {
                bucket_start: row.bucket_start,
                account_id: row.account_id,
                project_id: row.project_id,
                api_key_id: row.api_key_id,
                user_id: row.user_id,
                user_name: row.user_name,
                model: row.model,
                metric_name: row.metric_name,
                signal_type: row.signal_type,
                requests: row.requests.unwrap_or(0),
                usage_value: row.usage_value.unwrap_or(0.0),
                total_cost: row.total_cost.unwrap_or(0.0),
                prompt_tokens: row.prompt_tokens.unwrap_or(0),
                completion_tokens: row.completion_tokens.unwrap_or(0),
                total_tokens: row.total_tokens.unwrap_or(0),
                latency_samples: row.latency_samples.unwrap_or(0),
                latency_p50_ms: row.latency_p50_ms,
                latency_p95_ms: row.latency_p95_ms,
                latency_p99_ms: row.latency_p99_ms,
            })
            .collect();

        Ok((points, truncated))
    }

    /// The bucket-scoped half of #578's fix: returns the newest `input.limit` DISTINCT
    /// `bucket_start` values matching `input`'s time range/scope/filters (ascending order, ready
    /// to bind straight into the aggregation query's `= ANY(...)`), plus whether more than
    /// `input.limit` distinct buckets existed at all. Deliberately ignores `group_by` entirely --
    /// this is a `SELECT DISTINCT` over `bucket_start` alone, which is what makes the resulting
    /// `truncated` flag and kept-bucket set BUCKET-scoped rather than row-scoped (see
    /// `query_usage`'s own doc comment for the failure mode this replaces).
    async fn select_kept_buckets(
        &self,
        input: &UsageQueryRequest,
    ) -> Result<(Vec<DateTime<Utc>>, bool)> {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT DISTINCT date_bin(CAST(");
        builder.push_bind(&input.bucket).push(
            " AS interval), observed_at, TIMESTAMPTZ '1970-01-01 00:00:00+00') AS bucket_start FROM usage_events WHERE ",
        );
        push_scope_filters(&mut builder, input);

        let fetch_limit = i64::from(input.limit).saturating_add(1);
        builder.push(" ORDER BY bucket_start DESC LIMIT ");
        builder.push_bind(fetch_limit);

        let mut buckets: Vec<(DateTime<Utc>,)> =
            builder.build_query_as().fetch_all(self.pool()).await?;

        let limit = input.limit as usize;
        let truncated = buckets.len() > limit;
        if truncated {
            // DESC order means the single extra bucket (there can be at most one, since the
            // query's own LIMIT caps `buckets.len()` at `limit + 1`) is the OLDEST -- drop it.
            buckets.truncate(limit);
        }

        let mut kept: Vec<DateTime<Utc>> = buckets.into_iter().map(|(b,)| b).collect();
        kept.reverse(); // ascending, matching this method's own doc comment.

        Ok((kept, truncated))
    }
}

/// Appends the shared time-range/scope/filter predicates both `StoreRepo::query_usage`'s
/// aggregation query and `StoreRepo::select_kept_buckets`'s bucket-selection query need --
/// duplicated across the two queries rather than run once and reused, since they answer two
/// different questions (which buckets exist vs. what do they sum to) that must stay
/// bit-for-bit consistent with each other or `truncated`/the kept-bucket filter could silently
/// drift from what the aggregation actually returns.
fn push_scope_filters(builder: &mut QueryBuilder<Postgres>, input: &UsageQueryRequest) {
    builder.push("observed_at >= ");
    builder.push_bind(input.start_time);
    builder.push(" AND observed_at < ");
    builder.push_bind(input.end_time);

    match input.scope {
        UsageScope::User => {
            builder.push(" AND user_id = ");
            builder.push_bind(&input.scope_id);
        }
        UsageScope::ApiKey => {
            builder.push(" AND api_key_id = ");
            builder.push_bind(&input.scope_id);
        }
        UsageScope::Project => {
            builder.push(" AND project_id = ");
            builder.push_bind(&input.scope_id);
        }
        UsageScope::Account => {
            builder.push(" AND account_id = ");
            builder.push_bind(&input.scope_id);
        }
        // Estate-wide: deliberately no entity filter at all -- this is the one arm of this match
        // that adds nothing to the `WHERE` clause beyond the time range already pushed above.
        // Authorization for this scope is enforced entirely in
        // `handlers::query::query_usage` (requires `Permission::UsageReadAll`) before this
        // function is ever called; by the time a query reaches this repo, `scope=all` is already
        // known-authorized.
        UsageScope::All => {}
    }

    if let Some(account_id) = &input.filters.account_id {
        builder.push(" AND account_id = ");
        builder.push_bind(account_id);
    }
    if let Some(project_id) = &input.filters.project_id {
        builder.push(" AND project_id = ");
        builder.push_bind(project_id);
    }
    if let Some(api_key_id) = &input.filters.api_key_id {
        builder.push(" AND api_key_id = ");
        builder.push_bind(api_key_id);
    }
    if let Some(user_id) = &input.filters.user_id {
        builder.push(" AND user_id = ");
        builder.push_bind(user_id);
    }
    if let Some(user_name) = &input.filters.user_name {
        builder.push(" AND user_name = ");
        builder.push_bind(user_name);
    }
    if let Some(model) = &input.filters.model {
        builder.push(" AND model = ");
        builder.push_bind(model);
    }
    if let Some(metric_name) = &input.filters.metric_name {
        builder.push(" AND metric_name = ");
        builder.push_bind(metric_name);
    }
    if let Some(signal_type) = &input.filters.signal_type {
        builder.push(" AND signal_type = ");
        builder.push_bind(signal_type);
    }
}

fn append_dimension(
    builder: &mut QueryBuilder<Postgres>,
    grouped_columns: &mut Vec<&'static str>,
    group_set: &HashSet<UsageGroupBy>,
    group_key: UsageGroupBy,
    column: &'static str,
) {
    if group_set.contains(&group_key) {
        builder.push(", ");
        builder.push(column);
        grouped_columns.push(column);
    } else {
        builder.push(", NULL::text AS ");
        builder.push(column);
    }
}

fn validate_bucket_interval(bucket: &str) -> Result<()> {
    static BUCKET_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\d+\s+(second|seconds|minute|minutes|hour|hours|day|days)$")
            .expect("bucket regex should be valid")
    });

    if BUCKET_RE.is_match(bucket.trim()) {
        Ok(())
    } else {
        Err(Error::BadRequest(
            "bucket must look like `5 minutes`, `1 hour`, or `1 day`".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bucket_interval_accepts_supported_units() {
        assert!(validate_bucket_interval("1 minute").is_ok());
        assert!(validate_bucket_interval("15 minutes").is_ok());
        assert!(validate_bucket_interval("2 hours").is_ok());
        assert!(validate_bucket_interval("1 day").is_ok());
    }

    #[test]
    fn validate_bucket_interval_rejects_unexpected_values() {
        assert!(validate_bucket_interval("hour").is_err());
        assert!(validate_bucket_interval("1month").is_err());
        assert!(validate_bucket_interval("1 week").is_err());
    }
}
