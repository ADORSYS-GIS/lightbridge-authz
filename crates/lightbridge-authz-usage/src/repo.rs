use crate::models::{UsageGroupBy, UsageQueryRequest, UsageScope, UsageSeriesPoint};
use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::{Error, Result};
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
    /// The OAuth client (`azp`) this request arrived on -- "which channel" (#648). Promoted out of
    /// the `attributes` blob so it can be grouped and filtered; `None` when the signal carried
    /// none of `AZP_KEYS`.
    pub azp: Option<String>,
    /// Which API surface was called, derived from the request path at ingest
    /// (`handlers::ingest::operation_from_path`) and drawn from the closed
    /// [`crate::models::USAGE_OPERATIONS`] vocabulary (#648). `None` means the signal carried no
    /// path key at all -- which is NOT `Some("other")`: "we do not know which surface" and "a
    /// surface we do not have a name for" are different facts.
    pub operation: Option<String>,
    /// The billing plan Authorino stamped on the request (#648). `None` when the signal carried
    /// none of `BILLING_PLAN_KEYS` -- unknown, never a default plan name.
    pub billing_plan: Option<String>,
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
    azp: Option<String>,
    operation: Option<String>,
    billing_plan: Option<String>,
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
    /// Whole-result-set fact, not a per-row one: `true` when more DISTINCT `bucket_start` values
    /// matched than `input.limit` allowed and the oldest were dropped whole. Computed once by a
    /// window function over the distinct bucket list and repeated on every row, which is what
    /// lets the whole thing be ONE round trip instead of two (see [`build_usage_query`]).
    truncated: bool,
}

impl StoreRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    // `skip_all` + an explicit count, for the same reason `handlers::ingest`'s handlers do it
    // (owner report, 2026-09-03): `#[instrument(skip(self))]` recorded the `events` ARGUMENT into
    // the span, and a `UsageEvent`'s `Debug` used to include its whole `attributes` blob -- so
    // every insert stamped the decoded contents of the export (account ids, user names, and
    // whatever else the exporter put in the attributes) into the trace span. The count is the
    // only part of that field anyone ever wanted. (`attributes` itself was dropped at ingest,
    // #549 AC1, but the `skip_all` stays: the argument is still a slice of caller-supplied
    // structs and its `Debug` is not something to echo into a span.)
    #[instrument(skip_all, fields(events = events.len()))]
    pub async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize> {
        debug!("inserting {} usage events", events.len());
        if events.is_empty() {
            return Ok(0);
        }

        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO usage_events (observed_at, signal_type, account_id, project_id, api_key_id, user_id, user_name, model, metric_name, azp, operation, billing_plan, usage_value, request_count, prompt_tokens, completion_tokens, total_tokens, total_cost, latency_ms) ",
        );

        builder.push_values(events, |mut row, event| {
            row.push_bind(event.observed_at)
                .push_bind(&event.signal_type)
                .push_bind(&event.account_id)
                .push_bind(&event.project_id)
                .push_bind(&event.api_key_id)
                .push_bind(&event.user_id)
                .push_bind(&event.user_name)
                .push_bind(&event.model)
                .push_bind(&event.metric_name)
                .push_bind(&event.azp)
                .push_bind(&event.operation)
                .push_bind(&event.billing_plan)
                .push_bind(event.usage_value)
                .push_bind(event.request_count)
                .push_bind(event.prompt_tokens)
                .push_bind(event.completion_tokens)
                .push_bind(event.total_tokens)
                .push_bind(event.total_cost.unwrap_or(0.0))
                .push_bind(event.latency_ms);
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
    ///
    /// ## Reads raw UNION ALL rollup (#549 AC2)
    ///
    /// Since the retention job rolls rows older than `raw_days` out of `usage_events` into
    /// `usage_events_daily`, a spend query must read both or it would silently under-count once
    /// data ages past the boundary. The two arms are `UNION ALL`ed and summed as one set, which
    /// preserves the exact `SUM`-over-NULL semantics: an empty combined set, or one where every
    /// `total_cost` is NULL, yields `None`; any non-NULL cost yields `Some(sum)`. The current
    /// billing period is always within the raw window, so for the queries budget actually issues
    /// the rollup arm is empty and the result is identical to the pre-rollup query (AC3).
    ///
    /// ## Day-granularity of the rollup arm
    ///
    /// The rollup arm matches on `bucket_start` (the truncated day), not `observed_at`, because a
    /// rolled-up day is stored as a single row keyed by its day boundary. A day is either entirely
    /// raw or entirely rolled up (only complete days are rolled up), so there is no double-count
    /// between the arms. The consequence is that a spend query whose `[start, end)` boundary falls
    /// MID-DAY on a day that has aged into the rollup is **day-granular**: the rollup row for that
    /// day is included only if its `bucket_start` is within `[start, end)`, so a sub-day slice of a
    /// rolled-up day is not answered exactly. This never manifests for budget's real queries --
    /// billing periods are month-aligned (day boundaries) and always within the raw window, so the
    /// rollup arm is empty -- but callers should treat spend over a rolled-up period as
    /// day-granular, not sub-day-exact.
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
            "SELECT SUM(total_cost)::double precision FROM ( \
                 SELECT total_cost FROM usage_events \
                 WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3 \
                 UNION ALL \
                 SELECT total_cost FROM usage_events_daily \
                 WHERE account_id = $1 AND bucket_start >= $2 AND bucket_start < $3 \
             ) AS spend_rows",
        )
        .bind(account_id)
        .bind(start)
        .bind(end)
        .bind(account_id)
        .bind(start)
        .bind(end)
        .fetch_one(self.pool())
        .await?;

        Ok(total_cost)
    }

    /// Returns up to `input.limit` WHOLE buckets plus whether more existed (#578). `truncated` is
    /// derived from the count of DISTINCT `bucket_start` values that matched, never from row
    /// count -- see below for why that distinction is load-bearing whenever `group_by` is
    /// non-empty. `Vec<UsageSeriesPoint>` comes back in ascending `bucket_start` order.
    ///
    /// ## #578: truncation is BUCKET-scoped, not row-scoped
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
    /// ## The bucket-scoped fix used to cost a SECOND full scan (owner report, 2026-09-03)
    ///
    /// #578 implemented the bucket scoping as TWO queries: a `SELECT DISTINCT date_bin(...) ...
    /// ORDER BY ... DESC LIMIT $n+1` to pick the surviving buckets, then the grouped aggregation
    /// filtered to `= ANY($kept_buckets)`. Both carried the SAME `WHERE` clause, so both scanned
    /// the same rows -- the estate-wide 30-day shape the console's overview page issues read the
    /// whole table twice. Worse, the first query's `DISTINCT ... ORDER BY ... LIMIT` shape makes
    /// Postgres pick `Sort -> Unique` rather than a hash aggregate, so it sorted every matching
    /// row (933,494 of them, spilling ~11 MB to disk at `work_mem = 4MB`) purely to learn that 21
    /// distinct days existed. Measured on production (`lightbridge-main-db`/`usage`, read-only
    /// replica, 2026-09-03): 2,993 ms for that first query alone.
    ///
    /// [`build_usage_query`] now does the whole thing in ONE statement: the aggregation runs once,
    /// and a `dense_rank()` window over its own output -- tens of rows, not a million -- does the
    /// bucket ranking. Semantics are unchanged: the DISTINCT `bucket_start` values of the
    /// aggregate are by construction exactly the DISTINCT `bucket_start` values of the matching
    /// rows, because `bucket_start` is always a `GROUP BY` key.
    ///
    /// This is not a free lunch on production TODAY, and the PR that made the change says so: the
    /// second scan was 2,993 ms of a 34,799 ms query, and the other 31,806 ms is raw heap I/O that
    /// only `migrations-usage/20260903000002_usage_event_query_covering_index.sql` addresses.
    ///
    /// Known caveat (#586): a bucket that straddles the truncation boundary is dropped or kept as
    /// a whole bucket, not split -- this does not attempt partial-bucket truncation, only which
    /// whole buckets survive.
    // `skip_all`: `input` carries `scope_id` and the whole `filters` set (user ids, api key ids,
    // user names). `handlers::query::query_usage` already refuses to put those in ITS span for
    // exactly that reason, and this span re-adding them would have undone that. The `debug!`
    // immediately below names the four fields that are actually useful for correlating a slow
    // query, and nothing else.
    #[instrument(skip_all)]
    pub async fn query_usage(
        &self,
        input: &UsageQueryRequest,
    ) -> Result<(Vec<UsageSeriesPoint>, bool)> {
        debug!(
            "querying usage with scope={:?}, scope_id={}, bucket={}, limit={}",
            input.scope, input.scope_id, input.bucket, input.limit
        );
        validate_bucket_interval(&input.bucket)?;

        let mut builder = build_usage_query(input);
        let rows: Vec<UsageQueryRow> = builder.build_query_as().fetch_all(self.pool()).await?;

        // Every surviving row carries the same `truncated` flag (it is a whole-result-set fact
        // computed by a window function over the distinct bucket list, not a per-row one), so the
        // first row speaks for all of them. No rows at all means no buckets matched, which is
        // never a truncation.
        let truncated = rows.first().is_some_and(|row| row.truncated);

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
                azp: row.azp,
                operation: row.operation,
                billing_plan: row.billing_plan,
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
}

/// Every dimension column `usage_events` can be grouped by, in the fixed order the `SELECT` list
/// and the `ORDER BY` tiebreaker both use. One list, so the two can never drift apart.
const DIMENSION_COLUMNS: [(UsageGroupBy, &str); 11] = [
    (UsageGroupBy::AccountId, "account_id"),
    (UsageGroupBy::ProjectId, "project_id"),
    (UsageGroupBy::ApiKeyId, "api_key_id"),
    (UsageGroupBy::UserId, "user_id"),
    (UsageGroupBy::UserName, "user_name"),
    (UsageGroupBy::Model, "model"),
    (UsageGroupBy::MetricName, "metric_name"),
    (UsageGroupBy::SignalType, "signal_type"),
    (UsageGroupBy::Azp, "azp"),
    (UsageGroupBy::Operation, "operation"),
    (UsageGroupBy::BillingPlan, "billing_plan"),
];

/// Builds the single statement [`StoreRepo::query_usage`] runs: the grouped aggregation, the
/// bucket-scoped truncation, and the `truncated` flag, in one pass over `usage_events`.
///
/// Extracted as a free function so the exact SQL this store emits can be asserted -- and
/// `EXPLAIN`ed -- without a database. A query-plan review is only as good as the query it
/// reviewed, and hand-transcribing a `QueryBuilder` into a test fixture is how the two silently
/// drift apart.
///
/// ## Shape
///
/// ```sql
/// SELECT <cols>, counted.bucket_count > $limit AS truncated
/// FROM (SELECT ranked.*, max(ranked.bucket_rank) OVER () AS bucket_count
///       FROM (SELECT agg.*, dense_rank() OVER (ORDER BY agg.bucket_start DESC) AS bucket_rank
///             FROM (SELECT date_bin(...) AS bucket_start, <dims>, <sums> [, <percentiles>]
///                   FROM usage_events WHERE <scope/time/filters>
///                   GROUP BY bucket_start<, dims>) agg) ranked) counted
/// WHERE counted.bucket_rank <= $limit
/// ORDER BY counted.bucket_start ASC, <dims>
/// ```
///
/// `dense_rank()` (not `row_number()`) is what makes truncation BUCKET-scoped rather than
/// row-scoped: every row sharing a `bucket_start` gets the same rank, so `bucket_rank <= $limit`
/// keeps or drops a bucket WHOLE -- every series that has any row in it, or none of them -- which
/// is the property #578 exists to guarantee. The window is `DESC`, so the buckets that survive
/// are the NEWEST ones and it is the oldest that get dropped. `max(bucket_rank) OVER ()` is the
/// total number of distinct buckets that matched, evaluated BEFORE the `WHERE` filters any away,
/// which is what makes `truncated` an honest "there were more" rather than a guess.
///
/// ## Why nested subqueries and not a `WITH` CTE
///
/// The obvious spelling is `WITH agg AS (...)` referenced twice. Measured back to back on a 2M-row
/// production-width fixture (estate-wide, 30 days, 1-day buckets) the two forms are
/// indistinguishable -- 652 ms / 279,627 buffers for the CTE against 669 ms / 279,627 buffers for
/// this one without the covering index, 237 ms against 228 ms with it -- so this is not a
/// performance claim.
///
/// It is a durability claim. The CTE form scans the base table once only because Postgres
/// MATERIALISES a CTE that is referenced more than once; a CTE referenced once is inlined, and an
/// inlined `agg` referenced from both the ranking and the final join would be evaluated twice --
/// silently restoring the exact double-scan this change removed, with no visible edit to the
/// query. The nested form has one `FROM usage_events` and one `dense_rank()` over its output, with
/// no join back to the aggregate at all, so it cannot regress that way whatever the planner
/// decides.
///
/// ## Why it is ONE statement at all
///
/// See [`StoreRepo::query_usage`]'s doc comment: this replaced two queries that carried the same
/// `WHERE` clause and therefore scanned the same rows twice.
fn build_usage_query(input: &UsageQueryRequest) -> QueryBuilder<Postgres> {
    let group_set: HashSet<UsageGroupBy> = input.group_by.iter().cloned().collect();
    let with_percentiles = input.wants_latency_percentiles();
    let limit = i64::from(input.limit);

    // Level 0: the aggregation itself -- the only thing that touches `usage_events`.
    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT counted.bucket_start, counted.account_id, counted.project_id, counted.api_key_id, counted.user_id, counted.user_name, counted.model, counted.metric_name, counted.signal_type, counted.azp, counted.operation, counted.billing_plan, counted.requests, counted.usage_value, counted.prompt_tokens, counted.completion_tokens, counted.total_tokens, counted.total_cost, counted.latency_samples, ",
    );
    if with_percentiles {
        builder.push("counted.latency_percentiles[1]::double precision AS latency_p50_ms, counted.latency_percentiles[2]::double precision AS latency_p95_ms, counted.latency_percentiles[3]::double precision AS latency_p99_ms, ");
    } else {
        builder.push("NULL::double precision AS latency_p50_ms, NULL::double precision AS latency_p95_ms, NULL::double precision AS latency_p99_ms, ");
    }
    builder.push("counted.bucket_count > ");
    builder.push_bind(limit);
    builder.push(" AS truncated FROM (SELECT ranked.*, max(ranked.bucket_rank) OVER () AS bucket_count FROM (SELECT agg.*, dense_rank() OVER (ORDER BY agg.bucket_start DESC) AS bucket_rank FROM (SELECT date_bin(CAST(");
    builder
        .push_bind(&input.bucket)
        .push(" AS interval), observed_at, TIMESTAMPTZ '1970-01-01 00:00:00+00') AS bucket_start");

    let mut grouped_columns: Vec<&'static str> = Vec::new();
    for (group_key, column) in DIMENSION_COLUMNS {
        if group_set.contains(&group_key) {
            builder.push(", ").push(column);
            grouped_columns.push(column);
        } else {
            builder.push(", NULL::text AS ").push(column);
        }
    }

    builder.push(", SUM(request_count)::bigint AS requests");
    builder.push(", SUM(usage_value)::double precision AS usage_value");
    builder.push(", SUM(prompt_tokens)::bigint AS prompt_tokens");
    builder.push(", SUM(completion_tokens)::bigint AS completion_tokens");
    builder.push(", SUM(total_tokens)::bigint AS total_tokens");
    builder.push(", SUM(total_cost)::double precision AS total_cost");
    builder.push(", COUNT(latency_ms)::bigint AS latency_samples");
    if with_percentiles {
        // ONE ordered-set aggregate returning all three quantiles, not three separate
        // `percentile_cont` calls. Each ordered-set aggregate builds its OWN tuplesort of the
        // group's values, so the three-call form sorted the same latencies three times over; the
        // multi-quantile form sorts once. (The bigger cost is structural and is why
        // `UsageMetric::LatencyPercentiles` exists at all -- see that type's docs.)
        builder.push(
            ", percentile_cont(ARRAY[0.5, 0.95, 0.99]) WITHIN GROUP (ORDER BY latency_ms) AS latency_percentiles",
        );
    }

    builder.push(" FROM usage_events WHERE ");
    push_scope_filters(&mut builder, input);

    builder.push(" GROUP BY bucket_start");
    for column in &grouped_columns {
        builder.push(", ").push(column);
    }

    builder.push(") agg) ranked) counted WHERE counted.bucket_rank <= ");
    builder.push_bind(limit);

    // Deterministic tiebreaker: every dimension column, grouped or not. An ungrouped one is a
    // constant `NULL` across every row, so ordering by it is free and changes nothing -- but it
    // means the clause's shape never depends on `group_by`, and a grouped dimension always gets a
    // real, stable sort key instead of Postgres' free choice among ties.
    builder.push(" ORDER BY counted.bucket_start ASC");
    for (_, column) in DIMENSION_COLUMNS {
        builder.push(", counted.").push(column);
    }

    builder
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
    if let Some(azp) = &input.filters.azp {
        builder.push(" AND azp = ");
        builder.push_bind(azp);
    }
    if let Some(operation) = &input.filters.operation {
        builder.push(" AND operation = ");
        builder.push_bind(operation);
    }
    if let Some(billing_plan) = &input.filters.billing_plan {
        builder.push(" AND billing_plan = ");
        builder.push_bind(billing_plan);
    }
    // #648: set membership, as ONE bound `text[]` parameter -- never an interpolated `IN (...)`
    // list. The console's "chats" view asks for three operations at once; making it issue three
    // queries and sum them client-side would both triple the load and let the three disagree
    // whenever a bucket boundary or the `truncated` limit fell differently between them. Values
    // are validated against the closed `USAGE_OPERATIONS` vocabulary
    // (`UsageQueryFilters::validate`) before the request ever reaches this repo.
    if let Some(operations) = &input.filters.operation_in {
        builder.push(" AND operation = ANY(");
        builder.push_bind(operations.as_slice());
        builder.push(")");
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

#[cfg(test)]
mod query_shape_tests {
    use super::*;
    use crate::models::{UsageMetric, UsageQueryFilters, UsageScope};
    use chrono::TimeZone;

    fn request(
        group_by: Vec<UsageGroupBy>,
        metrics: Option<Vec<UsageMetric>>,
    ) -> UsageQueryRequest {
        UsageQueryRequest {
            scope: UsageScope::All,
            scope_id: String::new(),
            start_time: Utc.with_ymd_and_hms(2026, 8, 4, 0, 0, 0).unwrap(),
            end_time: Utc.with_ymd_and_hms(2026, 9, 4, 0, 0, 0).unwrap(),
            bucket: "1 day".to_string(),
            filters: UsageQueryFilters::default(),
            group_by,
            limit: 1000,
            metrics,
        }
    }

    /// The single-statement shape is the whole point of the 2026-09-03 rewrite: two queries over
    /// the same rows became one, with the bucket ranking running over the aggregate's own output.
    /// A future edit that reintroduces a second `FROM usage_events` -- or that stops referencing
    /// `agg` twice, which is what makes Postgres materialise it instead of inlining (and
    /// re-scanning) it -- silently doubles the I/O of every console query, so it is asserted here
    /// rather than left to a plan review nobody will re-run.
    #[test]
    fn usage_query_should_touch_the_base_table_exactly_once() {
        let sql = build_usage_query(&request(vec![], None));
        let sql = sql.sql();
        let sql = sql.as_str();
        assert_eq!(
            sql.matches("FROM usage_events").count(),
            1,
            "the base table must be scanned once, got: {sql}"
        );
        assert!(
            !sql.contains("WITH "),
            "a CTE only avoids the double scan while Postgres chooses to materialise it; the \
             nested form cannot regress that way -- got: {sql}"
        );
        assert!(sql.contains("dense_rank() OVER (ORDER BY agg.bucket_start DESC) AS bucket_rank"));
        assert!(sql.contains("max(ranked.bucket_rank) OVER () AS bucket_count"));
    }

    /// `percentile_cont` is an ordered-set aggregate and cannot be hash-aggregated, so asking for
    /// percentiles changes the PLAN (HashAggregate over a handful of groups -> GroupAggregate fed
    /// by a full Sort of every matching row), not just its cost. Omitting the family must
    /// therefore remove the call entirely, not merely discard its result.
    #[test]
    fn omitting_latency_percentiles_should_remove_the_ordered_set_aggregate() {
        let with = build_usage_query(&request(vec![], None));
        assert!(with.sql().as_str().contains("percentile_cont"));

        let without = build_usage_query(&request(vec![], Some(vec![UsageMetric::Totals])));
        let without = without.sql();
        let without = without.as_str();
        assert!(
            !without.contains("percentile_cont"),
            "the ordered-set aggregate must be gone, got: {without}"
        );
        // The columns still exist on the wire -- they are just honestly null.
        assert!(without.contains("NULL::double precision AS latency_p50_ms"));
        // `latency_samples` is part of `Totals` and stays a true count.
        assert!(without.contains("COUNT(latency_ms)::bigint AS latency_samples"));
    }

    /// Three `percentile_cont` calls meant three tuplesorts of the same latencies. One
    /// multi-quantile call sorts once.
    #[test]
    fn latency_percentiles_should_be_one_multi_quantile_aggregate() {
        let sql = build_usage_query(&request(vec![], None));
        let sql = sql.sql();
        let sql = sql.as_str();
        assert_eq!(sql.matches("percentile_cont").count(), 1, "got: {sql}");
        assert!(sql.contains(
            "percentile_cont(ARRAY[0.5, 0.95, 0.99]) WITHIN GROUP (ORDER BY latency_ms)"
        ));
    }

    /// A grouped dimension is selected as itself; every other one stays a constant `NULL::text`
    /// so the row shape -- and the `ORDER BY` tiebreaker -- never depends on `group_by`.
    #[test]
    fn grouped_dimensions_should_be_selected_and_the_rest_held_null() {
        let sql = build_usage_query(&request(
            vec![UsageGroupBy::AccountId, UsageGroupBy::Model],
            None,
        ));
        let sql = sql.sql();
        let sql = sql.as_str();
        assert!(sql.contains(" GROUP BY bucket_start, account_id, model"));
        assert!(sql.contains("NULL::text AS project_id"));
        assert!(!sql.contains("NULL::text AS account_id"));
        assert!(!sql.contains("NULL::text AS model"));
    }
}
