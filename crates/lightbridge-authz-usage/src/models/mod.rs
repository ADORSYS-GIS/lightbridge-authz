use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Error, Result};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct IngestResponse {
    pub accepted_events: usize,
}

/// The closed `usage_events.operation` vocabulary (#648).
///
/// Ingest derives it from the request path (`ingest::operation_from_path`), the backfill migration
/// `migrations-usage/20260902000002_usage_event_dimensions_backfill.sql` derives the same values
/// from `attributes` with the same prefix table, and
/// [`UsageQueryFilters::validate`] refuses any `operation_in` entry outside this list. One list,
/// three consumers -- a value that can never be stored must never be silently accepted as a
/// filter either, because "zero rows" and "you asked for something that does not exist" are
/// different answers and only one of them is worth a caller's time.
///
/// `"other"` is a real, storable value: the request had a path and it was not one of the four
/// known surfaces. It is NOT the same as `NULL`, which means the signal carried no path key at
/// all -- "we do not know" is not "something else". `NULL` is therefore deliberately absent from
/// this list: it is not a filterable value, it is the absence of one.
///
/// #581's `usage_request_events` rewrite (PR-1b) reuses this vocabulary verbatim -- see
/// `docs/plans/0581-multi-source-usage-plan-of-work.md`.
pub const USAGE_OPERATIONS: [&str; 5] = [
    "chat_completions",
    "responses",
    "messages",
    "embeddings",
    "other",
];

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
    /// Which metric families to COMPUTE (owner report, 2026-09-03: "requests made to the query
    /// backend are very slow"). `None` -- the default, and what every caller written before this
    /// field existed sends -- means all of them, so the wire contract is unchanged.
    ///
    /// The only family worth NOT computing is [`UsageMetric::LatencyPercentiles`]; see that
    /// variant's docs for the measured reason. [`UsageMetric::Totals`] is computed unconditionally
    /// and listing it is a documented no-op.
    #[serde(default)]
    pub metrics: Option<Vec<UsageMetric>>,
}

/// A family of metrics `/usage/v1/usage/query` can compute, selectable per request via
/// [`UsageQueryRequest::metrics`].
///
/// This exists because the two families have wildly different costs and only one of them is
/// optional in practice. The gap is STRUCTURAL, not incremental: `percentile_cont` is an
/// ordered-set aggregate, and Postgres cannot hash-aggregate one. Asking for percentiles forces
/// the planner out of a `HashAggregate` over a handful of groups and into a `GroupAggregate` fed
/// by a full `Sort` of every matching row -- which at `work_mem = 4MB` spills to disk. Dropping
/// the family does not shave a step off the plan; it changes the plan.
///
/// Measured on a 2M-row, production-width fixture (estate-wide, 30 days, 1-day buckets, no
/// `group_by`, covering index present), same query, same rows, only `metrics` differing:
///
/// | request                      | plan                                          | execution |
/// |------------------------------|-----------------------------------------------|-----------|
/// | totals + latency percentiles | `GroupAggregate` <- `Sort` (32 MB to disk)    | 222 ms    |
/// | totals only                  | `HashAggregate`, no sort at all               | 130 ms    |
///
/// On production (933,494 rows / 3,267 MB, read-only replica, 2026-09-03, BEFORE the covering
/// index landed, where raw heap I/O still dominated everything else) the same pair measured
/// 34,387 ms against 31,500 ms -- which is the honest shape of this lever: it is worth having,
/// and it is not the main problem. The main problem was the heap width, and that is what
/// `migrations-usage/20260903000002_usage_event_query_covering_index.sql` addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageMetric {
    /// `requests`, `usage_value`, `prompt_tokens`, `completion_tokens`, `total_tokens`,
    /// `total_cost` and `latency_samples`.
    ///
    /// ALWAYS computed, whatever `metrics` says, and always echoed back in
    /// [`UsageQueryResponse::metrics`]. These are plain `SUM`/`COUNT` aggregates evaluated in the
    /// same single pass that already has to read the row to apply the `WHERE` clause -- there is
    /// no measurable saving available by dropping them, so offering to drop them would be an API
    /// that lies about what it does. Listing this variant is accepted and is a no-op.
    Totals,
    /// `latency_p50_ms` / `latency_p95_ms` / `latency_p99_ms`.
    ///
    /// Omit this to skip the percentile computation entirely. When it is omitted the three
    /// percentile fields come back `null` and [`UsageQueryResponse::metrics`] says why --
    /// `latency_samples` is still a true count (it is part of `Totals` and costs nothing), so a
    /// response with `latency_samples > 0` and `latency_p50_ms: null` means "not asked for", and
    /// `latency_samples == 0` still means "no row in this bucket reported a latency at all".
    LatencyPercentiles,
}

impl UsageMetric {
    /// Every family, in the fixed order [`UsageQueryResponse::metrics`] echoes them.
    pub const ALL: [UsageMetric; 2] = [UsageMetric::Totals, UsageMetric::LatencyPercentiles];
}

impl UsageQueryRequest {
    /// Whether this request asked for `latency_p*_ms`. `metrics: None` (the pre-existing wire
    /// shape) means "everything", so absence of the field is a YES -- a caller who never heard of
    /// this field must keep getting exactly what they got before.
    pub fn wants_latency_percentiles(&self) -> bool {
        match &self.metrics {
            None => true,
            Some(metrics) => metrics.contains(&UsageMetric::LatencyPercentiles),
        }
    }

    /// The metric families this request's response will actually carry, for
    /// [`UsageQueryResponse::metrics`]. [`UsageMetric::Totals`] is unconditional (see its docs).
    pub fn effective_metrics(&self) -> Vec<UsageMetric> {
        if self.wants_latency_percentiles() {
            UsageMetric::ALL.to_vec()
        } else {
            vec![UsageMetric::Totals]
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageScope {
    User,
    ApiKey,
    Project,
    Account,
    /// Estate-wide query: no `account_id`/`project_id`/`user_id`/`api_key_id` filter is added at
    /// all (`repo::push_scope_filters`'s `All` arm), so the query spans every account. Requires
    /// the caller's validated bearer token to hold `Permission::UsageReadAll`
    /// (`handlers::query::query_usage`) -- there is no per-row ownership predicate for "all", by
    /// definition, so this is gated on a coarse RBAC permission instead of `ScopeAuthority`.
    /// `scope_id` is still a required wire field (see `UsageQueryRequest::scope_id`) but is
    /// ignored for this scope; callers should send `""`.
    All,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UsageGroupBy {
    AccountId,
    ProjectId,
    ApiKeyId,
    UserId,
    UserName,
    Model,
    MetricName,
    SignalType,
    /// The OAuth client (`azp` claim) the request arrived on -- "which channel" (#648).
    Azp,
    /// Which API surface was called, from the closed [`USAGE_OPERATIONS`] vocabulary (#648).
    Operation,
    /// The billing plan Authorino stamped on the request (#648).
    BillingPlan,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UsageQueryFilters {
    pub account_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub model: Option<String>,
    pub metric_name: Option<String>,
    pub signal_type: Option<String>,
    /// Equality filter on `usage_events.azp` (#648).
    pub azp: Option<String>,
    /// Equality filter on `usage_events.operation` (#648). For "any of several operations" use
    /// [`Self::operation_in`] instead of issuing one query per value.
    pub operation: Option<String>,
    /// Equality filter on `usage_events.billing_plan` (#648).
    pub billing_plan: Option<String>,
    /// Set-membership filter on `usage_events.operation` (#648): `AND operation = ANY($1)`, one
    /// bound `text[]` parameter, never string-interpolated.
    ///
    /// This exists because the console's "chats" view is inherently a three-value question
    /// (`chat_completions`, `responses`, `messages`) and the alternative -- three separate
    /// queries, summed client-side -- would triple the load, and would silently disagree with
    /// itself whenever a bucket boundary or the `truncated` limit fell differently between the
    /// three. Every entry is validated against [`USAGE_OPERATIONS`] by [`Self::validate`] before
    /// the query runs.
    ///
    /// Combines with [`Self::operation`] by AND, like every other filter pair here: sending both
    /// is legal and means "in this set AND equal to this one", which is either redundant or empty.
    pub operation_in: Option<Vec<String>>,
}

impl UsageQueryFilters {
    /// Validates the filters whose value space is closed. Returns [`Error::BadRequest`] rather
    /// than quietly returning zero rows: a caller who asked for `operation_in: ["chat"]` has a
    /// bug, and an empty result set would let them keep it.
    ///
    /// Deliberately rejects an EMPTY `operation_in` too. `operation = ANY('{}')` is false for
    /// every row, so an empty list is a filter that can only ever return nothing -- almost always
    /// a caller that meant to send no filter at all and dropped the field's contents on the way.
    pub fn validate(&self) -> Result<()> {
        let Some(operations) = &self.operation_in else {
            return Ok(());
        };

        if operations.is_empty() {
            return Err(Error::BadRequest(
                "filters.operation_in must not be empty; omit it to filter on no operation"
                    .to_string(),
            ));
        }

        for operation in operations {
            if !USAGE_OPERATIONS.contains(&operation.as_str()) {
                return Err(Error::BadRequest(format!(
                    "filters.operation_in contains an unknown operation `{operation}`; valid values are {}",
                    USAGE_OPERATIONS.join(", ")
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UsageQueryResponse {
    pub points: Vec<UsageSeriesPoint>,
    /// #578: `true` when more than `limit` DISTINCT `bucket_start` values matched the query and
    /// the OLDEST one was dropped WHOLE to fit. `limit` bounds bucket count, not `points.len()`
    /// (a row count) -- with a non-empty `group_by`, `points` can hold more entries than `limit`
    /// (one per series per surviving bucket), still in the same ascending `bucket_start` order as
    /// before this field existed, and every surviving bucket keeps its FULL series set, never an
    /// arbitrary subset while a sibling bucket keeps all of its own. `false` means every matching
    /// bucket is present. See `StoreRepo::query_usage`'s doc comment for why truncation drops the
    /// oldest bucket, not the newest, why it must be bucket-scoped rather than row-scoped, and for
    /// the known mid-bucket-cut caveat tracked as #586.
    pub truncated: bool,
    /// Which metric families this response actually carries, so a `null` percentile is never
    /// ambiguous: `latency_percentiles` present here means the percentiles were computed (and a
    /// `null` one means the bucket had no latency samples), absent means they were not asked for.
    /// Always contains [`UsageMetric::Totals`].
    pub metrics: Vec<UsageMetric>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct UsageSeriesPoint {
    pub bucket_start: DateTime<Utc>,
    pub account_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub model: Option<String>,
    pub metric_name: Option<String>,
    pub signal_type: Option<String>,
    /// The OAuth client the requests in this bucket arrived on. Present when `group_by` includes
    /// `azp`, `null` otherwise -- exactly like every other dimension echo here (#648).
    pub azp: Option<String>,
    /// Which API surface was called, from the closed [`USAGE_OPERATIONS`] vocabulary. Present when
    /// `group_by` includes `operation`, `null` otherwise. A `null` here when `operation` IS
    /// grouped is a real value: those rows carried no request path at all (#648).
    pub operation: Option<String>,
    /// The billing plan stamped on the requests in this bucket. Present when `group_by` includes
    /// `billing_plan`, `null` otherwise (#648).
    pub billing_plan: Option<String>,
    pub requests: i64,
    pub usage_value: f64,
    pub total_cost: f64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    /// How many rows in this bucket actually carried a latency measurement. A percentile computed
    /// over a handful of samples is noise, and `p99` needs ~100 samples before it means anything,
    /// so this count is returned alongside the percentiles rather than left for the caller to
    /// guess. `0` means no row in this bucket reported latency at all -- which is a legitimate,
    /// per-series outcome (see `UsageEvent::latency_ms`), not an error.
    pub latency_samples: i64,
    /// Median request latency in milliseconds, `percentile_cont(0.5)` over the bucket's
    /// `latency_ms` values. `None` exactly when `latency_samples == 0` -- never collapsed to `0.0`,
    /// because "no latency was reported" and "every request took 0 ms" are different facts and the
    /// console has to be able to say which one it is.
    pub latency_p50_ms: Option<f64>,
    /// 95th-percentile request latency in milliseconds. `None` when `latency_samples == 0`.
    pub latency_p95_ms: Option<f64>,
    /// 99th-percentile request latency in milliseconds. `None` when `latency_samples == 0`.
    /// Meaningful only once `latency_samples` is large (~100+); below that it degenerates towards
    /// the bucket maximum.
    pub latency_p99_ms: Option<f64>,
}

fn default_bucket() -> String {
    "1 hour".to_string()
}

fn default_limit() -> u32 {
    1_000
}

/// Request body for the internal, mTLS-protected `/usage/v1/spend/query` endpoint (the query
/// listener requires and verifies a client certificate -- see `UsageServerGroup::query`'s doc
/// comment; this route carries no Basic-auth or bearer check of its own). Answers
/// exactly the question `lightbridge-authz-budget`'s `SpendReader` asks: the summed
/// `usage_events.total_cost` for one account over a half-open `[start, end)` interval. Deliberately
/// takes explicit `start`/`end` bounds rather than a `Period` -- period-to-bounds conversion
/// (`period_bounds_utc`) stays a budget-domain concern; this endpoint only ever runs the SQL.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SpendQueryRequest {
    pub account_id: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Response body for `/usage/v1/spend/query`. `total_cost` is the raw, nullable
/// `SUM(total_cost)::double precision` result -- `None` when no `usage_events` rows matched
/// (account_id + half-open interval), `Some` (including `Some(0.0)`) when at least one row
/// matched. Deliberately preserved as `Option<f64>` rather than collapsed to `0.0`: the caller
/// (`lightbridge-authz-budget`'s `UsageServiceSpendReader`) depends on this exact SQL-NULL-vs-zero
/// distinction to keep `Spend::Unavailable` distinct from `Spend::Known(0)`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SpendQueryResponse {
    pub total_cost: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #648: the closed `operation_in` vocabulary. An unknown value is a `400`, never a silently
    /// empty result set -- the caller has a typo, and zero rows would let them ship it.
    #[test]
    fn operation_in_should_accept_only_the_published_vocabulary() {
        let valid = UsageQueryFilters {
            operation_in: Some(USAGE_OPERATIONS.iter().map(|v| (*v).to_string()).collect()),
            ..Default::default()
        };
        assert!(valid.validate().is_ok());

        let unknown = UsageQueryFilters {
            operation_in: Some(vec!["chat_completions".to_string(), "chat".to_string()]),
            ..Default::default()
        };
        let error = unknown
            .validate()
            .expect_err("an unknown operation must be refused");
        assert!(
            matches!(&error, Error::BadRequest(message) if message.contains("chat")),
            "expected a BadRequest naming the offending value, got {error:?}"
        );
    }

    /// #648: an EMPTY `operation_in` matches nothing at all (`= ANY('{}')` is false for every
    /// row), which is a filter that can only lie about the estate having no usage. Refused.
    #[test]
    fn operation_in_should_refuse_an_empty_list() {
        let empty = UsageQueryFilters {
            operation_in: Some(vec![]),
            ..Default::default()
        };
        assert!(matches!(empty.validate(), Err(Error::BadRequest(_))));
    }

    /// Absent `operation_in` is the overwhelmingly common case and must stay free.
    #[test]
    fn validate_should_pass_when_no_closed_vocabulary_filter_is_set() {
        assert!(UsageQueryFilters::default().validate().is_ok());
    }
}
