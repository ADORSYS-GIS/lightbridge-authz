//! Execution-grain query builder and repository method (#726): aggregates `usage_executions`
//! joined with its children `usage_model_calls` / `usage_tool_calls` into time buckets, with
//! bucket-scoped truncation (the #578 `dense_rank()` pattern) and the shared ownership gate's
//! `scope=user`/`scope=all` filter.

use crate::models::execution::{ExecutionGroupBy, ExecutionQueryRequest, ExecutionSeriesPoint};
use crate::repo::StoreRepo;
use chrono::{DateTime, Utc};
use lightbridge_authz_core::Result;
use sqlx::{FromRow, Postgres, QueryBuilder};
use std::collections::HashSet;
use tracing::{debug, instrument};

#[derive(Debug, FromRow)]
struct ExecutionQueryRow {
    bucket_start: DateTime<Utc>,
    source: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    executions_count: Option<i64>,
    total_duration_ms: Option<i64>,
    total_cost: Option<i64>,
    total_input_tokens: Option<i64>,
    total_output_tokens: Option<i64>,
    tool_call_count: Option<i64>,
    /// Whole-result-set fact, not a per-row one: `true` when more DISTINCT `bucket_start` values
    /// matched than `input.limit` allowed and the oldest were dropped whole. Computed once by a
    /// window function over the distinct bucket list and repeated on every row.
    truncated: bool,
}

impl StoreRepo {
    /// Returns up to `input.limit` WHOLE buckets of the execution grain plus whether more existed
    /// (#578). `truncated` is derived from the count of DISTINCT `bucket_start` values, never from
    /// row count. `Vec<ExecutionSeriesPoint>` comes back in ascending `bucket_start` order.
    // `skip_all`: `input` carries `scope_id` and the whole `filters` set. `handlers::execution::
    // query_executions` already refuses to put those in ITS span for exactly that reason, and this
    // span re-adding them would have undone that.
    #[instrument(skip_all)]
    pub async fn query_executions(
        &self,
        input: &ExecutionQueryRequest,
    ) -> Result<(Vec<ExecutionSeriesPoint>, bool)> {
        debug!(
            "querying executions with scope={:?}, scope_id={}, bucket={}, limit={}",
            input.scope, input.scope_id, input.bucket, input.limit
        );
        super::bucket::validate_bucket_interval(&input.bucket)?;

        let mut builder = build_execution_query(input);
        let rows: Vec<ExecutionQueryRow> = builder.build_query_as().fetch_all(self.pool()).await?;

        let truncated = rows.first().is_some_and(|row| row.truncated);

        let points = rows
            .into_iter()
            .map(|row| ExecutionSeriesPoint {
                bucket_start: row.bucket_start,
                source: row.source,
                model: row.model,
                provider: row.provider,
                executions_count: row.executions_count.unwrap_or(0),
                total_duration_ms: row.total_duration_ms.unwrap_or(0),
                total_cost: row.total_cost,
                total_input_tokens: row.total_input_tokens.unwrap_or(0),
                total_output_tokens: row.total_output_tokens.unwrap_or(0),
                tool_call_count: row.tool_call_count.unwrap_or(0),
            })
            .collect();

        Ok((points, truncated))
    }
}

/// Builds the single statement [`StoreRepo::query_executions`] runs: the grouped aggregation, the
/// bucket-scoped truncation, and the `truncated` flag, in one pass over `usage_executions`.
///
/// Mirrors `build_usage_query`'s nested-subquery + `dense_rank()` shape (one `FROM
/// usage_executions`, bucket-scoped, newest-kept). Children are pre-aggregated per execution in
/// subqueries (`mc`, `tc`) and LEFT JOINed 1:1, so an execution with 2 model calls + 2 tool calls
/// still contributes exactly one row to the aggregation -- `executions_count`/`total_duration_ms`/
/// `total_cost` are never multiplied by child counts.
///
/// ## The `model` dimension (Option A)
///
/// When `model` is in `group_by` or `filters`, the model-call subquery is NOT pre-aggregated to a
/// single row per execution; instead `usage_model_calls` is joined at row level and `mc.model`
/// becomes a group key / filter. This is the fan-out case documented on `ExecutionSeriesPoint`.
/// `source`/`provider` stay on `usage_executions`.
fn build_execution_query(input: &ExecutionQueryRequest) -> QueryBuilder<Postgres> {
    let group_set: HashSet<ExecutionGroupBy> = input.group_by.iter().cloned().collect();
    let limit = i64::from(input.limit);
    let model_is_dimension =
        group_set.contains(&ExecutionGroupBy::Model) || input.filters.model.is_some();

    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT counted.bucket_start, counted.source, counted.model, counted.provider, counted.executions_count, counted.total_duration_ms, counted.total_cost, counted.total_input_tokens, counted.total_output_tokens, counted.tool_call_count, counted.bucket_count > ",
    );
    builder.push_bind(limit);
    builder.push(
        " AS truncated FROM (SELECT ranked.*, max(ranked.bucket_rank) OVER () AS bucket_count FROM (SELECT agg.*, dense_rank() OVER (ORDER BY agg.bucket_start DESC) AS bucket_rank FROM (SELECT date_bin(CAST(",
    );
    builder.push_bind(&input.bucket).push(
        " AS interval), e.observed_at, TIMESTAMPTZ '1970-01-01 00:00:00+00') AS bucket_start",
    );

    if group_set.contains(&ExecutionGroupBy::Source) {
        builder.push(", e.source");
    } else {
        builder.push(", NULL::text AS source");
    }
    if group_set.contains(&ExecutionGroupBy::Model) {
        builder.push(", mc.model");
    } else {
        builder.push(", NULL::text AS model");
    }
    if group_set.contains(&ExecutionGroupBy::Provider) {
        builder.push(", e.provider");
    } else {
        builder.push(", NULL::text AS provider");
    }

    builder.push(", COUNT(e.id)::bigint AS executions_count");
    builder.push(", SUM(e.duration_ms)::bigint AS total_duration_ms");
    builder.push(", SUM(e.estimated_cost_micro_usd)::bigint AS total_cost");
    if model_is_dimension {
        builder.push(", COALESCE(SUM(mc.input_tokens), 0)::bigint AS total_input_tokens");
        builder.push(", COALESCE(SUM(mc.output_tokens), 0)::bigint AS total_output_tokens");
    } else {
        builder.push(", COALESCE(SUM(mc.total_input_tokens), 0)::bigint AS total_input_tokens");
        builder.push(", COALESCE(SUM(mc.total_output_tokens), 0)::bigint AS total_output_tokens");
    }
    builder.push(", COALESCE(SUM(tc.tool_call_count), 0)::bigint AS tool_call_count");

    builder.push(" FROM usage_executions e");
    if model_is_dimension {
        builder.push(" LEFT JOIN usage_model_calls mc ON mc.execution_id = e.id");
    } else {
        builder.push(
            " LEFT JOIN (SELECT execution_id, SUM(input_tokens) AS total_input_tokens, SUM(output_tokens) AS total_output_tokens FROM usage_model_calls GROUP BY execution_id) mc ON mc.execution_id = e.id",
        );
    }
    builder.push(
        " LEFT JOIN (SELECT execution_id, COUNT(*) AS tool_call_count FROM usage_tool_calls GROUP BY execution_id) tc ON tc.execution_id = e.id WHERE ",
    );
    super::execution_filters::push_execution_scope_filters(&mut builder, input);

    builder.push(" GROUP BY bucket_start");
    if group_set.contains(&ExecutionGroupBy::Source) {
        builder.push(", e.source");
    }
    if group_set.contains(&ExecutionGroupBy::Model) {
        builder.push(", mc.model");
    }
    if group_set.contains(&ExecutionGroupBy::Provider) {
        builder.push(", e.provider");
    }

    builder.push(") agg) ranked) counted WHERE counted.bucket_rank <= ");
    builder.push_bind(limit);

    // Deterministic tiebreaker: every dimension column, grouped or not. An ungrouped one is a
    // constant `NULL` across every row, so ordering by it is free and changes nothing.
    builder.push(
        " ORDER BY counted.bucket_start ASC, counted.source, counted.model, counted.provider",
    );

    builder
}
