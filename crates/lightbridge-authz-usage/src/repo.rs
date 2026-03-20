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
    pub user_id: Option<String>,
    pub model: Option<String>,
    pub metric_name: Option<String>,
    pub usage_value: f64,
    pub request_count: i64,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub total_cost: Option<f64>,
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
    user_id: Option<String>,
    model: Option<String>,
    metric_name: Option<String>,
    signal_type: Option<String>,
    requests: Option<i64>,
    usage_value: Option<f64>,
    prompt_tokens: Option<i64>,
    completion_tokens: Option<i64>,
    total_tokens: Option<i64>,
    total_cost: Option<f64>,
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
            "INSERT INTO usage_events (observed_at, signal_type, account_id, project_id, user_id, model, metric_name, usage_value, request_count, prompt_tokens, completion_tokens, total_tokens, total_cost, attributes) ",
        );

        builder.push_values(events, |mut row, event| {
            debug!("inserting event {:?}", event);
            row.push_bind(event.observed_at)
                .push_bind(&event.signal_type)
                .push_bind(&event.account_id)
                .push_bind(&event.project_id)
                .push_bind(&event.user_id)
                .push_bind(&event.model)
                .push_bind(&event.metric_name)
                .push_bind(event.usage_value)
                .push_bind(event.request_count)
                .push_bind(event.prompt_tokens)
                .push_bind(event.completion_tokens)
                .push_bind(event.total_tokens)
                .push_bind(event.total_cost)
                .push_bind(&event.attributes);
        });

        let result = builder.build().execute(self.pool()).await?;
        usize::try_from(result.rows_affected())
            .map_err(|_| Error::Database("rows_affected overflowed usize".to_string()))
    }

    #[instrument(skip(self))]
    pub async fn query_usage(&self, input: &UsageQueryRequest) -> Result<Vec<UsageSeriesPoint>> {
        debug!(
            "querying usage with scope={:?}, scope_id={}, bucket={}, limit={}",
            input.scope, input.scope_id, input.bucket, input.limit
        );
        validate_bucket_interval(&input.bucket)?;

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
            UsageGroupBy::UserId,
            "user_id",
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

        builder.push(" FROM usage_events WHERE observed_at >= ");
        builder.push_bind(input.start_time);
        builder.push(" AND observed_at < ");
        builder.push_bind(input.end_time);

        match input.scope {
            UsageScope::User => {
                builder.push(" AND user_id = ");
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
        }

        if let Some(account_id) = &input.filters.account_id {
            builder.push(" AND account_id = ");
            builder.push_bind(account_id);
        }
        if let Some(project_id) = &input.filters.project_id {
            builder.push(" AND project_id = ");
            builder.push_bind(project_id);
        }
        if let Some(user_id) = &input.filters.user_id {
            builder.push(" AND user_id = ");
            builder.push_bind(user_id);
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

        builder.push(" GROUP BY bucket_start");
        for col in grouped_columns {
            builder.push(", ");
            builder.push(col);
        }

        builder.push(" ORDER BY bucket_start ASC LIMIT ");
        builder.push_bind(i64::from(input.limit));

        let rows: Vec<UsageQueryRow> = builder.build_query_as().fetch_all(self.pool()).await?;

        Ok(rows
            .into_iter()
            .map(|row| UsageSeriesPoint {
                bucket_start: row.bucket_start,
                account_id: row.account_id,
                project_id: row.project_id,
                user_id: row.user_id,
                model: row.model,
                metric_name: row.metric_name,
                signal_type: row.signal_type,
                requests: row.requests.unwrap_or(0),
                usage_value: row.usage_value.unwrap_or(0.0),
                total_cost: row.total_cost.unwrap_or(0.0),
                prompt_tokens: row.prompt_tokens.unwrap_or(0),
                completion_tokens: row.completion_tokens.unwrap_or(0),
                total_tokens: row.total_tokens.unwrap_or(0),
            })
            .collect())
    }
}

fn append_dimension(
    builder: &mut QueryBuilder<'_, Postgres>,
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
        Err(Error::Database(
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
