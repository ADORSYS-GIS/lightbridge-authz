use axum::Json;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use lightbridge_authz_core::{Result, async_trait};
use lightbridge_authz_usage_rest::UsageRepoTrait;
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::handlers::query::query_usage;
use lightbridge_authz_usage_rest::models::{
    UsageGroupBy, UsageQueryFilters, UsageQueryRequest, UsageScope, UsageSeriesPoint,
};
use lightbridge_authz_usage_rest::repo::UsageEvent;
use std::sync::Arc;

#[derive(Debug)]
struct MockUsageRepo {
    points: Vec<UsageSeriesPoint>,
}

#[async_trait]
impl UsageRepoTrait for MockUsageRepo {
    async fn insert_usage_events(&self, _events: &[UsageEvent]) -> Result<usize> {
        Ok(0)
    }

    async fn query_usage(&self, _input: &UsageQueryRequest) -> Result<Vec<UsageSeriesPoint>> {
        Ok(self.points.clone())
    }
}

fn base_request() -> UsageQueryRequest {
    let start = Utc::now() - Duration::hours(1);
    let end = Utc::now();

    UsageQueryRequest {
        scope: UsageScope::Project,
        scope_id: "proj_1".to_string(),
        start_time: start,
        end_time: end,
        bucket: "5 minutes".to_string(),
        filters: UsageQueryFilters::default(),
        group_by: vec![UsageGroupBy::Model],
        limit: 100,
    }
}

#[tokio::test]
async fn query_usage_returns_bad_request_when_time_window_is_invalid() {
    let req = UsageQueryRequest {
        start_time: Utc::now(),
        end_time: Utc::now() - Duration::hours(1),
        ..base_request()
    };

    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo { points: vec![] }),
    });

    let result = query_usage(axum::extract::State(state), Json(req)).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn query_usage_returns_timeseries_points_when_query_is_valid() {
    let now = Utc::now();
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![UsageSeriesPoint {
                bucket_start: now,
                account_id: Some("acct_1".to_string()),
                project_id: Some("proj_1".to_string()),
                user_id: Some("user_1".to_string()),
                model: Some("gpt-4.1".to_string()),
                metric_name: Some("gen_ai.usage.total_tokens".to_string()),
                signal_type: Some("metric".to_string()),
                requests: 3,
                usage_value: 120.0,
                prompt_tokens: 80,
                completion_tokens: 40,
                total_tokens: 120,
            }],
        }),
    });

    let req = base_request();
    let response = query_usage(axum::extract::State(state), Json(req))
        .await
        .expect("query should succeed");

    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1.0.points.len(), 1);
    assert_eq!(response.1.0.points[0].project_id.as_deref(), Some("proj_1"));
}
