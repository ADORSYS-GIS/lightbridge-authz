use axum::http::StatusCode;
use axum::{Json, body::Bytes, http::HeaderMap};
use chrono::{Duration, Utc};
use lightbridge_authz_core::{Error, Result, async_trait};
use lightbridge_authz_usage_rest::UsageRepoTrait;
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::handlers::ingest::ingest_logs;
use lightbridge_authz_usage_rest::handlers::query::query_usage;
use lightbridge_authz_usage_rest::models::{
    UsageGroupBy, UsageQueryFilters, UsageQueryRequest, UsageScope, UsageSeriesPoint,
};
use lightbridge_authz_usage_rest::repo::UsageEvent;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use prost::Message;
use std::sync::Arc;

#[derive(Debug)]
struct MockUsageRepo {
    points: Vec<UsageSeriesPoint>,
    inserted_events: usize,
}

#[async_trait]
impl UsageRepoTrait for MockUsageRepo {
    async fn insert_usage_events(&self, _events: &[UsageEvent]) -> Result<usize> {
        Ok(self.inserted_events)
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
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
        }),
    });

    let result = query_usage(axum::extract::State(state), Json(req)).await;

    assert!(matches!(
        result,
        Err(Error::BadRequest(message)) if message == "start_time must be before end_time"
    ));
}

#[tokio::test]
async fn query_usage_returns_timeseries_points_when_query_is_valid() {
    let now = Utc::now();
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            inserted_events: 1,
            points: vec![UsageSeriesPoint {
                bucket_start: now,
                account_id: Some("acct_1".to_string()),
                project_id: Some("proj_1".to_string()),
                api_key_id: Some("key_1".to_string()),
                user_id: Some("user_1".to_string()),
                user_name: Some("Ada Lovelace".to_string()),
                model: Some("gpt-4.1".to_string()),
                metric_name: Some("gen_ai.usage.total_tokens".to_string()),
                signal_type: Some("metric".to_string()),
                requests: 3,
                total_cost: 42.0,
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

#[tokio::test]
async fn ingest_logs_treats_noop_insert_as_success() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
        }),
    });

    let response = ingest_logs(
        axum::extract::State(state),
        HeaderMap::new(),
        encoded_log_request(),
    )
    .await
    .expect("noop insert should still acknowledge OTLP logs");

    assert_eq!(response.0, StatusCode::ACCEPTED);
    assert_eq!(response.1.0.accepted_events, 1);
}

#[tokio::test]
async fn ingest_logs_rejects_invalid_protobuf_as_bad_request() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
        }),
    });

    let result = ingest_logs(
        axum::extract::State(state),
        HeaderMap::new(),
        Bytes::from_static(b"not protobuf"),
    )
    .await;

    assert!(matches!(
        result,
        Err(Error::BadRequest(message))
            if message.contains("invalid OTLP logs protobuf payload")
    ));
}

fn encoded_log_request() -> Bytes {
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: None,
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![LogRecord {
                    time_unix_nano: 1_700_000_000_000_000_000,
                    severity_text: "INFO".to_string(),
                    attributes: vec![
                        string_attr("account_id", "acct_1"),
                        string_attr("project_id", "proj_1"),
                        int_attr("prompt_tokens", 8),
                        int_attr("completion_tokens", 4),
                    ],
                    ..Default::default()
                }],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };

    let mut encoded = Vec::new();
    request
        .encode(&mut encoded)
        .expect("log request should encode");
    Bytes::from(encoded)
}

fn string_attr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
    }
}

fn int_attr(key: &str, value: i64) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::IntValue(value)),
        }),
    }
}
