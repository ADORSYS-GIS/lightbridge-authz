#![cfg(feature = "it-tests")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_ingest_router;
use lightbridge_authz_usage_rest::models::{
    UsageGroupBy, UsageQueryFilters, UsageQueryRequest, UsageScope,
};
use lightbridge_authz_usage_rest::repo::{StoreRepo, UsageEvent};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

fn sample_event(observed_at: chrono::DateTime<Utc>) -> UsageEvent {
    UsageEvent {
        observed_at,
        signal_type: "trace".to_string(),
        account_id: Some("acct_1".to_string()),
        project_id: Some("proj_1".to_string()),
        api_key_id: Some("key_1".to_string()),
        user_id: Some("user_1".to_string()),
        user_name: Some("Ada Lovelace".to_string()),
        model: Some("gpt-4.1".to_string()),
        metric_name: Some("chat.completion".to_string()),
        usage_value: 10.0,
        request_count: 1,
        prompt_tokens: Some(6),
        completion_tokens: Some(4),
        total_tokens: Some(10),
        total_cost: Some(0.05),
        latency_ms: Some(410.0),
        attributes: json!({"k": "v"}),
    }
}

fn event_with_latency(
    observed_at: chrono::DateTime<Utc>,
    model: &str,
    latency_ms: Option<f64>,
) -> UsageEvent {
    UsageEvent {
        model: Some(model.to_string()),
        latency_ms,
        ..sample_event(observed_at)
    }
}

fn base_query(now: chrono::DateTime<Utc>) -> UsageQueryRequest {
    UsageQueryRequest {
        scope: UsageScope::Project,
        scope_id: "proj_1".to_string(),
        start_time: now - Duration::hours(1),
        end_time: now + Duration::hours(1),
        bucket: "1 hour".to_string(),
        filters: UsageQueryFilters::default(),
        group_by: vec![],
        limit: 100,
    }
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn insert_usage_events_persists_all_rows(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    let events = vec![sample_event(now), sample_event(now)];

    let persisted = repo
        .insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    assert_eq!(persisted, 2);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn insert_usage_events_is_a_noop_for_empty_batch(pool: PgPool) {
    let repo = build_repo(pool);

    let persisted = repo
        .insert_usage_events(&[])
        .await
        .expect("empty insert should succeed");

    assert_eq!(persisted, 0);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_aggregates_inserted_events_by_group(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[sample_event(now), sample_event(now)])
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        group_by: vec![UsageGroupBy::Model, UsageGroupBy::ProjectId],
        ..base_query(now)
    };

    let points = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 1);
    let point = &points[0];
    assert_eq!(point.model.as_deref(), Some("gpt-4.1"));
    assert_eq!(point.project_id.as_deref(), Some("proj_1"));
    assert_eq!(point.account_id, None);
    assert_eq!(point.requests, 2);
    assert_eq!(point.usage_value, 20.0);
    assert_eq!(point.total_cost, 0.1);
    assert_eq!(point.prompt_tokens, 12);
    assert_eq!(point.completion_tokens, 8);
    assert_eq!(point.total_tokens, 20);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_without_group_by_collapses_into_a_single_bucket(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[sample_event(now)])
        .await
        .expect("insert should succeed");

    let points = repo
        .query_usage(&base_query(now))
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 1);
    assert_eq!(points[0].model, None);
    assert_eq!(points[0].requests, 1);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_scopes_by_account_project_api_key_and_user(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[sample_event(now)])
        .await
        .expect("insert should succeed");

    for (scope, scope_id) in [
        (UsageScope::Account, "acct_1"),
        (UsageScope::Project, "proj_1"),
        (UsageScope::ApiKey, "key_1"),
        (UsageScope::User, "user_1"),
    ] {
        let request = UsageQueryRequest {
            scope,
            scope_id: scope_id.to_string(),
            ..base_query(now)
        };

        let points = repo
            .query_usage(&request)
            .await
            .expect("query should succeed");

        assert_eq!(
            points.len(),
            1,
            "scope_id {scope_id} should match the seeded event"
        );
    }
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_returns_empty_when_scope_id_does_not_match(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[sample_event(now)])
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        scope_id: "other-project".to_string(),
        ..base_query(now)
    };

    let points = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert!(points.is_empty());
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_returns_empty_when_time_window_excludes_events(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[sample_event(now)])
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        start_time: now - Duration::days(2),
        end_time: now - Duration::days(1),
        ..base_query(now)
    };

    let points = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert!(points.is_empty());
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_applies_every_optional_filter(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[sample_event(now)])
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        filters: UsageQueryFilters {
            account_id: Some("acct_1".to_string()),
            project_id: Some("proj_1".to_string()),
            api_key_id: Some("key_1".to_string()),
            user_id: Some("user_1".to_string()),
            user_name: Some("Ada Lovelace".to_string()),
            model: Some("gpt-4.1".to_string()),
            metric_name: Some("chat.completion".to_string()),
            signal_type: Some("trace".to_string()),
        },
        ..base_query(now)
    };

    let points = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 1);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_filters_exclude_non_matching_events(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[sample_event(now)])
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        filters: UsageQueryFilters {
            model: Some("some-other-model".to_string()),
            ..UsageQueryFilters::default()
        },
        ..base_query(now)
    };

    let points = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert!(points.is_empty());
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_rejects_an_unsupported_bucket_interval(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();

    let request = UsageQueryRequest {
        bucket: "1 fortnight".to_string(),
        ..base_query(now)
    };

    let err = repo
        .query_usage(&request)
        .await
        .expect_err("an unsupported bucket unit must be rejected");

    assert!(matches!(err, lightbridge_authz_core::Error::BadRequest(_)));
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn healthz_ready_reports_ok_against_a_live_database(pool: PgPool) {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(build_repo(pool));
    let state = Arc::new(UsageState { repo });
    let app = build_ingest_router(state, readiness_pool, false);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// `percentile_cont` is an interpolating ordered-set aggregate, so for the 100 values 1..=100 the
/// answers are exact and hand-checkable: Postgres indexes at `p * (n - 1)` and interpolates
/// linearly between neighbours, giving 0.5 -> 49.5 -> 50.5, 0.95 -> 94.05 -> 95.05, and
/// 0.99 -> 98.01 -> 99.01. Asserting those exact numbers -- rather than a range -- is what makes
/// this test able to catch a wrong percentile argument, a `percentile_disc` swap, or a unit slip.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_reports_percentiles_over_recorded_latency(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    let events: Vec<UsageEvent> = (1..=100)
        .map(|ms| event_with_latency(now, "gpt-4.1", Some(f64::from(ms))))
        .collect();

    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let points = repo
        .query_usage(&base_query(now))
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 1);
    let point = &points[0];
    assert_eq!(point.latency_samples, 100);
    assert_eq!(point.latency_p50_ms, Some(50.5));
    assert_eq!(point.latency_p95_ms, Some(95.05));
    assert_eq!(point.latency_p99_ms, Some(99.01));
}

/// The honest-absence case, and the reason the percentile fields are `Option<f64>` rather than
/// `f64`. An aggregate metric signal (OTLP histogram/summary) records no per-request duration at
/// all, so a bucket made only of those rows must come back as "no samples, no percentiles" --
/// never as `0.0`, which the console would draw as a chart of instantaneous responses.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_reports_no_percentiles_when_nothing_recorded_a_latency(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    let events = vec![
        event_with_latency(now, "gpt-4.1", None),
        event_with_latency(now, "gpt-4.1", None),
    ];

    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let points = repo
        .query_usage(&base_query(now))
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 1);
    let point = &points[0];
    assert_eq!(point.requests, 2);
    assert_eq!(point.latency_samples, 0);
    assert_eq!(point.latency_p50_ms, None);
    assert_eq!(point.latency_p95_ms, None);
    assert_eq!(point.latency_p99_ms, None);
}

/// Mixed bucket: rows without a latency must not participate as zeros. If they did, the median of
/// (100, 200, 300) plus two NULL rows would come out at 200 -> 100 rather than staying 200.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_percentiles_ignore_rows_that_reported_no_latency(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    let events = vec![
        event_with_latency(now, "gpt-4.1", Some(100.0)),
        event_with_latency(now, "gpt-4.1", Some(200.0)),
        event_with_latency(now, "gpt-4.1", Some(300.0)),
        event_with_latency(now, "gpt-4.1", None),
        event_with_latency(now, "gpt-4.1", None),
    ];

    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let points = repo
        .query_usage(&base_query(now))
        .await
        .expect("query should succeed");

    let point = &points[0];
    assert_eq!(point.requests, 5);
    assert_eq!(point.latency_samples, 3);
    assert_eq!(point.latency_p50_ms, Some(200.0));
}

/// Per-series honesty end to end: grouping by model, one model reports latency and the other does
/// not. The console needs to be able to name exactly which series is missing data, which is only
/// possible if `latency_samples` is carried per group rather than collapsed across the bucket.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_reports_latency_per_group_so_one_silent_model_does_not_blank_the_rest(
    pool: PgPool,
) {
    let repo = build_repo(pool);
    let now = Utc::now();
    let events = vec![
        event_with_latency(now, "gpt-4.1", Some(410.0)),
        event_with_latency(now, "gpt-4.1", Some(430.0)),
        event_with_latency(now, "embed-3", None),
    ];

    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let mut query = base_query(now);
    query.group_by = vec![UsageGroupBy::Model];

    let points = repo
        .query_usage(&query)
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 2);

    let chat = points
        .iter()
        .find(|point| point.model.as_deref() == Some("gpt-4.1"))
        .expect("gpt-4.1 series should be present");
    assert_eq!(chat.latency_samples, 2);
    assert_eq!(chat.latency_p50_ms, Some(420.0));

    let embed = points
        .iter()
        .find(|point| point.model.as_deref() == Some("embed-3"))
        .expect("embed-3 series should be present, not dropped");
    assert_eq!(embed.latency_samples, 0);
    assert_eq!(embed.latency_p95_ms, None);
}

/// The sparse case the console has to render honestly. One request in the bucket means every
/// percentile collapses onto that single observation -- `percentile_cont` cannot say anything
/// else. `latency_samples` is what lets the UI mark it unstable instead of drawing a confident
/// p99.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_collapses_every_percentile_onto_a_lone_sample(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();

    repo.insert_usage_events(&[event_with_latency(now, "gpt-4.1", Some(777.0))])
        .await
        .expect("insert should succeed");

    let points = repo
        .query_usage(&base_query(now))
        .await
        .expect("query should succeed");

    let point = &points[0];
    assert_eq!(point.latency_samples, 1);
    assert_eq!(point.latency_p50_ms, Some(777.0));
    assert_eq!(point.latency_p95_ms, Some(777.0));
    assert_eq!(point.latency_p99_ms, Some(777.0));
}
