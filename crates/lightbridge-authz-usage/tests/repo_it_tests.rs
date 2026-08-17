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
        attributes: json!({"k": "v"}),
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
