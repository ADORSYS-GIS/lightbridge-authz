#![cfg(feature = "it-tests")]

#[path = "support/mod.rs"]
mod support;

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_usage_rest::{UsageState, build_ingest_router, repo::StoreRepo};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

fn app(pool: &PgPool) -> axum::Router {
    let pool = Arc::new(DbPool::from_pool(pool.clone()));
    let state = Arc::new(UsageState {
        repo: Arc::new(StoreRepo::new(pool.clone())),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_auth: None,
        raw_days: Some(90),
    });
    build_ingest_router(state, pool, false)
}

fn body(account: &str, request_id: Option<&str>) -> String {
    let mut attrs = vec![
        json!({"key":"account_id", "value":{"stringValue":account}}),
        json!({"key":"user_id", "value":{"stringValue":"synthetic-user"}}),
        json!({"key":"event.name", "value":{"stringValue":"claude_code.api_request"}}),
        json!({"key":"input_tokens", "value":{"intValue":"12"}}),
        json!({"key":"output_tokens", "value":{"intValue":"3"}}),
        json!({"key":"cost_usd_micros", "value":{"intValue":"42"}}),
    ];
    if let Some(request_id) = request_id {
        attrs.push(json!({"key":"client_request_id", "value":{"stringValue":request_id}}));
    }
    json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[{
        "timeUnixNano":"1790060000000000000", "attributes":attrs
    }]}]}]})
    .to_string()
}

async fn send(app: axum::Router, body: String) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/otel/logs")
                .header("content-type", "application/json")
                .header("x-source", "claude-code")
                .body(Body::from(body))
                .expect("synthetic fixture operation must succeed"),
        )
        .await
        .expect("synthetic fixture operation must succeed");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn real_ingest_path_absorbs_request_redelivery(pool: PgPool) {
    let app = app(&pool);
    let payload = body("synthetic-account-a", Some("request-1"));
    send(app.clone(), payload.clone()).await;
    send(app, payload).await;
    let measures: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), sum(total_tokens)::bigint, sum(total_cost)::bigint FROM usage_events",
    )
    .fetch_one(&pool)
    .await
    .expect("synthetic fixture operation must succeed");
    assert_eq!(measures, (1, 15, 42));
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn equal_request_ids_from_different_accounts_do_not_collide(pool: PgPool) {
    let app = app(&pool);
    send(app.clone(), body("synthetic-account-a", Some("request-1"))).await;
    send(app, body("synthetic-account-b", Some("request-1"))).await;
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events")
        .fetch_one(&pool)
        .await
        .expect("synthetic fixture operation must succeed");
    assert_eq!(rows, 2);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn absent_request_id_is_explicitly_outside_the_dedup_contract(pool: PgPool) {
    let app = app(&pool);
    let payload = body("synthetic-account-a", None);
    send(app.clone(), payload.clone()).await;
    send(app, payload).await;
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events WHERE dedup_key IS NULL")
        .fetch_one(&pool)
        .await
        .expect("synthetic fixture operation must succeed");
    assert_eq!(rows, 2);
}
