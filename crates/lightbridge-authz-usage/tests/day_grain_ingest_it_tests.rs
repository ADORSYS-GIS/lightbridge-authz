#![cfg(feature = "it-tests")]
//! Integration tests for the day-grain receiver (#588): repo upserts and the end-to-end ingest
//! path (`/v1/otel/logs` with `X-Source: github-copilot` → `usage_day_facts`/`usage_seat_snapshots`).
//!
//! These apply the real `migrations-usage/` directory fresh per test via `#[sqlx::test]` and run
//! in CI unconditionally (plain Postgres — no Timescale-specific behavior is exercised).

use std::sync::Arc;

mod support;

use axum::{
    body::Body,
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::{
    UsageRepoTrait, UsageState, build_ingest_router,
    models::day_seat::{DayFact, SeatSnapshot, SubjectKind},
    repo::StoreRepo,
};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

fn repo(pool: &PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
}

fn app(pool: PgPool) -> axum::Router {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool))));
    let state = Arc::new(UsageState {
        repo,
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_auth: None,
        raw_days: Some(90),
    });
    build_ingest_router(state, readiness_pool, false)
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn upsert_day_facts_is_idempotent_on_natural_key(pool: PgPool) {
    let r = repo(&pool);
    let fact = DayFact {
        source: "github-copilot".into(),
        day: chrono::NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
        subject_kind: SubjectKind::Org,
        subject_id: "g1".into(),
        provider_user_id: None,
        active_users: Some(10),
        engaged_users: Some(4),
        total_interactions: Some(150),
        total_completions: Some(120),
        ai_credits: Some(0),
        coding_agent_activity: None,
        code_review_activity: None,
        pull_request_activity: None,
        team_id: None,
        team_slug: None,
        cost_micro_usd: Some(0),
        is_aggregate_only: false,
    };
    r.upsert_day_facts(std::slice::from_ref(&fact))
        .await
        .expect("first upsert");
    r.upsert_day_facts(std::slice::from_ref(&fact))
        .await
        .expect("replay upsert");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM usage_day_facts WHERE source='github-copilot' AND day='2026-09-01'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 1, "replaying a day must not change counts");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn upsert_seat_snapshots_is_idempotent_on_natural_key(pool: PgPool) {
    let r = repo(&pool);
    let snap = SeatSnapshot {
        source: "github-copilot".into(),
        snapshot_day: chrono::NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
        subject_kind: SubjectKind::Org,
        subject_id: "g1".into(),
        provider_user_id: "1001".into(),
        seat_state: "active".into(),
        assignee_login: Some("octocat".into()),
        seat_created_at: None,
        last_activity_at: None,
        last_activity_editor: None,
        plan_type: None,
    };
    r.upsert_seat_snapshots(std::slice::from_ref(&snap))
        .await
        .expect("first");
    r.upsert_seat_snapshots(std::slice::from_ref(&snap))
        .await
        .expect("replay");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM usage_seat_snapshots WHERE source='github-copilot'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 1, "replaying a seat snapshot must not change counts");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn duplicate_day_fact_in_one_batch_does_not_21000(pool: PgPool) {
    let r = repo(&pool);
    let fact = DayFact {
        source: "github-copilot".into(),
        day: chrono::NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
        subject_kind: SubjectKind::Org,
        subject_id: "g1".into(),
        provider_user_id: None,
        active_users: Some(10),
        engaged_users: Some(4),
        total_interactions: Some(150),
        total_completions: Some(120),
        ai_credits: Some(0),
        coding_agent_activity: None,
        code_review_activity: None,
        pull_request_activity: None,
        team_id: None,
        team_slug: None,
        cost_micro_usd: Some(0),
        is_aggregate_only: false,
    };
    // A re-emitted record during the cutover replay can carry the same natural key twice in one
    // payload; the multi-row `ON CONFLICT DO UPDATE` must not refuse the whole batch (21000).
    r.upsert_day_facts(&[fact.clone(), fact])
        .await
        .expect("a duplicate day fact in one batch must not 21000");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM usage_day_facts WHERE source='github-copilot' AND day='2026-09-01'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 1, "the duplicate collapses to one row");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn ingest_day_grain_logs_refuses_a_record_without_report(pool: PgPool) {
    let router = app(pool.clone());
    // A github-copilot source emits only day-grain records per RFC-0001, so a record missing the
    // `report` attribute is malformed and must be refused (fail-loud), never silently dropped.
    let body = json!({
        "resourceLogs": [{
            "scopeLogs": [{
                "logRecords": [
                    {
                        "timeUnixNano": "1735689600000000000",
                        "attributes": [
                            {"key":"source","value":{"stringValue":"github-copilot"}},
                            {"key":"day","value":{"stringValue":"2026-09-01"}},
                            {"key":"subject_kind","value":{"stringValue":"org"}},
                            {"key":"subject_id","value":{"stringValue":"g1"}}
                        ]
                    }
                ]
            }]
        }]
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/otel/logs")
                .header("x-source", "github-copilot")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a record without a report attribute must be refused, not dropped"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn ingest_day_grain_logs_end_to_end(pool: PgPool) {
    let router = app(pool.clone());
    let body = json!({
        "resourceLogs": [{
            "scopeLogs": [{
                "logRecords": [
                    {
                        "timeUnixNano": "1735689600000000000",
                        "attributes": [
                            {"key":"source","value":{"stringValue":"github-copilot"}},
                            {"key":"tenant_id","value":{"stringValue":"t1"}},
                            {"key":"org","value":{"stringValue":"g1"}},
                            {"key":"report","value":{"stringValue":"organization-1-day"}},
                            {"key":"day","value":{"stringValue":"2026-09-01"}},
                            {"key":"subject_kind","value":{"stringValue":"org"}},
                            {"key":"subject_id","value":{"stringValue":"g1"}},
                            {"key":"active_users","value":{"intValue":"10"}},
                            {"key":"engaged_users","value":{"intValue":"4"}},
                            {"key":"total_interactions","value":{"intValue":"150"}},
                            {"key":"total_completions","value":{"intValue":"120"}},
                            {"key":"ai_credits","value":{"intValue":"0"}},
                            {"key":"net_cost_micro_usd","value":{"intValue":"0"}}
                        ]
                    },
                    {
                        "timeUnixNano": "1735689600000000000",
                        "attributes": [
                            {"key":"source","value":{"stringValue":"github-copilot"}},
                            {"key":"tenant_id","value":{"stringValue":"t1"}},
                            {"key":"org","value":{"stringValue":"g1"}},
                            {"key":"report","value":{"stringValue":"billing-seats"}},
                            {"key":"day","value":{"stringValue":"2026-09-01"}},
                            {"key":"subject_kind","value":{"stringValue":"org"}},
                            {"key":"subject_id","value":{"stringValue":"g1"}},
                            {"key":"provider_user_id","value":{"stringValue":"1001"}},
                            {"key":"user_login","value":{"stringValue":"octocat"}},
                            {"key":"seat_state","value":{"stringValue":"active"}}
                        ]
                    }
                ]
            }]
        }]
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/otel/logs")
                .header("x-source", "github-copilot")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let day_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usage_day_facts WHERE source='github-copilot'")
            .fetch_one(&pool)
            .await
            .expect("count day facts");
    assert_eq!(day_count, 1, "one org day fact must land");

    let seat_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM usage_seat_snapshots WHERE source='github-copilot'",
    )
    .fetch_one(&pool)
    .await
    .expect("count seats");
    assert_eq!(seat_count, 1, "one seat snapshot must land");
}
