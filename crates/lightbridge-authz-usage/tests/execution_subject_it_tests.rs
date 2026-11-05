#![cfg(feature = "it-tests")]

//! DB-backed tests for the execution grain's `subject_id` dimension (#767): per-engineer IDE-agent
//! spend for lightbridge-governance#36's admin view.
//!
//! Each test pins one acceptance criterion of #767: the unattributed bucket, erased subjects,
//! additivity across subject groups, cross-source attribution, the filter, and -- through the full
//! router -- that grouping by subject never widens a non-admin's `scope=user` query.

#[path = "support/mod.rs"]
mod support;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, TimeZone, Utc};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_query_router;
use lightbridge_authz_usage_rest::models::UsageScope;
use lightbridge_authz_usage_rest::models::execution::{
    ExecutionGroupBy, ExecutionQueryFilters, ExecutionQueryRequest, ExecutionQueryResponse,
    ExecutionSeriesPoint,
};
use lightbridge_authz_usage_rest::repo::StoreRepo;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

const ISSUER: &str = "https://issuer.test";

fn day(d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, d, 12, 0, 0).unwrap()
}

async fn insert_identity(pool: &PgPool, id: &str, source: &str, subject_id: &str) {
    sqlx::query(
        "INSERT INTO usage_identities (id, source, subject_kind, subject_id) VALUES ($1, $2, 'user', $3)",
    )
    .bind(id)
    .bind(source)
    .bind(subject_id)
    .execute(pool)
    .await
    .expect("insert identity");
}

/// One execution with no children -- the subject dimension never reads them.
async fn insert_execution(
    pool: &PgPool,
    span_id: &str,
    source: &str,
    identity_id: Option<&str>,
    cost: Option<i64>,
) {
    sqlx::query(
        "INSERT INTO usage_executions \
         (id, observed_at, source, trace_id, span_id, identity_id, raw_schema_version, estimated_cost_micro_usd) \
         VALUES ($1, $2, $3, 'trace', $4, $5, 1, $6)",
    )
    .bind(format!("exec_{source}_{span_id}"))
    .bind(day(15))
    .bind(source)
    .bind(span_id)
    .bind(identity_id)
    .bind(cost)
    .execute(pool)
    .await
    .expect("insert execution");
}

fn request(
    group_by: Vec<ExecutionGroupBy>,
    filters: ExecutionQueryFilters,
) -> ExecutionQueryRequest {
    ExecutionQueryRequest {
        scope: UsageScope::All,
        scope_id: String::new(),
        start_time: day(1),
        end_time: day(31),
        // One bucket for the whole window, so every assertion is about grouping, not bucketing.
        bucket: "30 days".to_string(),
        filters,
        group_by,
        limit: 100,
    }
}

async fn query(pool: &PgPool, request: &ExecutionQueryRequest) -> Vec<ExecutionSeriesPoint> {
    let repo = StoreRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    let (points, truncated) = repo
        .query_executions(request)
        .await
        .expect("query executions");
    assert!(!truncated);
    points
}

/// `(subject_id, executions, cost)` per point, in the query's own deterministic order.
fn by_subject(points: &[ExecutionSeriesPoint]) -> Vec<(Option<String>, i64, Option<i64>)> {
    points
        .iter()
        .map(|p| (p.subject_id.clone(), p.executions_count, p.total_cost))
        .collect()
}

/// Two engineers and one unattributed execution, shared by the tests below.
async fn seed_two_engineers_and_one_unattributed(pool: &PgPool) {
    insert_identity(pool, "id-alice", "claude-code", "alice").await;
    insert_identity(pool, "id-bob", "claude-code", "bob").await;
    insert_execution(pool, "a1", "claude-code", Some("id-alice"), Some(1_000)).await;
    insert_execution(pool, "a2", "claude-code", Some("id-alice"), Some(2_000)).await;
    insert_execution(pool, "b1", "claude-code", Some("id-bob"), Some(500)).await;
    insert_execution(pool, "u1", "claude-code", None, Some(7_000)).await;
}

/// AC1 + AC3: grouping by subject ranks engineers, and an execution with no identity lands in a
/// `subject_id: null` bucket with its cost intact -- a LEFT JOIN, never an INNER one.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn groups_by_subject_and_keeps_the_unattributed_bucket(pool: PgPool) {
    seed_two_engineers_and_one_unattributed(&pool).await;

    let points = query(
        &pool,
        &request(
            vec![ExecutionGroupBy::SubjectId],
            ExecutionQueryFilters::default(),
        ),
    )
    .await;

    assert_eq!(
        by_subject(&points),
        vec![
            (Some("alice".to_string()), 2, Some(3_000)),
            (Some("bob".to_string()), 1, Some(500)),
            (None, 1, Some(7_000)),
        ]
    );
}

/// AC5: one execution, one group. The subject groups sum to the ungrouped total -- unlike the
/// `model` fan-out, which is documented as non-additive.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn subject_groups_sum_to_the_ungrouped_total(pool: PgPool) {
    seed_two_engineers_and_one_unattributed(&pool).await;

    let grouped = query(
        &pool,
        &request(
            vec![ExecutionGroupBy::SubjectId],
            ExecutionQueryFilters::default(),
        ),
    )
    .await;
    let total = query(&pool, &request(vec![], ExecutionQueryFilters::default())).await;

    assert_eq!(total.len(), 1);
    assert_eq!(
        grouped.iter().map(|p| p.executions_count).sum::<i64>(),
        total[0].executions_count
    );
    assert_eq!(
        grouped.iter().filter_map(|p| p.total_cost).sum::<i64>(),
        total[0]
            .total_cost
            .expect("every seeded execution is priced")
    );
}

/// AC4: an erased identity groups under its literal `erased:<id>` value -- neither the original
/// subject nor the unattributed bucket.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn an_erased_subject_groups_as_its_literal_value(pool: PgPool) {
    seed_two_engineers_and_one_unattributed(&pool).await;
    sqlx::query("UPDATE usage_identities SET subject_id = 'erased:' || id WHERE id = 'id-bob'")
        .execute(&pool)
        .await
        .expect("erase bob");

    let points = query(
        &pool,
        &request(
            vec![ExecutionGroupBy::SubjectId],
            ExecutionQueryFilters::default(),
        ),
    )
    .await;
    let subjects: Vec<_> = points.iter().map(|p| p.subject_id.clone()).collect();

    assert_eq!(
        subjects,
        vec![
            Some("alice".to_string()),
            Some("erased:id-bob".to_string()),
            None
        ]
    );
}

/// One engineer reporting from two tools has two identity rows (one per source) carrying the same
/// `subject_id`. Grouped by subject alone they are ONE engineer; grouped by subject and source,
/// one row per tool. This is what makes a per-engineer total across tools possible.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn one_subject_across_two_sources_is_one_engineer(pool: PgPool) {
    insert_identity(&pool, "id-alice-cc", "claude-code", "alice").await;
    insert_identity(&pool, "id-alice-codex", "codex", "alice").await;
    insert_execution(&pool, "cc", "claude-code", Some("id-alice-cc"), Some(1_000)).await;
    insert_execution(&pool, "cx", "codex", Some("id-alice-codex"), Some(4_000)).await;

    let per_engineer = query(
        &pool,
        &request(
            vec![ExecutionGroupBy::SubjectId],
            ExecutionQueryFilters::default(),
        ),
    )
    .await;
    assert_eq!(
        by_subject(&per_engineer),
        vec![(Some("alice".to_string()), 2, Some(5_000))]
    );

    let per_tool = query(
        &pool,
        &request(
            vec![ExecutionGroupBy::SubjectId, ExecutionGroupBy::Source],
            ExecutionQueryFilters::default(),
        ),
    )
    .await;
    let rows: Vec<_> = per_tool
        .iter()
        .map(|p| (p.subject_id.as_deref(), p.source.as_deref(), p.total_cost))
        .collect();
    assert_eq!(
        rows,
        vec![
            (Some("alice"), Some("claude-code"), Some(1_000)),
            (Some("alice"), Some("codex"), Some(4_000)),
        ]
    );
}

/// AC2: the `subject_id` filter narrows to one engineer, with or without grouping by it.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn subject_filter_narrows_to_one_engineer(pool: PgPool) {
    seed_two_engineers_and_one_unattributed(&pool).await;

    let points = query(
        &pool,
        &request(
            vec![],
            ExecutionQueryFilters {
                subject_id: Some("bob".to_string()),
                ..ExecutionQueryFilters::default()
            },
        ),
    )
    .await;

    assert_eq!(points.len(), 1);
    assert_eq!(points[0].executions_count, 1);
    assert_eq!(points[0].total_cost, Some(500));
    // Filtered but not grouped: the echo stays null, like every other ungrouped dimension.
    assert_eq!(points[0].subject_id, None);
}

/// AC6, through the real router and ownership gate: a NON-admin caller grouping their own
/// `scope=user` query by subject sees only themselves -- the dimension never widens the scope.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn grouping_a_self_query_by_subject_returns_only_the_caller(pool: PgPool) {
    seed_two_engineers_and_one_unattributed(&pool).await;

    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let state = Arc::new(UsageState {
        repo: Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool)))),
        bearer: support::bearer_with("token-alice", ISSUER, "alice"),
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_auth: None,
        raw_days: Some(90),
    });
    let router = build_query_router(state, readiness_pool, false);

    let body = json!({
        "scope": "user",
        "scope_id": "alice",
        "start_time": "2026-08-01T00:00:00Z",
        "end_time": "2026-09-01T00:00:00Z",
        "bucket": "30 days",
        "group_by": ["subject_id"],
    });
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/usage/v1/usage/executions/query")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer token-alice")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let parsed: ExecutionQueryResponse = serde_json::from_slice(&bytes).expect("response shape");
    let subjects: Vec<_> = parsed.points.iter().map(|p| p.subject_id.clone()).collect();
    assert_eq!(subjects, vec![Some("alice".to_string())]);
}
