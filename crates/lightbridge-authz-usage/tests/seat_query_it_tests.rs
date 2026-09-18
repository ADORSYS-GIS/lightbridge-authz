#![cfg(feature = "it-tests")]

//! DB-backed integration tests for the seat-grain query endpoint (#728):
//! `StoreRepo::query_seat_snapshots` against a real Postgres, plus the full-router authorization
//! gate (`POST /usage/v1/usage/seats/query`).
//!
//! These seed `usage_seat_snapshots` directly through SQL (there is no seat-grain ingest yet --
//! #583 shipped tables only, matching `day_seat_grain_it_tests.rs`).

#[path = "support/mod.rs"]
mod support;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_query_router;
use lightbridge_authz_usage_rest::models::UsageScope;
use lightbridge_authz_usage_rest::models::day_seat::SubjectKind;
use lightbridge_authz_usage_rest::models::seat::{
    SeatGroupBy, SeatSnapshotQueryFilters, SeatSnapshotQueryRequest, SeatSnapshotQueryResponse,
};
use lightbridge_authz_usage_rest::repo::StoreRepo;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

const SOURCE: &str = "github-copilot";
const ISSUER: &str = "https://issuer.test";

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
}

fn ts(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper binding the fixed set of usage_seat_snapshots columns"
)]
async fn insert_seat(
    pool: &PgPool,
    source: &str,
    snapshot_day: NaiveDate,
    subject_kind: &str,
    subject_id: &str,
    provider_user_id: &str,
    seat_state: &str,
    assignee_team: Option<&str>,
    pending_cancellation_date: Option<NaiveDate>,
    plan_type: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO usage_seat_snapshots \
         (source, snapshot_day, subject_kind, subject_id, provider_user_id, seat_state, assignee_team, pending_cancellation_date, plan_type) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(source)
    .bind(snapshot_day)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(provider_user_id)
    .bind(seat_state)
    .bind(assignee_team)
    .bind(pending_cancellation_date)
    .bind(plan_type)
    .execute(pool)
    .await
    .expect("insert seat snapshot");
}

fn repo(pool: &PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
}

fn request(
    scope: UsageScope,
    scope_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    group_by: Vec<SeatGroupBy>,
    limit: u32,
) -> SeatSnapshotQueryRequest {
    SeatSnapshotQueryRequest {
        scope,
        scope_id: scope_id.to_string(),
        start_time: start,
        end_time: end,
        bucket: "1 day".to_string(),
        filters: SeatSnapshotQueryFilters::default(),
        group_by,
        limit,
    }
}

/// The three counts are seat-days, partition-disjoint and additive: `active_count +
/// pending_cancellation_count = seat_count`, with "active" = `pending_cancellation_date IS NULL`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn seat_counts_are_additive_active_plus_pending(pool: PgPool) {
    // 2 active seats (no pending cancellation) + 1 pending-cancellation seat on the same day.
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-2",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-3",
        "pending_cancellation",
        Some("eng"),
        Some(day(2026, 9, 1)),
        Some("business"),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "one bucket for one day");
    let point = &points[0];
    assert_eq!(point.seat_count, 3);
    assert_eq!(point.active_count, 2);
    assert_eq!(point.pending_cancellation_count, 1);
    assert_eq!(
        point.active_count + point.pending_cancellation_count,
        point.seat_count,
        "active + pending must equal seat_count"
    );
}

/// `scope=user` returns only the matching subject's seats.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn user_scope_returns_only_matching_subject(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "sub-a",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "sub-b",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&request(
            UsageScope::User,
            "sub-a",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only sub-a's seat");
    assert_eq!(points[0].seat_count, 1);
}

/// `scope=all` returns every seat.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn all_scope_returns_every_seat(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "sub-a",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 16),
        "org",
        "org-1",
        "sub-b",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 2, "both seats, one per day");
}

/// Bucket-scoped truncation (#578): 15 distinct days, limit 10 -> `truncated: true` and the 10
/// NEWEST buckets survive (the oldest 5 are dropped whole).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn bucket_truncation_drops_the_oldest_buckets(pool: PgPool) {
    for d in 1..=15 {
        insert_seat(
            &pool,
            SOURCE,
            day(2026, 8, d),
            "org",
            "org-1",
            &format!("user-{d}"),
            "active",
            Some("eng"),
            None,
            Some("business"),
        )
        .await;
    }

    let (points, truncated) = repo(&pool)
        .query_seat_snapshots(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 8, 16),
            vec![],
            10,
        ))
        .await
        .expect("query must succeed");

    assert!(
        truncated,
        "15 distinct buckets with limit 10 must be truncated"
    );
    assert_eq!(points.len(), 10, "exactly 10 whole buckets survive");
    // Newest-kept: the surviving buckets are days 6..15 (ascending order). `date_bin` with a
    // 1-day bucket anchored at epoch truncates to midnight UTC.
    assert_eq!(points[0].bucket_start, ts(2026, 8, 6));
    assert_eq!(points[9].bucket_start, ts(2026, 8, 15));
}

/// Filtering by `seat_state` returns only rows of that state.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn filter_by_seat_state_returns_only_matching_rows(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-2",
        "inactive",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let mut input = request(
        UsageScope::All,
        "",
        ts(2026, 8, 1),
        ts(2026, 9, 1),
        vec![],
        100,
    );
    input.filters.seat_state = Some("active".to_string());

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&input)
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only the active seat");
    assert_eq!(points[0].seat_count, 1);
}

/// Filtering by `source` returns only rows of that source.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn filter_by_source_returns_only_matching_rows(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        "m365-copilot",
        day(2026, 8, 15),
        "org",
        "org-2",
        "user-2",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let mut input = request(
        UsageScope::All,
        "",
        ts(2026, 8, 1),
        ts(2026, 9, 1),
        vec![],
        100,
    );
    input.filters.source = Some(SOURCE.to_string());

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&input)
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only the github-copilot seat");
    assert_eq!(points[0].seat_count, 1);
}

/// Filtering by `subject_kind` returns only rows of that subject kind.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn filter_by_subject_kind_returns_only_matching_rows(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-2",
        "user-2",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let mut input = request(
        UsageScope::All,
        "",
        ts(2026, 8, 1),
        ts(2026, 9, 1),
        vec![],
        100,
    );
    input.filters.subject_kind = Some(SubjectKind::Org);

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&input)
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only the org seat");
    assert_eq!(points[0].seat_count, 1);
}

/// Filtering by `assignee_team` returns only rows of that team.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn filter_by_assignee_team_returns_only_matching_rows(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-2",
        "active",
        Some("sales"),
        None,
        Some("business"),
    )
    .await;

    let mut input = request(
        UsageScope::All,
        "",
        ts(2026, 8, 1),
        ts(2026, 9, 1),
        vec![],
        100,
    );
    input.filters.assignee_team = Some("eng".to_string());

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&input)
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only the eng seat");
    assert_eq!(points[0].seat_count, 1);
}

/// Filtering by `plan_type` returns only rows of that plan.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn filter_by_plan_type_returns_only_matching_rows(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-2",
        "active",
        Some("eng"),
        None,
        Some("pro"),
    )
    .await;

    let mut input = request(
        UsageScope::All,
        "",
        ts(2026, 8, 1),
        ts(2026, 9, 1),
        vec![],
        100,
    );
    input.filters.plan_type = Some("business".to_string());

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&input)
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only the business-plan seat");
    assert_eq!(points[0].seat_count, 1);
}

/// Grouping by `seat_state` splits the bucket into one point per state, echoing the state.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn group_by_seat_state_splits_into_one_point_per_state(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-2",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-3",
        "pending_cancellation",
        Some("eng"),
        Some(day(2026, 9, 1)),
        Some("business"),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![SeatGroupBy::SeatState],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 2, "one point per distinct seat_state");
    let active = points
        .iter()
        .find(|p| p.seat_state.as_deref() == Some("active"))
        .expect("active group");
    let pending = points
        .iter()
        .find(|p| p.seat_state.as_deref() == Some("pending_cancellation"))
        .expect("pending group");
    assert_eq!(active.seat_count, 2);
    assert_eq!(pending.seat_count, 1);
}

/// Grouping by `subject_kind` splits the bucket into one point per kind, echoing the kind.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn group_by_subject_kind_splits_into_one_point_per_kind(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "user-1",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-2",
        "user-2",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_seat_snapshots(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![SeatGroupBy::SubjectKind],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 2, "one point per subject kind");
    let org = points
        .iter()
        .find(|p| p.subject_kind.as_deref() == Some("org"))
        .expect("org group");
    let user = points
        .iter()
        .find(|p| p.subject_kind.as_deref() == Some("user"))
        .expect("user group");
    assert_eq!(org.seat_count, 1);
    assert_eq!(user.seat_count, 1);
}

// ---------------------------------------------------------------------------------------------
// Full-router authorization gate (the shared ownership gate, GrainScope::DaySeat)
// ---------------------------------------------------------------------------------------------

fn app(
    pool: PgPool,
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
) -> axum::Router {
    app_with_authority(pool, bearer, support::refuse_everything_scope_authority())
}

/// Same as [`app`], but with an explicit scope authority -- tests that must prove a refusal comes
/// from the ownership gate itself (not from a refusing authority) pass an authorizing one.
fn app_with_authority(
    pool: PgPool,
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
    scope_authority: Arc<dyn lightbridge_authz_usage_rest::scope_authority::ScopeAuthority>,
) -> axum::Router {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool))));
    let state = Arc::new(UsageState {
        repo,
        bearer,
        scope_authority,
        ingest_auth: None,
        raw_days: Some(90),
    });
    build_query_router(state, readiness_pool, false)
}

async fn post_seats(
    router: axum::Router,
    bearer_header: Option<&str>,
    scope: &str,
    scope_id: &str,
) -> (StatusCode, serde_json::Value) {
    let body = json!({
        "scope": scope,
        "scope_id": scope_id,
        "start_time": "2026-08-01T00:00:00Z",
        "end_time": "2026-09-01T00:00:00Z",
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/usage/v1/usage/seats/query")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(bearer) = bearer_header {
        request = request.header(header::AUTHORIZATION, bearer);
    }
    let request = request
        .body(Body::from(
            serde_json::to_vec(&body).expect("request body must serialize"),
        ))
        .expect("request must build");

    let response = router
        .oneshot(request)
        .await
        .expect("router must produce a response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must be readable");
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

/// `scope=user` self-ownership: the caller reading their OWN subject sees their seeded seats.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn own_user_scope_returns_200_with_seeded_seats(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "sub-a",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, body) =
        post_seats(app(pool, bearer), Some("Bearer token-a"), "user", "sub-a").await;

    assert_eq!(status, StatusCode::OK);
    let response: SeatSnapshotQueryResponse =
        serde_json::from_value(body).expect("response must be a SeatSnapshotQueryResponse");
    assert_eq!(response.points.len(), 1);
    assert_eq!(response.points[0].seat_count, 1);
}

/// Two-tenant 403 (fail-first per the epic): a caller asking for a DIFFERENT subject's
/// `scope=user` data is refused with 403 and no data.
///
/// The scope authority here is deliberately AUTHORIZING for exactly this `(sub-b, user, sub-a)`
/// combination: if the authority were refusing, the 403 could come from it rather than the
/// self-ownership gate. With an authorizing authority, the only thing that can still refuse is
/// the ownership check itself -- which is the property under test.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn other_subjects_user_scope_is_refused_with_403(pool: PgPool) {
    insert_seat(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        "sub-a",
        "active",
        Some("eng"),
        None,
        Some("business"),
    )
    .await;

    let authority =
        support::FakeScopeAuthority::new().authorizing(ISSUER, "sub-b", &UsageScope::User, "sub-a");
    let bearer = support::bearer_with("token-b", ISSUER, "sub-b");
    let (status, body) = post_seats(
        app_with_authority(pool, bearer, Arc::new(authority)),
        Some("Bearer token-b"),
        "user",
        "sub-a",
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        serde_json::Value::Null,
        "a refused query must never leak data"
    );
}

/// `scope=account` is not applicable to the seat grain and is rejected with `400`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn account_scope_is_rejected_with_400(pool: PgPool) {
    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, _) = post_seats(
        app(pool, bearer),
        Some("Bearer token-a"),
        "account",
        "acct-1",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A missing bearer token is `401`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn missing_bearer_is_refused_with_401(pool: PgPool) {
    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, _) = post_seats(app(pool, bearer), None, "user", "sub-a").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
