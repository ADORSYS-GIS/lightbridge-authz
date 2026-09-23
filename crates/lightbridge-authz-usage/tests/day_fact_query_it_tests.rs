#![cfg(feature = "it-tests")]

//! DB-backed integration tests for the day-facts grain query endpoint (#727):
//! `StoreRepo::query_day_facts` against a real Postgres, plus the full-router authorization
//! gate (`POST /usage/v1/usage/facts/query`).
//!
//! These seed `usage_day_facts` directly through SQL (there is no day-facts ingest yet -- #583
//! shipped tables only, matching `day_seat_grain_it_tests.rs`).

#[path = "support/mod.rs"]
mod support;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::aggregate_refresh::record_last_refresh;
use lightbridge_authz_usage_rest::build_query_router;
use lightbridge_authz_usage_rest::models::UsageScope;
use lightbridge_authz_usage_rest::models::day_fact::{
    DayFactGroupBy, DayFactQueryFilters, DayFactQueryRequest, DayFactQueryResponse,
};
use lightbridge_authz_usage_rest::models::day_seat::SubjectKind;
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
    reason = "test helper binding the fixed set of usage_day_facts columns"
)]
async fn insert_day_fact(
    pool: &PgPool,
    source: &str,
    day: NaiveDate,
    subject_kind: &str,
    subject_id: &str,
    provider_user_id: Option<&str>,
    suggestions: Option<i64>,
    acceptances: Option<i64>,
    cost: Option<i64>,
) {
    sqlx::query(
        "INSERT INTO usage_day_facts \
         (source, day, subject_kind, subject_id, provider_user_id, total_suggestions_count, total_acceptances_count, cost_micro_usd) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(source)
    .bind(day)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(provider_user_id)
    .bind(suggestions)
    .bind(acceptances)
    .bind(cost)
    .execute(pool)
    .await
    .expect("insert day fact");

    // #587: the query endpoint routes to the KPI aggregates when they exist (they do, the migration
    // applied), so refresh them after seeding or the query would see empty aggregates. Refreshing
    // per insert is wasteful in prod but cheap and robust in tests.
    refresh_day_fact_aggregates(pool).await;
}

/// Refreshes the three day-facts KPI aggregates the query endpoint routes to (#587), then records
/// the refresh so the routing's freshness check (`aggregate_views_available`) treats the aggregate
/// set as fresh and routes to it. Without the `record_last_refresh`, `last_refreshed_at` stays NULL
/// and the query paths fall back to the raw table (the #587 review's P2).
async fn refresh_day_fact_aggregates(pool: &PgPool) {
    for view in [
        "mv_day_facts_acceptances_daily",
        "mv_day_facts_active_users_daily",
        "mv_day_facts_spend_daily",
    ] {
        // `view` is a hardcoded static allowlist entry (never user input), so AssertSqlSafe is the
        // documented safe use of the escape hatch.
        let sql = format!("REFRESH MATERIALIZED VIEW CONCURRENTLY {view}");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(pool)
            .await
            .expect("refresh day-facts aggregate");
    }
    record_last_refresh(pool)
        .await
        .expect("record day-facts aggregate refresh");
}

fn repo(pool: &PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
}

fn request(
    scope: UsageScope,
    scope_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    group_by: Vec<DayFactGroupBy>,
    limit: u32,
) -> DayFactQueryRequest {
    DayFactQueryRequest {
        scope,
        scope_id: scope_id.to_string(),
        start_time: start,
        end_time: end,
        bucket: "1 day".to_string(),
        filters: DayFactQueryFilters::default(),
        group_by,
        limit,
    }
}

/// `scope=user` returns only the matching subject's per-user facts, excluding org-level facts
/// (which have `NULL` `provider_user_id`).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn user_scope_returns_only_matching_subject_and_excludes_org_facts(pool: PgPool) {
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-2",
        Some("sub-b"),
        Some(200),
        Some(150),
        Some(2_000),
    )
    .await;
    // Org-level fact: provider_user_id is NULL, so it must be excluded by scope=user.
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        None,
        Some(500),
        Some(400),
        Some(5_000),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_day_facts(&request(
            UsageScope::User,
            "sub-a",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only sub-a's per-user fact");
    assert_eq!(points[0].total_suggestions, Some(100));
    assert_eq!(points[0].total_acceptances, Some(80));
    assert_eq!(points[0].cost_micro_usd, Some(1_000));
}

/// `scope=all` returns every fact, including org-level rows with `NULL` `provider_user_id`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn all_scope_returns_every_fact_including_org_level(pool: PgPool) {
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 16),
        "org",
        "org-1",
        None,
        Some(500),
        Some(400),
        Some(5_000),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_day_facts(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 2, "both the user and org facts");
}

/// P1 regression (#733 review): an org-level aggregate row and the per-user rows it aggregates are
/// overlapping populations and must NOT be summed into one bucket by default. An org daily
/// (is_aggregate_only = TRUE, 500 suggestions, 5 000 µ$) and a member's user daily
/// (is_aggregate_only = FALSE, 100 suggestions, 1 000 µ$) on the SAME day must come back as two
/// points -- 500/5 000 and 100/1 000 -- never a single 600/6 000 point.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn aggregate_only_and_per_entity_rows_are_not_summed_together(pool: PgPool) {
    let d = day(2026, 8, 15);
    sqlx::query(
        "INSERT INTO usage_day_facts \
         (source, day, subject_kind, subject_id, provider_user_id, total_suggestions_count, total_acceptances_count, cost_micro_usd, is_aggregate_only) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)",
    )
    .bind(SOURCE)
    .bind(d)
    .bind("org")
    .bind("org-1")
    .bind(Option::<&str>::None)
    .bind(500_i64)
    .bind(400_i64)
    .bind(5_000_i64)
    .execute(&pool)
    .await
    .expect("insert aggregate-only org fact");
    insert_day_fact(
        &pool,
        SOURCE,
        d,
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_day_facts(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(
        points.len(),
        2,
        "aggregate-only and per-entity rows must be separate points, not summed"
    );
    let agg = points
        .iter()
        .find(|p| p.is_aggregate_only)
        .expect("aggregate-only point");
    let per = points
        .iter()
        .find(|p| !p.is_aggregate_only)
        .expect("per-entity point");
    assert_eq!(agg.total_suggestions, Some(500));
    assert_eq!(agg.cost_micro_usd, Some(5_000));
    assert_eq!(per.total_suggestions, Some(100));
    assert_eq!(per.cost_micro_usd, Some(1_000));
}

/// P1 regression (#733 review, follow-up): `is_aggregate_only` alone is not enough -- an org row
/// and its member repo rows are BOTH aggregate-only, so they share `bucket_start` AND
/// `is_aggregate_only` and would still be summed together. `subject_kind` must also be a group key
/// so each hierarchy level stays in its own point. An org daily (1000 suggestions) plus two repo
/// dailies inside it (200 + 150), all `is_aggregate_only = TRUE` on the same day, must come back as
/// two points -- org 1000 and repo 350 (the two disjoint repos sum; the org is NOT added on top).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn org_and_repo_aggregate_only_rows_are_not_summed_together(pool: PgPool) {
    let d = day(2026, 8, 15);
    for (kind, id, suggestions) in [
        ("org", "org-1", 1000_i64),
        ("repo", "repo-a", 200_i64),
        ("repo", "repo-b", 150_i64),
    ] {
        sqlx::query(
            "INSERT INTO usage_day_facts \
             (source, day, subject_kind, subject_id, provider_user_id, total_suggestions_count, is_aggregate_only) \
             VALUES ($1, $2, $3, $4, $5, $6, TRUE)",
        )
        .bind(SOURCE)
        .bind(d)
        .bind(kind)
        .bind(id)
        .bind(Option::<&str>::None)
        .bind(suggestions)
        .execute(&pool)
        .await
        .expect("insert aggregate-only fact");
    }
    refresh_day_fact_aggregates(&pool).await;

    let (points, _) = repo(&pool)
        .query_day_facts(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(
        points.len(),
        2,
        "org and repo must be separate points, not summed"
    );
    let org = points
        .iter()
        .find(|p| p.subject_kind == "org")
        .expect("org point");
    let repo = points
        .iter()
        .find(|p| p.subject_kind == "repo")
        .expect("repo point");
    assert_eq!(org.total_suggestions, Some(1000));
    assert_eq!(
        repo.total_suggestions,
        Some(350),
        "the two disjoint repos sum (200 + 150); the org is not added on top"
    );
}

/// P1 regression (#733 review): `total_active_users` is a per-day distinct count, not additive.
/// Summing it across a multi-day bucket would multiply it by the number of days; it must be
/// reported as the peak daily active users in the bucket (MAX), never the sum.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn total_active_users_is_peak_not_sum_across_days(pool: PgPool) {
    for (y, m, dd, users) in [(2026, 8, 15, 8_i64), (2026, 8, 16, 12_i64)] {
        sqlx::query(
            "INSERT INTO usage_day_facts \
             (source, day, subject_kind, subject_id, provider_user_id, total_active_users, is_aggregate_only) \
             VALUES ($1, $2, $3, $4, $5, $6, TRUE)",
        )
        .bind(SOURCE)
        .bind(day(y, m, dd))
        .bind("org")
        .bind("org-1")
        .bind(Option::<&str>::None)
        .bind(users)
        .execute(&pool)
        .await
        .expect("insert aggregate-only org fact");
    }
    refresh_day_fact_aggregates(&pool).await;

    let mut input = request(
        UsageScope::All,
        "",
        ts(2026, 8, 1),
        ts(2026, 9, 1),
        vec![],
        100,
    );
    // A 7-day bucket spans both seeded days (15th and 16th) into one point, so the MAX-vs-SUM
    // distinction is actually exercised.
    input.bucket = "7 days".to_string();

    let (points, _) = repo(&pool)
        .query_day_facts(&input)
        .await
        .expect("query must succeed");

    assert_eq!(
        points.len(),
        1,
        "one aggregate-only point spanning both days"
    );
    assert_eq!(
        points[0].total_active_users,
        Some(12),
        "peak daily active users (MAX), not the sum (20)"
    );
}

/// P1 regression (#727 review): the three day-facts aggregates are refreshed independently, so at
/// any instant one can be missing a row the others have. An INNER JOIN would silently drop that
/// row (losing its suggestions/acceptances/lines/cost); the FULL OUTER JOIN must keep it. Here the
/// spend aggregate is deliberately NOT refreshed, so it lacks the seeded row -- the query must
/// still return the row's suggestions with cost NULL, never drop it.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn divergent_aggregate_views_do_not_drop_rows(pool: PgPool) {
    // Seed a row directly (no refresh), then refresh only the acceptances and active_users views,
    // leaving the spend view stale (missing this row) -- the divergent-views state the INNER JOIN
    // bug dropped.
    sqlx::query(
        "INSERT INTO usage_day_facts \
         (source, day, subject_kind, subject_id, provider_user_id, total_suggestions_count, total_acceptances_count, cost_micro_usd) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(SOURCE)
    .bind(day(2026, 8, 15))
    .bind("user")
    .bind("user-1")
    .bind(Some("sub-a"))
    .bind(100_i64)
    .bind(80_i64)
    .bind(1_000_i64)
    .execute(&pool)
    .await
    .expect("insert day fact");

    for view in [
        "mv_day_facts_acceptances_daily",
        "mv_day_facts_active_users_daily",
    ] {
        let sql = format!("REFRESH MATERIALIZED VIEW CONCURRENTLY {view}");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&pool)
            .await
            .expect("refresh aggregate");
    }
    // mv_day_facts_spend_daily is deliberately NOT refreshed -> it lacks the row. Record the
    // refresh anyway so the routing's freshness check routes to the aggregate (the divergent-views
    // state this test exists to exercise); without it, routing would fall back to raw and the
    // spend would read as 1000, not NULL.
    record_last_refresh(&pool)
        .await
        .expect("record aggregate refresh");

    let (points, _) = repo(&pool)
        .query_day_facts(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(
        points.len(),
        1,
        "the row must not be dropped by a stale spend view"
    );
    assert_eq!(points[0].total_suggestions, Some(100));
    assert_eq!(points[0].total_acceptances, Some(80));
    assert_eq!(
        points[0].cost_micro_usd, None,
        "cost is unknown when the spend view lacks the row"
    );
}

/// A sub-day bucket on the daily day grain is rejected (it would collapse every row into the
/// midnight bucket -- degenerate and misleading).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn sub_day_bucket_is_rejected(pool: PgPool) {
    let mut input = request(
        UsageScope::All,
        "",
        ts(2026, 8, 1),
        ts(2026, 9, 1),
        vec![],
        100,
    );
    input.bucket = "1 hour".to_string();
    let err = repo(&pool)
        .query_day_facts(&input)
        .await
        .expect_err("sub-day bucket must be rejected");
    assert!(
        err.to_string().contains("at least 1 day"),
        "unexpected error: {err}"
    );
}

/// A bucket whose rows all carry `NULL` cost reports `cost_micro_usd: None`, never `0`
/// (governance#188).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn null_cost_round_trips_as_none_never_zero(pool: PgPool) {
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        None,
    )
    .await;

    let (points, _) = repo(&pool)
        .query_day_facts(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1);
    assert_eq!(
        points[0].cost_micro_usd, None,
        "NULL cost must round-trip as None, never 0"
    );
}

/// Bucket-scoped truncation (#578): 15 distinct days, limit 10 -> `truncated: true` and the 10
/// NEWEST buckets survive (the oldest 5 are dropped whole).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn bucket_truncation_drops_the_oldest_buckets(pool: PgPool) {
    for d in 1..=15 {
        insert_day_fact(
            &pool,
            SOURCE,
            day(2026, 8, d),
            "user",
            &format!("user-{d}"),
            Some("sub-a"),
            Some(100),
            Some(80),
            Some(1_000),
        )
        .await;
    }

    let (points, truncated) = repo(&pool)
        .query_day_facts(&request(
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

/// Filtering by `subject_kind` returns only rows of that subject kind.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn filter_by_subject_kind_returns_only_matching_rows(pool: PgPool) {
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        None,
        Some(500),
        Some(400),
        Some(5_000),
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
    input.filters.subject_kind = Some(SubjectKind::User);

    let (points, _) = repo(&pool)
        .query_day_facts(&input)
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only the user fact");
    assert_eq!(points[0].total_suggestions, Some(100));
}

/// Filtering by `source` returns only rows of that source.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn filter_by_source_returns_only_matching_rows(pool: PgPool) {
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;
    insert_day_fact(
        &pool,
        "m365-copilot",
        day(2026, 8, 15),
        "user",
        "user-2",
        Some("sub-b"),
        Some(200),
        Some(150),
        Some(2_000),
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
        .query_day_facts(&input)
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1, "only the github-copilot fact");
    assert_eq!(points[0].total_suggestions, Some(100));
}

/// Grouping by `subject_kind` splits the bucket into one point per subject kind.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn group_by_subject_kind_splits_into_one_point_per_kind(pool: PgPool) {
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "org",
        "org-1",
        None,
        Some(500),
        Some(400),
        Some(5_000),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_day_facts(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![DayFactGroupBy::SubjectKind],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 2, "one point per subject kind");
    let user = points
        .iter()
        .find(|p| p.subject_kind == "user")
        .expect("user group");
    let org = points
        .iter()
        .find(|p| p.subject_kind == "org")
        .expect("org group");
    assert_eq!(user.total_suggestions, Some(100));
    assert_eq!(org.total_suggestions, Some(500));
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
        raw_days: Some(90),
        ingest_auth: None,
    });
    build_query_router(state, readiness_pool, false)
}

async fn post_facts(
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
        .uri("/usage/v1/usage/facts/query")
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

/// `scope=user` self-ownership: the caller reading their OWN subject sees their seeded facts.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn own_user_scope_returns_200_with_seeded_facts(pool: PgPool) {
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, body) =
        post_facts(app(pool, bearer), Some("Bearer token-a"), "user", "sub-a").await;

    assert_eq!(status, StatusCode::OK);
    let response: DayFactQueryResponse =
        serde_json::from_value(body).expect("response must be a DayFactQueryResponse");
    assert_eq!(response.points.len(), 1);
    assert_eq!(response.points[0].total_suggestions, Some(100));
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
    insert_day_fact(
        &pool,
        SOURCE,
        day(2026, 8, 15),
        "user",
        "user-1",
        Some("sub-a"),
        Some(100),
        Some(80),
        Some(1_000),
    )
    .await;

    let authority =
        support::FakeScopeAuthority::new().authorizing(ISSUER, "sub-b", &UsageScope::User, "sub-a");
    let bearer = support::bearer_with("token-b", ISSUER, "sub-b");
    let (status, body) = post_facts(
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

/// `scope=account` is not applicable to the day grain and is rejected with `400`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn account_scope_is_rejected_with_400(pool: PgPool) {
    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, _) = post_facts(
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
    let (status, _) = post_facts(app(pool, bearer), None, "user", "sub-a").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
