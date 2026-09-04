#![cfg(feature = "it-tests")]

#[path = "support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_ingest_router;
use lightbridge_authz_usage_rest::models::{
    UsageGroupBy, UsageMetric, UsageQueryFilters, UsageQueryRequest, UsageScope,
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
        azp: Some("console-web".to_string()),
        operation: Some("chat_completions".to_string()),
        billing_plan: Some("pro".to_string()),
        usage_value: 10.0,
        request_count: 1,
        prompt_tokens: Some(6),
        completion_tokens: Some(4),
        total_tokens: Some(10),
        total_cost: Some(0.05),
        latency_ms: Some(410.0),
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
        metrics: None,
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

    let (points, _truncated) = repo
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

    let (points, _truncated) = repo
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

        let (points, _truncated) = repo
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

/// `scope=all` adds no entity filter at all (`repo::push_scope_filters`'s `All` arm is a no-op
/// beyond the time range) -- proved here by seeding events under TWO different `account_id`s and
/// asserting a single `scope=all` query sums requests across BOTH of them, not just one.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_scope_all_spans_multiple_accounts(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    let event_a = UsageEvent {
        account_id: Some("acct_a".to_string()),
        project_id: Some("proj_a".to_string()),
        ..sample_event(now)
    };
    let event_b = UsageEvent {
        account_id: Some("acct_b".to_string()),
        project_id: Some("proj_b".to_string()),
        ..sample_event(now)
    };
    repo.insert_usage_events(&[event_a, event_b])
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        scope: UsageScope::All,
        scope_id: String::new(),
        ..base_query(now)
    };

    let (points, _truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert_eq!(
        points.len(),
        1,
        "both accounts' events land in the same bucket with no group_by"
    );
    assert_eq!(
        points[0].requests, 2,
        "scope=all must sum requests across both acct_a and acct_b"
    );
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

    let (points, _truncated) = repo
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

    let (points, _truncated) = repo
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
            azp: Some("console-web".to_string()),
            operation: Some("chat_completions".to_string()),
            billing_plan: Some("pro".to_string()),
            operation_in: Some(vec!["chat_completions".to_string()]),
        },
        ..base_query(now)
    };

    let (points, _truncated) = repo
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

    let (points, _truncated) = repo
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
    let state = Arc::new(UsageState {
        repo,
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
        raw_days: 90,
    });
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

    let (points, _truncated) = repo
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

    let (points, _truncated) = repo
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

    let (points, _truncated) = repo
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

    let (points, _truncated) = repo
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

    let (points, _truncated) = repo
        .query_usage(&base_query(now))
        .await
        .expect("query should succeed");

    let point = &points[0];
    assert_eq!(point.latency_samples, 1);
    assert_eq!(point.latency_p50_ms, Some(777.0));
    assert_eq!(point.latency_p95_ms, Some(777.0));
    assert_eq!(point.latency_p99_ms, Some(777.0));
}

fn event_at_hour(base: chrono::DateTime<Utc>, hour_offset: i64, usage_value: f64) -> UsageEvent {
    UsageEvent {
        usage_value,
        ..sample_event(base + Duration::hours(hour_offset))
    }
}

/// #578 regression (fail-first proved separately -- see the PR/commit description for the
/// before/after run against the pre-fix `ORDER BY bucket_start ASC LIMIT $n` query): N + 1 hourly
/// buckets, `limit = N`, must return the NEWEST N buckets (dropping the oldest), still in
/// ascending order, with `truncated: true`. The pre-fix query kept the OLDEST N buckets instead --
/// this test's `usage_value` assertions (0.0 was the oldest, dropped; 1.0/2.0/3.0 survive) are
/// exactly what would fail under that behavior.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_truncation_drops_the_oldest_bucket_and_sets_truncated_true(pool: PgPool) {
    let repo = build_repo(pool);
    let base = Utc::now();
    let events = vec![
        event_at_hour(base, 0, 0.0),
        event_at_hour(base, 1, 1.0),
        event_at_hour(base, 2, 2.0),
        event_at_hour(base, 3, 3.0),
    ];
    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        start_time: base - Duration::hours(1),
        end_time: base + Duration::hours(4),
        bucket: "1 hour".to_string(),
        limit: 3,
        ..base_query(base)
    };

    let (points, truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert!(
        truncated,
        "4 buckets with limit 3 must report truncated: true"
    );
    assert_eq!(points.len(), 3, "exactly `limit` buckets must be returned");

    let usage_values: Vec<f64> = points.iter().map(|p| p.usage_value).collect();
    assert_eq!(
        usage_values,
        vec![1.0, 2.0, 3.0],
        "the OLDEST bucket (usage_value 0.0) must be dropped, newest 3 kept in ascending order"
    );
    // Response order is ascending, unchanged from before this fix.
    for window in points.windows(2) {
        assert!(window[0].bucket_start < window[1].bucket_start);
    }
}

/// #578: exactly `limit` buckets must report `truncated: false` -- the boundary case that proves
/// the fetch-`limit + 1` logic doesn't off-by-one into reporting truncation when there was none.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_reports_truncated_false_when_bucket_count_equals_limit(pool: PgPool) {
    let repo = build_repo(pool);
    let base = Utc::now();
    let events = vec![
        event_at_hour(base, 0, 0.0),
        event_at_hour(base, 1, 1.0),
        event_at_hour(base, 2, 2.0),
    ];
    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        start_time: base - Duration::hours(1),
        end_time: base + Duration::hours(4),
        bucket: "1 hour".to_string(),
        limit: 3,
        ..base_query(base)
    };

    let (points, truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert!(
        !truncated,
        "exactly 3 buckets with limit 3 must not be truncated"
    );
    assert_eq!(points.len(), 3);
    let usage_values: Vec<f64> = points.iter().map(|p| p.usage_value).collect();
    assert_eq!(usage_values, vec![0.0, 1.0, 2.0]);
}

fn event_at_hour_with_model(
    base: chrono::DateTime<Utc>,
    hour_offset: i64,
    model: &str,
    usage_value: f64,
) -> UsageEvent {
    UsageEvent {
        model: Some(model.to_string()),
        usage_value,
        ..sample_event(base + Duration::hours(hour_offset))
    }
}

fn group_by_model_query(base: chrono::DateTime<Utc>, limit: u32) -> UsageQueryRequest {
    UsageQueryRequest {
        start_time: base - Duration::hours(1),
        end_time: base + Duration::hours(10),
        bucket: "1 hour".to_string(),
        limit,
        group_by: vec![UsageGroupBy::Model],
        ..base_query(base)
    }
}

/// #578 bucket-scoping correction, case (a): multiple series per bucket, but the DISTINCT bucket
/// count is within `limit` -- `truncated` must be `false` and every row for every series in every
/// bucket must come back, even though the ROW count (2 buckets x 3 models = 6) is well above a
/// row-scoped reading of the same `limit`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_multi_series_within_bucket_limit_is_not_truncated(pool: PgPool) {
    let repo = build_repo(pool);
    let base = Utc::now();
    let events = vec![
        event_at_hour_with_model(base, 0, "gpt-4.1", 1.0),
        event_at_hour_with_model(base, 0, "embed-3", 2.0),
        event_at_hour_with_model(base, 1, "gpt-4.1", 3.0),
        event_at_hour_with_model(base, 1, "embed-3", 4.0),
    ];
    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    // 2 DISTINCT buckets, limit 2 buckets -- must NOT be truncated, despite 4 rows.
    let (points, truncated) = repo
        .query_usage(&group_by_model_query(base, 2))
        .await
        .expect("query should succeed");

    assert!(
        !truncated,
        "2 distinct buckets with a bucket limit of 2 must not be truncated, regardless of row count"
    );
    assert_eq!(
        points.len(),
        4,
        "every series in every bucket must be present"
    );
}

/// #578 bucket-scoping correction, case (b) -- THE decisive case the row-scoped bug could not
/// pass: 3 buckets x 2 series each (6 rows), bucket limit 2. Truncation must drop the OLDEST
/// bucket WHOLE (both its series, not an arbitrary subset), and BOTH kept buckets must retain
/// their FULL series set -- never a partially-represented bucket.
///
/// FAIL-FIRST EVIDENCE: against the prior row-scoped fix (`ORDER BY bucket_start DESC LIMIT
/// $n+1` applied to ROWS, i.e. reverting `select_kept_buckets`/the `= ANY(kept_buckets)` filter
/// and going back to fetching `limit + 1` ROWS directly), this test fails: `limit + 1` = 3 rows
/// fetched, oldest 1 row dropped -- but 3 rows is not even a whole number of 2-row buckets, so the
/// surviving 2 buckets can each have anywhere from 0 to 2 of their 2 series present, and running
/// this test against that code confirms `points.len()` comes back as something other than 4
/// (observed: 3, one series short in the boundary bucket) rather than every kept bucket's full
/// series set. See this crate's git history for the exact revert/run/restore used to prove this.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_truncation_drops_the_oldest_bucket_whole_with_group_by(pool: PgPool) {
    let repo = build_repo(pool);
    let base = Utc::now();
    let events = vec![
        event_at_hour_with_model(base, 0, "gpt-4.1", 1.0),
        event_at_hour_with_model(base, 0, "embed-3", 2.0),
        event_at_hour_with_model(base, 1, "gpt-4.1", 3.0),
        event_at_hour_with_model(base, 1, "embed-3", 4.0),
        event_at_hour_with_model(base, 2, "gpt-4.1", 5.0),
        event_at_hour_with_model(base, 2, "embed-3", 6.0),
    ];
    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    // 3 DISTINCT buckets, limit 2 buckets -- the oldest bucket (hour 0) must be dropped WHOLE.
    let (points, truncated) = repo
        .query_usage(&group_by_model_query(base, 2))
        .await
        .expect("query should succeed");

    assert!(
        truncated,
        "3 buckets with a bucket limit of 2 must be truncated"
    );
    assert_eq!(
        points.len(),
        4,
        "both kept buckets must retain their FULL series set (2 buckets x 2 series), never a \
         partial subset from either bucket"
    );

    let mut buckets_seen: Vec<chrono::DateTime<Utc>> =
        points.iter().map(|p| p.bucket_start).collect();
    buckets_seen.sort();
    buckets_seen.dedup();
    assert_eq!(
        buckets_seen.len(),
        2,
        "exactly the 2 newest buckets must survive"
    );
    for bucket in &buckets_seen {
        let series_in_bucket = points.iter().filter(|p| p.bucket_start == *bucket).count();
        assert_eq!(
            series_in_bucket, 2,
            "bucket {bucket} must retain both of its series, not a subset"
        );
    }

    // The dropped bucket's usage_value pair (1.0, 2.0) must not appear at all.
    let usage_values: Vec<f64> = points.iter().map(|p| p.usage_value).collect();
    assert!(
        !usage_values.contains(&1.0) && !usage_values.contains(&2.0),
        "the oldest bucket's series must be dropped entirely, not partially: {usage_values:?}"
    );
}

/// #578 bucket-scoping correction, case (c) -- the exact spurious-truncation scenario named in
/// review: 3 models x 2 buckets (6 rows), bucket limit 5. A row-scoped reading of `limit` would
/// flag this `truncated: true` (6 rows > 5) and arbitrarily drop one row; bucket-scoped, this must
/// stay `truncated: false` because there are only 2 distinct buckets, well within a limit of 5.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_three_models_two_buckets_limit_five_is_not_truncated(pool: PgPool) {
    let repo = build_repo(pool);
    let base = Utc::now();
    let events = vec![
        event_at_hour_with_model(base, 0, "gpt-4.1", 1.0),
        event_at_hour_with_model(base, 0, "embed-3", 2.0),
        event_at_hour_with_model(base, 0, "claude-x", 3.0),
        event_at_hour_with_model(base, 1, "gpt-4.1", 4.0),
        event_at_hour_with_model(base, 1, "embed-3", 5.0),
        event_at_hour_with_model(base, 1, "claude-x", 6.0),
    ];
    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let (points, truncated) = repo
        .query_usage(&group_by_model_query(base, 5))
        .await
        .expect("query should succeed");

    assert!(
        !truncated,
        "6 rows across only 2 distinct buckets must not trip truncation at a bucket limit of 5"
    );
    assert_eq!(
        points.len(),
        6,
        "every row across both buckets must be present"
    );
}

// ---------------------------------------------------------------------------------------------
// #648 -- the usage dimensions bridge: `azp`, `operation`, `billing_plan` as real columns.
// ---------------------------------------------------------------------------------------------

/// A dimension-carrying event, so the three new columns can be grouped and filtered on.
fn dimension_event(
    observed_at: chrono::DateTime<Utc>,
    azp: &str,
    operation: &str,
    billing_plan: &str,
) -> UsageEvent {
    UsageEvent {
        azp: Some(azp.to_string()),
        operation: Some(operation.to_string()),
        billing_plan: Some(billing_plan.to_string()),
        ..sample_event(observed_at)
    }
}

/// #648: each of the three new dimensions must group independently, and each returned point must
/// echo the value it was grouped by (the console renders the echo, not the request it sent).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_groups_by_each_new_dimension(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[
        dimension_event(now, "console-web", "chat_completions", "pro"),
        dimension_event(now, "console-web", "chat_completions", "pro"),
        dimension_event(now, "cli", "embeddings", "free"),
    ])
    .await
    .expect("insert should succeed");

    for (group, expected) in [
        (UsageGroupBy::Azp, vec![("cli", 1), ("console-web", 2)]),
        (
            UsageGroupBy::Operation,
            vec![("chat_completions", 2), ("embeddings", 1)],
        ),
        (UsageGroupBy::BillingPlan, vec![("free", 1), ("pro", 2)]),
    ] {
        let request = UsageQueryRequest {
            group_by: vec![group.clone()],
            ..base_query(now)
        };

        let (points, _truncated) = repo
            .query_usage(&request)
            .await
            .expect("query should succeed");

        let mut seen: Vec<(String, i64)> = points
            .iter()
            .map(|point| {
                let value = match group {
                    UsageGroupBy::Azp => point.azp.clone(),
                    UsageGroupBy::Operation => point.operation.clone(),
                    UsageGroupBy::BillingPlan => point.billing_plan.clone(),
                    _ => unreachable!("only the three new dimensions are exercised here"),
                };
                (
                    value.expect("a grouped dimension must be echoed on the point"),
                    point.requests,
                )
            })
            .collect();
        seen.sort();

        let expected: Vec<(String, i64)> = expected
            .into_iter()
            .map(|(value, requests)| (value.to_string(), requests))
            .collect();
        assert_eq!(
            seen, expected,
            "grouping by {group:?} must split the series"
        );
    }
}

/// #648: an UNGROUPED dimension comes back `null` on every point -- the same contract every other
/// dimension here already honours, so the console can tell "not grouped" from "grouped, and this
/// bucket's value was NULL".
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_leaves_ungrouped_new_dimensions_null(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[dimension_event(now, "console-web", "responses", "pro")])
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        group_by: vec![UsageGroupBy::Azp],
        ..base_query(now)
    };

    let (points, _truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 1);
    assert_eq!(points[0].azp.as_deref(), Some("console-web"));
    assert_eq!(points[0].operation, None);
    assert_eq!(points[0].billing_plan, None);
}

/// #648: equality filters on each new column.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_filters_on_each_new_dimension(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[
        dimension_event(now, "console-web", "chat_completions", "pro"),
        dimension_event(now, "cli", "embeddings", "free"),
    ])
    .await
    .expect("insert should succeed");

    let cases = [
        UsageQueryFilters {
            azp: Some("cli".to_string()),
            ..Default::default()
        },
        UsageQueryFilters {
            operation: Some("embeddings".to_string()),
            ..Default::default()
        },
        UsageQueryFilters {
            billing_plan: Some("free".to_string()),
            ..Default::default()
        },
    ];

    for filters in cases {
        let request = UsageQueryRequest {
            filters,
            group_by: vec![UsageGroupBy::Azp],
            ..base_query(now)
        };

        let (points, _truncated) = repo
            .query_usage(&request)
            .await
            .expect("query should succeed");

        assert_eq!(points.len(), 1);
        assert_eq!(points[0].azp.as_deref(), Some("cli"));
        assert_eq!(points[0].requests, 1);
    }
}

/// #648's headline acceptance criterion: `operation_in` matches several operations in a SINGLE
/// query. The console's chat view asks for `chat_completions` + `responses` + `messages` at once;
/// before this filter that was three round trips summed client-side, which is both 3x the load
/// and 3 chances for the buckets to disagree.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_matches_several_operations_in_one_query(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[
        dimension_event(now, "console-web", "chat_completions", "pro"),
        dimension_event(now, "console-web", "responses", "pro"),
        dimension_event(now, "console-web", "messages", "pro"),
        dimension_event(now, "console-web", "embeddings", "pro"),
        dimension_event(now, "console-web", "other", "pro"),
    ])
    .await
    .expect("insert should succeed");

    let request = UsageQueryRequest {
        filters: UsageQueryFilters {
            operation_in: Some(vec![
                "chat_completions".to_string(),
                "responses".to_string(),
                "messages".to_string(),
            ]),
            ..Default::default()
        },
        group_by: vec![UsageGroupBy::Operation],
        ..base_query(now)
    };

    let (points, _truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    let mut operations: Vec<String> = points
        .iter()
        .map(|point| {
            point
                .operation
                .clone()
                .expect("operation is grouped, so it must be echoed")
        })
        .collect();
    operations.sort();
    assert_eq!(
        operations,
        vec![
            "chat_completions".to_string(),
            "messages".to_string(),
            "responses".to_string()
        ],
        "exactly the three requested operations, and nothing else, in one query"
    );

    let total: i64 = points.iter().map(|point| point.requests).sum();
    assert_eq!(total, 3);
}

/// #648: a row whose `operation` is NULL (no path key was ever emitted for it) must NOT be swept
/// up by `operation_in` -- SQL `= ANY` is false for NULL, and that is the behaviour we want:
/// "unknown" is not a member of any set of known values.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn operation_in_never_matches_rows_with_a_null_operation(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    repo.insert_usage_events(&[
        dimension_event(now, "console-web", "chat_completions", "pro"),
        UsageEvent {
            operation: None,
            ..dimension_event(now, "console-web", "chat_completions", "pro")
        },
    ])
    .await
    .expect("insert should succeed");

    let request = UsageQueryRequest {
        filters: UsageQueryFilters {
            operation_in: Some(vec!["chat_completions".to_string()]),
            ..Default::default()
        },
        ..base_query(now)
    };

    let (points, _truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert_eq!(points.len(), 1);
    assert_eq!(
        points[0].requests, 1,
        "the NULL-operation row must not be counted as a chat completion"
    );
}

/// #648: the three composite indexes the migration promises actually exist after migration --
/// a group-by on an unindexed dimension over this table is a sequential scan, which is the
/// difference between a dashboard and a timeout (#606).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn migration_creates_the_three_dimension_indexes(pool: PgPool) {
    for index in [
        "idx_usage_events_azp_time",
        "idx_usage_events_operation_time",
        "idx_usage_events_billing_plan_time",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'usage_events' AND indexname = $1)",
        )
        .bind(index)
        .fetch_one(&pool)
        .await
        .expect("index lookup should succeed");
        assert!(exists, "expected index {index} to exist after migration");
    }
}

/// The 2026-09-03 query-cost work: `metrics` omitting `latency_percentiles` must remove the
/// `percentile_cont` computation (which is what changes the PLAN from a sort-fed `GroupAggregate`
/// to a `HashAggregate`) WITHOUT changing anything else about the answer. Same rows, same sums,
/// same `latency_samples` -- only the three percentile fields go null.
///
/// The percentile values asserted here are the same exact numbers
/// `query_usage_reports_percentiles_over_recorded_latency` pins, so the two tests together say
/// "this is what the lever turns off, and this is what it must not touch".
#[sqlx::test(migrations = "../../migrations-usage")]
async fn query_usage_should_skip_percentiles_when_metrics_omits_them(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();
    let events: Vec<UsageEvent> = (1..=100)
        .map(|ms| event_with_latency(now, "gpt-4.1", Some(f64::from(ms))))
        .collect();

    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let with_percentiles = repo
        .query_usage(&base_query(now))
        .await
        .expect("query should succeed")
        .0;
    let without_percentiles = repo
        .query_usage(&UsageQueryRequest {
            metrics: Some(vec![UsageMetric::Totals]),
            ..base_query(now)
        })
        .await
        .expect("query should succeed")
        .0;

    assert_eq!(with_percentiles.len(), 1);
    assert_eq!(without_percentiles.len(), 1);
    let with = &with_percentiles[0];
    let without = &without_percentiles[0];

    assert_eq!(with.latency_p50_ms, Some(50.5));
    assert_eq!(without.latency_p50_ms, None);
    assert_eq!(without.latency_p95_ms, None);
    assert_eq!(without.latency_p99_ms, None);

    // `latency_samples` is part of `Totals`: a plain COUNT in the same pass, so it stays a true
    // count rather than being zeroed to make the response look like "no data".
    assert_eq!(without.latency_samples, 100);
    assert_eq!(without.latency_samples, with.latency_samples);
    assert_eq!(without.requests, with.requests);
    assert_eq!(without.total_tokens, with.total_tokens);
    assert_eq!(without.total_cost, with.total_cost);
    assert_eq!(without.bucket_start, with.bucket_start);
}

/// `metrics: None` is the wire shape every caller written before the field existed sends, and it
/// must keep meaning "everything". A regression here silently blanks latency on the console.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn absent_metrics_should_still_compute_percentiles(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();

    repo.insert_usage_events(&[event_with_latency(now, "gpt-4.1", Some(42.0))])
        .await
        .expect("insert should succeed");

    let request: UsageQueryRequest = serde_json::from_value(json!({
        "scope": "project",
        "scope_id": "proj_1",
        "start_time": (now - Duration::hours(1)).to_rfc3339(),
        "end_time": (now + Duration::hours(1)).to_rfc3339(),
        "bucket": "1 hour",
    }))
    .expect("a request without `metrics` must still deserialize");
    assert!(request.metrics.is_none());
    assert!(request.wants_latency_percentiles());

    let (points, _truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");
    assert_eq!(points[0].latency_p50_ms, Some(42.0));
}

/// #578's truncation contract, re-asserted against the single-statement rewrite. The flag now
/// comes from a `max(dense_rank()) OVER ()` inside the same query rather than from a separate
/// bucket-selection round trip, so it needs pinning again: `limit` bounds DISTINCT buckets, the
/// NEWEST ones survive, and every surviving bucket keeps its full series set.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn truncation_should_keep_the_newest_whole_buckets(pool: PgPool) {
    let repo = build_repo(pool);
    let now = Utc::now();

    // Five hourly buckets, two models in each -- ten rows, five distinct buckets.
    let mut events = Vec::new();
    for hour in 0..5 {
        for model in ["gpt-4.1", "claude-4"] {
            events.push(event_with_latency(
                now - Duration::hours(i64::from(hour)),
                model,
                Some(10.0),
            ));
        }
    }
    repo.insert_usage_events(&events)
        .await
        .expect("insert should succeed");

    let request = UsageQueryRequest {
        start_time: now - Duration::hours(24),
        end_time: now + Duration::hours(1),
        group_by: vec![UsageGroupBy::Model],
        limit: 3,
        ..base_query(now)
    };
    let (points, truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    assert!(
        truncated,
        "5 distinct buckets against limit 3 is a truncation"
    );

    let mut buckets: Vec<_> = points.iter().map(|point| point.bucket_start).collect();
    buckets.dedup();
    assert_eq!(buckets.len(), 3, "limit bounds DISTINCT buckets, not rows");
    assert_eq!(points.len(), 6, "each surviving bucket keeps BOTH series");
    assert!(
        buckets.windows(2).all(|pair| pair[0] < pair[1]),
        "points come back in ascending bucket order"
    );
    // The newest bucket survives; the oldest (now - 4h) does not.
    let oldest_kept = buckets[0];
    assert!(
        oldest_kept > now - Duration::hours(3),
        "truncation must drop the OLDEST buckets, kept {oldest_kept}"
    );

    // Under the limit, nothing is truncated and every bucket is present.
    let (points, truncated) = repo
        .query_usage(&UsageQueryRequest {
            limit: 10,
            ..request
        })
        .await
        .expect("query should succeed");
    assert!(!truncated);
    assert_eq!(points.len(), 10);
}

/// Owner report, 2026-09-03: every OTLP export was logging a line shaped like
/// `INFO ingest_logs{body=b"\x1f\x8b..."}: ... accepted 4 log events`.
///
/// Two separate defects in one line, and this test pins both:
///
/// 1. `#[instrument]` records every non-skipped ARGUMENT into the span at entry, so an unskipped
///    `body: Bytes` stamped the whole compressed protobuf payload into the span -- unreadable at
///    this endpoint's volume, and an OTLP body carries whatever the exporter put in it (prompts,
///    user names, request bodies), which has no business in a log sink. The span must carry
///    `bytes` and nothing else derived from the payload.
/// 2. "accepted N events" is per-request bookkeeping, not an operational event, so it belongs at
///    `DEBUG`. Rejects stay at `WARN` -- a refused export is worth waking up for.
///
/// Asserted against a real `tracing` subscriber driving the real handler, not by grepping the
/// source: the failure mode here is an attribute macro's behaviour, which source text does not
/// show.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn ingest_must_not_log_the_request_body_and_must_not_log_at_info(pool: PgPool) {
    use std::sync::Mutex;
    use tracing::field::{Field, Visit};
    use tracing::{Level, Subscriber};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;

    #[derive(Default)]
    struct Captured {
        span_fields: Vec<(String, String)>,
        span_names: Vec<String>,
        events: Vec<(Level, String)>,
    }

    #[derive(Default)]
    struct FieldVisitor(Vec<(String, String)>);

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    struct CaptureLayer(Arc<Mutex<Captured>>);

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for CaptureLayer {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor::default();
            attrs.record(&mut visitor);
            let mut captured = self.0.lock().expect("capture mutex");
            captured
                .span_names
                .push(attrs.metadata().name().to_string());
            captured.span_fields.extend(visitor.0);
        }

        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            let message = visitor
                .0
                .iter()
                .find(|(name, _)| name == "message")
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            self.0
                .lock()
                .expect("capture mutex")
                .events
                .push((*event.metadata().level(), message));
        }
    }

    let captured = Arc::new(Mutex::new(Captured::default()));
    let subscriber = tracing_subscriber::registry().with(CaptureLayer(Arc::clone(&captured)));
    let _guard = tracing::subscriber::set_default(subscriber);

    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let state = Arc::new(UsageState {
        repo: Arc::new(build_repo(pool)),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
        raw_days: 90,
    });
    let app = build_ingest_router(state, readiness_pool, false);

    // A minimal, valid OTLP/JSON logs export carrying one record.
    let body = json!({
        "resourceLogs": [{
            "scopeLogs": [{
                "logRecords": [{
                    "timeUnixNano": "1756800000000000000",
                    "attributes": [
                        {"key": "account_id", "value": {"stringValue": "acct_1"}},
                        {"key": "model", "value": {"stringValue": "gpt-4.1"}}
                    ]
                }]
            }]
        }]
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/otel/logs")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let captured = captured.lock().expect("capture mutex");

    assert!(
        captured.span_names.iter().any(|name| name == "ingest_logs"),
        "expected an `ingest_logs` span, saw {:?}",
        captured.span_names
    );

    let field_names: Vec<&str> = captured
        .span_fields
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        field_names.contains(&"bytes"),
        "the span must record the payload SIZE, saw {field_names:?}"
    );
    assert!(
        !field_names.contains(&"body"),
        "the span must never record the payload itself, saw {field_names:?}"
    );
    assert!(
        !captured
            .span_fields
            .iter()
            .any(|(_, value)| value.contains("acct_1")),
        "no span field may echo the export's contents, saw {:?}",
        captured.span_fields
    );

    let accepted: Vec<&(Level, String)> = captured
        .events
        .iter()
        .filter(|(_, message)| message.contains("accepted") && message.contains("log events"))
        .collect();
    assert_eq!(
        accepted.len(),
        1,
        "expected exactly one accept line, saw {:?}",
        captured.events
    );
    assert_eq!(
        accepted[0].0,
        Level::DEBUG,
        "the accept line must be DEBUG, not INFO"
    );
    assert!(
        !captured
            .events
            .iter()
            .any(|(level, _)| *level == Level::INFO),
        "a successful ingest must log nothing at INFO, saw {:?}",
        captured.events
    );
}
