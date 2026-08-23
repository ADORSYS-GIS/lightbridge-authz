#![cfg(feature = "it-tests")]
#![allow(clippy::unwrap_used)]

//! Postgres-backed coverage for `StoreRepo`'s `device_authorizations` methods (ADR-0012 Decision
//! 7, #423). Two things this file exists specifically to prove, per the ticket's own acceptance
//! criteria:
//!
//! 1. The CAS claim is demonstrated, not assumed --
//!    `concurrent_consume_of_the_same_approved_row_succeeds_exactly_once` below races two REAL
//!    concurrent `tokio::spawn` tasks against the same row, mirroring
//!    `lightbridge-authz-budget`'s `review_service_tests.rs` concurrency-proof pattern.
//! 2. Single-use enforcement: `consume_device_authorization` called twice on the same row returns
//!    `Some` once and `None` the second time.

use chrono::{Duration, Utc};
use lightbridge_authz_api_key::entities::device_authorization_row::NewDeviceAuthorization;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use sqlx::PgPool;
use std::sync::Arc;

fn repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

fn new_pending(device_code: &str, user_code: &str, ttl: Duration) -> NewDeviceAuthorization {
    NewDeviceAuthorization {
        id: cuid2(),
        device_code: device_code.to_string(),
        user_code: user_code.to_string(),
        client_id: "device-client".to_string(),
        scope: Some("openid".to_string()),
        interval_secs: 5,
        expires_at: Utc::now() + ttl,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_persists_a_pending_row_with_the_specified_ttl(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    let user_code = "ABCD2345";

    let row = repo
        .create_device_authorization(new_pending(&device_code, user_code, Duration::minutes(10)))
        .await
        .unwrap();

    assert_eq!(row.status, "pending");
    assert_eq!(row.device_code, device_code);
    assert_eq!(row.user_code, user_code);
    assert!(row.subject.is_none());
    assert!(row.expires_at > Utc::now() + Duration::minutes(9));
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_with_a_duplicate_user_code_is_a_conflict(pool: PgPool) {
    let repo = repo(pool);
    let user_code = "SAME1234";
    repo.create_device_authorization(new_pending(
        &format!("dc-{}", cuid2()),
        user_code,
        Duration::minutes(10),
    ))
    .await
    .unwrap();

    let err = repo
        .create_device_authorization(new_pending(
            &format!("dc-{}", cuid2()),
            user_code,
            Duration::minutes(10),
        ))
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Conflict(_)));
}

#[sqlx::test(migrations = "../../migrations")]
async fn approve_transitions_pending_to_approved_and_stamps_subject(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    repo.create_device_authorization(new_pending(&device_code, "APRV0001", Duration::minutes(10)))
        .await
        .unwrap();

    let approved = repo
        .approve_device_authorization(&device_code, "kc-subject-1", Utc::now())
        .await
        .unwrap()
        .expect("a pending row must be approvable");

    assert_eq!(approved.status, "approved");
    assert_eq!(approved.subject.as_deref(), Some("kc-subject-1"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn approve_fails_once_the_row_is_no_longer_pending(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    repo.create_device_authorization(new_pending(&device_code, "APRV0002", Duration::minutes(10)))
        .await
        .unwrap();
    repo.approve_device_authorization(&device_code, "kc-subject-1", Utc::now())
        .await
        .unwrap()
        .expect("first approval must succeed");

    // Prove-fail-first target #1: a second approval attempt on an already-approved row must be
    // rejected by the CAS guard (`WHERE status = 'pending'`), not silently re-applied.
    let second = repo
        .approve_device_authorization(&device_code, "kc-subject-2", Utc::now())
        .await
        .unwrap();
    assert!(
        second.is_none(),
        "an already-approved row must not be re-approvable"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn deny_transitions_pending_to_denied_with_no_subject(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    repo.create_device_authorization(new_pending(&device_code, "DENY0001", Duration::minutes(10)))
        .await
        .unwrap();

    let denied = repo
        .deny_device_authorization(&device_code, Utc::now())
        .await
        .unwrap()
        .expect("a pending row must be deniable");

    assert_eq!(denied.status, "denied");
    assert!(denied.subject.is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn consume_is_single_use(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    repo.create_device_authorization(new_pending(&device_code, "CNSM0001", Duration::minutes(10)))
        .await
        .unwrap();
    repo.approve_device_authorization(&device_code, "kc-subject-1", Utc::now())
        .await
        .unwrap()
        .expect("approval must succeed");

    let first = repo
        .consume_device_authorization(&device_code, Utc::now())
        .await
        .unwrap();
    assert!(first.is_some(), "the first consume must succeed");
    // The returned row reflects the PRE-consume status ("approved" here) -- the caller (the
    // upstream token endpoint) needs to know whether the code was approved or denied, and by
    // whom, which the post-update "consumed" value can no longer express. See
    // `consume_device_authorization`'s own doc comment for why this is a `WITH ... FOR UPDATE`
    // CTE rather than a plain `UPDATE ... RETURNING`.
    assert_eq!(first.unwrap().status, "approved");

    // Prove-fail-first target #2: a second consume of the same device_code must observe the row
    // no longer matches `status IN ('approved', 'denied')` and return `None`.
    let second = repo
        .consume_device_authorization(&device_code, Utc::now())
        .await
        .unwrap();
    assert!(
        second.is_none(),
        "consuming an already-consumed device code must return None"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn expired_row_is_treated_as_absent_by_both_read_paths(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    let user_code = "EXPR0001";
    // A negative TTL backdates `expires_at` into the past -- the row exists, but every read path
    // must treat it as gone.
    repo.create_device_authorization(new_pending(&device_code, user_code, Duration::seconds(-60)))
        .await
        .unwrap();

    let by_device_code = repo
        .find_active_device_authorization_by_device_code(&device_code, Utc::now())
        .await
        .unwrap();
    let by_user_code = repo
        .find_active_device_authorization_by_user_code(user_code, Utc::now())
        .await
        .unwrap();

    assert!(
        by_device_code.is_none(),
        "an expired row must be invisible to find_active_device_authorization_by_device_code"
    );
    assert!(
        by_user_code.is_none(),
        "an expired row must be invisible to find_active_device_authorization_by_user_code"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn consumed_row_is_treated_as_absent_by_read_paths(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    repo.create_device_authorization(new_pending(&device_code, "READ0001", Duration::minutes(10)))
        .await
        .unwrap();
    repo.approve_device_authorization(&device_code, "kc-subject-1", Utc::now())
        .await
        .unwrap();
    repo.consume_device_authorization(&device_code, Utc::now())
        .await
        .unwrap();

    let found = repo
        .find_active_device_authorization_by_device_code(&device_code, Utc::now())
        .await
        .unwrap();
    assert!(
        found.is_none(),
        "a consumed row must be invisible to get_device_code's backing read path"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn delete_removes_the_row_unconditionally(pool: PgPool) {
    let repo = repo(pool);
    let device_code = format!("dc-{}", cuid2());
    repo.create_device_authorization(new_pending(&device_code, "DELT0001", Duration::minutes(10)))
        .await
        .unwrap();

    repo.delete_device_authorization(&device_code)
        .await
        .unwrap();
    // Deleting an already-gone row is a no-op, not an error.
    repo.delete_device_authorization(&device_code)
        .await
        .unwrap();

    let found = repo
        .find_active_device_authorization_by_device_code(&device_code, Utc::now())
        .await
        .unwrap();
    assert!(found.is_none());
}

/// The real concurrency proof (ticket acceptance criterion: "prove this with a real concurrent
/// test against Postgres, not a single-threaded simulation"). Two genuinely concurrent
/// `tokio::spawn` tasks race to consume the SAME already-approved row. Postgres's row lock during
/// the `UPDATE ... WHERE status IN (...) ... RETURNING` statement is what the ticket claims makes
/// this safe -- this test is the demonstration, not an assumption.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_consume_of_the_same_approved_row_succeeds_exactly_once(pool: PgPool) {
    let repo = Arc::new(repo(pool));
    let device_code = format!("dc-{}", cuid2());
    repo.create_device_authorization(new_pending(&device_code, "RACE0001", Duration::minutes(10)))
        .await
        .unwrap();
    repo.approve_device_authorization(&device_code, "kc-subject-1", Utc::now())
        .await
        .unwrap();

    let repo_a = repo.clone();
    let device_code_a = device_code.clone();
    let repo_b = repo.clone();
    let device_code_b = device_code.clone();

    let task_a = tokio::spawn(async move {
        repo_a
            .consume_device_authorization(&device_code_a, Utc::now())
            .await
            .unwrap()
    });
    let task_b = tokio::spawn(async move {
        repo_b
            .consume_device_authorization(&device_code_b, Utc::now())
            .await
            .unwrap()
    });

    let (result_a, result_b) = tokio::try_join!(task_a, task_b).expect("neither task must panic");

    let a_won = result_a.is_some();
    let b_won = result_b.is_some();
    assert_ne!(
        a_won, b_won,
        "exactly one of the two racing consumes must succeed, got a={result_a:?} b={result_b:?}"
    );
}
