// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database coverage for `oauth2_op::device_store` (ADR-0012 Decision 7, #423): the real
//! `DeviceCodeStore` trait implementation over `device_authorizations`, plus the standalone
//! `create_pending_device_authorization`/`get_by_user_code_rate_limited` helpers a future
//! `/device_authorization` endpoint ticket is expected to call directly (see that module's own
//! doc comment for why they are free functions, not trait methods).
//!
//! Gated behind `it-tests` / `just it-tests` (needs a migrated Postgres via `DATABASE_URL`), same
//! as this crate's other `it-tests` files.

#![cfg(feature = "it-tests")]

use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use chrono::{Duration, Utc};
use cratestack_axum::ratelimit::{InMemoryRateLimitStore, RateLimitConfig};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::oauth2_op::device_store::{
    DbDeviceCodeStore, create_pending_device_authorization, get_by_user_code_rate_limited,
};
use sqlx::PgPool;

fn repo(pool: PgPool) -> Arc<StoreRepo> {
    let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(db_pool))
}

fn identity(sub: &str) -> Identity {
    Identity {
        provider_id: "keycloak".to_string(),
        external_id: sub.to_string(),
        email: None,
        username: None,
        attributes: Default::default(),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn store_then_get_round_trips_a_pending_session(pool: PgPool) {
    let store = DbDeviceCodeStore::new(repo(pool));
    let session = DeviceCodeSession {
        device_code: "dc-store-get".to_string(),
        user_code: "STOREGET".to_string(),
        client_id: "device-client".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::minutes(10),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    };

    store.store_device_code(session.clone()).await.unwrap();

    let fetched = store
        .get_device_code("dc-store-get")
        .await
        .unwrap()
        .expect("just-stored session must be readable back");
    assert_eq!(fetched.user_code, "STOREGET");
    assert!(matches!(fetched.status, DeviceCodeStatus::Pending));
}

#[sqlx::test(migrations = "../../migrations")]
async fn re_storing_a_pending_session_touches_last_polled_at_without_changing_status(pool: PgPool) {
    let store = DbDeviceCodeStore::new(repo(pool));
    let session = DeviceCodeSession {
        device_code: "dc-repoll".to_string(),
        user_code: "REPOLL01".to_string(),
        client_id: "device-client".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::minutes(10),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    };
    store.store_device_code(session.clone()).await.unwrap();

    let mut polled = session.clone();
    polled.last_polled_at = Some(Utc::now());
    store.store_device_code(polled).await.unwrap();

    let fetched = store
        .get_device_code("dc-repoll")
        .await
        .unwrap()
        .expect("row must still exist after the polling re-store");
    assert!(fetched.last_polled_at.is_some());
    assert!(matches!(fetched.status, DeviceCodeStatus::Pending));
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_device_code_with_approved_status_cas_approves_the_row(pool: PgPool) {
    let store = DbDeviceCodeStore::new(repo(pool));
    let session = DeviceCodeSession {
        device_code: "dc-approve".to_string(),
        user_code: "APPROVE1".to_string(),
        client_id: "device-client".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::minutes(10),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    };
    store.store_device_code(session.clone()).await.unwrap();

    let mut approved = session;
    approved.status = DeviceCodeStatus::Approved(identity("kc-sub-approve"));
    store.update_device_code(approved).await.unwrap();

    let fetched = store
        .get_device_code("dc-approve")
        .await
        .unwrap()
        .expect("approved row must still be readable");
    match fetched.status {
        DeviceCodeStatus::Approved(identity) => {
            assert_eq!(identity.external_id, "kc-sub-approve");
        }
        other => panic!("expected Approved, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn consume_device_code_is_single_use(pool: PgPool) {
    let store = DbDeviceCodeStore::new(repo(pool));
    let session = DeviceCodeSession {
        device_code: "dc-consume".to_string(),
        user_code: "CONSUME1".to_string(),
        client_id: "device-client".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::minutes(10),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    };
    store.store_device_code(session.clone()).await.unwrap();
    let mut approved = session;
    approved.status = DeviceCodeStatus::Approved(identity("kc-sub-consume"));
    store.update_device_code(approved).await.unwrap();

    let first = store.consume_device_code("dc-consume").await.unwrap();
    assert!(first.is_some());

    let second = store.consume_device_code("dc-consume").await.unwrap();
    assert!(
        second.is_none(),
        "consuming an already-consumed device code must return None"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_by_user_code_is_case_insensitive(pool: PgPool) {
    let repo = repo(pool);
    let session = create_pending_device_authorization(
        &repo,
        "device-client",
        "openid",
        Duration::minutes(10),
        5,
    )
    .await
    .unwrap();

    let store = DbDeviceCodeStore::new(repo);
    let lowercase = session.user_code.to_lowercase();
    let fetched = store
        .get_by_user_code(&lowercase)
        .await
        .unwrap()
        .expect("a lower-cased submission of the same code must still resolve");
    assert_eq!(fetched.device_code, session.device_code);
}

#[sqlx::test(migrations = "../../migrations")]
async fn delete_device_code_removes_the_row(pool: PgPool) {
    let store = DbDeviceCodeStore::new(repo(pool));
    let session = DeviceCodeSession {
        device_code: "dc-delete".to_string(),
        user_code: "DELETE01".to_string(),
        client_id: "device-client".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::minutes(10),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    };
    store.store_device_code(session).await.unwrap();
    store.delete_device_code("dc-delete").await.unwrap();

    let fetched = store.get_device_code("dc-delete").await.unwrap();
    assert!(fetched.is_none());
}

/// Functional proof of the rate-limited lookup wrapper: with a burst of 1 and no refill, the
/// first submission for a given `caller_key` succeeds and the second is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn get_by_user_code_rate_limited_throttles_after_the_configured_burst(pool: PgPool) {
    let repo = repo(pool);
    let session = create_pending_device_authorization(
        &repo,
        "device-client",
        "openid",
        Duration::minutes(10),
        5,
    )
    .await
    .unwrap();

    let limiter = InMemoryRateLimitStore::new();
    let config = RateLimitConfig::new(1, 0.0);
    let caller_key = "test-caller";

    let first =
        get_by_user_code_rate_limited(&repo, &limiter, config, caller_key, &session.user_code)
            .await
            .expect("the first submission within burst must be allowed");
    assert!(first.is_some());

    let second =
        get_by_user_code_rate_limited(&repo, &limiter, config, caller_key, &session.user_code)
            .await;
    assert!(
        second.is_err(),
        "a second submission from the same caller, past the burst, must be refused"
    );
}

/// A different `caller_key` gets its own bucket -- throttling one caller must not throttle
/// another.
#[sqlx::test(migrations = "../../migrations")]
async fn get_by_user_code_rate_limited_buckets_are_per_caller(pool: PgPool) {
    let repo = repo(pool);
    let session = create_pending_device_authorization(
        &repo,
        "device-client",
        "openid",
        Duration::minutes(10),
        5,
    )
    .await
    .unwrap();

    let limiter = InMemoryRateLimitStore::new();
    let config = RateLimitConfig::new(1, 0.0);

    get_by_user_code_rate_limited(&repo, &limiter, config, "caller-a", &session.user_code)
        .await
        .expect("caller-a's first submission must be allowed")
        .expect("row exists");

    let other_caller =
        get_by_user_code_rate_limited(&repo, &limiter, config, "caller-b", &session.user_code)
            .await;
    assert!(
        other_caller.is_ok(),
        "caller-b must have its own, unconsumed bucket"
    );
}
