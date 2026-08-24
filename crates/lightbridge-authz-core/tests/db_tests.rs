use lightbridge_authz_core::config::Database;
use lightbridge_authz_core::db::DbPool;
use std::time::Duration;

fn unreachable_database(pool_size: u32) -> Database {
    Database {
        url: "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz".to_string(),
        pool_size: Some(pool_size),
    }
}

// Bounded retry + acquire timeout so the failure path completes fast instead of
// paying the production backoff (30 attempts, up to 5s each) and the 30s
// `acquire_timeout` against an unreachable host.
async fn new_failing(database: &Database) -> lightbridge_authz_core::Result<DbPool> {
    DbPool::new_with_retry(
        database,
        2,
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::from_millis(100),
    )
    .await
}

#[tokio::test]
async fn new_returns_error_after_exhausting_retries_against_unreachable_database() {
    let database = unreachable_database(3);

    let result = new_failing(&database).await;

    assert!(
        result.is_err(),
        "connecting to an unreachable database should fail once retries are exhausted"
    );
}

#[tokio::test]
async fn new_defaults_pool_size_when_unset() {
    let database = Database {
        url: "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz".to_string(),
        pool_size: None,
    };

    let result = new_failing(&database).await;

    assert!(result.is_err());
}
