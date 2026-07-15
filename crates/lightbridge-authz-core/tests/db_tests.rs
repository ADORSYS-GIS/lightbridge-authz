use lightbridge_authz_core::config::Database;
use lightbridge_authz_core::db::DbPool;

fn unreachable_database(pool_size: u32) -> Database {
    Database {
        url: "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz".to_string(),
        pool_size: Some(pool_size),
    }
}

#[tokio::test(start_paused = true)]
async fn new_returns_error_after_exhausting_retries_against_unreachable_database() {
    let database = unreachable_database(3);

    let result = DbPool::new(&database).await;

    assert!(
        result.is_err(),
        "connecting to an unreachable database should fail once retries are exhausted"
    );
}

#[tokio::test(start_paused = true)]
async fn new_defaults_pool_size_when_unset() {
    let database = Database {
        url: "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz".to_string(),
        pool_size: None,
    };

    let result = DbPool::new(&database).await;

    assert!(result.is_err());
}
