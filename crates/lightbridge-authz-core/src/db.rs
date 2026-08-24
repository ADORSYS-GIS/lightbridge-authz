use crate::config::Database;
use crate::error::Result;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct DbPool {
    pool: PgPool,
}

#[crate::async_trait]
pub trait DbPoolTrait: Send + Sync + std::fmt::Debug {
    fn pool(&self) -> &PgPool;
}

impl DbPool {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn new(database: &Database) -> Result<Self> {
        Self::new_with_retry(
            database,
            30,
            Duration::from_millis(250),
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await
    }

    /// Connect with explicit retry bounds so tests can exercise the failure path
    /// without paying the production backoff (30 attempts, up to 5s each) or the
    /// 30s `acquire_timeout` against an unreachable host.
    pub async fn new_with_retry(
        database: &Database,
        max_attempts: u32,
        base_backoff: Duration,
        max_backoff: Duration,
        acquire_timeout: Duration,
    ) -> Result<Self> {
        let max_size = database.pool_size.unwrap_or(10);
        let options = PgPoolOptions::new()
            .max_connections(max_size)
            .min_connections(5)
            .acquire_timeout(acquire_timeout);

        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match options.clone().connect(&database.url).await {
                Ok(pool) => {
                    if attempt > 1 {
                        tracing::info!(attempt, "connected to database after retrying");
                    }
                    return Ok(Self { pool });
                }
                Err(err) if attempt >= max_attempts => {
                    tracing::error!(
                        attempt,
                        error = %err,
                        "database connection failed after exhausting retries"
                    );
                    return Err(err.into());
                }
                Err(err) => {
                    let backoff = base_backoff.saturating_mul(attempt).min(max_backoff);
                    tracing::warn!(
                        attempt,
                        error = %err,
                        backoff_ms = backoff.as_millis() as u64,
                        "database not ready, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
}

#[crate::async_trait]
impl DbPoolTrait for DbPool {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

pub async fn is_database_ready(pool: &dyn DbPoolTrait) -> bool {
    matches!(
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(pool.pool())
            .await,
        Ok(1)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn readiness_check_returns_false_when_database_is_down() {
        let pool = PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        let pool = DbPool::from_pool(pool);

        assert!(!is_database_ready(&pool).await);
    }
}
