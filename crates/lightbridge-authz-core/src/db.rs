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
        let max_size = database.pool_size.unwrap_or(10);
        let pool = PgPoolOptions::new()
            .max_connections(max_size)
            .min_connections(5)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&database.url)
            .await?;
        Ok(Self { pool })
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
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        let pool = DbPool::from_pool(pool);

        assert!(!is_database_ready(&pool).await);
    }
}
