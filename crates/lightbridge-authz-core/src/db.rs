use crate::config::Database;
use crate::error::{Error, Result};
use anyhow::anyhow;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::{Pool, PooledConnection};
use tracing;

#[derive(Clone, Debug)]
pub struct DbPool {
    pool: Pool<AsyncPgConnection>,
}

#[crate::async_trait]
pub trait DbPoolTrait: Send + Sync + std::fmt::Debug {
    async fn get(&self) -> Result<PooledConnection<'_, AsyncPgConnection>>;
}

impl DbPool {
    pub async fn new(database: &Database) -> Result<Self> {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database.url);
        let max_size = database.pool_size.unwrap_or(10);

        tracing::debug!("Building connection pool with max_size={}", max_size);
        
        let pool = Pool::builder()
            .max_size(max_size)
            .test_on_check_out(false)
            .connection_timeout(std::time::Duration::from_secs(30))
            .build(manager)
            .await
            .map_err(anyhow::Error::from)?;
        
        tracing::debug!("Connection pool built successfully");
        Ok(Self { pool })
    }
}

#[crate::async_trait]
impl DbPoolTrait for DbPool {
    async fn get(&self) -> Result<PooledConnection<'_, AsyncPgConnection>> {
        self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))
    }
}
