use crate::error::{Error, Result};
use anyhow::anyhow;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::{Pool, PooledConnection};

#[derive(Clone, Debug)]
pub struct DbPool {
    pool: Pool<AsyncPgConnection>,
}

impl DbPool {
    pub async fn new(database_url: &str) -> Result<Self> {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(20) // Increase maximum connections
            .min_idle(Some(5)) // Maintain minimum idle connections
            .connection_timeout(std::time::Duration::from_secs(30)) // Increase connection timeout
            .build(manager)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(Self { pool })
    }

    pub async fn get(&self) -> Result<PooledConnection<'_, AsyncPgConnection>> {
        self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))
    }
}
