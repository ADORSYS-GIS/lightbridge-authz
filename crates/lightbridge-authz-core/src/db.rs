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
    pub async fn new(database: &Database) -> Result<Self> {
        let max_size = database.pool_size.unwrap_or(10) as u32;
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
