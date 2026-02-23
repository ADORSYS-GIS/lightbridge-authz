use crate::Result;
use crate::error::Error;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;

pub async fn run_migrations(
    database_url: &str,
    migrator: &'static Migrator,
    success_message: &str,
) -> Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;

    migrator
        .run(&pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

    tracing::info!("{success_message}");
    Ok(())
}
