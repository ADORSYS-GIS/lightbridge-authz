use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::Result;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

pub async fn migrate(database_url: &str) -> Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;

    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;
    info!("Database migrations completed successfully.");
    Ok(())
}
