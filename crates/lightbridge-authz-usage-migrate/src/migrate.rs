use lightbridge_authz_core::Result;
use lightbridge_authz_core::migrate::run_migrations;

pub static USAGE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations-usage");

pub async fn migrate(database_url: &str) -> Result<()> {
    run_migrations(
        database_url,
        &USAGE_MIGRATOR,
        "Usage database migrations completed successfully.",
    )
    .await
}
