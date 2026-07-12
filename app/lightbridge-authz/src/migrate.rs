use lightbridge_authz_core::Result;
use lightbridge_authz_core::migrate::run_migrations;

static AUTHZ_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub async fn migrate(database_url: &str) -> Result<()> {
    run_migrations(
        database_url,
        &AUTHZ_MIGRATOR,
        "Database migrations completed successfully.",
    )
    .await
}
