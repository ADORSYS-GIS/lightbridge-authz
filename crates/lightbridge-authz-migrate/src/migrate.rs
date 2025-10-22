use diesel::{Connection, PgConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use lightbridge_authz_core::Result;
use tracing::info;

// embed migrations from the workspace migrations/ folder
// path is relative to this crate root
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");

pub fn migrate(database_url: &str) -> Result<()> {
    // Establish a direct PgConnection for running migrations
    let mut conn = PgConnection::establish(database_url)?;

    if let Err(e) = conn.run_pending_migrations(MIGRATIONS) {
        panic!("Failed to run database migrations: {}", e);
    }

    info!("Database migrations completed successfully.");
    Ok(())
}
