use diesel::{Connection, PgConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use lightbridge_authz_core::{Error, Result};
use tracing::{error, info};

// embed migrations from the workspace migrations/ folder
// path is relative to this crate root
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");

pub fn migrate(database_url: &str) -> Result<()> {
    // Establish a direct PgConnection for running migrations
    let mut conn = PgConnection::establish(database_url)
        .map_err(|e| Error::Database(format!("Failed to establish DB connection: {}", e)))?;

    // Run pending migrations using diesel_migrations' MigrationHarness
    if let Err(e) = conn.run_pending_migrations(MIGRATIONS) {
        error!("Failed to run database migrations: {}", e);
        std::process::exit(1);
    } else {
        info!("Database migrations completed successfully.");
    }

    Ok(())
}
