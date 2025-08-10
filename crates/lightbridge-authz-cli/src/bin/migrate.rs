// crates/lightbridge-authz-cli/src/bin/migrate.rs
use clap::Parser;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::error::{Error, Result};
use tracing::{error, info};

// embed migrations from the workspace migrations/ folder
// path is relative to this crate root
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");

#[derive(Parser)]
#[command(name = "lightbridge-authz-migrate", about = "Runs database migrations")]
struct Cli {
    #[arg(long, short)]
    config: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let config = load_from_path(&cli.config)?;

    // Establish a direct PgConnection for running migrations
    let mut conn = PgConnection::establish(&config.database.url)
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
