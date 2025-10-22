pub mod api;

use clap::Parser;
use diesel::{Connection, PgConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Database URL for the test database
    #[arg(short, long, env = "DATABASE_URL")]
    database_url: String,
}

/// Establishes a connection to the test database.
/// The database URL is read from the `DATABASE_URL` environment variable or CLI argument.
pub fn establish_connection() -> PgConnection {
    let cli = Cli::parse();
    PgConnection::establish(&cli.database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", cli.database_url))
}

/// Runs all pending database migrations.
pub fn run_migrations(connection: &mut PgConnection) {
    connection.run_pending_migrations(MIGRATIONS).unwrap();
}

/// Sets up a clean database state for testing.
/// This function establishes a new connection, runs migrations, and returns the connection.
/// It's intended to be used at the beginning of each test to ensure isolation.
pub fn setup_test_db() -> PgConnection {
    let mut connection = establish_connection();
    run_migrations(&mut connection);
    connection
}
