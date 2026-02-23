pub mod api;

use clap::Parser;
use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Database URL for the test database
    #[arg(short, long, env = "DATABASE_URL")]
    database_url: String,
}

/// Establishes a connection to the test database.
/// The database URL is read from the `DATABASE_URL` environment variable or CLI argument.
pub async fn establish_pool() -> PgPool {
    let cli = Cli::parse();
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&cli.database_url)
        .await
        .unwrap_or_else(|_| panic!("Error connecting to {}", cli.database_url))
}

/// Runs all pending database migrations.
pub async fn run_migrations(pool: &PgPool) {
    sqlx::migrate!("../../migrations").run(pool).await.unwrap();
}

/// Sets up a clean database state for testing.
/// This function establishes a new connection, runs migrations, and returns the connection.
/// It's intended to be used at the beginning of each test to ensure isolation.
pub async fn setup_test_db() -> PgPool {
    let pool = establish_pool().await;
    run_migrations(&pool).await;
    pool
}
