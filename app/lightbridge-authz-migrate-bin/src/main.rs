use clap::Parser;
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_migrate::migrate;

#[derive(Parser)]
#[command(
    name = "lightbridge-authz-migrate-bin",
    about = "Runs database migrations"
)]
struct Cli {
    #[arg(long, short, env = "CONFIG_PATH")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = load_from_path(&cli.config)?;
    lightbridge_authz_core::tracing::init_tracing(&config);

    let result = migrate(&config.database.url).await;

    lightbridge_authz_core::tracing::shutdown_tracing();

    result
}
