use clap::Parser;
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_migrate::migrate;

#[derive(Parser)]
#[command(name = "lightbridge-authz-migrate", about = "Runs database migrations")]
struct Cli {
    #[arg(long, short, env = "CONFIG_PATH")]
    config: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let config = load_from_path(&cli.config)?;
    migrate(&config.database.url)?;

    Ok(())
}
