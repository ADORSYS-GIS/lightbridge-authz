use clap::Parser;
use lightbridge_authz_core::{Error, Result, load_from_path};
use lightbridge_authz_rest::start_rest_server;
use std::sync::Arc;

use lightbridge_authz_core::db::DbPool;
use mimalloc::MiMalloc;
use tracing::info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(name = "lightbridge-authz-rest")]
#[command(about = "Lightbridge Authz REST", long_about = None)]
struct Cli {
    #[arg(long, short)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let Cli { config } = Cli::parse();

    let config = load_from_path(&config)?;

    info!("Connecting to DB...");
    let pool = Arc::new(DbPool::new(&config.database).await?);

    if let Some(rest) = config.server.rest {
        start_rest_server(&rest, pool, &config.oauth2).await?
    } else {
        return Err(Error::Server("no server Rest was configured".to_string()));
    }

    Ok(())
}
