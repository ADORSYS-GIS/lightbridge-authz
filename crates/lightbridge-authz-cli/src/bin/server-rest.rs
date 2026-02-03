use clap::Parser;
use lightbridge_authz_core::{Result, load_from_path};
use lightbridge_authz_rest::{start_api_server, start_opa_server};
use std::sync::Arc;

use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
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
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);

    let api = config.server.api.clone();
    let opa = config.server.opa.clone();
    let pool_api = pool.clone();
    let pool_opa = pool.clone();

    tokio::try_join!(
        start_api_server(&api, pool_api, &config.oauth2),
        start_opa_server(&opa, pool_opa)
    )?;

    Ok(())
}
