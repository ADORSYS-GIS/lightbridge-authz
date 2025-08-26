use clap::Parser;
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::{Error, Result};
use lightbridge_authz_grpc::start_grpc_server;
use std::sync::Arc;

use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use mimalloc::MiMalloc;
use tracing::info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(name = "lightbridge-authz-grpc")]
#[command(about = "Lightbridge Authz gRPC", long_about = None)]
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

    if let Some(grpc) = config.server.grpc {
        start_grpc_server(&grpc, pool).await?
    } else {
        return Err(Error::Server("no server gRPC was configured".to_string()));
    }

    Ok(())
}
