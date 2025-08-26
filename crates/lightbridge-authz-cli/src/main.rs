mod utils;

use clap::Parser;
use lightbridge_authz_core::Result;
use lightbridge_authz_grpc::start_grpc_server;
use lightbridge_authz_rest::start_rest_server;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::utils::banner::BANNER;
use crate::utils::cli::{Cli, Commands};
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    match Cli::parse().command {
        Some(Commands::Serve { config_path }) => {
            info!("{}", BANNER);

            let config = load_from_path(&config_path)?;

            info!("Connecting to DB...");
            let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);

            let (tx, mut rx) = mpsc::channel::<String>(32);

            let error_listener = tokio::spawn(async move {
                if let Some(error_msg) = rx.recv().await {
                    error!("Server error: {}", error_msg);
                    std::process::exit(1);
                }
            });

            if let Some(rest) = config.clone().server.rest {
                let config_clone = config.clone();
                let tx_clone = tx.clone();
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = start_rest_server(&rest, pool_clone, &config_clone.oauth2).await
                    {
                        let _ = tx_clone
                            .send(format!("REST server failed to start: {}", e))
                            .await;
                    }
                });
            }

            if let Some(grpc) = config.clone().server.grpc {
                let tx_clone = tx.clone();
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = start_grpc_server(&grpc, pool_clone).await {
                        let _ = tx_clone
                            .send(format!("gRPC server failed to start: {}", e))
                            .await;
                    }
                });
            }

            let _ = error_listener.await;
        }
        Some(Commands::Migrate { config_path }) => {
            let config = load_from_path(&config_path)?;
            lightbridge_authz_migrate::migrate(&config.database.url)?;
        }
        Some(Commands::Config { config_path }) => {
            let _ = load_from_path(&config_path)?;
        }
        None => {
            info!("No command provided. Use --help for more information.");
        }
    }
    Ok(())
}
