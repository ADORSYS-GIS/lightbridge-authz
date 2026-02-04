mod utils;

use clap::Parser;
use lightbridge_authz_core::Result;
use lightbridge_authz_rest::{start_api_server, start_opa_server};
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

            let api = config.clone().server.api;
            let opa = config.clone().server.opa;

            let config_clone = config.clone();
            let tx_clone = tx.clone();
            let pool_clone = pool.clone();
            tokio::spawn(async move {
                if let Err(e) = start_api_server(&api, pool_clone, &config_clone.oauth2).await {
                    let _ = tx_clone
                        .send(format!("API server failed to start: {}", e))
                        .await;
                }
            });

            let tx_clone = tx.clone();
            let pool_clone = pool.clone();
            tokio::spawn(async move {
                if let Err(e) = start_opa_server(&opa, pool_clone).await {
                    let _ = tx_clone
                        .send(format!("OPA server failed to start: {}", e))
                        .await;
                }
            });

            let _ = error_listener.await;
        }
        Some(Commands::Api { config_path }) => {
            info!("{}", BANNER);

            let config = load_from_path(&config_path)?;

            info!("Connecting to DB...");
            let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);

            start_api_server(&config.server.api, pool, &config.oauth2).await?;
        }
        Some(Commands::Opa { config_path }) => {
            info!("{}", BANNER);

            let config = load_from_path(&config_path)?;

            info!("Connecting to DB...");
            let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);

            start_opa_server(&config.server.opa, pool).await?;
        }
        Some(Commands::Migrate { config_path }) => {
            let config = load_from_path(&config_path)?;
            lightbridge_authz_migrate::migrate(&config.database.url).await?;
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
