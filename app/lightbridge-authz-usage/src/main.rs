mod utils;

use clap::Parser;
use lightbridge_authz_core::Result;
use lightbridge_authz_usage_migrate::migrate;
use lightbridge_authz_usage_rest::{load_from_path, start_usage_server};
use mimalloc::MiMalloc;
use tracing::info;

use crate::utils::banner::BANNER;
use crate::utils::cli::{Cli, Commands};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_path = match &cli.command {
        Some(Commands::Serve { config_path }) => Some(config_path),
        Some(Commands::Migrate { config_path }) => Some(config_path),
        Some(Commands::Config { config_path }) => Some(config_path),
        None => None,
    };

     if let Some(path) = config_path {
         let config = load_from_path(path)?;
         lightbridge_authz_usage_rest::instrumentation::init_tracing(&config);
     } else {
         tracing_subscriber::fmt::init();
     }

    let result = match cli.command {
        Some(Commands::Serve { config_path }) => {
            info!("{}", BANNER);
            let config = load_from_path(&config_path)?;
            start_usage_server(&config.server.usage, &config.database).await
        }
        Some(Commands::Migrate { config_path }) => {
            let config = load_from_path(&config_path)?;
            migrate(&config.database.url).await
        }
        Some(Commands::Config { config_path }) => {
            let _ = load_from_path(&config_path)?;
            Ok(())
        }
        None => {
            info!("No command provided. Use --help for more information.");
            Ok(())
        }
    };

     lightbridge_authz_usage_rest::instrumentation::shutdown_tracing();
 
     result
 }
