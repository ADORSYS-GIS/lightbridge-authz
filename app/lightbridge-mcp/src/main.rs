mod utils;

use clap::Parser;
use lightbridge_authz_core::{Result, config::load_from_path};
use lightbridge_authz_mcp::start_mcp_server_from_config;
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
        Some(Commands::Config { config_path }) => Some(config_path),
        None => None,
    };

    if let Some(path) = config_path {
        let config = load_from_path(path)?;
        lightbridge_authz_core::tracing::init_tracing(&config);
    } else {
        tracing_subscriber::fmt::init();
    }

    let result = match cli.command {
        Some(Commands::Serve { config_path }) => {
            info!("{}", BANNER);
            let config = load_from_path(&config_path)?;
            start_mcp_server_from_config(&config).await
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

    lightbridge_authz_core::tracing::shutdown_tracing();

    result
}
