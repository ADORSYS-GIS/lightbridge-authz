mod migrate;
mod utils;

use clap::Parser;
use lightbridge_authz_core::Result;
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
        // `version` reads no config on purpose -- see the subcommand's doc comment.
        Some(Commands::Version) => None,
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
            start_usage_server(
                &config.server.usage,
                &config.server.query,
                &config.database,
                &config.oauth2,
                &config.scope_authority,
            )
            .await
        }
        Some(Commands::Migrate { config_path }) => {
            let config = load_from_path(&config_path)?;
            migrate::migrate(&config.database.url).await
        }
        Some(Commands::Config { config_path }) => {
            let _ = load_from_path(&config_path)?;
            Ok(())
        }
        Some(Commands::Version) => {
            let info = lightbridge_authz_core::build_info(crate::utils::cli::SERVICE_CLI);
            println!(
                "{}",
                serde_json::to_string_pretty(&info).map_err(|e| {
                    lightbridge_authz_core::Error::Server(format!(
                        "failed to serialize build info: {e}"
                    ))
                })?
            );
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
