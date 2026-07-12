use clap::{Parser, Subcommand};
use lightbridge_authz::mcp::start_mcp_server_from_config;
use lightbridge_authz_core::{Result, config::load_from_path};
use mimalloc::MiMalloc;
use tracing::info;

const BANNER: &str = r#"
                  _
 |  o  _  |_ _|_ |_) ._ o  _|  _   _     /\     _|_ |_  _
 |_ | (_| | | |_ |_) |  | (_| (_| (/_   /--\ |_| |_ | | /_
       _|                      _|

    mcp

"#;

#[derive(Parser)]
#[command(
    name = "lightbridge-mcp",
    author,
    version,
    about = "LightBridge MCP CLI",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Config {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
}

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_path = match &cli.command {
        Some(Commands::Serve { config_path }) | Some(Commands::Config { config_path }) => {
            Some(config_path)
        }
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
            info!("{BANNER}");
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
