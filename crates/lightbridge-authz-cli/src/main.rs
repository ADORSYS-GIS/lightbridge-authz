use clap::{Parser, Subcommand};
use lightbridge_authz_rest::start_rest_server;
use tracing::info;

#[derive(Parser)]
#[command(name = "lightbridge-authz")]
#[command(about = "Lightbridge Authz CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(long)]
        config: String,
        #[arg(long)]
        rest: bool,
        #[arg(long)]
        grpc: bool,
    },
    Config {
        #[arg(long)]
        config: String,
        #[arg(long)]
        check_config: bool,
    },
    Client {
        #[arg(long)]
        config: String,
        #[arg(long, default_value = "rest")]
        transport: String,
        #[arg(long)]
        health: bool,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve {
            config: _,
            rest,
            grpc: _,
        }) => {
            if rest {
                let config =
                    lightbridge_authz_core::config::load_from_path("config/default.yaml").unwrap();
                start_rest_server(&config).await.unwrap();
            }
        }
        Some(Commands::Config {
            config: _,
            check_config: _,
        }) => {
            info!("Config command not yet implemented.");
        }
        Some(Commands::Client {
            config: _,
            transport: _,
            health: _,
        }) => {
            info!("Client command not yet implemented.");
        }
        None => {
            info!("No command provided. Use --help for more information.");
        }
    }
}
