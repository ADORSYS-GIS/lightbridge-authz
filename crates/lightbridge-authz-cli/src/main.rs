use clap::{Parser, Subcommand};
use lightbridge_authz_grpc::start_grpc_server;
use lightbridge_authz_rest::start_rest_server;
use tokio::sync::mpsc;
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
        #[arg(long, short)]
        config: String,
    },
    Config {
        #[arg(long, short)]
        config: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), lightbridge_authz_core::error::Error> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve { config }) => {
            let config = lightbridge_authz_core::config::load_from_path(&config).unwrap();

            let (tx, mut rx) = mpsc::channel::<String>(32);

            let error_listener = tokio::spawn(async move {
                if let Some(error_msg) = rx.recv().await {
                    eprintln!("Server error: {}", error_msg);
                    std::process::exit(1);
                }
            });

            if let Some(rest) = config.clone().server.rest {
                let config_clone = config.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = start_rest_server(&rest, &config_clone.database).await {
                        let _ = tx_clone
                            .send(format!("REST server failed to start: {}", e))
                            .await;
                    }
                });
            }

            if let Some(grpc) = config.clone().server.grpc {
                let config_clone = config.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = start_grpc_server(&grpc, &config_clone.database).await {
                        let _ = tx_clone
                            .send(format!("gRPC server failed to start: {}", e))
                            .await;
                    }
                });
            }

            let _ = error_listener.await;
        }
        Some(Commands::Config { config }) => {
            info!("Config command not yet implemented.");
            let _ = lightbridge_authz_core::config::load_from_path(&config).unwrap();
        }
        None => {
            info!("No command provided. Use --help for more information.");
        }
    }
    Ok(())
}
