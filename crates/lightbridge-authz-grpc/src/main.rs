use lightbridge_authz_core::load_from_path;
use lightbridge_authz_grpc::start_grpc_server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load_from_path("config/default.yaml")?;
    let filter =
        EnvFilter::try_new(cfg.logging.level.clone()).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Check if gRPC server is configured
    let grpc_config = match &cfg.server.grpc {
        Some(grpc) => grpc,
        None => {
            tracing::error!("gRPC server configuration is missing");
            return Ok(());
        }
    };

    tracing::info!(
        "authz-grpc starting on {}:{}",
        grpc_config.address,
        grpc_config.port
    );

    // Start the gRPC server
    start_grpc_server(grpc_config, &cfg.database).await?;

    Ok(())
}
