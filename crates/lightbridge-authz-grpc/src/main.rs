use lightbridge_authz_core::load_from_path;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load_from_path("config/default.yaml")?;
    let filter =
        EnvFilter::try_new(cfg.logging.level.clone()).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    tracing::info!(
        "authz-grpc starting on {}:{}",
        cfg.server.grpc.address,
        cfg.server.grpc.port
    );
    Ok(())
}
