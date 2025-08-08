// Minimal library scaffold for the gRPC server component.
// This provides the public API that the CLI can call later.
// Real gRPC server wiring will be added in subsequent steps.

use lightbridge_authz_core::config::Config;
use lightbridge_authz_core::error::Result;

/// Start the gRPC server with the provided configuration.
/// Currently a placeholder that returns immediately to establish
/// the library boundary. The real server implementation will
/// replace the body with tonic-based server startup and graceful shutdown.
///
/// # Arguments
/// - `config`: reference to the parsed application configuration.
///
/// # Returns
/// - `Ok(())` on success (placeholder)
/// - `Err(Error)` on failure (to be mapped from underlying IO/proto errors)
pub async fn start_grpc_server(_config: &Config) -> Result<()> {
    // Placeholder: no real server started yet.
    Ok(())
}
