pub mod server;

use std::net::AddrParseError;
use std::sync::Arc;

use crate::server::AuthServer;
use lightbridge_authz_core::config::Grpc;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_proto::envoy_types::ext_authz::v3::pb::AuthorizationServer;
use tonic::transport::Server;

/// Start the gRPC server with the provided configuration.
///
/// # Arguments
/// - `grpc`: gRPC server configuration
/// - `pool`: database pool
///
/// # Returns
/// - `Ok(())` on success
/// - `Err(lightbridge_authz_core::error::Error)` on failure
pub async fn start_grpc_server(grpc: &Grpc, pool: Arc<DbPool>) -> Result<()> {
    let addr = format!("{}:{}", grpc.address, grpc.port)
        .parse()
        .map_err(|e: AddrParseError| Error::AddrParseError(e))?;

    let authz_service = AuthServer::new(pool);

    tracing::info!("Starting gRPC server on {}", addr);

    // Build the server and optionally register the reflection service if descriptors exist.
    let server_builder = Server::builder().add_service(AuthorizationServer::new(authz_service));

    server_builder
        .serve(addr)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?;

    Ok(())
}
