mod server;

use std::net::AddrParseError;
use std::sync::Arc;

use crate::server::AuthServer;
use lightbridge_authz_core::config::{Database, Grpc};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_proto::envoy_types::ext_authz::v3::pb::AuthorizationServer;
use tonic::transport::Server;

/// Start the gRPC server with the provided configuration.
///
/// # Arguments
/// - `grpc`: gRPC server configuration
/// - `db`: database configuration
///
/// # Returns
/// - `Ok(())` on success
/// - `Err(Error)` on failure
pub async fn start_grpc_server(grpc: &Grpc, db: &Database) -> Result<()> {
    let addr = format!("{}:{}", grpc.address, grpc.port)
        .parse()
        .map_err(|e: AddrParseError| Error::AddrParseError(e))?;

    let pool = Arc::new(DbPool::new(&db.url).await?);
    let authz_service = AuthServer::new(pool);

    tracing::info!("Starting gRPC server on {}", addr);

    Server::builder()
        .add_service(AuthorizationServer::new(authz_service))
        .serve(addr)
        .await
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(())
}
