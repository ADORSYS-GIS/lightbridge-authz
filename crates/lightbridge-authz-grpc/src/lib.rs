mod server;

use std::net::AddrParseError;
use std::sync::Arc;

use crate::server::AuthServer;
use lightbridge_authz_core::config::Grpc;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_proto::envoy_types::ext_authz::v3::pb::AuthorizationServer;
use tonic::transport::Server;
use tonic_reflection::server::Builder as ReflectionBuilder;

/// Placeholder module for file descriptor bytes used by tonic-reflection.
///
/// Purpose:
/// - Provide a safe, compile-time placeholder so the crate compiles even when
///   no descriptor bytes have been exported yet.
///
/// How to enable reflection for your service:
/// 1. Ensure your proto build emits an encoded FileDescriptorSet (a binary).
///    With `tonic_build` you can use `.file_descriptor_set_path(...)` during compile.
/// 2. Expose that encoded bytes from `crates/lightbridge-authz-proto` as a public constant,
///    e.g. `pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lightbridge_descriptor.bin"));`
/// 3. Replace the `None` below with `Some(lightbridge_authz_proto::FILE_DESCRIPTOR_SET)`.
mod descriptor {
    /// When available, set this to `Some(&[u8])` pointing to the encoded FileDescriptorSet
    /// for your protos (see the comment above). Leaving this as `None` disables registration
    /// of the reflection service at runtime.
    pub const FILE_DESCRIPTOR_SET: Option<&'static [u8]> = None;
}

/// Start the gRPC server with the provided configuration.
///
/// # Arguments
/// - `grpc`: gRPC server configuration
/// - `pool`: database pool
///
/// # Returns
/// - `Ok(())` on success
/// - `Err(Error)` on failure
pub async fn start_grpc_server(grpc: &Grpc, pool: Arc<DbPool>) -> Result<()> {
    let addr = format!("{}:{}", grpc.address, grpc.port)
        .parse()
        .map_err(|e: AddrParseError| Error::AddrParseError(e))?;

    let authz_service = AuthServer::new(pool);

    tracing::info!("Starting gRPC server on {}", addr);

    // Build the server and optionally register the reflection service if descriptors exist.
    let mut server_builder = Server::builder().add_service(AuthorizationServer::new(authz_service));

    if let Some(fd_bytes) = descriptor::FILE_DESCRIPTOR_SET {
        // Register reflection service using the provided encoded file descriptor set.
        let reflection_service = ReflectionBuilder::configure()
            .register_encoded_file_descriptor_set(fd_bytes)
            .build_v1()
            .map_err(|e| Error::Server(format!("failed to build reflection service: {}", e)))?;

        server_builder = server_builder.add_service(reflection_service);
        tracing::info!("gRPC reflection service registered");
    } else {
        tracing::warn!(
            "gRPC reflection not registered: no file descriptor set provided. \
            To enable, export a `FILE_DESCRIPTOR_SET` from `crates/lightbridge-authz-proto` \
            and set `descriptor::FILE_DESCRIPTOR_SET` to `Some(lightbridge_authz_proto::FILE_DESCRIPTOR_SET)`."
        );
    }

    server_builder
        .serve(addr)
        .await
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(())
}
