use lightbridge_authz_core::config::{Database, Grpc};
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_proto::*;
use std::net::AddrParseError;
use tonic::{Request, Response, Status, transport::Server};

// Implementation of the API key service
#[derive(Debug, Default)]
pub struct ApiKeyService {}

#[tonic::async_trait]
impl api_key_service_server::ApiKeyService for ApiKeyService {
    async fn validate_api_key(
        &self,
        request: Request<ValidateApiKeyRequest>,
    ) -> std::result::Result<Response<ValidateApiKeyResponse>, Status> {
        let req = request.into_inner();
        let api_key = req.api_key;

        // Simple validation - in a real implementation, this would check against a database
        let valid = api_key == "valid-key";

        let reply = ValidateApiKeyResponse {
            valid,
            error_message: if valid {
                String::new()
            } else {
                "Invalid API key".to_string()
            },
        };

        Ok(Response::new(reply))
    }
}

/// Start the gRPC server with the provided configuration.
///
/// # Arguments
/// - `config`: reference to the parsed application configuration.
///
/// # Returns
/// - `Ok(())` on success
/// - `Err(Error)` on failure
pub async fn start_grpc_server(grpc: &Grpc, _db: &Database) -> Result<()> {
    let addr = format!("{}:{}", grpc.address, grpc.port)
        .parse()
        .map_err(|e: AddrParseError| Error::AddrParseError(e))?;

    let service = ApiKeyService::default();

    tracing::info!("Starting gRPC server on {}", addr);

    Server::builder()
        .add_service(api_key_service_server::ApiKeyServiceServer::new(service))
        .serve(addr)
        .await
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(())
}
