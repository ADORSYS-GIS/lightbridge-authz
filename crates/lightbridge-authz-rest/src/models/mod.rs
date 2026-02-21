pub mod authorino;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request for OPA validation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OpaCheckRequest {
    /// The API key secret to validate.
    pub api_key: String,
    /// The IP address of the client.
    pub ip: Option<String>,
}

/// Response for OPA validation.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpaCheckResponse {
    /// The validated API key details.
    pub api_key: lightbridge_authz_core::ApiKey,
    /// The project associated with the API key.
    pub project: lightbridge_authz_core::Project,
    /// The account associated with the API key.
    pub account: lightbridge_authz_core::Account,
}

/// Error response for OPA/Authorino validation.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpaErrorResponse {
    /// The error message.
    pub error: String,
}
