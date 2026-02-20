use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use utoipa::ToSchema;

/// Authorino metadata structure for enrichment.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthorinoMetadata {
    /// The account ID associated with the API key.
    pub account_id: String,
    /// The project ID associated with the API key.
    pub project_id: String,
    /// The unique ID of the API key.
    pub api_key_id: String,
    /// The current status of the API key.
    pub api_key_status: String,
    /// Arbitrary metadata fields preserved from the request.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Request for Authorino validation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorinoCheckRequest {
    /// The API key secret to validate.
    pub api_key: String,
    /// The IP address of the client.
    pub ip: Option<String>,
    /// Dynamic metadata provided by Authorino or external sources.
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
}

/// Response for Authorino validation.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorinoCheckResponse {
    /// The validated API key details.
    pub api_key: lightbridge_authz_core::ApiKey,
    /// The project associated with the API key.
    pub project: lightbridge_authz_core::Project,
    /// The account associated with the API key.
    pub account: lightbridge_authz_core::Account,
    /// Enriched dynamic metadata for Authorino.
    pub dynamic_metadata: AuthorinoMetadata,
}
