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
