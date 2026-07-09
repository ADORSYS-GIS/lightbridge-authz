pub mod authorino;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// RFC 7662 token introspection request (form-encoded).
#[derive(Debug, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    /// The opaque API key to introspect.
    pub token: String,
    /// Optional hint about the token type; ignored (only access tokens are supported).
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

/// RFC 7662 token introspection response. When `active` is false, all other fields are omitted.
#[derive(Debug, Serialize, ToSchema)]
pub struct IntrospectResponse {
    /// Whether the key is currently valid (exists, `Active`, not expired).
    pub active: bool,
    /// Subject of the credential (the API key id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Owning account id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Owning project id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// The API key id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// The API key status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_status: Option<String>,
    /// Project billing plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_plan: Option<String>,
    /// Models the project is allowed to use (empty/absent means all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    /// Expiry as a Unix timestamp, when the key has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

impl IntrospectResponse {
    /// Builds the canonical inactive response (`{"active": false}`).
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            account_id: None,
            project_id: None,
            api_key_id: None,
            api_key_status: None,
            billing_plan: None,
            allowed_models: None,
            exp: None,
        }
    }
}
