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
    /// Billing plan id the key is minted on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_plan: Option<String>,
    /// Human-facing name of the billing plan, resolved from config (absent when the id is not in
    /// the configured catalogue).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_plan_name: Option<String>,
    /// Rate/usage limits of the billing plan, resolved from config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_plan_limits: Option<lightbridge_authz_core::config::BillingLimits>,
    /// Models the project is allowed to use (empty/absent means all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    /// The project's pooled spending ceiling, from the governance tier catalogue (ADR-0006).
    /// Costs no extra query — it rides on the project row already loaded for `allowed_models` —
    /// and keeps the gateway's `x-project-quota` header sourced from the database rather than from
    /// a claim frozen at mint time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_quota: Option<String>,
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
            billing_plan_name: None,
            billing_plan_limits: None,
            allowed_models: None,
            project_quota: None,
            exp: None,
        }
    }
}
