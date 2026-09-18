//! The API-key validation MCP tools (lightbridge-authz#520): `validate-api-key` and
//! `validate-authorino-api-key`, both hand-written OPA-path tools outside the cratestack CRUD
//! migration's scope. Split out of `mcp.rs`'s single tool-router impl block to keep that file
//! under the 200-LoC gate (`docs/code-size-baseline.md` split order item 4) -- every item below is
//! moved verbatim, no behavior change. See `mcp_tools_accounts.rs`'s module doc for the mechanics.
//!
//! `run_validate_api_key`/`run_validate_authorino` (the RBAC-gate-independent cores each tool
//! delegates to) and their `Params` structs are `pub(crate)`-re-exported from `mcp.rs`, because
//! `mcp.rs`'s own test module exercises them directly (constructing the `Params` structs and
//! calling the `run_*` functions without going through the tool-call/permission-gate machinery).

use std::collections::HashMap;

use rmcp::{ErrorData, Json, handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::mcp::{EndpointResponse, LightbridgeMcpHandler, to_json_value, to_tool_error};
use lightbridge_authz_rest::{
    OpaState, handlers::opa::validate_api_key_context, models::authorino::AuthorinoMetadata,
};
use std::sync::Arc;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ValidateApiKeyParams {
    pub(crate) api_key: String,
    #[serde(default)]
    pub(crate) ip: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ValidateAuthorinoApiKeyParams {
    pub(crate) api_key: String,
    #[serde(default)]
    pub(crate) ip: Option<String>,
    #[serde(default)]
    pub(crate) metadata: HashMap<String, Value>,
}

#[tool_router(router = validation_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "validate-api-key",
        description = "Validate an API key: hash lookup with status/expiry check, returns account/project context"
    )]
    async fn validate_api_key_tool(
        &self,
        Parameters(params): Parameters<ValidateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        run_validate_api_key(&self.opa_state, params).await
    }

    #[tool(
        name = "validate-authorino-api-key",
        description = "Validate an API key and return account/project context plus dynamic metadata enrichment"
    )]
    async fn validate_authorino_api_key(
        &self,
        Parameters(params): Parameters<ValidateAuthorinoApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        run_validate_authorino(&self.opa_state, params).await
    }
}

/// Core of the `validate-api-key` tool, factored out of the RBAC-gated tool method (which takes
/// no `RequestContext`, so the method itself is already directly callable, but keeping the two
/// validation tools symmetric makes the "unauthorized" branch trivial to exercise in isolation).
pub(crate) async fn run_validate_api_key(
    opa_state: &Arc<OpaState>,
    params: ValidateApiKeyParams,
) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
    let validated = validate_api_key_context(opa_state, &params.api_key, params.ip)
        .await
        .map_err(to_tool_error)?;

    let Some(validated) = validated else {
        return Err(ErrorData::invalid_params(
            "unauthorized",
            Some(json!({ "http_status": 401 })),
        ));
    };

    // `account_id`, not a nested `account` object: introspection stopped fetching the account row
    // in Phase E (ADR-0006) because the `api_key_validation` view already carries the id, so there
    // is no `Account` here to embed and re-adding the query would undo that. Matches
    // `IntrospectResponse.account_id` on the REST surface.
    to_json_value(json!({
        "api_key": validated.api_key,
        "project": validated.project,
        "account_id": validated.account_id
    }))
}

/// Core of the `validate-authorino-api-key` tool (validation + dynamic-metadata enrichment),
/// factored out of the RBAC-gated tool method so it can be exercised directly in tests.
pub(crate) async fn run_validate_authorino(
    opa_state: &Arc<OpaState>,
    params: ValidateAuthorinoApiKeyParams,
) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
    let validated = validate_api_key_context(opa_state, &params.api_key, params.ip)
        .await
        .map_err(to_tool_error)?;

    let Some(validated) = validated else {
        return Err(ErrorData::invalid_params(
            "unauthorized",
            Some(json!({ "http_status": 401 })),
        ));
    };

    let dynamic_metadata = AuthorinoMetadata {
        account_id: validated.account_id.clone(),
        project_id: validated.project.id.clone(),
        api_key_id: validated.api_key.id.clone(),
        api_key_status: validated.api_key.status.to_string(),
        extra: params.metadata,
    };

    to_json_value(json!({
        "api_key": validated.api_key,
        "project": validated.project,
        "account_id": validated.account_id,
        "dynamic_metadata": dynamic_metadata
    }))
}
