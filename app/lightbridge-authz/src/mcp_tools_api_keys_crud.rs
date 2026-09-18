//! The generic-CRUD API-key MCP tools (lightbridge-authz#520): list/get/update/delete, all backed
//! by the generated cratestack client. Split out of `mcp.rs`'s single tool-router impl block to
//! keep that file under the 200-LoC gate (`docs/code-size-baseline.md` split order item 4) --
//! every tool body below is moved verbatim, no behavior change. See `mcp_tools_accounts.rs`'s
//! module doc for the mechanics.
//!
//! Sibling `mcp_tools_api_keys_lifecycle.rs` carries create/revoke/rotate -- the secret-minting
//! lifecycle ops that route through `AuthzStoreImpl` and the `SecretClaimStore` rather than the
//! generic cratestack CRUD verbs these four tools use.
//!
//! `ApiKeyByIdParams` stays in `mcp.rs` (`pub(crate)`) because `revoke-api-key` in the sibling file
//! uses it too -- the alternative, one definition per file, would be the exact "same list in two
//! places" AGENTS.md warns against.

use lightbridge_authz_api::schema;
use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::mcp::{
    ApiKeyByIdParams, EndpointResponse, LightbridgeMcpHandler, cratestack_context_from_token_info,
    cratestack_error_to_tool_error, default_list_limit, normalize_list_pagination, require_found,
    to_json_value, token_info_from_request_context,
};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListApiKeysParams {
    project_id: String,
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_list_limit")]
    limit: u32,
}

// No `expires_at` here (lightbridge-authz#395): the generic `model.ApiKey.update` verb this tool
// wraps had its `expiresAt` field removed at the schema level (`@readonly` on `ApiKey.expiresAt`
// in `authz.cstack`) because it was a live, unvalidated bypass -- a caller could set any expiry,
// including explicit `null`, with no cap and no procedure in the path. Changing a key's expiry now
// goes exclusively through `rotate-api-key` (which validates it) or minting a new key via
// `create-api-key`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateApiKeyParams {
    key_id: String,
    #[serde(default)]
    name: Option<String>,
}

#[tool_router(router = api_keys_crud_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "list-api-keys",
        description = "List API keys under a project (RPC model.ApiKey.list)"
    )]
    async fn list_api_keys_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListApiKeysParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let api_keys = bound
            .api_key()
            .find_many()
            .where_(schema::api_key::projectId().eq(params.project_id))
            .limit(limit as i64)
            .offset(offset as i64)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(api_keys)
    }

    #[tool(
        name = "get-api-key",
        description = "Get an API key (RPC model.ApiKey.get)"
    )]
    async fn get_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let api_key = bound
            .api_key()
            .find_unique(params.key_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(require_found(api_key)?)
    }

    #[tool(
        name = "update-api-key",
        description = "Update an API key's name (RPC model.ApiKey.update); expires_at can only be changed via rotate-api-key or by creating a new key (lightbridge-authz#395)"
    )]
    async fn update_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let mut input = schema::inputs::UpdateApiKeyInput::default();
        if let Some(name) = params.name {
            input.name = Some(name);
        }
        let api_key = bound
            .api_key()
            .update(params.key_id)
            .set(input)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "delete-api-key",
        description = "Delete (soft-delete) an API key (RPC model.ApiKey.delete)"
    )]
    async fn delete_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let api_key = bound
            .api_key()
            .delete(params.key_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(api_key)
    }
}
