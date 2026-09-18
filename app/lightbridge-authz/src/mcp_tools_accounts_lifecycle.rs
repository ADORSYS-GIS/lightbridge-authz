//! The `account:*` delete/suspend/reactivate MCP tools (lightbridge-authz#520): delete/disable/
//! enable. Split out of `mcp.rs`'s single tool-router impl block to keep that file under the
//! 200-LoC gate (`docs/code-size-baseline.md` split order item 4) -- every tool body below is
//! moved verbatim, no behavior change. See `mcp_tools_accounts.rs`'s module doc for the mechanics
//! and for why the eight original `account:*` tools split into these two files.
//!
//! Uses `AccountByIdParams`, which stays in `mcp.rs` (`pub(crate)`) because `get-account` in the
//! sibling `mcp_tools_accounts.rs` uses it too.

use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, service::RequestContext,
    tool, tool_router,
};

use crate::mcp::{
    AccountByIdParams, EndpointResponse, LightbridgeMcpHandler, subject_from_request_context,
    to_json_value, to_tool_error,
};

#[tool_router(router = accounts_lifecycle_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "delete-account",
        description = "Permanently delete an account and cascade-delete its projects/api-keys/memberships (RPC procedure.deleteAccountPermanently); owner-only"
    )]
    async fn delete_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        // Repointed from the generic `model.Account.delete` client call: that op is now denied
        // unconditionally (membership-role gating -- owner-only -- can't be expressed as an
        // `@@allow` policy, see the schema's comment on `Account`), so this now calls the
        // `deleteAccountPermanently` procedure instead, same as the RPC surface.
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .delete_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "disable-account",
        description = "Suspend an account (RPC procedure.disableAccount); every API key beneath it fails validation"
    )]
    async fn disable_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .disable_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "enable-account",
        description = "Reactivate a suspended account (RPC procedure.enableAccount)"
    )]
    async fn enable_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .enable_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }
}
