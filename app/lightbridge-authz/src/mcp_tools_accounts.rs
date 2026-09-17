//! The `account:*` create/read/update MCP tools (lightbridge-authz#520): create/list/get/update
//! (default quota)/update (name). Split out of `mcp.rs`'s single
//! `#[tool_router(router = tool_router)]` impl block purely to keep that file under the 200-LoC
//! gate (`docs/code-size-baseline.md` split order item 4) -- every tool body below is moved
//! verbatim, no behavior change. `LightbridgeMcpHandler::new` in `mcp.rs` sums this file's
//! `accounts_tool_router()` with the other domain routers via `ToolRouter`'s `Add` impl (rmcp
//! 3.2.0, `tests/test_tool_routers.rs`).
//!
//! Sibling `mcp_tools_accounts_lifecycle.rs` carries delete/disable/enable -- the eight original
//! `account:*` tools didn't fit one 200-LoC file. Shared helpers (`subject_from_request_context`,
//! `to_tool_error`, `to_json_value`, ...) and `AccountByIdParams` (used by `get-account` here and
//! by all three lifecycle tools) stay in `mcp.rs`, which keeps its role as the file that owns
//! server construction and cross-domain support code; this file reaches into it exactly like
//! `mcp_procedure_tool.rs`/`mcp_rbac.rs` already do.

use lightbridge_authz_core::CreateAccount;
use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::mcp::{
    AccountByIdParams, EndpointResponse, LightbridgeMcpHandler, cratestack_context_from_token_info,
    cratestack_error_to_tool_error, default_list_limit, normalize_list_pagination, require_found,
    subject_from_request_context, to_json_value, to_tool_error, token_info_from_request_context,
};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateAccountParams {
    /// A governance tier for the account's own default-project usage, validated against the
    /// operator-configured catalogue. Since ADR-0006 `billingIdentity` lives on `Project`, and the
    /// account's id is taken from the caller's JWT subject rather than any input field.
    #[serde(default)]
    default_quota: Option<String>,
    /// Optional human-facing display label for the account. Blank/whitespace-only is treated as
    /// "no name" rather than rejected. Purely a label: it is never unique and nothing resolves an
    /// account by it -- `account_id` (the caller's JWT subject) remains the only handle.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListAccountsParams {
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_list_limit")]
    limit: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateAccountParams {
    account_id: String,
    /// A tier drawn from the operator-configured catalogue, or omitted/`null` to clear it. Unlike
    /// before #379, this always writes (no PATCH "leave untouched" state) -- `updateAccountDefaultQuota`
    /// is a dedicated single-field procedure, not the generic `model.Account.update` verb, mirroring
    /// `SetProjectMemberQuotaTierParams::quota_tier` below.
    #[serde(default)]
    default_quota: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateAccountNameParams {
    account_id: String,
    /// The new display label, or omitted/`null`/blank to clear it back to unnamed. Like
    /// `UpdateAccountParams::default_quota` above this always writes -- there is no PATCH
    /// "leave untouched" state.
    #[serde(default)]
    name: Option<String>,
}

#[tool_router(router = accounts_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "create-account",
        description = "Create an account (RPC procedure.createAccount); seeds the caller as the account's first member"
    )]
    async fn create_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateAccountParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .create_account(
                &subject,
                CreateAccount {
                    default_quota: params.default_quota,
                    name: params.name,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "list-accounts",
        description = "List accounts (RPC model.Account.list)"
    )]
    async fn list_accounts_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListAccountsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let accounts = bound
            .account()
            .find_many()
            .limit(limit as i64)
            .offset(offset as i64)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(accounts)
    }

    #[tool(
        name = "get-account",
        description = "Get an account (RPC model.Account.get)"
    )]
    async fn get_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let account = bound
            .account()
            .find_unique(params.account_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(require_found(account)?)
    }

    #[tool(
        name = "update-account",
        description = "Update an account's default quota tier (RPC procedure.updateAccountDefaultQuota); tier validated against the configured catalogue"
    )]
    async fn update_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateAccountParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        // Repointed from the generic `model.Account.update` client call (#379): `defaultQuota` is
        // now `@readonly` on that verb's generated input (it has no hook for the runtime-configured
        // quota-tier catalogue check), so this now calls the `updateAccountDefaultQuota` procedure
        // instead, same as the RPC surface -- mirrors how `delete-account` was already repointed
        // from `model.Account.delete` to `deleteAccountPermanently`.
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .update_account_default_quota(
                &subject,
                &params.account_id,
                params.default_quota.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "update-account-name",
        description = "Set or clear an account's human-facing display name (RPC procedure.updateAccountName); the name is a label, never an identifier"
    )]
    async fn update_account_name_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateAccountNameParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        // Separate from `update-account` rather than another optional field on it: that tool is a
        // single-field write onto `updateAccountDefaultQuota`, and folding a second column into it
        // would resurrect exactly the "which fields did the caller mean to leave alone" ambiguity
        // #379 removed from the account surface. Same `account:update` permission either way.
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .update_account_name(&subject, &params.account_id, params.name.as_deref())
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }
}
