//! The read-only generic-CRUD project MCP tools (lightbridge-authz#520): list/get, both backed by
//! the generated cratestack client. Split out of `mcp.rs`'s single tool-router impl block to keep
//! that file under the 200-LoC gate (`docs/code-size-baseline.md` split order item 4) -- every
//! tool body below is moved verbatim, no behavior change. See `mcp_tools_accounts.rs`'s module doc
//! for the mechanics.
//!
//! Sibling of `mcp_tools_project_crud.rs` (the mutating half: create/update/delete) -- see that
//! file's module doc for why the five original generic-CRUD project tools split into two files.

use lightbridge_authz_api::schema;
use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::mcp::{
    EndpointResponse, LightbridgeMcpHandler, ProjectByIdParams, cratestack_context_from_token_info,
    cratestack_error_to_tool_error, default_list_limit, normalize_list_pagination, require_found,
    to_json_value, token_info_from_request_context,
};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListProjectsParams {
    account_id: String,
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_list_limit")]
    limit: u32,
}

#[tool_router(router = project_crud_read_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "list-projects",
        description = "List projects under an account (RPC model.Project.list)"
    )]
    async fn list_projects_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListProjectsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let projects = bound
            .project()
            .find_many()
            .where_(schema::project::accountId().eq(params.account_id))
            .limit(limit as i64)
            .offset(offset as i64)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(projects)
    }

    #[tool(
        name = "get-project",
        description = "Get a project (RPC model.Project.get)"
    )]
    async fn get_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let project = bound
            .project()
            .find_unique(params.project_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(require_found(project)?)
    }
}
