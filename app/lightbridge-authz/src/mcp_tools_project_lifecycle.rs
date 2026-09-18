//! The project suspend/promote MCP tools (lightbridge-authz#520): disable/enable a project and
//! promote a new default. Split out of `mcp.rs`'s single tool-router impl block to keep that file
//! under the 200-LoC gate (`docs/code-size-baseline.md` split order item 4) -- every tool body
//! below is moved verbatim, no behavior change. See `mcp_tools_accounts.rs`'s module doc for the
//! mechanics.
//!
//! Uses `ProjectByIdParams`, which stays in `mcp.rs` (`pub(crate)`) because it is shared with
//! `mcp_tools_project_crud.rs`/`mcp_tools_project_crud_read.rs`'s get/delete tools too -- see
//! those files' module docs.

use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, service::RequestContext,
    tool, tool_router,
};

use crate::mcp::{
    EndpointResponse, LightbridgeMcpHandler, ProjectByIdParams, subject_from_request_context,
    to_json_value, to_tool_error,
};

#[tool_router(router = project_lifecycle_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "disable-project",
        description = "Suspend a project (RPC procedure.disableProject); every API key beneath it fails validation"
    )]
    async fn disable_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .disable_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "enable-project",
        description = "Reactivate a suspended project (RPC procedure.enableProject)"
    )]
    async fn enable_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .enable_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-default-project",
        description = "Promote a different project to be its account's default (RPC procedure.setDefaultProject); frees the old default project up for hard deletion"
    )]
    async fn set_default_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_default_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }
}
