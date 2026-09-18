//! The `project:member` roster MCP tools (lightbridge-authz#520): list/add/remove a project's
//! roster and change a member's role. Split out of `mcp.rs`'s single tool-router impl block to
//! keep that file under the 200-LoC gate (`docs/code-size-baseline.md` split order item 4) -- every
//! tool body below is moved verbatim, no behavior change. See `mcp_tools_accounts.rs`'s module doc
//! for the mechanics (`ToolRouter`'s `Add` impl, shared helpers staying in `mcp.rs`).
//!
//! Sibling `mcp_tools_project_limits.rs` carries this domain's quota/model-policy tools --
//! sixteen project tools in one file exceeded the LoC gate, so the split follows the same
//! roster-vs-limits seam `rpc_authorize.rs`'s permission gating already draws.

use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::mcp::{
    EndpointResponse, LightbridgeMcpHandler, subject_from_request_context, to_json_value,
    to_tool_error,
};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListProjectRosterParams {
    project_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AddProjectMemberParams {
    project_id: String,
    /// The account being added. Since ADR-0006 an account id *is* the member's JWT subject.
    account_id: String,
    /// "lead" | "member"; defaults to "member" if omitted.
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RemoveProjectMemberParams {
    project_id: String,
    account_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectMemberRoleParams {
    project_id: String,
    account_id: String,
    /// "lead" | "member". Lead-only.
    role: String,
}

#[tool_router(router = project_roster_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "list-project-roster",
        description = "List a project's roster (RPC procedure.listProjectRoster); readable by any member of the project and by the owning account"
    )]
    async fn list_project_roster_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListProjectRosterParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let members = self
            .issuer
            .list_project_roster(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(members)
    }

    #[tool(
        name = "add-project-member",
        description = "Add an account to a project's roster (RPC procedure.addProjectMember); idempotent, lead-only"
    )]
    async fn add_project_member_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AddProjectMemberParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .add_project_member(
                &subject,
                &params.project_id,
                &params.account_id,
                params.role.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "remove-project-member",
        description = "Remove an account from a project's roster (RPC procedure.removeProjectMember); lead-only"
    )]
    async fn remove_project_member_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<RemoveProjectMemberParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .remove_project_member(&subject, &params.project_id, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-member-role",
        description = "Change a roster member's role between lead and member (RPC procedure.setProjectMemberRole); lead-only"
    )]
    async fn set_project_member_role_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectMemberRoleParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_member_role(
                &subject,
                &params.project_id,
                &params.account_id,
                &params.role,
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }
}
