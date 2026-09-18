//! The project spending/model-policy MCP tools (lightbridge-authz#520): per-member quota tier,
//! pooled project quota, model allowlist and model policy. Split out of `mcp.rs`'s single
//! tool-router impl block to keep that file under the 200-LoC gate
//! (`docs/code-size-baseline.md` split order item 4) -- every tool body below is moved verbatim,
//! no behavior change. See `mcp_tools_accounts.rs`'s module doc for the mechanics.
//!
//! Sibling of `mcp_tools_project_roster.rs` (membership) and `mcp_tools_project_crud.rs`/
//! `mcp_tools_project_lifecycle.rs` (the generic-CRUD and suspend/promote halves) -- the sixteen
//! original `project:*` tools split four ways to each stay under the gate.

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
struct SetProjectMemberQuotaTierParams {
    project_id: String,
    account_id: String,
    /// A tier drawn from the operator-configured catalogue, or omitted to clear the ceiling.
    #[serde(default)]
    quota_tier: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectQuotaParams {
    project_id: String,
    /// The pooled, tier-catalogue-validated ceiling shared by everyone on the project, drawn from
    /// the operator-configured catalogue, or omitted/`null` to clear it.
    #[serde(default)]
    project_quota: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectAllowedModelsParams {
    project_id: String,
    /// Model ids drawn from the operator-configured catalogue (`list-model-catalog`), or omitted/
    /// `null` for "all models allowed". Rejected (#415, ADR-0018 Decision 5) if any entry is
    /// absent from a non-empty catalogue.
    #[serde(default)]
    allowed_models: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectModelPolicyParams {
    project_id: String,
    /// One of `"allow_all"` (every model, present and future -- the default), `"allowlist"`
    /// (only `allowed_models` entries), or `"deny_all"` (no models). Any other value is refused
    /// (ADR-0018 Decision 5 follow-up). Switching to `"allowlist"` while the project's current
    /// `allowed_models` is empty/absent is refused -- populate it via `set-project-allowed-models`
    /// first. `allowed_models` itself is never touched by this tool; it is preserved across a
    /// policy change in either direction.
    model_policy: String,
}

#[tool_router(router = project_limits_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "set-project-member-quota-tier",
        description = "Set a roster member's per-project spending ceiling (RPC procedure.setProjectMemberQuotaTier); lead-only, tier validated against the configured catalogue"
    )]
    async fn set_project_member_quota_tier_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectMemberQuotaTierParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_member_quota_tier(
                &subject,
                &params.project_id,
                &params.account_id,
                params.quota_tier.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-quota",
        description = "Set a project's pooled spending ceiling (RPC procedure.setProjectQuota); owner or any roster member, tier validated against the configured catalogue"
    )]
    async fn set_project_quota_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectQuotaParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_quota(
                &subject,
                &params.project_id,
                params.project_quota.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-allowed-models",
        description = "Set a project's AI-model allowlist (RPC procedure.setProjectAllowedModels); owner or any roster member, every entry validated against the operator-configured model catalogue (#415, ADR-0018 Decision 5)"
    )]
    async fn set_project_allowed_models_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectAllowedModelsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_allowed_models(&subject, &params.project_id, params.allowed_models)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-model-policy",
        description = "Set a project's model access policy to allow_all/allowlist/deny_all (RPC procedure.setProjectModelPolicy); owner or any roster member. Refuses switching to allowlist while allowedModels is empty; never touches allowedModels itself (ADR-0018 Decision 5 follow-up)"
    )]
    async fn set_project_model_policy_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectModelPolicyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_model_policy(&subject, &params.project_id, &params.model_policy)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }
}
