//! The mutating generic-CRUD project MCP tools (lightbridge-authz#520): create/update/delete,
//! all backed by the generated cratestack client. Split out of `mcp.rs`'s single tool-router impl
//! block to keep that file under the 200-LoC gate (`docs/code-size-baseline.md` split order item
//! 4) -- every tool body below is moved verbatim, no behavior change. See
//! `mcp_tools_accounts.rs`'s module doc for the mechanics.
//!
//! Sibling `mcp_tools_project_crud_read.rs` carries the read half (list/get) -- the five original
//! generic-CRUD project tools didn't fit one 200-LoC file together with
//! `json_to_cratestack_value`/`cratestack_json`, which travel with `create`/`update` (their only
//! two callers) rather than staying centrally in `mcp.rs`.
//!
//! `ProjectByIdParams` stays in `mcp.rs` (`pub(crate)`) because it is also shared with
//! `mcp_tools_project_lifecycle.rs`'s disable/enable/set-default tools -- the alternative, one
//! definition per file, would be the exact "same list in two places" AGENTS.md warns against.

use cratestack::Value as CratestackValue;
use lightbridge_authz_api::schema;
use lightbridge_authz_core::{DefaultLimits, cuid::cuid2};
use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::mcp::{
    DefaultLimitsInput, EndpointResponse, LightbridgeMcpHandler, ProjectByIdParams,
    cratestack_context_from_token_info, cratestack_error_to_tool_error, to_json_value,
    token_info_from_request_context,
};

/// Lower a `serde_json::Value` (the shape MCP tool inputs speak) into cratestack's own `Value`
/// enum, which is what the generated model input structs carry for `Json` columns. Mirrors the
/// identical private helper in `lightbridge-authz-rest` (the two crates use different JSON value
/// types and neither ships a cross-conversion).
fn json_to_cratestack_value(value: Value) -> CratestackValue {
    match value {
        Value::Null => CratestackValue::Null,
        Value::Bool(b) => CratestackValue::Bool(b),
        Value::Number(n) => n
            .as_i64()
            .map(CratestackValue::Int)
            .unwrap_or_else(|| CratestackValue::Float(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => CratestackValue::String(s),
        Value::Array(items) => {
            CratestackValue::List(items.into_iter().map(json_to_cratestack_value).collect())
        }
        Value::Object(map) => CratestackValue::Map(
            map.into_iter()
                .map(|(k, v)| (k, json_to_cratestack_value(v)))
                .collect(),
        ),
    }
}

/// Build a `cratestack::Json<cratestack::Value>` payload from any serde_json value.
fn cratestack_json(value: Value) -> cratestack::Json<CratestackValue> {
    cratestack::Json(json_to_cratestack_value(value))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateProjectParams {
    account_id: String,
    name: String,
    #[serde(default)]
    default_limits: Option<DefaultLimitsInput>,
    billing_plan: String,
    /// Who is paying for this project. Moved here from `Account` by ADR-0006 so one account can
    /// bill several projects to different parties; unique across all projects.
    billing_identity: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateProjectParams {
    project_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    default_limits: Option<DefaultLimitsInput>,
    #[serde(default)]
    billing_plan: Option<String>,
}

#[tool_router(router = project_crud_write_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "create-project",
        description = "Create a project (RPC model.Project.create); allowedModels is set afterward via set-project-allowed-models, projectQuota via set-project-quota"
    )]
    async fn create_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateProjectParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let default_limits = params
            .default_limits
            .map(DefaultLimits::from)
            .unwrap_or_default();
        let default_limits_json =
            serde_json::to_value(default_limits).unwrap_or_else(|_| json!({}));
        // `projectQuota`/`allowedModels` are both `@readonly` on this generated input (#379 and
        // #415 respectively -- neither has a hook for a runtime-configured catalogue check on the
        // generic verb) -- a brand-new project always starts with `projectQuota = NULL`/
        // `allowedModels = NULL` (both always valid), settable afterward via the
        // `set-project-quota`/`set-project-allowed-models` tools below.
        let input = schema::inputs::CreateProjectInput {
            id: cuid2(),
            accountId: params.account_id,
            name: params.name,
            defaultLimits: cratestack_json(default_limits_json),
            billingPlan: params.billing_plan,
            billingIdentity: params.billing_identity,
        };
        let project = bound
            .project()
            .create(input)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "update-project",
        description = "Update a project (RPC model.Project.update); allowedModels is set via set-project-allowed-models, not this tool (#415, ADR-0018 Decision 5)"
    )]
    async fn update_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateProjectParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let mut input = schema::inputs::UpdateProjectInput::default();
        if let Some(name) = params.name {
            input.name = Some(name);
        }
        if let Some(billing_plan) = params.billing_plan {
            input.billingPlan = Some(billing_plan);
        }
        if let Some(default_limits) = params.default_limits {
            let value = serde_json::to_value(DefaultLimits::from(default_limits))
                .unwrap_or_else(|_| json!({}));
            input.defaultLimits = Some(cratestack_json(value));
        }
        let project = bound
            .project()
            .update(params.project_id)
            .set(input)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "delete-project",
        description = "Delete a project (RPC model.Project.delete)"
    )]
    async fn delete_project_tool(
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
            .delete(params.project_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(project)
    }
}
