//! The one shape every procedure-backed MCP tool has, and the macro that stamps it out
//! (lightbridge-authz#645).
//!
//! A procedure tool is a thin transport adapter, nothing more: it decodes the procedure's OWN
//! generated `Args` struct from the tool arguments, builds the caller's `CratestackContext` at the
//! op-id's own `RpcScope`, and hands both to the generated `invoke_with_db` — the same entry point
//! the RPC router's dispatch arm calls, which runs the schema's `@allow`/`@deny` clauses and mints
//! the `Authorized` witness the `ProcedureRegistry` method demands. Nothing here can skip policy:
//! the witness is constructible only inside the generated module (cratestack#512).
//!
//! **Input/output shapes are identical to the RPC surface by construction, not by mirroring.** The
//! tool argument object IS `procedures::<name>::Args` (`{"args": {...}}` for every procedure in
//! `authz.cstack`, which declares a single `args` parameter throughout), decoded with the same
//! serde impl the CBOR codec uses; the result is the procedure's own `Output`, serialized with the
//! same impl. A hand-written per-tool input struct would have been a second declaration of the
//! same shape and therefore a second thing to drift — see `mcp_parity_tests.rs` for the guard that
//! would otherwise have to police it.
//!
//! The advertised JSON Schema is deliberately the permissive envelope rather than a per-procedure
//! expansion: cratestack derives no `schemars::JsonSchema` for its generated types, so the only
//! honest options were "an object with an `args` object" or a hand-transcribed schema per
//! procedure that nothing checks against the real type. The tool description names the schema's
//! own input type (`OpDescriptor::input_ty`) so a caller can look it up.

use std::sync::Arc;

use rmcp::{
    ErrorData,
    handler::server::tool::ToolCallContext,
    model::{CallToolResponse, CallToolResult, JsonObject, Tool},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::mcp::LightbridgeMcpHandler;

/// The input schema advertised for every procedure tool: one required `args` object, the exact
/// envelope `POST /rpc/procedure.<name>` takes.
pub(crate) fn procedure_args_schema() -> Arc<JsonObject> {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "args": {
                "type": "object",
                "description": "The procedure's input object, identical to the RPC request body's `args` field."
            }
        },
        "required": ["args"],
        "additionalProperties": false
    });
    let serde_json::Value::Object(object) = schema else {
        unreachable!("the literal above is a JSON object")
    };
    Arc::new(object)
}

/// Build the advertised [`Tool`] for a procedure-backed tool. The description always ends with the
/// canonical op-id, so an operator reading the tool list can map it to `docs/rbac.md` and to the
/// REST route without guessing at the kebab-case-to-camelCase transform.
pub(crate) fn procedure_tool_attr(
    name: &'static str,
    procedure_name: &str,
    description: &str,
) -> Tool {
    Tool::new(
        name,
        format!("{description} (RPC procedure.{procedure_name})"),
        procedure_args_schema(),
    )
}

/// Decode the tool arguments into a procedure's generated `Args`. Absent arguments decode as an
/// empty object so a no-input procedure can be called with no `arguments` key at all.
pub(crate) fn parse_procedure_args<T: DeserializeOwned>(
    arguments: Option<JsonObject>,
) -> std::result::Result<T, ErrorData> {
    let value = serde_json::Value::Object(arguments.unwrap_or_default());
    serde_json::from_value(value)
        .map_err(|error| ErrorData::invalid_params(format!("invalid arguments: {error}"), None))
}

/// Wrap a procedure `Output` in the same `{"result": ...}` structured envelope every hand-written
/// MCP tool in `mcp.rs` returns through `to_json_value`, so a client sees one result shape across
/// the whole surface.
pub(crate) fn procedure_result<T: Serialize>(
    value: T,
) -> std::result::Result<CallToolResponse, ErrorData> {
    let result = serde_json::to_value(value).map_err(|error| {
        ErrorData::internal_error(format!("failed to serialize response: {error}"), None)
    })?;
    Ok(CallToolResult::structured(serde_json::json!({ "result": result })).into())
}

/// The boxed-future shape `rmcp::handler::server::router::tool::ToolRoute::new_dyn` demands. Spelled
/// out rather than reusing rmcp's own `MaybeBoxFuture` alias, which is `pub(crate)` to that crate;
/// this is structurally the same type (`futures::future::BoxFuture`).
pub(crate) type ToolFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = std::result::Result<CallToolResponse, ErrorData>>
            + Send
            + 'a,
    >,
>;

/// Re-exported for the macro's expansion site, which names it in the generated route fn signature.
pub(crate) type ToolCtx<'a> = ToolCallContext<'a, LightbridgeMcpHandler>;

/// Declare the procedure-backed MCP tools.
///
/// One entry per RPC procedure: `"tool-name" => snake_case_procedure_module, "description"`. The
/// module ident is the generated `schema::procedures::<module>`, which is also the
/// `ProcedureRegistry` method name and carries the camelCase op-id in its own `NAME` const — so
/// the op-id is read from the schema, never retyped here.
///
/// Each entry expands to a private module holding an `async fn call` (the body) and a
/// lifetime-generic `fn route` that boxes it. `route` is a *function item*, not a closure:
/// `new_dyn`'s `for<'a> Fn(ToolCallContext<'a, _>) -> MaybeBoxFuture<'a, _>` bound is higher-ranked,
/// and closure signature inference does not reliably produce a higher-ranked signature for a boxed
/// future, while a generic fn item coerces to one by construction.
macro_rules! procedure_tools {
    ($( $tool:literal => $module:ident, $desc:literal );* $(;)?) => {
        $(
            #[allow(non_snake_case)]
            mod $module {
                use lightbridge_authz_api::schema::procedures::{self, ProcedureRegistry};

                use crate::mcp_procedure_tool::{
                    ToolCtx, ToolFuture, parse_procedure_args, procedure_result,
                };

                pub(super) const TOOL: &str = $tool;
                pub(super) const DESC: &str = $desc;
                pub(super) const PROCEDURE: &str = procedures::$module::NAME;

                async fn call(
                    tcc: ToolCtx<'_>,
                ) -> std::result::Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
                    let handler = tcc.service;
                    let args: procedures::$module::Args = parse_procedure_args(tcc.arguments)?;
                    let op_id = format!("procedure.{PROCEDURE}");
                    let ctx = handler
                        .procedure_context(&tcc.request_context, &op_id)
                        .await?;
                    let db = handler.cratestack_db();
                    let registry = handler.procedures();
                    // `invoke_with_db` borrows `args` to evaluate the policy, then hands the
                    // witness to `f`, which needs its own owned copy for the registry call.
                    let owned = args.clone();
                    let ctx = &ctx;
                    procedures::$module::invoke_with_db(db, &args, ctx, move |authorized| async move {
                        registry.$module(db, ctx, owned, authorized).await
                    })
                    .await
                    .map_err(crate::mcp::cratestack_error_to_tool_error)
                    .and_then(procedure_result)
                }

                pub(super) fn route<'a>(tcc: ToolCtx<'a>) -> ToolFuture<'a> {
                    Box::pin(call(tcc))
                }
            }
        )*

        /// Every procedure tool paired with the canonical RPC op-id it serves — the table the
        /// permission gate and the parity test both read.
        pub fn procedure_tool_op_ids() -> Vec<(&'static str, String)> {
            vec![$( ($module::TOOL, format!("procedure.{}", $module::PROCEDURE)) ),*]
        }

        /// The routes to merge into the handler's `ToolRouter`.
        pub fn procedure_tool_routes()
        -> Vec<rmcp::handler::server::router::tool::ToolRoute<crate::mcp::LightbridgeMcpHandler>>
        {
            vec![$(
                rmcp::handler::server::router::tool::ToolRoute::new_dyn(
                    crate::mcp_procedure_tool::procedure_tool_attr(
                        $module::TOOL,
                        $module::PROCEDURE,
                        $module::DESC,
                    ),
                    $module::route,
                )
            ),*]
        }
    };
}

pub(crate) use procedure_tools;
