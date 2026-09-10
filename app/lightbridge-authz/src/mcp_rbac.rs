//! The MCP surface's permission gate — one lookup, one source of truth (lightbridge-authz#122,
//! lightbridge-authz#645).
//!
//! Before this module, `mcp.rs` carried its own hand-typed `tool -> Permission` match arm. It was
//! correct on the day it was written and wrong by 37 tools' worth the day the api/budget RPC
//! surfaces grew past it, because nothing failed when the two disagreed. What replaces it is a
//! `tool -> op-id` table plus a delegation to
//! [`lightbridge_authz_rest::rpc_authorize::required_permission`] — the SAME function the REST
//! middleware calls, paired arm-for-arm with `rpc_permission_map::MAPPED_OP_ID_PERMISSIONS` by
//! that crate's own `every_mapped_op_id_maps_to_the_documented_permission` test. There is no
//! second permission table to keep in step; there is only a claim about which op-id a tool serves,
//! and `tests/mcp_parity_tests.rs` fails if that claim is unbacked or if a mapped op-id has no
//! tool at all.
//!
//! Composition matches `docs/rbac.md` exactly as the REST gate does: this coarse permission check
//! runs FIRST, in `call_tool`, before any tool body executes; the schema's `@allow`/`@@allow`
//! membership policy runs SECOND, inside cratestack dispatch. Both must pass.

use lightbridge_authz_core::Permission;
use lightbridge_authz_rest::rpc_authorize::{is_authenticated_only_op_id, required_permission};

use crate::mcp_procedure_tools::procedure_tool_op_ids;

/// What a tool call must satisfy before its body runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolGate {
    /// The caller's token must carry this permission.
    Permission(Permission),
    /// A valid, active bearer token and nothing more — the MCP mirror of
    /// [`lightbridge_authz_rest::rpc_permission_map::AUTHENTICATED_ONLY_OP_IDS`]. The token is
    /// already validated by the `bearer_auth` middleware in front of the `/mcp` nest, so reaching
    /// this arm at all means the requirement is met.
    AuthenticatedOnly,
}

/// The RPC op-id each hand-written tool in `mcp.rs` serves.
///
/// Several entries are deliberately NOT the obvious generic verb: `update-account` serves
/// `procedure.updateAccountDefaultQuota` and `delete-account` serves
/// `procedure.deleteAccountPermanently`, because #379/#398 removed `model.Account.update`/`delete`
/// from both the schema policy and the permission map. Naming the op-id a tool actually serves —
/// not the one its name suggests — is the whole point of the table.
const HAND_WRITTEN_TOOL_OP_IDS: &[(&str, &str)] = &[
    ("create-account", "procedure.createAccount"),
    ("list-accounts", "model.Account.list"),
    ("get-account", "model.Account.get"),
    ("update-account", "procedure.updateAccountDefaultQuota"),
    ("update-account-name", "procedure.updateAccountName"),
    ("delete-account", "procedure.deleteAccountPermanently"),
    ("disable-account", "procedure.disableAccount"),
    ("enable-account", "procedure.enableAccount"),
    ("list-project-roster", "procedure.listProjectRoster"),
    ("add-project-member", "procedure.addProjectMember"),
    ("remove-project-member", "procedure.removeProjectMember"),
    ("set-project-member-role", "procedure.setProjectMemberRole"),
    (
        "set-project-member-quota-tier",
        "procedure.setProjectMemberQuotaTier",
    ),
    ("set-project-quota", "procedure.setProjectQuota"),
    (
        "set-project-allowed-models",
        "procedure.setProjectAllowedModels",
    ),
    (
        "set-project-model-policy",
        "procedure.setProjectModelPolicy",
    ),
    ("create-project", "model.Project.create"),
    ("list-projects", "model.Project.list"),
    ("get-project", "model.Project.get"),
    ("update-project", "model.Project.update"),
    ("delete-project", "model.Project.delete"),
    ("disable-project", "procedure.disableProject"),
    ("enable-project", "procedure.enableProject"),
    ("set-default-project", "procedure.setDefaultProject"),
    ("create-api-key", "procedure.createApiKey"),
    ("list-api-keys", "model.ApiKey.list"),
    ("get-api-key", "model.ApiKey.get"),
    ("update-api-key", "model.ApiKey.update"),
    ("delete-api-key", "model.ApiKey.delete"),
    ("revoke-api-key", "procedure.revokeApiKey"),
    ("rotate-api-key", "procedure.rotateApiKey"),
];

/// Tools with no RPC twin, and the permission each is gated at.
///
/// The two API-key validation tools are the OPA hand-written path (`OpaState`), not cratestack
/// CRUD: `authz-opa` serves them over its own REST endpoints, never over `/rpc`, so there is no
/// op-id for them to claim. `apikey:validate` is the same permission `authz-opa`'s own route
/// requires — see `docs/rbac.md`.
const MCP_ONLY_TOOL_PERMISSIONS: &[(&str, Permission)] = &[
    ("validate-api-key", Permission::ApiKeyValidate),
    ("validate-authorino-api-key", Permission::ApiKeyValidate),
];

/// The op-id a tool serves, or `None` for an MCP-only tool (and for an unknown name).
pub fn op_id_for_tool(tool: &str) -> Option<String> {
    if let Some((_, op_id)) = HAND_WRITTEN_TOOL_OP_IDS
        .iter()
        .find(|(name, _)| *name == tool)
    {
        return Some((*op_id).to_owned());
    }
    procedure_tool_op_ids()
        .into_iter()
        .find(|(name, _)| *name == tool)
        .map(|(_, op_id)| op_id)
}

/// Every tool the MCP surface gates, paired with the op-id it serves (`None` for MCP-only tools).
/// Read by `tests/mcp_parity_tests.rs`; also the enumeration `docs/rbac.md`'s tool table is
/// generated against.
pub fn gated_tools() -> Vec<(String, Option<String>)> {
    HAND_WRITTEN_TOOL_OP_IDS
        .iter()
        .map(|(tool, op_id)| ((*tool).to_owned(), Some((*op_id).to_owned())))
        .chain(
            procedure_tool_op_ids()
                .into_iter()
                .map(|(tool, op_id)| (tool.to_owned(), Some(op_id))),
        )
        .chain(
            MCP_ONLY_TOOL_PERMISSIONS
                .iter()
                .map(|(tool, _)| ((*tool).to_owned(), None)),
        )
        .collect()
}

/// The gate a tool call must clear, or `None` when the tool is unknown OR its op-id is one the
/// REST map denies unconditionally.
///
/// Fail-closed by the same rule `rpc_authorize` uses and for the same reason: an op-id absent from
/// `required_permission` and from `AUTHENTICATED_ONLY_OP_IDS` is denied, never defaulted. That is
/// what keeps a tool from being reachable here after the REST map deliberately drops its op-id
/// (`model.Account.update`, `model.ApiKey.create`, `model.ProjectMember.*`).
pub fn tool_gate(tool: &str) -> Option<ToolGate> {
    if let Some((_, permission)) = MCP_ONLY_TOOL_PERMISSIONS
        .iter()
        .find(|(name, _)| *name == tool)
    {
        return Some(ToolGate::Permission(*permission));
    }
    let op_id = op_id_for_tool(tool)?;
    if let Some(permission) = required_permission(&op_id) {
        Some(ToolGate::Permission(permission))
    } else if is_authenticated_only_op_id(&op_id) {
        Some(ToolGate::AuthenticatedOnly)
    } else {
        None
    }
}
