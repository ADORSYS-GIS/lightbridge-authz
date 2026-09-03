//! The drift guard the MCP surface never had (lightbridge-authz#645, owner directive 2026-09-03).
//!
//! Everything before this file was a promise: `ai-helm-values`' `mcp` config block says the MCP
//! server applies "the same role -> permission map as the api, applied per MCP tool"
//! (lightbridge-authz#122), and that was true when written and quietly false by 37 procedures the
//! moment the api/budget surfaces grew. Nothing failed, because nothing checked. These tests are
//! that check, in both directions:
//!
//! 1. every RPC op-id a caller can reach on `authz-api`/`authz-budget` has an MCP tool, and
//! 2. every MCP tool's gate is the SAME permission the REST map assigns its op-id.
//!
//! They read `schema::axum::OPS` (cratestack's own generated op descriptor table, the same one the
//! RPC dispatcher is built from) rather than a hand-written list of op-ids, so a procedure added
//! to `authz.cstack` tomorrow fails test 1 the day it is added, with no third list to remember to
//! update.

use std::collections::{BTreeMap, BTreeSet};

use lightbridge_authz::mcp_rbac::{ToolGate, gated_tools, tool_gate};
use lightbridge_authz_api::schema;
use lightbridge_authz_rest::rpc_authorize::{is_authenticated_only_op_id, required_permission};
use lightbridge_authz_rest::rpc_permission_map::MAPPED_OP_ID_PERMISSIONS;

/// Op-ids that a caller CAN reach over RPC: mapped to a permission, or enumerated as
/// authenticated-only. Everything else in `OPS` is fail-closed at `rpc_authorize` (`403`) and must
/// therefore NOT gain an MCP tool.
fn reachable_op_ids() -> BTreeSet<&'static str> {
    schema::axum::OPS
        .iter()
        .map(|op| op.op_id)
        .filter(|op_id| required_permission(op_id).is_some() || is_authenticated_only_op_id(op_id))
        .collect()
}

fn tool_op_ids() -> BTreeMap<String, String> {
    gated_tools()
        .into_iter()
        .filter_map(|(tool, op_id)| op_id.map(|op_id| (op_id, tool)))
        .collect()
}

/// Direction 1: no reachable RPC op-id may be missing from the MCP surface.
///
/// This is the assertion that would have failed on 2026-09-02 for `resolveUserProfiles`,
/// `querySessions`, the six `*BudgetResetSchedule*` procedures and the rest — and the reason the
/// gap table in the PR body could be produced mechanically rather than by reading two files side
/// by side.
#[test]
fn every_reachable_rpc_op_id_has_an_mcp_tool() {
    let tools = tool_op_ids();
    let missing: Vec<&str> = reachable_op_ids()
        .into_iter()
        .filter(|op_id| !tools.contains_key(*op_id))
        .collect();
    assert!(
        missing.is_empty(),
        "these RPC op-ids are reachable on authz-api/authz-budget but have no MCP tool -- add one \
         in `mcp_procedure_tools.rs` (or, for a deliberate omission, say why here): {missing:?}"
    );
}

/// Direction 2: every MCP tool that claims an op-id must be gated at exactly the permission the
/// REST map assigns that op-id — no tighter, no looser.
#[test]
fn every_mcp_tool_gate_equals_the_rest_permission_for_its_op_id() {
    for (tool, op_id) in gated_tools() {
        let Some(op_id) = op_id else { continue };
        let gate = tool_gate(&tool)
            .unwrap_or_else(|| panic!("tool `{tool}` resolves to no gate at all (fail-closed)"));
        let expected = match required_permission(&op_id) {
            Some(permission) => ToolGate::Permission(permission),
            None if is_authenticated_only_op_id(&op_id) => ToolGate::AuthenticatedOnly,
            None => panic!(
                "tool `{tool}` claims op-id `{op_id}`, which the REST map denies unconditionally \
                 -- an MCP tool must never be reachable where the RPC surface returns 403"
            ),
        };
        assert_eq!(
            gate, expected,
            "tool `{tool}` (op-id `{op_id}`) is gated differently on MCP than on REST"
        );
    }
}

/// Every op-id an MCP tool claims must actually exist in the generated schema. Catches a typo in
/// `HAND_WRITTEN_TOOL_OP_IDS` — which would otherwise fail closed silently (the tool becomes
/// uncallable) rather than loudly.
#[test]
fn every_mcp_tool_op_id_exists_in_the_generated_schema() {
    let known: BTreeSet<&str> = schema::axum::OPS.iter().map(|op| op.op_id).collect();
    for (tool, op_id) in gated_tools() {
        let Some(op_id) = op_id else { continue };
        assert!(
            known.contains(op_id.as_str()),
            "tool `{tool}` claims op-id `{op_id}`, which the generated schema does not dispatch"
        );
    }
}

/// The MCP tool names must be unique, and each must resolve to a gate. A duplicate name would make
/// `ToolRouter::add_route` silently win-last, so the permission actually enforced would depend on
/// registration order.
#[test]
fn mcp_tool_names_are_unique_and_all_gated() {
    let mut seen = BTreeSet::new();
    for (tool, _) in gated_tools() {
        assert!(
            tool_gate(&tool).is_some(),
            "tool `{tool}` is listed but resolves to no gate"
        );
        assert!(
            seen.insert(tool.clone()),
            "duplicate MCP tool name `{tool}`"
        );
    }
}

/// The one documented gap between the hand-maintained `MAPPED_OP_ID_PERMISSIONS` enumeration and
/// cratestack's generated `OPS`: `AccountSummary` is a `view`, and cratestack-pg generates no RPC
/// dispatch arm for a view, so its two entries are forward-looking/defensive (see
/// `rpc_permission_map`'s own doc comment). Pinned here so that if a future cratestack DOES start
/// dispatching views, this test fails and someone decides deliberately whether the MCP surface
/// should gain the two tools rather than the gap silently widening.
#[test]
fn the_only_mapped_op_id_without_a_generated_op_is_the_account_summary_view() {
    let generated: BTreeSet<&str> = schema::axum::OPS.iter().map(|op| op.op_id).collect();
    let undispatched: BTreeSet<&str> = MAPPED_OP_ID_PERMISSIONS
        .iter()
        .map(|(op_id, _)| *op_id)
        .filter(|op_id| !generated.contains(op_id))
        .collect();
    assert_eq!(
        undispatched,
        BTreeSet::from(["model.AccountSummary.get", "model.AccountSummary.list"]),
        "the set of mapped-but-undispatched op-ids changed; see this test's doc comment"
    );
}

/// A tool must never exist for an op-id the REST surface fail-closes. Guards the specific
/// deliberate omissions `required_permission` documents (`model.Account.update`,
/// `model.ApiKey.create`, `model.ProjectMember.*`, `model.Session.*`), which the MCP surface used
/// to be free to expose because its permission table was its own.
#[test]
fn no_mcp_tool_exists_for_a_fail_closed_op_id() {
    let tools = tool_op_ids();
    for op in schema::axum::OPS {
        if required_permission(op.op_id).is_some() || is_authenticated_only_op_id(op.op_id) {
            continue;
        }
        assert!(
            !tools.contains_key(op.op_id),
            "op-id `{}` is denied unconditionally on REST but tool `{}` exposes it",
            op.op_id,
            tools[op.op_id]
        );
    }
}
