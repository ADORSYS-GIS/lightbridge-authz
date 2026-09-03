//! The procedure-backed MCP tool surface: one tool per RPC procedure that `authz-api` or
//! `authz-budget` serves and that `mcp.rs`'s hand-written tools do not already cover
//! (lightbridge-authz#645, ADR-0033 / ADR-0032 / ADR-0007 / #647 / #649).
//!
//! `mcp.rs` keeps the tools it already had: those predate this module, several of them do more
//! than their RPC twin (`rotate-api-key` takes a name/expiry/grace period the `keyId`-only
//! `rotateApiKey` procedure cannot express) or exist only here (`validate-api-key`), and rewriting
//! them onto this path would be churn with a behaviour change attached. What this module adds is
//! everything that had NO tool at all — the whole budget domain, sessions, identity resolution,
//! platform role grants, the two catalogues, and the two self-describing reads.
//!
//! Scope is per tool, not per process: `procedure_context` picks `RpcScope::Budget` for a
//! `budget:*` op-id and `RpcScope::Crud` otherwise, from the SAME `is_budget_op_id` predicate that
//! splits the two REST routers. So a budget procedure's `@allow(... auth().rpcScope == "budget")`
//! clause is satisfied here exactly when it would be on `authz-budget`, and a crud procedure's is
//! not accidentally satisfied by it. This is the one place the hard api/budget listener split does
//! not apply: `lightbridge-mcp` is a single agent-facing surface over both, which is what the
//! owner directive asked for — it is not a third RPC listener, and it exposes no route a caller
//! could reach without going through the per-tool permission gate in `mcp_rbac`.

use crate::mcp_procedure_tool::procedure_tools;

procedure_tools! {
    // --- Catalogues and self-scoped api-key reads (crud) ---------------------------------------
    "list-billing-plans" => list_billing_plans,
        "List the operator-configured billing plan ids a new API key may be created against";
    "list-model-catalog" => list_model_catalog,
        "List the model catalogue a project's allowedModels/modelPolicy is edited against";
    "list-my-expiring-api-keys" => list_my_expiring_api_keys,
        "List the caller's own API keys expiring within a window, across every project";

    // --- Sessions (#649, crud) -----------------------------------------------------------------
    "query-sessions" => query_sessions,
        "Page through sessions; own-scope callers see only their own rows regardless of filter";
    "revoke-session" => revoke_session,
        "Revoke one session by id; revoking someone else's additionally requires session:revoke";
    "revoke-own-sessions" => revoke_own_sessions,
        "Revoke every refresh-token session belonging to the caller";
    "revoke-subject-sessions" => revoke_subject_sessions,
        "Revoke every refresh-token session belonging to a named subject (offboarding kill switch)";

    // --- Identity resolution (#647, crud) ------------------------------------------------------
    "resolve-user-profiles" => resolve_user_profiles,
        "Batch-resolve account ids to display profiles";
    "resolve-actor-labels" => resolve_actor_labels,
        "Batch-resolve actor ids to audit-trail display labels";
    "search-users" => search_users,
        "Search the estate's users by name or email";

    // --- Platform role grants (ADR-0033, crud) -------------------------------------------------
    "list-platform-role-grants" => list_platform_role_grants,
        "Page through platform role grants";
    "grant-platform-role" => grant_platform_role,
        "Grant a platform role to a subject; the role must exist in the configured catalogue";
    "revoke-platform-role" => revoke_platform_role,
        "Revoke a platform role from a subject";

    // --- Self-describing reads (authenticated-only, crud) --------------------------------------
    "get-my-access" => get_my_access,
        "Return the caller's own roles and the permission set the server derives from them";
    "get-build-info" => get_build_info,
        "Return this process's build stamp (version, commit, image), same values as GET /version";

    // --- Budget policy lifecycle (ADR-0007, budget) --------------------------------------------
    "activate-budget-policy" => activate_budget_policy,
        "Activate a budget policy revision, hot-swapping the live evaluation engine";
    "get-budget-policy-status" => get_budget_policy_status,
        "Report which budget policy revision is currently serving";
    "simulate-budget-policy" => simulate_budget_policy,
        "Evaluate a proposed policy against a supplied scenario, in memory, with no DB write";
    "create-budget-policy-revision" => create_budget_policy_revision,
        "Author a new budget policy revision without activating it";

    // --- Self-service refill and the review queue (#191/#295, budget) --------------------------
    "request-budget-refill" => request_budget_refill,
        "Request a self-service budget refill, evaluated against the active policy";
    "get-my-budget-refill-ladder" => get_my_budget_refill_ladder,
        "Preview the caller's own position on the refill ladder before requesting";
    "list-pending-augmentation-requests" => list_pending_augmentation_requests,
        "Page through augmentation requests awaiting review";
    "approve-augmentation-request" => approve_augmentation_request,
        "Approve a pending augmentation request";
    "reject-augmentation-request" => reject_augmentation_request,
        "Reject a pending augmentation request";
    "list-my-augmentation-requests" => list_my_augmentation_requests,
        "Page through the caller's own augmentation-request history";

    // --- Balances and grants (ADR-0014, budget) ------------------------------------------------
    "get-my-budget-balance" => get_my_budget_balance,
        "Read the caller's own budget balance in integer micro-USD";
    "get-budget-balance" => get_budget_balance,
        "Read any account's budget balance in integer micro-USD";
    "list-my-budget-grants" => list_my_budget_grants,
        "Page through the caller's own budget grant ledger";
    "list-budget-grants" => list_budget_grants,
        "Page through any account's budget grant ledger (audit read)";
    "grant-budget" => grant_budget,
        "Write a direct budget grant, bypassing self-service policy evaluation";
    "revoke-budget-grant" => revoke_budget_grant,
        "Revoke a previously written budget grant";

    // --- Reset schedules (ADR-0032, budget) ----------------------------------------------------
    "list-budget-reset-schedules" => list_budget_reset_schedules,
        "List the standing budget reset schedules";
    "create-budget-reset-schedule" => create_budget_reset_schedule,
        "Create a standing budget reset schedule";
    "update-budget-reset-schedule" => update_budget_reset_schedule,
        "Update a standing budget reset schedule";
    "delete-budget-reset-schedule" => delete_budget_reset_schedule,
        "Delete a standing budget reset schedule";
    "run-budget-reset-schedule-now" => run_budget_reset_schedule_now,
        "Fire a reset schedule by hand; dryRun still enumerates the whole estate, so it is gated \
         at the same budget:schedule-manage permission";
    "get-effective-reset-schedule" => get_effective_reset_schedule,
        "Report which schedule governs one account, and when it next fires";
}
