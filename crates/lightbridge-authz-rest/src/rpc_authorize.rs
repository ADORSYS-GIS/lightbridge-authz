//! RBAC permission gate for the cratestack RPC surface (ADR-0003 follow-up).
//!
//! cratestack's generated `@@allow` policies only encode the *fine-grained, per-tenant* membership
//! check ("is this caller a member of the account this resource belongs to"). They do NOT encode the
//! *coarse* role -> permission gate that `docs/rbac.md` mandates as a separate, mandatory-first
//! layer: a read-only `lightbridge-viewer` who is nonetheless an account member must not be able to
//! create/update/delete. This module supplies that missing layer as an Axum middleware wrapping the
//! RPC router.
//!
//! Composition (matching `docs/rbac.md`): the RBAC gate runs **first** — a caller lacking the
//! required permission is rejected with `403 Forbidden` before the request ever reaches cratestack's
//! dispatch; the membership `@@allow` policy runs **second** (a non-member yields `404`). Both must
//! pass.
//!
//! The map below is the single source of truth for op-id -> required permission on the RPC surface.
//! It is **fail-closed**: any unary op-id not listed here (unknown ops, `model.ProjectMember.*`,
//! `model.ApiKey.create`) is denied unconditionally, mirroring the pre-migration REST `authorize`
//! middleware's documented behavior for unmapped routes.
//!
//! `POST /rpc/batch` is a special case: it bundles multiple ops in its frame body, so there is no
//! single op-id this coarse, URL-derived gate could check permission against. Rather than denying the
//! endpoint wholesale, this gate only requires *some* valid, active caller up front (so a wholly
//! unauthenticated batch call gets a clean top-level `401` rather than a `200` envelope full of
//! per-frame `unauthenticated` errors) and defers the actual per-op permission check to
//! `CratestackAuthProvider::authenticate`, which cratestack's batch dispatch calls once per frame —
//! each time with that frame's own canonical `/rpc/<op_id>` path — so every frame is authorized
//! individually against the *same* [`required_permission`] map used here for unary calls.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::Permission;
use serde_json::json;

/// The permission an RPC op-id requires, or `None` when the op-id must be denied unconditionally
/// (fail closed). Op-ids follow cratestack's canonical scheme: generated model verbs are
/// `model.<Model>.<verb>` (`verb` in `list|get|create|update|delete`) and procedures are
/// `procedure.<name>` (the schema name verbatim, e.g. `procedure.rotateApiKey`).
///
/// Deliberately unmapped (=> denied):
/// - `model.Account.create` — the schema removed its `@@allow("create")`, so it is already
///   fail-closed at the policy layer; denying it here as well guarantees a clean `403`. The generic
///   verb would let a caller choose the row's id, and since ADR-0006 the account id IS the caller's
///   JWT subject — a caller-supplied id would be an impersonation primitive. Account creation goes
///   through `procedure.createAccount`, which takes the id from the authenticated subject.
/// - `model.ApiKey.create` — the schema removed its `@@allow("create")`, so it is already
///   fail-closed at the policy layer; denying it here as well guarantees a clean `403` even if the
///   schema-level removal alone did not produce one. API-key creation goes through
///   `procedure.createApiKey`.
/// - `model.ProjectMember.*` — that model is policy-locked to read-only and has no generated
///   mutation verbs; denied here too for defense in depth. Roster changes go through
///   `procedure.addProjectMember` / `procedure.removeProjectMember` / `procedure.setProjectMemberRole`
///   / `procedure.setProjectMemberQuotaTier`, which enforce the lead check in SQL.
///
/// `batch` (the op-id `op_id_from_path` extracts from `/rpc/batch`) is *not* denied here — it is
/// intercepted earlier, in [`rpc_authorize`], before this map is even consulted. A batch bundles
/// multiple ops in its frame body, so there is no single op-id this function could look up; per-frame
/// permission is instead enforced once per frame, deeper in the dispatch pipeline, by
/// `CratestackAuthProvider::authenticate` (see `auth_provider.rs`), which cratestack calls once per
/// op — including once per batch frame, each time with that frame's own canonical `/rpc/<op_id>` path.
pub(crate) fn required_permission(op_id: &str) -> Option<Permission> {
    use Permission::*;
    Some(match op_id {
        "procedure.createAccount" => AccountCreate,
        "model.Account.list" => AccountRead,
        "model.Account.get" => AccountRead,
        "model.Account.update" => AccountUpdate,
        // model.Account.delete is intentionally absent (falls through to `_ => None`, denied): the
        // schema carries no `@@allow("delete", ...)` on Account, so the cratestack policy layer
        // already fail-closes this op-id -- omitted here too, same defense-in-depth pattern as
        // `model.ApiKey.create`. Account deletion is `procedure.deleteAccountPermanently`, below,
        // whose SQL check is now simply "the caller is this account" (ADR-0006: one account is one
        // person, so there is no role left to gate on).
        "procedure.disableAccount" => AccountDisable,
        "procedure.enableAccount" => AccountDisable,
        "procedure.deleteAccountPermanently" => AccountDelete,

        "model.Project.create" => ProjectCreate,
        "model.Project.list" => ProjectRead,
        "model.Project.get" => ProjectRead,
        "model.Project.update" => ProjectUpdate,
        "model.Project.delete" => ProjectDelete,
        "procedure.disableProject" => ProjectDisable,
        "procedure.enableProject" => ProjectDisable,
        "procedure.setDefaultProject" => ProjectUpdate,
        // Roster management (ADR-0006). These replace the removed account-member procedures, and
        // the capability moved with them: `project:member`, not `account:member`. Note this is only
        // the coarse gate — the lead check ("the member row matching my subject must ALSO have
        // role=lead") lives in the procedures' hand-written SQL, since cratestack's policy layer
        // cannot express a compound condition on one related row.
        // The roster's read path. Gated at `project:member` like the mutations rather than at
        // `project:read`: the roster section is a single UI concern, and converse-frontends
        // already gates its rendering on `project:member`, so splitting the read out would let a
        // caller reach data the client never asks for at that grant. The finer "who may read"
        // check (any member, not only leads) lives in the procedure's SQL.
        "procedure.listProjectRoster" => ProjectMember,
        "procedure.addProjectMember" => ProjectMember,
        "procedure.removeProjectMember" => ProjectMember,
        "procedure.setProjectMemberRole" => ProjectMember,
        "procedure.setProjectMemberQuotaTier" => ProjectMember,

        "procedure.createApiKey" => ApiKeyCreate,
        "model.ApiKey.list" => ApiKeyRead,
        "model.ApiKey.get" => ApiKeyRead,
        "model.ApiKey.update" => ApiKeyUpdate,
        "model.ApiKey.delete" => ApiKeyDelete,
        "procedure.revokeApiKey" => ApiKeyRevoke,
        "procedure.rotateApiKey" => ApiKeyRotate,

        // AccountSummary is the read-only dashboard aggregate this migration adds. It is gated at
        // `account:read` (same coarse capability as reading accounts). NB: in cratestack-pg 0.4.9 a
        // `view` is served via the server-side `runtime.views()` accessor and generates NO RPC
        // dispatch arm, so `model.AccountSummary.*` is not actually reachable on `/rpc/{op_id}` today
        // (it would 404 at dispatch). These entries are therefore forward-looking / defensive: if a
        // future cratestack exposes views over RPC, the correct coarse gate is already in place.
        "model.AccountSummary.list" | "model.AccountSummary.get" => AccountRead,

        // Budget policy lifecycle (ADR-0007). `getBudgetPolicyStatus` is gated coarser than
        // `activateBudgetPolicy` -- reading what's serving should not require the ability to
        // change it. Both are `@allow(auth() != null)` only in the schema (no per-tenant
        // ownership check -- the policy set is a single, platform-wide singleton), so this coarse
        // gate is the entire authorization story for these two op-ids.
        "procedure.activateBudgetPolicy" => BudgetPolicyActivate,
        "procedure.getBudgetPolicyStatus" => BudgetPolicyRead,
        // Simulation (#190): evaluates a proposed policy against a caller-supplied scenario
        // entirely in memory, no database read or write. Gated separately from both
        // `budget:policy-read` and `budget:policy-activate` -- it is neither.
        "procedure.simulateBudgetPolicy" => BudgetPolicySimulate,

        // Self-service refill and the admin review queue (#191, PR 3.4). Requesting a refill is
        // gated separately from reviewing one -- a caller who can ask for more budget should not
        // thereby be able to approve/reject requests (including their own), and vice versa.
        "procedure.requestBudgetRefill" => BudgetSelfRefill,
        "procedure.listPendingAugmentationRequests" => BudgetReview,
        "procedure.approveAugmentationRequest" => BudgetReview,
        "procedure.rejectAugmentationRequest" => BudgetReview,

        // Refresh-token session revocation (the offboarding kill switch). Same self/admin split
        // as the budget refill pair above -- see docs/rbac.md.
        "procedure.revokeOwnSessions" => SessionRevokeOwn,
        "procedure.revokeSubjectSessions" => SessionRevoke,

        _ => return None,
    })
}

/// Extract a bearer token from the `Authorization` header, tolerating `Bearer`/`bearer` casing and
/// surrounding whitespace. Mirrors `auth_provider::extract_bearer` (kept local so this module does
/// not depend on that one's internals).
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("authorization")?.to_str().ok()?.trim();
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

fn deny(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// The op-id segment of an RPC request path — the part after the last `/rpc/`, or an empty string
/// when the path contains no `/rpc/` segment (which the map treats as unmapped -> denied anyway).
///
/// Matches on `/rpc/` anywhere rather than only as a leading prefix so the gate is correct whether
/// the RPC surface is mounted at the root (`/rpc/<op_id>`) or under a configured base path
/// (`server.api.rpc_base_path`, e.g. `/api/rpc/<op_id>`). axum's `nest` normally strips the prefix
/// before this middleware runs, but matching the substring keeps the gate correct regardless of
/// layer ordering. Op-ids never contain `/rpc/` (they are dot-delimited, e.g. `model.Account.list`).
pub(crate) fn op_id_from_path(path: &str) -> &str {
    match path.rfind("/rpc/") {
        Some(idx) => &path[idx + "/rpc/".len()..],
        None => "",
    }
}

/// The op-id `op_id_from_path` extracts from `POST /rpc/batch` — handled specially in
/// [`rpc_authorize`] rather than through the [`required_permission`] map (see module docs).
const BATCH_OP_ID: &str = "batch";

/// Axum middleware enforcing the coarse RBAC gate ahead of cratestack's RPC dispatch. Wire it with
/// [`axum::middleware::from_fn_with_state`], passing the bearer service as state, and layer it over
/// the RPC router (see `build_api_router`).
///
/// Behavior:
/// - `batch` op-id -> only a valid, active bearer token is required here; per-frame permission is
///   enforced deeper, once per frame, by `CratestackAuthProvider::authenticate` (see module docs);
/// - unmapped op-id (fail-closed set above) -> `403` unconditionally, no token required;
/// - mapped op-id, missing/invalid/inactive token -> `401` (matching the RPC `AuthProvider`'s
///   fail-closed posture; the provider re-validates on the allowed path);
/// - mapped op-id, valid token lacking the permission -> `403`;
/// - mapped op-id, valid token holding the permission -> forwarded to dispatch, where cratestack's
///   membership `@@allow` policy applies as the second gate.
pub async fn rpc_authorize(
    State(bearer): State<Arc<dyn BearerTokenServiceTrait>>,
    request: Request,
    next: Next,
) -> Response {
    let op_id = op_id_from_path(request.uri().path()).to_owned();

    if op_id == BATCH_OP_ID {
        let Some(token) = extract_bearer(request.headers()) else {
            return deny(StatusCode::UNAUTHORIZED, "missing bearer token");
        };
        return match bearer.validate_bearer_token(&token).await {
            Ok(info) if info.active => next.run(request).await,
            Ok(_) | Err(_) => deny(StatusCode::UNAUTHORIZED, "invalid bearer token"),
        };
    }

    let Some(required) = required_permission(&op_id) else {
        return deny(StatusCode::FORBIDDEN, "operation not permitted");
    };

    let Some(token) = extract_bearer(request.headers()) else {
        return deny(StatusCode::UNAUTHORIZED, "missing bearer token");
    };

    match bearer.validate_bearer_token(&token).await {
        Ok(info) if info.active => {
            if info.has_permission(required) {
                next.run(request).await
            } else {
                deny(StatusCode::FORBIDDEN, "insufficient permissions")
            }
        }
        // Invalid/inactive token or validation error -> uniform 401, never leaking which step failed.
        Ok(_) | Err(_) => deny(StatusCode::UNAUTHORIZED, "invalid bearer token"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mapped_op_id_maps_to_the_documented_permission() {
        let cases = [
            ("procedure.createAccount", Permission::AccountCreate),
            ("model.Account.list", Permission::AccountRead),
            ("model.Account.get", Permission::AccountRead),
            ("model.Account.update", Permission::AccountUpdate),
            ("procedure.disableAccount", Permission::AccountDisable),
            ("procedure.enableAccount", Permission::AccountDisable),
            (
                "procedure.deleteAccountPermanently",
                Permission::AccountDelete,
            ),
            ("model.Project.create", Permission::ProjectCreate),
            ("model.Project.list", Permission::ProjectRead),
            ("model.Project.get", Permission::ProjectRead),
            ("model.Project.update", Permission::ProjectUpdate),
            ("model.Project.delete", Permission::ProjectDelete),
            ("procedure.disableProject", Permission::ProjectDisable),
            ("procedure.enableProject", Permission::ProjectDisable),
            ("procedure.setDefaultProject", Permission::ProjectUpdate),
            ("procedure.addProjectMember", Permission::ProjectMember),
            ("procedure.removeProjectMember", Permission::ProjectMember),
            ("procedure.listProjectRoster", Permission::ProjectMember),
            ("procedure.setProjectMemberRole", Permission::ProjectMember),
            (
                "procedure.setProjectMemberQuotaTier",
                Permission::ProjectMember,
            ),
            ("procedure.createApiKey", Permission::ApiKeyCreate),
            ("model.ApiKey.list", Permission::ApiKeyRead),
            ("model.ApiKey.get", Permission::ApiKeyRead),
            ("model.ApiKey.update", Permission::ApiKeyUpdate),
            ("model.ApiKey.delete", Permission::ApiKeyDelete),
            ("procedure.revokeApiKey", Permission::ApiKeyRevoke),
            ("procedure.rotateApiKey", Permission::ApiKeyRotate),
            ("model.AccountSummary.list", Permission::AccountRead),
            ("model.AccountSummary.get", Permission::AccountRead),
            (
                "procedure.activateBudgetPolicy",
                Permission::BudgetPolicyActivate,
            ),
            (
                "procedure.getBudgetPolicyStatus",
                Permission::BudgetPolicyRead,
            ),
            (
                "procedure.simulateBudgetPolicy",
                Permission::BudgetPolicySimulate,
            ),
            (
                "procedure.requestBudgetRefill",
                Permission::BudgetSelfRefill,
            ),
            (
                "procedure.listPendingAugmentationRequests",
                Permission::BudgetReview,
            ),
            (
                "procedure.approveAugmentationRequest",
                Permission::BudgetReview,
            ),
            (
                "procedure.rejectAugmentationRequest",
                Permission::BudgetReview,
            ),
            ("procedure.revokeOwnSessions", Permission::SessionRevokeOwn),
            ("procedure.revokeSubjectSessions", Permission::SessionRevoke),
        ];
        for (op_id, expected) in cases {
            assert_eq!(
                required_permission(op_id),
                Some(expected),
                "op-id {op_id} should require {expected:?}"
            );
        }
    }

    #[test]
    fn unmapped_and_sensitive_op_ids_are_fail_closed() {
        for op_id in [
            "model.Account.create",
            "model.Account.delete",
            "model.ApiKey.create",
            "model.ProjectMember.list",
            "model.ProjectMember.get",
            "model.ProjectMember.create",
            "model.ProjectMember.delete",
            // Removed by ADR-0006 — these must not linger as mapped op-ids after the rename.
            "procedure.addAccountMember",
            "procedure.removeAccountMember",
            "procedure.setAccountMemberRole",
            "procedure.setDefaultAccount",
            // Still correctly unmapped in this map — `rpc_authorize` no longer reaches this call for
            // "batch" (it's intercepted earlier, see module docs), but the map itself has no entry
            // for it either way, so this assertion stays valid on its own terms.
            "batch",
            "",
            "model.Account.frobnicate",
            "procedure.unknown",
        ] {
            assert_eq!(
                required_permission(op_id),
                None,
                "op-id {op_id} must be unmapped (fail closed)"
            );
        }
    }

    #[test]
    fn op_id_is_extracted_from_the_rpc_path() {
        assert_eq!(
            op_id_from_path("/rpc/model.Account.create"),
            "model.Account.create"
        );
        assert_eq!(op_id_from_path("/rpc/batch"), "batch");
        assert_eq!(op_id_from_path("/healthz"), "");
    }

    #[test]
    fn op_id_is_extracted_under_a_configured_base_path() {
        // With `server.api.rpc_base_path` set (e.g. `/api`), the externally-visible path is
        // `/api/rpc/<op_id>`. The gate must still resolve the op-id.
        assert_eq!(
            op_id_from_path("/api/rpc/model.Account.list"),
            "model.Account.list"
        );
        assert_eq!(
            op_id_from_path("/gateway/v1/rpc/procedure.createAccount"),
            "procedure.createAccount"
        );
        assert_eq!(op_id_from_path("/api/rpc/batch"), "batch");
        // No `/rpc/` segment anywhere -> unmapped (denied).
        assert_eq!(op_id_from_path("/api/healthz"), "");
    }

    #[test]
    fn extract_bearer_tolerates_casing_and_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer  abc ".parse().unwrap());
        assert_eq!(extract_bearer(&headers).as_deref(), Some("abc"));
        headers.insert("authorization", "bearer xyz".parse().unwrap());
        assert_eq!(extract_bearer(&headers).as_deref(), Some("xyz"));
        headers.insert("authorization", "Bearer   ".parse().unwrap());
        assert_eq!(extract_bearer(&headers), None);
    }
}
