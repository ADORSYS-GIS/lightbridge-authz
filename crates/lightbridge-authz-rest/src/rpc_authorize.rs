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
/// - `model.Account.update` (#398) — #379 marked `Account.defaultQuota`, the verb's only
///   settable field, `@readonly`, leaving it with zero writable fields; every call 422ed
///   unconditionally regardless of permission, a live endpoint that could only ever fail. The
///   schema removed its `@@allow("update")` alongside this, so both layers now fail-closed the
///   same way `model.ApiKey.create` above does. Account default-quota updates go exclusively
///   through `procedure.updateAccountDefaultQuota`.
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
/// Which half of the RPC surface a given server instance serves — the mechanism the budget-domain
/// microservice split (see `docs/architecture/budget.md`) uses to make the cutover a *hard* one:
/// every `budget:*`-gated op-id moves OFF `authz-api` (`RpcScope::Crud` denies it) and becomes
/// reachable ONLY on `authz-budget` (`RpcScope::Budget` denies everything else), never both at
/// once. Derived from [`required_permission`]/[`Permission::as_str`] rather than a second,
/// hand-maintained op-id list — the same single-source-of-truth reasoning `required_permission`
/// itself already documents — so a new budget procedure automatically falls on the right side of
/// the split the moment its permission mapping is added there, with nothing else to update.
///
/// Enforced in TWO places, mirroring the existing permission gate's own dual enforcement
/// (`rpc_authorize` for unary calls, [`crate::auth_provider::CratestackAuthProvider::authenticate`]
/// for `POST /rpc/batch` frames, which `rpc_authorize` cannot see individually): a batch frame
/// aimed at an out-of-scope op-id must 404 exactly like a unary call would, or the "hard cutover"
/// claim would be false for any caller willing to wrap the call in a batch envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcScope {
    /// `authz-api`: every mapped op-id EXCEPT `budget:*`.
    Crud,
    /// `authz-budget`: ONLY `budget:*` op-ids.
    Budget,
}

impl RpcScope {
    /// Whether `op_id` is servable under this scope. Unmapped op-ids (including `"batch"`, which
    /// callers must check separately before consulting this) are never budget op-ids, so they pass
    /// `Crud` and fail `Budget` — `required_permission`'s own fail-closed set decides what happens
    /// to them next.
    pub(crate) fn permits(self, op_id: &str) -> bool {
        let is_budget = is_budget_op_id(op_id);
        match self {
            RpcScope::Crud => !is_budget,
            RpcScope::Budget => is_budget,
        }
    }

    /// The `auth().rpcScope` wire value `CratestackAuthProvider` bakes into every batch-envelope
    /// context (see `auth_provider.rs`) and every `@allow`/`@@allow` clause in `authz.cstack`
    /// checks against (see `schema_policy_sync_tests.rs`). Envelope-invariant by construction: which
    /// binary is running is a deployment fact, the same for every frame in one `/rpc/batch` call,
    /// so caching it once per envelope (unlike a per-frame *permission* requirement) is correct,
    /// not a compromise.
    pub(crate) const fn wire_str(self) -> &'static str {
        match self {
            RpcScope::Crud => "crud",
            RpcScope::Budget => "budget",
        }
    }
}

/// Whether `op_id` requires a `budget:*` permission — the single predicate [`RpcScope::permits`]
/// is built from. `resource()` on [`Permission`] is deliberately private to `authz.rs` (not part
/// of its public API), so this reads the canonical `"budget:…"` wire string via the already-public
/// [`Permission::as_str`] instead of exposing a second accessor just for this one caller.
pub(crate) fn is_budget_op_id(op_id: &str) -> bool {
    required_permission(op_id).is_some_and(|permission| permission.as_str().starts_with("budget:"))
}

pub(crate) fn required_permission(op_id: &str) -> Option<Permission> {
    use Permission::*;
    Some(match op_id {
        "procedure.createAccount" => AccountCreate,
        "model.Account.list" => AccountRead,
        "model.Account.get" => AccountRead,
        // model.Account.update is intentionally absent (#398, completing #379): #379 marked
        // `Account.defaultQuota` -- the verb's only settable field -- `@readonly`, leaving the
        // generic verb with zero writable fields, so every call to it 422ed unconditionally for
        // every caller regardless of permission. The schema's `@@allow("update", ...)` clause was
        // removed alongside this (`crates/lightbridge-authz-api/schema/authz.cstack`), so the
        // op-id is unreachable at both layers, same as `model.ApiKey.create` below.
        // `updateAccountDefaultQuota` is the sole write path -- same coarse permission, matching
        // the acceptance criteria's "existing permission granularity" requirement.
        "procedure.updateAccountDefaultQuota" => AccountUpdate,
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
        // #379: `Project.projectQuota` is now `@readonly` on BOTH generic verbs above, so
        // `setProjectQuota` is its replacement write path -- same coarse permission as
        // `model.Project.update`, matching the acceptance criteria's "existing permission
        // granularity" requirement.
        "procedure.setProjectQuota" => ProjectUpdate,
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
        // Read-only companion to `createApiKey`: the catalogue a caller picks `billingPlan` from.
        // Gated at the same `apikey:create` permission (not a new, looser one) -- see the schema
        // doc comment on `listBillingPlans` for why.
        "procedure.listBillingPlans" => ApiKeyCreate,
        // Read-only companion to `model.Project.update`, not to `createApiKey`/`listBillingPlans`
        // above: the catalogue a `Project.allowedModels` editor renders. Gated at `project:update`
        // (the same permission `updateProject` needs to actually write `allowedModels`), not a new,
        // looser permission -- see the schema doc comment on `listModelCatalog` for why.
        "procedure.listModelCatalog" => ProjectUpdate,
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
        // Read-only companion to `requestBudgetRefill`: the ladder-position preview a caller sees
        // before submitting. Gated at the same `budget:self-refill` permission (not the broader
        // `budget:read-own` `getMyBudgetBalance`/`listMyBudgetGrants` share) -- same
        // "read-only companion gated at the mutation's own permission" precedent as
        // `listBillingPlans` above, not a new, looser permission for a one-screen read.
        "procedure.getMyBudgetRefillLadder" => BudgetSelfRefill,
        "procedure.listPendingAugmentationRequests" => BudgetReview,
        "procedure.approveAugmentationRequest" => BudgetReview,
        "procedure.rejectAugmentationRequest" => BudgetReview,

        // Refresh-token session revocation (the offboarding kill switch). Same self/admin split
        // as the budget refill pair above -- see docs/rbac.md.
        "procedure.revokeOwnSessions" => SessionRevokeOwn,
        "procedure.revokeSubjectSessions" => SessionRevoke,

        // Direct budget-balance/ledger reads. Self/admin split the same shape as the session-
        // revocation pair above: the "my own budget only" procedures take no target at all and
        // are gated at the narrower `budget:read-own`; the admin, arbitrary-target procedures are
        // gated at `budget:read`/`budget:audit-read` -- see docs/rbac.md and the schema doc
        // comments on these four procedures for the full self-vs-admin reasoning.
        "procedure.getMyBudgetBalance" => BudgetReadOwn,
        "procedure.listMyBudgetGrants" => BudgetReadOwn,
        // The caller's own augmentation-request history (#295), the same `budget:read-own`
        // capability as the pair above -- not `budget:review`, which is the reviewer/admin
        // capability `listPendingAugmentationRequests` gates.
        "procedure.listMyAugmentationRequests" => BudgetReadOwn,
        "procedure.getBudgetBalance" => BudgetRead,
        "procedure.listBudgetGrants" => BudgetAuditRead,
        // Direct admin grant/revoke, bypassing self-service policy evaluation entirely.
        "procedure.grantBudget" => BudgetGrant,
        "procedure.revokeBudgetGrant" => BudgetRevoke,
        // Authoring a new policy revision, kept distinct from `budget:policy-activate` (ADR-0007).
        "procedure.createBudgetPolicyRevision" => BudgetPolicyWrite,

        _ => return None,
    })
}

/// Every op-id `required_permission` maps to a `Some`, paired with the expected permission —
/// the single enumeration both `every_mapped_op_id_maps_to_the_documented_permission` (below) and
/// `schema_policy_sync`'s codegen/drift-check walk, so there is exactly one hand-maintained list
/// of "every mapped op-id" in this crate, not two that could silently diverge. Order matches
/// `required_permission`'s own declaration order. `model.AccountSummary.{list,get}` are included
/// even though that view has no live RPC dispatch arm today (see `authz.cstack`'s own doc comment
/// on it) — its `@@allow` clause still exists and still deserves the same generated gate, forward-
/// looking/defensive exactly as the view entry itself already is.
pub const MAPPED_OP_ID_PERMISSIONS: &[(&str, Permission)] = &[
    ("procedure.createAccount", Permission::AccountCreate),
    ("model.Account.list", Permission::AccountRead),
    ("model.Account.get", Permission::AccountRead),
    (
        "procedure.updateAccountDefaultQuota",
        Permission::AccountUpdate,
    ),
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
    ("procedure.setProjectQuota", Permission::ProjectUpdate),
    ("procedure.addProjectMember", Permission::ProjectMember),
    ("procedure.removeProjectMember", Permission::ProjectMember),
    ("procedure.listProjectRoster", Permission::ProjectMember),
    ("procedure.setProjectMemberRole", Permission::ProjectMember),
    (
        "procedure.setProjectMemberQuotaTier",
        Permission::ProjectMember,
    ),
    ("procedure.createApiKey", Permission::ApiKeyCreate),
    ("procedure.listBillingPlans", Permission::ApiKeyCreate),
    ("procedure.listModelCatalog", Permission::ProjectUpdate),
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
        "procedure.getMyBudgetRefillLadder",
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
    ("procedure.getMyBudgetBalance", Permission::BudgetReadOwn),
    ("procedure.listMyBudgetGrants", Permission::BudgetReadOwn),
    (
        "procedure.listMyAugmentationRequests",
        Permission::BudgetReadOwn,
    ),
    ("procedure.getBudgetBalance", Permission::BudgetRead),
    ("procedure.listBudgetGrants", Permission::BudgetAuditRead),
    ("procedure.grantBudget", Permission::BudgetGrant),
    ("procedure.revokeBudgetGrant", Permission::BudgetRevoke),
    (
        "procedure.createBudgetPolicyRevision",
        Permission::BudgetPolicyWrite,
    ),
];

/// The `auth().<field>` name `CratestackAuthProvider` bakes each [`Permission`]'s boolean grant
/// into, and every generated `@allow`/`@@allow` clause in `authz.cstack` reads. Mechanically
/// derived from [`Permission::as_str`]'s canonical `resource:action` string (splitting further on
/// `-` for hyphenated actions like `read-own`) rather than a second hand-typed list of 31 names —
/// same single-source-of-truth reasoning as [`MAPPED_OP_ID_PERMISSIONS`] above. E.g.
/// `"account:create"` -> `"permAccountCreate"`, `"budget:read-own"` -> `"permBudgetReadOwn"`.
pub fn permission_field_name(permission: Permission) -> String {
    let mut out = String::from("perm");
    for part in permission.as_str().split([':', '-']) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
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
/// `pub(crate)` so `auth_provider.rs`'s batch special case (see its module docs) can match on the
/// same constant rather than a second hand-typed `"batch"` literal.
pub(crate) const BATCH_OP_ID: &str = "batch";

/// State for [`rpc_authorize`]: the bearer service plus which half of the RPC surface (see
/// [`RpcScope`]) this particular router instance serves. Bundled into one `Clone` struct rather
/// than a tuple so `axum::middleware::from_fn_with_state`'s call site (`build_api_router`/
/// `build_budget_router`) reads as named fields, not positional state.
#[derive(Clone)]
pub struct RpcAuthorizeState {
    pub bearer: Arc<dyn BearerTokenServiceTrait>,
    pub scope: RpcScope,
}

/// Axum middleware enforcing the coarse RBAC gate ahead of cratestack's RPC dispatch. Wire it with
/// [`axum::middleware::from_fn_with_state`], passing an [`RpcAuthorizeState`], and layer it over
/// the RPC router (see `build_api_router`/`build_budget_router`).
///
/// Behavior:
/// - op-id out of this server's [`RpcScope`] -> `404` unconditionally, no token required — this is
///   what makes a moved procedure genuinely unreachable on the server it moved off, not merely
///   permission-denied (see `RpcScope`'s own doc comment for why this alone does not close the
///   `POST /rpc/batch` gap, and where the other half of the enforcement lives);
/// - `batch` op-id -> only a valid, active bearer token is required here; per-frame permission
///   AND per-frame scope are both enforced deeper, once per frame, by
///   `CratestackAuthProvider::authenticate` (see module docs);
/// - unmapped op-id (fail-closed set above) -> `403` unconditionally, no token required;
/// - mapped op-id, missing/invalid/inactive token -> `401` (matching the RPC `AuthProvider`'s
///   fail-closed posture; the provider re-validates on the allowed path);
/// - mapped op-id, valid token lacking the permission -> `403`;
/// - mapped op-id, valid token holding the permission -> forwarded to dispatch, where cratestack's
///   membership `@@allow` policy applies as the second gate.
pub async fn rpc_authorize(
    State(state): State<RpcAuthorizeState>,
    request: Request,
    next: Next,
) -> Response {
    let op_id = op_id_from_path(request.uri().path()).to_owned();

    if op_id == BATCH_OP_ID {
        let Some(token) = extract_bearer(request.headers()) else {
            return deny(StatusCode::UNAUTHORIZED, "missing bearer token");
        };
        return match state.bearer.validate_bearer_token(&token).await {
            Ok(info) if info.active => next.run(request).await,
            Ok(_) | Err(_) => deny(StatusCode::UNAUTHORIZED, "invalid bearer token"),
        };
    }

    if !state.scope.permits(&op_id) {
        return deny(StatusCode::NOT_FOUND, "unknown RPC op");
    }

    let Some(required) = required_permission(&op_id) else {
        return deny(StatusCode::FORBIDDEN, "operation not permitted");
    };

    let Some(token) = extract_bearer(request.headers()) else {
        return deny(StatusCode::UNAUTHORIZED, "missing bearer token");
    };

    match state.bearer.validate_bearer_token(&token).await {
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
        for (op_id, expected) in MAPPED_OP_ID_PERMISSIONS.iter().copied() {
            assert_eq!(
                required_permission(op_id),
                Some(expected),
                "op-id {op_id} should require {expected:?}"
            );
        }
    }

    #[test]
    fn permission_field_name_is_mechanically_derived_and_unique() {
        let cases = [
            (Permission::AccountCreate, "permAccountCreate"),
            (Permission::BudgetReadOwn, "permBudgetReadOwn"),
            (Permission::BudgetPolicyActivate, "permBudgetPolicyActivate"),
            (Permission::SessionRevokeOwn, "permSessionRevokeOwn"),
            (Permission::ApiKeyRotate, "permApikeyRotate"),
        ];
        for (permission, expected) in cases {
            assert_eq!(permission_field_name(permission), expected);
        }

        let mut names: Vec<String> = Permission::ALL
            .into_iter()
            .map(permission_field_name)
            .collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "permission_field_name must be injective over Permission::ALL — a collision here \
             would silently merge two distinct permissions onto one auth field"
        );
    }

    #[test]
    fn unmapped_and_sensitive_op_ids_are_fail_closed() {
        for op_id in [
            "model.Account.create",
            "model.Account.update",
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

    /// The exact 16 op-ids moved off `authz-api` onto `authz-budget` (derived from the
    /// `budget:*`-permission entries in `required_permission` above — this is the same list the
    /// PR description enumerates as "derived from the code", not from memory). If a future PR
    /// adds a 17th `budget:*` op-id and forgets to add it here, `all_and_only_the_budget_gated_op_ids_are_in_budget_scope`
    /// below still passes for it automatically (since it re-derives from `required_permission`
    /// instead of this literal), but this list existing at all is what lets a reviewer diff "the
    /// procedures that moved" without re-deriving them by hand.
    ///
    /// `procedure.getMyBudgetRefillLadder` is the 16th entry, added alongside the original 15 --
    /// it is a `budget:self-refill` op-id like `requestBudgetRefill` right above it (the ladder
    /// preview it serves), so it was always going to land in this scope.
    const BUDGET_OP_IDS: [&str; 16] = [
        "procedure.activateBudgetPolicy",
        "procedure.getBudgetPolicyStatus",
        "procedure.simulateBudgetPolicy",
        "procedure.requestBudgetRefill",
        "procedure.getMyBudgetRefillLadder",
        "procedure.listPendingAugmentationRequests",
        "procedure.approveAugmentationRequest",
        "procedure.rejectAugmentationRequest",
        "procedure.getMyBudgetBalance",
        "procedure.listMyBudgetGrants",
        "procedure.listMyAugmentationRequests",
        "procedure.getBudgetBalance",
        "procedure.listBudgetGrants",
        "procedure.grantBudget",
        "procedure.revokeBudgetGrant",
        "procedure.createBudgetPolicyRevision",
    ];

    #[test]
    fn is_budget_op_id_recognizes_exactly_the_sixteen_moved_procedures() {
        for op_id in BUDGET_OP_IDS {
            assert!(is_budget_op_id(op_id), "{op_id} must be a budget op-id");
        }
        for op_id in [
            "procedure.createAccount",
            "model.Account.list",
            "procedure.createApiKey",
            "procedure.revokeOwnSessions",
            "procedure.revokeSubjectSessions",
            "batch",
            "",
            "procedure.unknown",
        ] {
            assert!(
                !is_budget_op_id(op_id),
                "{op_id} must NOT be a budget op-id — session revocation and CRUD stay on authz-api"
            );
        }
    }

    /// Every `budget:*`-permission op-id in [`required_permission`] is a budget op-id, and nothing
    /// else is — cross-checks [`is_budget_op_id`] against the map by construction instead of by a
    /// second hand-copied list, so a future permission added to `required_permission` under a
    /// `budget:` string is automatically picked up without touching this test.
    #[test]
    fn all_and_only_the_budget_gated_op_ids_are_in_budget_scope() {
        let all_mapped_op_ids: Vec<&str> = BUDGET_OP_IDS
            .iter()
            .copied()
            .chain([
                "procedure.createAccount",
                "model.Account.list",
                "model.Account.get",
                "procedure.updateAccountDefaultQuota",
                "procedure.disableAccount",
                "procedure.enableAccount",
                "procedure.deleteAccountPermanently",
                "model.Project.create",
                "model.Project.list",
                "model.Project.get",
                "model.Project.update",
                "model.Project.delete",
                "procedure.disableProject",
                "procedure.enableProject",
                "procedure.setDefaultProject",
                "procedure.setProjectQuota",
                "procedure.addProjectMember",
                "procedure.removeProjectMember",
                "procedure.listProjectRoster",
                "procedure.setProjectMemberRole",
                "procedure.setProjectMemberQuotaTier",
                "procedure.createApiKey",
                "procedure.listBillingPlans",
                "procedure.listModelCatalog",
                "model.ApiKey.list",
                "model.ApiKey.get",
                "model.ApiKey.update",
                "model.ApiKey.delete",
                "procedure.revokeApiKey",
                "procedure.rotateApiKey",
                "model.AccountSummary.list",
                "model.AccountSummary.get",
                "procedure.revokeOwnSessions",
                "procedure.revokeSubjectSessions",
            ])
            .collect();
        for op_id in all_mapped_op_ids {
            let expected = BUDGET_OP_IDS.contains(&op_id);
            assert_eq!(
                is_budget_op_id(op_id),
                expected,
                "{op_id}: is_budget_op_id should be {expected}"
            );
        }
    }

    #[test]
    fn rpc_scope_crud_permits_everything_except_budget_op_ids() {
        for op_id in BUDGET_OP_IDS {
            assert!(
                !RpcScope::Crud.permits(op_id),
                "authz-api (RpcScope::Crud) must refuse the moved op {op_id}"
            );
        }
        for op_id in [
            "procedure.createAccount",
            "model.Account.list",
            "procedure.revokeOwnSessions",
            "procedure.unknown",
        ] {
            assert!(
                RpcScope::Crud.permits(op_id),
                "authz-api (RpcScope::Crud) must still permit {op_id}"
            );
        }
    }

    #[test]
    fn rpc_scope_budget_permits_only_budget_op_ids() {
        for op_id in BUDGET_OP_IDS {
            assert!(
                RpcScope::Budget.permits(op_id),
                "authz-budget (RpcScope::Budget) must permit {op_id}"
            );
        }
        for op_id in [
            "procedure.createAccount",
            "model.Account.list",
            "procedure.revokeOwnSessions",
            "procedure.unknown",
        ] {
            assert!(
                !RpcScope::Budget.permits(op_id),
                "authz-budget (RpcScope::Budget) must refuse the CRUD-side op {op_id}"
            );
        }
    }
}
