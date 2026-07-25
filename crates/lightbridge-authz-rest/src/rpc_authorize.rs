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
//! It is **fail-closed**: any op-id not listed here (unknown ops, `model.AccountMembership.*`,
//! `model.ApiKey.create`, the `/rpc/batch` fan-out endpoint) is denied unconditionally, mirroring
//! the pre-migration REST `authorize` middleware's documented behavior for unmapped routes.

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
///   verb only inserts the `accounts` row and never seeds `account_memberships`, which would lock
///   the creator out of every membership-scoped policy. Account creation goes through
///   `procedure.createAccount`, which seeds the creator's membership in the same transaction.
/// - `model.ApiKey.create` — the schema removed its `@@allow("create")`, so it is already
///   fail-closed at the policy layer; denying it here as well guarantees a clean `403` even if the
///   schema-level removal alone did not produce one. API-key creation goes through
///   `procedure.createApiKey`.
/// - `model.AccountMembership.*` — that model is policy-locked to read-self and has no generated
///   mutation verbs; denied here too for defense in depth. Membership changes go through
///   `procedure.addAccountMember` / `procedure.removeAccountMember`.
/// - `/rpc/batch` (op-id `batch`) — a batch bundles multiple ops in its frame body; the per-op
///   permission cannot be evaluated from the URL path alone, so the whole endpoint is fail-closed.
pub fn required_permission(op_id: &str) -> Option<Permission> {
    use Permission::*;
    Some(match op_id {
        "procedure.createAccount" => AccountCreate,
        "model.Account.list" => AccountRead,
        "model.Account.get" => AccountRead,
        "model.Account.update" => AccountUpdate,
        // model.Account.delete is intentionally absent (falls through to `_ => None`, denied): the
        // schema no longer carries `@@allow("delete", ...)` on Account (membership-role gating can't
        // be expressed as a relation-quantifier policy predicate, see the schema's own comment on
        // `Account`), so the cratestack policy layer already fail-closes this op-id -- omitted here
        // too, same defense-in-depth pattern as `model.ApiKey.create`. Account deletion is now
        // `procedure.deleteAccountPermanently`, below.
        "procedure.disableAccount" => AccountDisable,
        "procedure.enableAccount" => AccountDisable,
        "procedure.addAccountMember" => AccountMember,
        "procedure.removeAccountMember" => AccountMember,
        // Role changes are membership management, same coarse capability as add/remove.
        "procedure.setAccountMemberRole" => AccountMember,
        "procedure.deleteAccountPermanently" => AccountDelete,
        // Reassigning the default account is an update to `isDefault`, same coarse capability as
        // any other account mutation short of delete/disable/membership.
        "procedure.setDefaultAccount" => AccountUpdate,

        "model.Project.create" => ProjectCreate,
        "model.Project.list" => ProjectRead,
        "model.Project.get" => ProjectRead,
        "model.Project.update" => ProjectUpdate,
        "model.Project.delete" => ProjectDelete,
        "procedure.disableProject" => ProjectDisable,
        "procedure.enableProject" => ProjectDisable,
        "procedure.setDefaultProject" => ProjectUpdate,

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
fn op_id_from_path(path: &str) -> &str {
    match path.rfind("/rpc/") {
        Some(idx) => &path[idx + "/rpc/".len()..],
        None => "",
    }
}

/// Axum middleware enforcing the coarse RBAC gate ahead of cratestack's RPC dispatch. Wire it with
/// [`axum::middleware::from_fn_with_state`], passing the bearer service as state, and layer it over
/// the RPC router (see `build_api_router`).
///
/// Behavior:
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
            ("procedure.addAccountMember", Permission::AccountMember),
            ("procedure.removeAccountMember", Permission::AccountMember),
            ("procedure.setAccountMemberRole", Permission::AccountMember),
            (
                "procedure.deleteAccountPermanently",
                Permission::AccountDelete,
            ),
            ("procedure.setDefaultAccount", Permission::AccountUpdate),
            ("model.Project.create", Permission::ProjectCreate),
            ("model.Project.list", Permission::ProjectRead),
            ("model.Project.get", Permission::ProjectRead),
            ("model.Project.update", Permission::ProjectUpdate),
            ("model.Project.delete", Permission::ProjectDelete),
            ("procedure.disableProject", Permission::ProjectDisable),
            ("procedure.enableProject", Permission::ProjectDisable),
            ("procedure.setDefaultProject", Permission::ProjectUpdate),
            ("procedure.createApiKey", Permission::ApiKeyCreate),
            ("model.ApiKey.list", Permission::ApiKeyRead),
            ("model.ApiKey.get", Permission::ApiKeyRead),
            ("model.ApiKey.update", Permission::ApiKeyUpdate),
            ("model.ApiKey.delete", Permission::ApiKeyDelete),
            ("procedure.revokeApiKey", Permission::ApiKeyRevoke),
            ("procedure.rotateApiKey", Permission::ApiKeyRotate),
            ("model.AccountSummary.list", Permission::AccountRead),
            ("model.AccountSummary.get", Permission::AccountRead),
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
            "model.AccountMembership.list",
            "model.AccountMembership.get",
            "model.AccountMembership.create",
            "model.AccountMembership.delete",
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
