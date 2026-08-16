//! `AuthProvider` bridging the existing bearer/JWKS validation into cratestack's RPC router
//! (ADR-0003, "AuthProvider bridges the existing JWT/JWKS validation").
//!
//! The RPC router calls [`CratestackAuthProvider::authenticate`] once per op — for a unary
//! `POST /rpc/<op_id>` call that's once per request; for `POST /rpc/batch` it's once *per frame*,
//! each time with that frame's own canonical `/rpc/<op_id>` path (see `docs/adr/0003-*`, "RPC
//! transport"). It reuses the unchanged [`BearerTokenServiceTrait`] validation (JWKS fetch/cache,
//! RS256 verification, audience matching — see `lightbridge-authz-bearer`, migrated to
//! `authkestra-resource` in ADR-0004), enforces the same coarse role -> permission gate as
//! [`crate::rpc_authorize`] (this is what gives `/rpc/batch` real per-frame RBAC: `rpc_authorize`
//! can't evaluate a single op-id for a whole batch, but this provider is invoked once per frame with
//! that frame's own op-id, so the check happens here instead), and on success projects the validated
//! subject into a [`CoolContext`] so the schema's `@@allow`/`@@deny` policies — all of which reference
//! `auth().id` against `auth Principal { id String }` — resolve to the caller's subject.

use std::sync::Arc;

use cratestack::axum::http;
use cratestack::{AuthProvider, CoolContext, CoolError, RequestContext, Value};
use lightbridge_authz_bearer::BearerTokenServiceTrait;

use crate::rpc_authorize::{RpcScope, op_id_from_path, required_permission};

/// Context key under which the validated caller's raw access token is stashed, so procedures that
/// still need it (e.g. `rotateApiKey`'s downstream secret issuance / token exchange) can read it
/// without the RPC layer having to thread the `Authorization` header through separately.
pub const ACCESS_TOKEN_CONTEXT_KEY: &str = "access_token";

/// Context key under which the caller's raw role strings are stashed (informational; the finalized
/// schema authorizes on `auth().id` membership, not roles).
pub const ROLES_CONTEXT_KEY: &str = "roles";

/// Context key under which [`TokenInfo::caller_kind`] is stashed, when present, so procedures that
/// need to exclude API-key-derived callers (`requestBudgetRefill`, #191/#216) can read it. Absent
/// from the context entirely when the token carries no such claim -- see
/// [`lightbridge_authz_bearer::TokenInfo::caller_kind`]'s docs for why that must be treated as
/// "unknown", not "human".
pub const CALLER_KIND_CONTEXT_KEY: &str = "caller_kind";

#[derive(Clone)]
pub struct CratestackAuthProvider {
    bearer: Arc<dyn BearerTokenServiceTrait>,
    /// Which half of the RPC surface this provider's router serves (see [`RpcScope`]). Checked
    /// first, ahead of even the bearer/permission checks below — this is the sole place that
    /// closes the `POST /rpc/batch` gap `rpc_authorize`'s own out-of-scope check cannot reach
    /// (that check only sees the outer `/rpc/batch` request, never an individual frame's op-id).
    scope: RpcScope,
}

impl CratestackAuthProvider {
    pub fn new(bearer: Arc<dyn BearerTokenServiceTrait>, scope: RpcScope) -> Self {
        Self { bearer, scope }
    }
}

/// Extract a bearer token from the `Authorization` header, tolerating `Bearer`/`bearer` casing and
/// surrounding whitespace, mirroring the pre-migration `bearer_auth` middleware.
fn extract_bearer(headers: &http::HeaderMap) -> Option<String> {
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

impl AuthProvider for CratestackAuthProvider {
    type Error = CoolError;

    fn authenticate(
        &self,
        request: &RequestContext<'_>,
    ) -> impl core::future::Future<Output = Result<CoolContext, Self::Error>> + Send {
        let bearer = self.bearer.clone();
        let scope = self.scope;
        let token = extract_bearer(request.headers);
        // `request.path` is the canonical `/rpc/<op_id>` for whichever op is being dispatched right
        // now — for a unary call that's the request's own path (already checked once by
        // `rpc_authorize`, so this is a harmless second check); for a `POST /rpc/batch` frame it's
        // that frame's own op-id, which `rpc_authorize` structurally cannot see. This is the sole
        // permission enforcement point for batch frames.
        let op_id = op_id_from_path(request.path).to_owned();
        async move {
            // Out-of-scope op-id (moved to the other service) → 404, before even looking at the
            // bearer token, mirroring `rpc_authorize`'s own scope check for unary calls. For a
            // batch frame this is the ONLY place that check happens at all.
            if !scope.permits(&op_id) {
                return Err(CoolError::NotFound(format!("unknown RPC op `{op_id}`")));
            }
            // Unmapped op-id → 403 unconditionally, mirroring `rpc_authorize`'s fail-closed set
            // (unknown ops, `model.ProjectMember.*`, `model.ApiKey.create`, ...).
            let Some(required) = required_permission(&op_id) else {
                return Err(CoolError::Forbidden("operation not permitted".to_owned()));
            };
            // No bearer at all → 401, matching the prior middleware's fail-closed posture (rather
            // than an anonymous context, which would surface as a policy-driven empty read).
            let Some(token) = token else {
                return Err(CoolError::Unauthorized("missing bearer token".to_owned()));
            };
            match bearer.validate_bearer_token(&token).await {
                Ok(info) if info.active => {
                    if !info.has_permission(required) {
                        return Err(CoolError::Forbidden("insufficient permissions".to_owned()));
                    }
                    // Project the validated subject as `auth().id`.
                    let mut ctx = CoolContext::authenticated([(
                        "id".to_owned(),
                        Value::String(info.sub.clone()),
                    )]);
                    ctx.extensions.insert(
                        ACCESS_TOKEN_CONTEXT_KEY.to_owned(),
                        Value::String(info.access_token.clone()),
                    );
                    if !info.roles.is_empty() {
                        ctx.extensions.insert(
                            ROLES_CONTEXT_KEY.to_owned(),
                            Value::List(info.roles.iter().cloned().map(Value::String).collect()),
                        );
                    }
                    if let Some(caller_kind) = info.caller_kind {
                        ctx.extensions.insert(
                            CALLER_KIND_CONTEXT_KEY.to_owned(),
                            Value::String(caller_kind),
                        );
                    }
                    Ok(ctx)
                }
                // Invalid/inactive token or validation error → uniform 401, never leaking which step
                // failed (matching the bearer service's existing security posture).
                Ok(_) | Err(_) => Err(CoolError::Unauthorized("invalid bearer token".to_owned())),
            }
        }
    }
}
