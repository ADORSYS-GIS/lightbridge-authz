//! `AuthProvider` bridging the existing bearer/JWKS validation into cratestack's RPC router
//! (ADR-0003, "AuthProvider bridges the existing JWT/JWKS validation").
//!
//! The RPC router calls [`CratestackAuthProvider::authenticate`] once per request. It reuses the
//! unchanged [`BearerTokenServiceTrait`] validation (JWKS fetch/cache, RS256 verification, audience
//! matching — see `lightbridge-authz-bearer`, migrated to `authkestra-guard` in ADR-0004) and, on
//! success, projects the validated subject into a [`CoolContext`] so the schema's `@@allow`/`@@deny`
//! policies — all of which reference `auth().id` against `auth Principal { id String }` — resolve to
//! the caller's subject. No new authentication logic lives here; this is glue.

use std::sync::Arc;

use cratestack::axum::http;
use cratestack::{AuthProvider, CoolContext, CoolError, RequestContext, Value};
use lightbridge_authz_bearer::BearerTokenServiceTrait;

/// Context key under which the validated caller's raw access token is stashed, so procedures that
/// still need it (e.g. `rotateApiKey`'s downstream secret issuance / token exchange) can read it
/// without the RPC layer having to thread the `Authorization` header through separately.
pub const ACCESS_TOKEN_CONTEXT_KEY: &str = "access_token";

/// Context key under which the caller's raw role strings are stashed (informational; the finalized
/// schema authorizes on `auth().id` membership, not roles).
pub const ROLES_CONTEXT_KEY: &str = "roles";

#[derive(Clone)]
pub struct CratestackAuthProvider {
    bearer: Arc<dyn BearerTokenServiceTrait>,
}

impl CratestackAuthProvider {
    pub fn new(bearer: Arc<dyn BearerTokenServiceTrait>) -> Self {
        Self { bearer }
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
        let token = extract_bearer(request.headers);
        async move {
            // No bearer at all → 401, matching the prior middleware's fail-closed posture (rather
            // than an anonymous context, which would surface as a policy-driven empty read).
            let Some(token) = token else {
                return Err(CoolError::Unauthorized("missing bearer token".to_owned()));
            };
            match bearer.validate_bearer_token(&token).await {
                Ok(info) if info.active => {
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
                    Ok(ctx)
                }
                // Invalid/inactive token or validation error → uniform 401, never leaking which step
                // failed (matching the bearer service's existing security posture).
                Ok(_) | Err(_) => Err(CoolError::Unauthorized("invalid bearer token".to_owned())),
            }
        }
    }
}
