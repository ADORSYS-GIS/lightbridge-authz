//! `AuthProvider` bridging the existing bearer/JWKS validation into cratestack's RPC router
//! (ADR-0003, "AuthProvider bridges the existing JWT/JWKS validation").
//!
//! ## Batch vs unary (issue #383)
//!
//! Before cratestack 0.8.4, the RPC router called [`CratestackAuthProvider::authenticate`] once
//! per op — for a unary `POST /rpc/<op_id>` call that's once per request; for `POST /rpc/batch` it
//! was once *per frame*, each time with that frame's own canonical `/rpc/<op_id>` path, which is
//! what let this provider be the sole per-frame RBAC enforcement point. cratestack 0.8.4 rewrote
//! `POST /rpc/batch` to authenticate the real envelope — method, path (always the literal
//! `/rpc/batch`), raw body — exactly ONCE via a new `CachedAuthProvider`, then reuses that one
//! resulting [`CratestackContext`] for every frame's dispatch. This provider's `authenticate` is
//! therefore invoked once per *unary* request still, but for a batch call it is invoked once for
//! the *whole envelope*, never once per frame — `request.path` for that one call is always the
//! literal `/rpc/batch`, never an individual frame's `/rpc/<op_id>`.
//!
//! The per-frame RBAC decision this provider used to make here (`required_permission(op_id)` +
//! `TokenInfo::has_permission`) has moved to `authz.cstack`'s `@allow`/`@@allow` clauses instead —
//! see that schema file's own doc comment on `auth Principal`, and
//! `crates/lightbridge-authz-rest/tests/schema_policy_sync_tests.rs` for how those clauses are
//! generated (not hand-transcribed) from [`crate::rpc_authorize::MAPPED_OP_ID_PERMISSIONS`]. Those
//! clauses are evaluated by cratestack's OWN per-frame policy machinery
//! (`authorize_procedure`/the model read-policy equivalent, invoked from inside `#dispatch_ident`
//! — unaffected by the `CachedAuthProvider` change, since that only touches
//! `AuthProvider::authenticate`, a separate call site), reading back the exact permission booleans
//! `authenticate` bakes into the context here. This is what restores real per-frame mixed
//! pass/fail semantics for `/rpc/batch` without any upstream cratestack change: `authenticate`
//! still only runs once per envelope, but it now hands every frame's dispatch the caller's FULL,
//! REAL computed permission set (every [`lightbridge_authz_core::Permission`], via
//! [`build_context`]) rather than a single, already-narrowed-to-one-op-id verdict — and it is
//! cratestack's per-frame policy evaluation, not this function, that narrows it back down per
//! frame.
//!
//! For a UNARY call, `build_context` populates the exact same fields, but the pre-existing
//! `required_permission`/`scope.permits`/`has_permission` checks below still run FIRST and are
//! completely unchanged — the schema clauses are a second, now-redundant-for-unary but harmless
//! check on that path (unary was never broken by 0.8.4 in the first place: `request.path` for a
//! unary call was always its own canonical path, both before and after 0.8.4).
//!
//! ## Two accepted, documented behavior differences (batch path only — unary is unaffected)
//!
//! 1. **Out-of-scope op-id: `403` instead of `404`.** `RpcScope` (which server — `authz-api` vs
//!    `authz-budget`) is baked into every batch-envelope context as `auth().rpcScope`, and every
//!    mapped op-id's schema clause checks it. Since `CratestackAuthProvider` is invoked once for
//!    the whole envelope and structurally cannot see individual frames ahead of dispatch, there is
//!    no point to reject a frame before policy evaluation runs — and cratestack's
//!    `authorize_procedure` can only ever return `Forbidden` on denial, never `NotFound`. So a
//!    batch frame aimed at a budget op-id on `authz-api` now gets `403 permission_denied` where a
//!    unary call to the same op-id still gets a clean `404` (that check is untouched — see the
//!    unary branch below). The refusal itself is unaffected and still fail-closed — an admin
//!    holding every permission is still refused purely on `rpcScope`, proven by
//!    `budget_gated_op_ids_are_unreachable_on_authz_api_even_for_an_admin` — the only observable
//!    consequence is that `403` confirms the op-id EXISTS in the schema where `404` previously did
//!    not, which is negligible here since every op-id in `authz.cstack` is already public.
//! 2. **`model.*` `list`/`get` verbs filter to empty/not-found, not `permission_denied`.**
//!    `@@allow("read", ...)` compiles into the SQL `WHERE` clause itself
//!    (`cratestack-sqlx/src/render/policy.rs`), not a hard pre-check — a caller whose read
//!    permission field is `false` simply matches zero rows, indistinguishable from any other
//!    caller-scoping predicate. `create`/`update`/`delete` verbs, by contrast, DO hard-gate
//!    (`cratestack-sqlx/src/query/support/create.rs`'s `evaluate_create_policy_expr`,
//!    `update.rs`'s existence-probe-then-`Forbidden`), matching `authorize_procedure`'s
//!    all-or-nothing behavior for procedures — see
//!    `batch_rpc_frames_all_deny_for_a_caller_with_zero_permissions` (write verbs + procedures,
//!    `permission_denied`) vs
//!    `batch_rpc_read_verbs_filter_to_empty_not_an_error_for_a_caller_lacking_read_permission`
//!    (read verbs, empty/not-found) in `rpc_it_tests.rs` for both halves verified directly. This
//!    is a pre-existing, upstream cratestack property of read policies this fix did not create and
//!    cannot change without a much larger rewrite (there is no schema-level way to make a
//!    `@@allow("read", ...)` clause reject instead of filter). The security-relevant property
//!    holds regardless: no row a caller cannot read is ever returned, in batch or unary.
//!
//! It reuses the unchanged [`BearerTokenServiceTrait`] validation (JWKS fetch/cache, RS256
//! verification, audience matching — see `lightbridge-authz-bearer`, migrated to
//! `authkestra-resource` in ADR-0004).

use std::sync::Arc;

use cratestack::axum::http;
use cratestack::{AuthProvider, CratestackContext, CratestackError, RequestContext, Value};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::Permission;
use lightbridge_authz_core::identity::AccountId;

use crate::rpc_authorize::{
    BATCH_OP_ID, RpcScope, op_id_from_path, permission_field_name, required_permission,
};

/// ADR-0025 Stage 2: translates a validated bearer token's `(iss, sub)` into the acting account
/// id -- the seam [`build_context`] routes `auth().id` through instead of trusting
/// [`TokenInfo::sub`] directly. A trait (not a bare `Arc<StoreRepo>`) so tests can substitute a
/// resolver that never touches a database.
#[lightbridge_authz_core::async_trait]
pub trait SubjectResolver: Send + Sync {
    async fn resolve(
        &self,
        iss: &str,
        sub: &str,
    ) -> Result<AccountId, lightbridge_authz_core::Error>;
}

/// The real, Postgres-backed [`SubjectResolver`]. Handles TWO cases, deliberately not conflated:
///
/// 1. **A bearer token this service minted itself** (`iss` equals `own_issuer`, i.e.
///    `oauth2.signing.issuer` under `oauth2.type: self`): `sub` is already the resolved acting
///    account id by construction (ADR-0025 Stage 3 -- `ApiKeyJwtSigner`/`TokenExchangeOpStore`
///    both mint `sub` from `KeyOwner::account_id`, never a raw upstream claim), so it is trusted
///    directly with NO database call, rather than run back through
///    `resolve_account_for_federated_subject` -- which would refuse it outright, since no
///    `federated_identities` row is ever written for `(own_issuer, sub)`, and `own_issuer` is
///    never `oauth2.federation.issuer`. This is the common case for every `oauth2.type: self`
///    deployment (this repo's own dev/prod config): every RPC/MCP bearer token authz-api/
///    authz-budget/lightbridge-mcp ever see was minted by this same service.
/// 2. **Anything else** (a genuinely external issuer -- relevant under `oauth2.type: external`,
///    where every bearer token presented to this surface IS an externally-issued one): delegates
///    to `StoreRepo::resolve_account_for_federated_subject`, the real translation seam.
///
/// `own_issuer` is `None` under `oauth2.type: external` (there is no self-signed issuer to short-
/// circuit against -- every token always needs real resolution).
pub struct FederatedSubjectResolver {
    repo: Arc<StoreRepo>,
    own_issuer: Option<String>,
    grandfather_issuer: String,
}

impl FederatedSubjectResolver {
    pub fn new(
        repo: Arc<StoreRepo>,
        own_issuer: Option<String>,
        grandfather_issuer: String,
    ) -> Self {
        Self {
            repo,
            own_issuer,
            grandfather_issuer,
        }
    }
}

#[lightbridge_authz_core::async_trait]
impl SubjectResolver for FederatedSubjectResolver {
    async fn resolve(
        &self,
        iss: &str,
        sub: &str,
    ) -> Result<AccountId, lightbridge_authz_core::Error> {
        if self.own_issuer.as_deref() == Some(iss) {
            return Ok(AccountId::assert_already_resolved(sub));
        }
        self.repo
            .resolve_account_for_federated_subject(iss, sub, &self.grandfather_issuer)
            .await
            .map(AccountId::assert_already_resolved)
    }
}

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
    /// first, ahead of even the bearer/permission checks below, for a unary call — the sole place
    /// that closed the `POST /rpc/batch` gap pre-#383. Now ALSO baked into every batch-envelope
    /// context's `rpcScope` auth field (see [`build_context`]), which is what lets `authz.cstack`
    /// close that same gap per frame today.
    scope: RpcScope,
    /// ADR-0025 Stage 2: translates the validated bearer's `(iss, sub)` into the acting account
    /// id before it ever reaches `auth().id` -- see [`build_context`]'s doc comment.
    resolver: Arc<dyn SubjectResolver>,
}

impl CratestackAuthProvider {
    pub fn new(
        bearer: Arc<dyn BearerTokenServiceTrait>,
        scope: RpcScope,
        resolver: Arc<dyn SubjectResolver>,
    ) -> Self {
        Self {
            bearer,
            scope,
            resolver,
        }
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

/// Builds the full [`CratestackContext`] for a validated caller: `auth().id` (the subject),
/// `auth().rpcScope` (this server instance's [`RpcScope`], the same for every frame of one
/// envelope), and one `auth().perm<Permission>` boolean per [`Permission::ALL`] variant, each set
/// from the caller's OWN, REAL [`TokenInfo::has_permission`] verdict — never a blanket `true`, and
/// never anything narrower than the caller's actual grants. This is the single most
/// security-sensitive function in this crate: every `authz.cstack` `@allow`/`@@allow` clause's
/// permission gate is only as fail-closed as the values populated here. Looping over
/// [`Permission::ALL`] rather than 31 hand-written field insertions is deliberate — a variant
/// added to `Permission` later is picked up automatically, with no separate list to remember to
/// update here.
///
/// `pub` and called from TWO independent entry points, deliberately kept as ONE function rather
/// than two copies of "how a context gets its permission fields": [`CratestackAuthProvider`]
/// above (the HTTP RPC surface, `authz-api`/`authz-budget`), and
/// `lightbridge-authz::mcp::cratestack_context_from_token_info` (the MCP surface, `authz-mcp`,
/// `app/lightbridge-authz/src/mcp.rs`). Both build a [`CratestackContext`] from a validated
/// [`TokenInfo`] to hand to the SAME generated cratestack client, which evaluates the SAME
/// `authz.cstack` `@allow`/`@@allow` clauses regardless of which surface reached it — a schema
/// clause added for the RPC surface (like every clause `authz.cstack`'s `auth Principal` doc
/// comment on issue #383 describes) applies to MCP too, whether or not MCP's own context-builder
/// was updated to populate the new fields. Before this was unified, MCP's copy set only `id`,
/// which satisfied the old `@allow(auth() != null)` but silently failed every #383-added clause —
/// found in CI (`integration-test`, `it-servers`), not locally. A drift between two independent
/// copies of this logic is an authorization bug, not a cosmetic one, so there is exactly one
/// version now; see `mcp.rs`'s own `cratestack_context_from_token_info_matches_the_shared_helper` test for
/// the regression coverage pinning "every context-construction path sets the full field set."
///
/// ADR-0025 Stage 2: `auth().id` is no longer `info.sub` directly -- it is
/// `resolver.resolve(&info.iss, &info.sub)`'s result. A resolver error REFUSES the request
/// (`CratestackError::Unauthorized`) rather than ever falling through to an unauthenticated or
/// raw-subject context; see [`SubjectResolver`]'s own doc comment for what the resolver does with
/// a self-signed-vs-external issuer.
pub async fn build_context(
    info: &TokenInfo,
    scope: RpcScope,
    resolver: &dyn SubjectResolver,
) -> Result<CratestackContext, CratestackError> {
    let account_id = resolver.resolve(&info.iss, &info.sub).await.map_err(|_| {
        CratestackError::Unauthorized("unable to resolve caller identity".to_owned())
    })?;
    let mut fields: Vec<(String, Value)> = Vec::with_capacity(Permission::ALL.len() + 2);
    fields.push(("id".to_owned(), Value::String(account_id.into())));
    fields.push((
        "rpcScope".to_owned(),
        Value::String(scope.wire_str().to_owned()),
    ));
    for permission in Permission::ALL {
        fields.push((
            permission_field_name(permission),
            Value::Bool(info.has_permission(permission)),
        ));
    }
    let mut ctx = CratestackContext::authenticated(fields);
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
    if let Some(caller_kind) = &info.caller_kind {
        ctx.extensions.insert(
            CALLER_KIND_CONTEXT_KEY.to_owned(),
            Value::String(caller_kind.clone()),
        );
    }
    Ok(ctx)
}

impl AuthProvider for CratestackAuthProvider {
    type Error = CratestackError;

    fn authenticate(
        &self,
        request: &RequestContext<'_>,
    ) -> impl core::future::Future<Output = Result<CratestackContext, Self::Error>> + Send {
        let bearer = self.bearer.clone();
        let scope = self.scope;
        let resolver = self.resolver.clone();
        let token = extract_bearer(request.headers);
        // `request.path` is `/rpc/batch` (literal, envelope-level — see module docs) when this
        // call is authenticating a whole `POST /rpc/batch` request, or the canonical `/rpc/<op_id>`
        // for a unary call.
        let op_id = op_id_from_path(request.path).to_owned();
        async move {
            if op_id == BATCH_OP_ID {
                // The envelope-level call (see module docs): per-op-id scope/permission can no
                // longer be checked here at all (there is no single op-id for a batch), so — same
                // as `rpc_authorize`'s own batch special case — this only requires SOME valid,
                // active caller, and hands back their FULL real permission set for cratestack's
                // per-frame schema policies to narrow down per frame. This is the single most
                // dangerous branch in this file: it must never attach a blanket-permissive
                // context — `build_context` is the same function the fully-checked unary path
                // below uses, populated from the SAME real `TokenInfo`, so a caller with zero
                // permissions gets a context where every `perm*` field is `false`, and every
                // frame's `@allow` clause denies them exactly as it would for a unary call.
                let Some(token) = token else {
                    return Err(CratestackError::Unauthorized(
                        "missing bearer token".to_owned(),
                    ));
                };
                return match bearer.validate_bearer_token(&token).await {
                    Ok(info) if info.active => build_context(&info, scope, resolver.as_ref()).await,
                    Ok(_) | Err(_) => Err(CratestackError::Unauthorized(
                        "invalid bearer token".to_owned(),
                    )),
                };
            }

            // Unary path — byte-for-byte unchanged from pre-#383: `request.path` here was always
            // this request's own canonical path, so nothing about the 0.8.4 batch-auth rewrite
            // affects it. Kept as real, independent enforcement (not merely redundant with the
            // new schema clauses) rather than relying solely on the schema, so a unary call's
            // scope/permission refusal keeps its own well-tested 404/403 shape unconditionally.
            //
            // Out-of-scope op-id (moved to the other service) → 404, before even looking at the
            // bearer token, mirroring `rpc_authorize`'s own scope check.
            if !scope.permits(&op_id) {
                return Err(CratestackError::NotFound(format!(
                    "unknown RPC op `{op_id}`"
                )));
            }
            // Unmapped op-id → 403 unconditionally, mirroring `rpc_authorize`'s fail-closed set
            // (unknown ops, `model.ProjectMember.*`, `model.ApiKey.create`, ...).
            let Some(required) = required_permission(&op_id) else {
                return Err(CratestackError::Forbidden(
                    "operation not permitted".to_owned(),
                ));
            };
            // No bearer at all → 401, matching the prior middleware's fail-closed posture (rather
            // than an anonymous context, which would surface as a policy-driven empty read).
            let Some(token) = token else {
                return Err(CratestackError::Unauthorized(
                    "missing bearer token".to_owned(),
                ));
            };
            match bearer.validate_bearer_token(&token).await {
                Ok(info) if info.active => {
                    if !info.has_permission(required) {
                        return Err(CratestackError::Forbidden(
                            "insufficient permissions".to_owned(),
                        ));
                    }
                    build_context(&info, scope, resolver.as_ref()).await
                }
                // Invalid/inactive token or validation error → uniform 401, never leaking which step
                // failed (matching the bearer service's existing security posture).
                Ok(_) | Err(_) => Err(CratestackError::Unauthorized(
                    "invalid bearer token".to_owned(),
                )),
            }
        }
    }
}
