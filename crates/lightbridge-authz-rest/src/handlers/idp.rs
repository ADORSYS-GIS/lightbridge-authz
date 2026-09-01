use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use lightbridge_authz_core::Result;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{AuthorizeUsageScopeRequest, ResolveContextRequest, ResolvedContext};
use tracing::instrument;

use crate::OpaState;

/// Resolves the tenant context (`account_id`/`project_id`) for an authenticated subject scoped to a
/// project. Membership is enforced: a subject that is not a member of the project's account, or an
/// unknown project, is a uniform 404. Basic-auth protected — the IdP adapter presents the OPA
/// credentials.
///
/// ADR-0025 Stage 2: `input.subject` is translated through [`crate::auth_provider::SubjectResolver`]
/// (the SAME translation seam every other ingress uses) before it ever reaches
/// `StoreRepo::resolve_context` -- `input.issuer`, defaulting to `oauth2.federation.issuer` when
/// the request body omits it (the legacy `lightbridge-keycloak-spi` adapter never sends this
/// field), names which issuer authenticated `subject`. A resolver refusal maps to the SAME uniform
/// 404 `resolve_context`'s own not-a-member branch already returns -- never a distinct status that
/// would let a caller distinguish "wrong issuer"/"no such account" from "not a member", preserving
/// this endpoint's existing no-account-existence-oracle contract.
#[utoipa::path(
    post,
    path = "/idp/v1/resolve-context",
    request_body = ResolveContextRequest,
    responses(
        (status = 200, body = ResolvedContext),
        (status = 404, description = "Unknown project or subject is not a member")
    ),
    tag = "idp"
)]
#[instrument(skip(state, input))]
pub async fn resolve_context(
    State(state): State<Arc<OpaState>>,
    Json(input): Json<ResolveContextRequest>,
) -> Result<axum::response::Response> {
    let subject = input.subject.unwrap_or_default();
    let project_id = input.project_id.unwrap_or_default();
    let issuer = input
        .issuer
        .unwrap_or_else(|| state.federation_issuer.clone());
    let account_id = state
        .resolver
        .resolve(&issuer, &subject)
        .await
        .map_err(|err| match err {
            Error::Forbidden(_) => Error::NotFound,
            other => other,
        })?;
    let context: ResolvedContext = state
        .repo
        .resolve_context(account_id.as_str(), &project_id)
        .await?;
    tracing::info!(
        subject = %subject,
        project_id = %project_id,
        account_id = %context.account_id,
        "resolved tenant context"
    );
    Ok((StatusCode::OK, Json(context)).into_response())
}

/// Ownership authority for `lightbridge-authz-usage`'s query listener (#570): does the
/// authenticated end user (`issuer`, `subject`) own `scope_id` under `scope`? The usage service
/// has no `accounts`/`projects`/`project_members` tables of its own -- this is the one place that
/// question is answered, over the same Basic-auth boundary `resolve_context` already uses.
///
/// Follows `resolve_context`'s exact non-leaking-oracle shape: `input.subject` is translated
/// through [`crate::auth_provider::SubjectResolver`] first (a resolver refusal maps to the same
/// uniform 404 an ownership miss produces), then [`crate::OpaState::repo`]'s
/// `authorize_usage_scope` evaluates the ownership predicate itself
/// (`StoreRepo::authorize_usage_scope`) -- one query per scope, one `NotFound` branch, never a
/// distinct status a caller could use to tell "wrong issuer"/"unknown scope_id" apart from "known
/// but not owned".
#[utoipa::path(
    post,
    path = "/idp/v1/authorize-usage-scope",
    request_body = AuthorizeUsageScopeRequest,
    responses(
        (status = 200, description = "Authorized"),
        (status = 404, description = "Not authorized, unknown scope_id, or unrecognized scope")
    ),
    tag = "idp"
)]
#[instrument(skip(state, input))]
pub async fn authorize_usage_scope(
    State(state): State<Arc<OpaState>>,
    Json(input): Json<AuthorizeUsageScopeRequest>,
) -> Result<axum::response::Response> {
    let subject = input.subject.unwrap_or_default();
    let scope = input.scope.unwrap_or_default();
    let scope_id = input.scope_id.unwrap_or_default();
    let issuer = input
        .issuer
        .unwrap_or_else(|| state.federation_issuer.clone());

    let account_id = state
        .resolver
        .resolve(&issuer, &subject)
        .await
        .map_err(|err| match err {
            Error::Forbidden(_) => Error::NotFound,
            other => other,
        })?;

    state
        .repo
        .authorize_usage_scope(account_id.as_str(), &scope, &scope_id)
        .await?;

    tracing::info!(
        subject = %subject,
        scope = %scope,
        scope_id = %scope_id,
        "authorized usage scope"
    );
    Ok(StatusCode::OK.into_response())
}
