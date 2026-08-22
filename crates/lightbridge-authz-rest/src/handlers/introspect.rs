use std::sync::Arc;

use axum::{Form, Json, extract::State, http::StatusCode, response::IntoResponse};
use lightbridge_authz_core::{Result, hash_api_key};
use tracing::instrument;

use crate::OpaState;
use crate::handlers::exchange_token::resolve_exchange_token_context;
use crate::handlers::opa::validate_api_key_context;
use crate::models::{IntrospectRequest, IntrospectResponse};

/// RFC 7662 token introspection. Authorino's `oauth2Introspection` identity calls this to
/// authenticate a presented bearer and read its authorization context in one call.
///
/// Two credential shapes are handled, dispatched by whether `api_keys` has ANY row (any status)
/// matching the presented bearer's hash -- checked FIRST and unconditionally, before either path
/// runs, so the dispatch itself can never be tricked into skipping a revocation check:
///
/// 1. **A row exists.** This is, or was, a real API key (opaque secret or self-signed JWT --
///    both are hashed into `key_hash` at mint time, see `handlers::mod::AuthzStoreImpl::
///    issue_api_key_secret`). Handled EXCLUSIVELY by [`validate_api_key_context`], unchanged from
///    before this dispatch existed -- a revoked/expired self-signed API-key JWT still verifies
///    fine as a JWT (revocation only flips a DB column, it cannot invalidate an already-issued
///    signature), so it is critical this branch never falls through to JWT verification below:
///    doing so would let a revoked key's own still-valid signature resurrect it as if it were an
///    exchange session. A row existing, active or not, always means "the `api_keys` table is
///    authoritative for this credential" and nothing else gets a vote.
/// 2. **No row exists at all.** This credential was never minted as an API key, so it cannot be
///    revoked through that table by definition. It may be a native RFC 8693 token-exchange access
///    token (`oauth2_op::store::TokenExchangeOpStore`) -- verified and re-resolved by
///    [`resolve_exchange_token_context`], which independently re-checks this service's own JWKS
///    signature, expiry, current project membership, and project/account suspension before
///    trusting anything on it. Anything else here (a forged token, an opaque secret from before
///    this service existed, an `id_token`) fails that verification and resolves inactive.
#[utoipa::path(
    post,
    path = "/v1/authorino/validate/introspect",
    request_body = IntrospectRequest,
    responses(
        (status = 200, body = IntrospectResponse)
    ),
    tag = "authorino"
)]
#[instrument(skip(state, input))]
pub async fn introspect_api_key(
    State(state): State<Arc<OpaState>>,
    Form(input): Form<IntrospectRequest>,
) -> Result<axum::response::Response> {
    let key_hash = hash_api_key(&input.token);
    let is_api_key_credential = state
        .repo
        .find_api_key_validation_by_hash(&key_hash)
        .await?
        .is_some();

    if is_api_key_credential {
        return introspect_api_key_row(&state, &input.token).await;
    }

    introspect_exchange_token(&state, &input.token).await
}

async fn introspect_api_key_row(
    state: &Arc<OpaState>,
    token: &str,
) -> Result<axum::response::Response> {
    let Some(validated) = validate_api_key_context(state, token, None).await? else {
        tracing::info!(active = false, "api key introspection resolved inactive");
        return Ok((StatusCode::OK, Json(IntrospectResponse::inactive())).into_response());
    };

    tracing::info!(
        active = true,
        api_key_id = %validated.api_key.id,
        account_id = %validated.account_id,
        project_id = %validated.project.id,
        "api key introspection resolved active"
    );

    let plan = state.billing.get(&validated.api_key.billing_plan);
    if plan.is_none() {
        tracing::warn!(
            api_key_id = %validated.api_key.id,
            billing_plan = %validated.api_key.billing_plan,
            "api key references a billing plan absent from the configured catalogue; \
             billing_plan_name/billing_plan_limits omitted (a downstream enforcer will see the key \
             as having no limits — reconcile the catalogue with keys still in use)"
        );
    }
    let response = IntrospectResponse {
        active: true,
        sub: Some(validated.api_key.id.clone()),
        account_id: Some(validated.account_id.clone()),
        project_id: Some(validated.project.id.clone()),
        api_key_id: Some(validated.api_key.id.clone()),
        api_key_status: Some(validated.api_key.status.to_string()),
        billing_plan: Some(validated.api_key.billing_plan.clone()),
        billing_plan_name: plan.map(|p| p.name.clone()),
        billing_plan_limits: plan.and_then(|p| p.limits.clone()),
        allowed_models: validated.project.allowed_models.clone(),
        model_policy: Some(validated.project.model_policy.to_string()),
        project_quota: validated.project.project_quota.clone(),
        role: validated.owner_role.clone(),
        quota_tier: validated.owner_quota_tier.clone(),
        exp: validated.api_key.expires_at.map(|value| value.timestamp()),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// The exchange-token counterpart of [`introspect_api_key_row`]. No `api_key_id`/`api_key_status`
/// (there is no `api_keys` row); `sub` is the token's own session id rather than a key id, and
/// `exp` is omitted -- unlike an API key, there is no persisted expiry to report, and this
/// response's `active: true` already means "unexpired as of this call" (see
/// [`resolve_exchange_token_context`]'s doc comment for exactly what `active` asserts here).
async fn introspect_exchange_token(
    state: &Arc<OpaState>,
    token: &str,
) -> Result<axum::response::Response> {
    let Some(ctx) = resolve_exchange_token_context(state, token).await? else {
        tracing::info!(
            active = false,
            "exchange token introspection resolved inactive"
        );
        return Ok((StatusCode::OK, Json(IntrospectResponse::inactive())).into_response());
    };

    let plan = state.billing.get(&ctx.project.billing_plan);
    if plan.is_none() {
        tracing::warn!(
            project_id = %ctx.project.id,
            billing_plan = %ctx.project.billing_plan,
            "exchange session's project references a billing plan absent from the configured \
             catalogue; billing_plan_name/billing_plan_limits omitted"
        );
    }
    let response = IntrospectResponse {
        active: true,
        sub: ctx.session_id,
        account_id: Some(ctx.account_id),
        project_id: Some(ctx.project.id.clone()),
        api_key_id: None,
        api_key_status: None,
        billing_plan: Some(ctx.project.billing_plan.clone()),
        billing_plan_name: plan.map(|p| p.name.clone()),
        billing_plan_limits: plan.and_then(|p| p.limits.clone()),
        allowed_models: ctx.project.allowed_models.clone(),
        model_policy: Some(ctx.project.model_policy.to_string()),
        project_quota: ctx.project.project_quota.clone(),
        role: ctx.role,
        quota_tier: ctx.quota_tier,
        exp: None,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}
