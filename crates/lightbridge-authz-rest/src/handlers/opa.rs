use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use lightbridge_authz_core::{ApiKeyStatus, Result, error::Error, hash_api_key};
use tracing::instrument;

use crate::OpaState;
use crate::models::{OpaCheckRequest, OpaCheckResponse, OpaErrorResponse};

/// Context for a validated API key.
pub struct ValidatedApiKeyContext {
    pub api_key: lightbridge_authz_core::ApiKey,
    pub project: lightbridge_authz_core::Project,
    pub account: lightbridge_authz_core::Account,
}

/// Validates an API key and returns its context (project, account).
#[instrument(skip(state, raw_api_key))]
pub async fn validate_api_key_context(
    state: &Arc<OpaState>,
    raw_api_key: &str,
    ip: Option<String>,
) -> Result<Option<ValidatedApiKeyContext>> {
    let key_hash = hash_api_key(raw_api_key);
    let Some(api_key) = state.repo.find_api_key_by_hash(&key_hash).await? else {
        return Ok(None);
    };

    let now = chrono::Utc::now();
    if api_key.status != ApiKeyStatus::Active {
        return Ok(None);
    }
    if let Some(expires_at) = api_key.expires_at
        && expires_at <= now
    {
        return Ok(None);
    }

    let api_key = state.repo.record_api_key_usage(&api_key.id, ip).await?;
    let project = state
        .repo
        .get_project_by_id(&api_key.project_id)
        .await?
        .ok_or_else(|| Error::NotFound)?;
    let account = state
        .repo
        .get_account_by_id(&project.account_id)
        .await?
        .ok_or_else(|| Error::NotFound)?;

    Ok(Some(ValidatedApiKeyContext {
        api_key,
        project,
        account,
    }))
}

/// OPA validation handler.
#[utoipa::path(
    post,
    path = "/v1/opa/validate",
    request_body = OpaCheckRequest,
    responses(
        (status = 200, body = OpaCheckResponse),
        (status = 401, body = OpaErrorResponse)
    ),
    tag = "opa"
)]
#[instrument(skip(state, input))]
pub async fn validate_api_key(
    State(state): State<Arc<OpaState>>,
    Json(input): Json<OpaCheckRequest>,
) -> Result<axum::response::Response> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(OpaErrorResponse {
                error: "unauthorized".to_string(),
            }),
        )
            .into_response()
    };

    let Some(validated) = validate_api_key_context(&state, &input.api_key, input.ip).await? else {
        return Ok(unauthorized());
    };

    Ok((
        StatusCode::OK,
        Json(OpaCheckResponse {
            api_key: validated.api_key,
            project: validated.project,
            account: validated.account,
        }),
    )
        .into_response())
}
