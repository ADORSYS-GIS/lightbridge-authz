use std::sync::Arc;

use lightbridge_authz_core::{ApiKeyStatus, Result, error::Error, hash_api_key};
use tracing::instrument;

use crate::OpaState;

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
        tracing::info!(
            active = false,
            reason = "not_found",
            "api key validation failed"
        );
        return Ok(None);
    };

    let now = chrono::Utc::now();
    if api_key.status != ApiKeyStatus::Active {
        tracing::info!(
            active = false,
            reason = "inactive_status",
            api_key_id = %api_key.id,
            status = %api_key.status,
            "api key validation failed"
        );
        return Ok(None);
    }
    if let Some(expires_at) = api_key.expires_at
        && expires_at <= now
    {
        tracing::info!(
            active = false,
            reason = "expired",
            api_key_id = %api_key.id,
            "api key validation failed"
        );
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

    tracing::info!(
        active = true,
        api_key_id = %api_key.id,
        account_id = %account.id,
        project_id = %project.id,
        "api key validated"
    );

    Ok(Some(ValidatedApiKeyContext {
        api_key,
        project,
        account,
    }))
}
