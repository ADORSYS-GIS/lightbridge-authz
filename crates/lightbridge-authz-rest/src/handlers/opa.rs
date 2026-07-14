use std::sync::Arc;

use lightbridge_authz_core::{Result, error::Error, hash_api_key};
use tracing::instrument;

use crate::OpaState;

/// Context for a validated API key.
pub struct ValidatedApiKeyContext {
    pub api_key: lightbridge_authz_core::ApiKey,
    pub project: lightbridge_authz_core::Project,
    pub account: lightbridge_authz_core::Account,
}

/// Validates an API key and returns its context (project, account).
///
/// Gating is a single indexed read of the `api_key_validation` view: the account -> project -> key
/// status cascade (revoked key, expired key, suspended project, suspended account) is resolved by
/// the database, so disabling an account/project instantly invalidates every key beneath it.
#[instrument(skip(state, raw_api_key))]
pub async fn validate_api_key_context(
    state: &Arc<OpaState>,
    raw_api_key: &str,
    ip: Option<String>,
) -> Result<Option<ValidatedApiKeyContext>> {
    let key_hash = hash_api_key(raw_api_key);
    let Some(validation) = state
        .repo
        .find_api_key_validation_by_hash(&key_hash)
        .await?
    else {
        tracing::info!(
            active = false,
            reason = "not_found",
            "api key validation failed"
        );
        return Ok(None);
    };

    if !validation.is_active() {
        tracing::info!(
            active = false,
            reason = %validation.effective_status,
            api_key_id = %validation.api_key_id,
            account_id = %validation.account_id,
            project_id = %validation.project_id,
            "api key validation failed"
        );
        return Ok(None);
    }

    let api_key = state
        .repo
        .record_api_key_usage(&validation.api_key_id, ip)
        .await?;
    let project = state
        .repo
        .get_project_by_id(&validation.project_id)
        .await?
        .ok_or_else(|| Error::NotFound)?;
    let account = state
        .repo
        .get_account_by_id(&validation.account_id)
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
