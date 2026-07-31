use std::sync::Arc;

use lightbridge_authz_core::{Result, error::Error, hash_api_key};
use tracing::instrument;

use crate::OpaState;

/// Context for a validated API key.
///
/// `account_id` is a bare id rather than a loaded `Account`: it comes straight off the
/// `api_key_validation` view, and the only consumer (introspection) needs nothing else from the
/// account row. Loading the whole account cost a third database round trip to re-fetch an id the
/// first query had already returned.
pub struct ValidatedApiKeyContext {
    pub api_key: lightbridge_authz_core::ApiKey,
    pub project: lightbridge_authz_core::Project,
    pub account_id: String,
    /// The key OWNER's roster standing (ADR-0006 follow-up). Distinct from `account_id`, which is
    /// the project's owning account: a lead who is not the owner may mint keys, and it is their
    /// per-member ceiling that bounds the key. Both are `None` when the owner holds no
    /// `project_members` row, which is the normal case for the project's owning account.
    ///
    /// Costs no extra round trip — the `api_key_validation` view resolves them via a LEFT JOIN
    /// alongside the status cascade it already computes.
    pub owner_role: Option<String>,
    pub owner_quota_tier: Option<String>,
}

/// Validates an API key and returns its context (project, account id).
///
/// Gating is a single indexed read of the `api_key_validation` view: the account -> project -> key
/// status cascade (revoked key, expired key, suspended project, suspended account) is resolved by
/// the database, so disabling an account/project instantly invalidates every key beneath it.
///
/// Three round trips total, deliberately: the indexed view read above, the usage-telemetry UPDATE
/// (which returns the api-key row, so it doubles as that fetch), and the project read that supplies
/// `allowed_models`/`project_quota`. Authorino caches the result for 30s per `jti`, so this runs
/// roughly twice a minute per active key per replica — cheap enough that keeping the database
/// authoritative is worth more than shaving it further. Anything moved into JWT claims instead
/// stops reflecting operator changes until the token is re-minted.
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
    let account_id = validation.account_id.clone();

    tracing::info!(
        active = true,
        api_key_id = %api_key.id,
        account_id = %account_id,
        project_id = %project.id,
        "api key validated"
    );

    Ok(Some(ValidatedApiKeyContext {
        api_key,
        project,
        account_id,
        owner_role: validation.owner_role.clone(),
        owner_quota_tier: validation.owner_quota_tier.clone(),
    }))
}
