//! Evaluates `oauth2.signing.claim_mappers` into concrete claims for a token being minted.
//!
//! Split out of `store.rs` (which sits on its committed LoC-gate baseline and may be touched but
//! not grown) as a free function taking its two repository handles explicitly, rather than a
//! method on `TokenExchangeOpStore`. All three human-plane mint paths —
//! `handle_token_exchange`, `handle_refresh_token` and the `authorization_code` grant — call
//! [`resolve_mapped_claims`] with the same arguments they used to pass to the method, so a mapper
//! resolves identically no matter which grant produced the token; the refresh path in particular
//! re-resolves LIVE on every rotation, which is what bounds a grant's or revocation's propagation
//! delay to one access-token TTL rather than one session.
//!
//! # Fail-closed
//!
//! A lookup failure REFUSES the mint (`server_error`), matching `resolve_quota_tier` rather than
//! `resolve_budget_tier`. Omitting the claim instead would produce a token whose roles are empty,
//! which `permissions_for_roles` reads as "no permissions" — indistinguishable on the wire from a
//! legitimately unprivileged user, so a database blip would surface as a silent, confusing
//! authorization failure that looks like a policy decision. Refusing says what actually happened.
//!
//! An EMPTY result is not a failure. A subject with no `project_members` row and no
//! `platform_role_grants` row resolves to nothing, falls through to the mapper's `default`, and
//! mints normally: "granted nothing" is an answer, not an outage.
//!
//! # Several mappers, one claim: union, never overwrite (ADR-0033)
//!
//! Mappers are evaluated in declaration order and their values MERGED per claim name, deduplicated,
//! first-seen order preserved. This is the whole mechanism by which `project_role` (an account
//! owner's default `lightbridge-viewer`) and `platform_roles` (whatever `platform_role_grants`
//! says) coexist on `lightbridge_api_roles`. Last-one-wins would make the roles claim depend on
//! YAML ordering — a values-file edit must not be able to cause that kind of silent authorization
//! surprise. See `ClaimMapper`'s own doc comment.

use std::collections::HashSet;

use authkestra_op::handlers::token::TokenErrorResponse;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::{ClaimMapper, ClaimSource};
use lightbridge_authz_core::identity::AccountId;
use serde_json::Value;

use super::oauth_err;

/// Resolves every configured mapper for one mint.
///
/// `quota_repo` is the `project_members` handle [`ClaimSource::ProjectRole`] reads (the same
/// deliberately-independent injection seam `resolve_quota_tier` uses, so a test can prove this
/// function's own fail-closed branch fires rather than context resolution failing first);
/// `platform_repo` is the `platform_role_grants` handle [`ClaimSource::PlatformRoles`] reads.
/// Production points both at the same pool.
pub(crate) async fn resolve_mapped_claims(
    mappers: &[ClaimMapper],
    quota_repo: &StoreRepo,
    platform_repo: &StoreRepo,
    project_id: &str,
    acting_account_id: &AccountId,
    owning_account_id: &str,
) -> Result<Vec<(String, Value)>, TokenErrorResponse> {
    if mappers.is_empty() {
        return Ok(Vec::new());
    }
    // Per-claim accumulator: `Vec` for order (declaration order is the operator's own), `HashSet`
    // for the dedupe. Claims themselves stay in first-declared order too.
    let mut order: Vec<String> = Vec::with_capacity(mappers.len());
    let mut merged: Vec<(String, Vec<String>, HashSet<String>)> = Vec::with_capacity(mappers.len());

    for mapper in mappers {
        let sources = resolve_source(
            mapper,
            quota_repo,
            platform_repo,
            project_id,
            acting_account_id,
            owning_account_id,
        )
        .await?;
        let values = map_source_values(mapper, &sources);

        let slot = match order.iter().position(|claim| claim == &mapper.claim) {
            Some(index) => &mut merged[index],
            None => {
                order.push(mapper.claim.clone());
                merged.push((mapper.claim.clone(), Vec::new(), HashSet::new()));
                merged.last_mut().expect("just pushed")
            }
        };
        for value in values {
            if slot.2.insert(value.clone()) {
                slot.1.push(value);
            }
        }
    }

    Ok(merged
        .into_iter()
        .map(|(claim, values, _)| {
            (
                claim,
                Value::Array(values.into_iter().map(Value::String).collect()),
            )
        })
        .collect())
}

/// The raw source values one mapper resolves to, before `map`/`default` are applied. Empty means
/// "resolved to nothing", which is a normal answer; an `Err` means the lookup itself failed.
async fn resolve_source(
    mapper: &ClaimMapper,
    quota_repo: &StoreRepo,
    platform_repo: &StoreRepo,
    project_id: &str,
    acting_account_id: &AccountId,
    owning_account_id: &str,
) -> Result<Vec<String>, TokenErrorResponse> {
    match mapper.source {
        ClaimSource::ProjectRole => {
            // The account owner is implicitly authorized and normally holds no roster row -- the
            // same rule `authorize_project_lead` layers on top of `project_member_role`. Checked
            // FIRST so an owner is never reported as whatever roster row they may additionally
            // hold.
            if owning_account_id == acting_account_id.as_str() {
                return Ok(vec!["owner".to_string()]);
            }
            let role = quota_repo
                .project_member_role(project_id, acting_account_id)
                .await
                .map_err(|err| refuse(mapper, &err))?;
            Ok(role.into_iter().collect())
        }
        ClaimSource::PlatformRoles => {
            // Grants are keyed on the PERSON, not the account (ADR-0026): translate first. No
            // `accounts` row means the ADR-0025 bootstrap window (a brand-new subject whose only
            // pending operation is `createAccount`) -- a person with no account cannot have been
            // granted anything, so that resolves to nothing rather than refusing the mint.
            let Some(user_id) = platform_repo
                .resolve_user_id_for_account(acting_account_id.as_str())
                .await
                .map_err(|err| refuse(mapper, &err))?
            else {
                return Ok(Vec::new());
            };
            platform_repo
                .active_platform_roles_for_user(&user_id)
                .await
                .map_err(|err| refuse(mapper, &err))
        }
    }
}

/// Applies `map`/`default` to the resolved source values.
///
/// Two different rules, deliberately, because the two sources mean different things:
///
/// - [`ClaimSource::ProjectRole`] resolves to a ROSTER position (`owner`/`lead`/`member`), which is
///   not a role name — it must be translated, so an unmapped value falls through to `default`.
/// - [`ClaimSource::PlatformRoles`] resolves to role names already. An unmapped value contributes
///   ITSELF, so an operator who grants `lightbridge-admin` gets `lightbridge-admin` in the claim
///   without also maintaining an identity mapping they would have to extend for every new role.
///   `default` therefore fires only when the person holds NO active grants at all.
fn map_source_values(mapper: &ClaimMapper, sources: &[String]) -> Vec<String> {
    if sources.is_empty() {
        return mapper.default_values.clone();
    }
    match mapper.source {
        ClaimSource::ProjectRole => sources
            .iter()
            .flat_map(|value| {
                mapper
                    .map
                    .get(value)
                    .cloned()
                    .unwrap_or_else(|| mapper.default_values.clone())
            })
            .collect(),
        ClaimSource::PlatformRoles => sources
            .iter()
            .flat_map(|value| match mapper.map.get(value) {
                Some(mapped) => mapped.clone(),
                None => vec![value.clone()],
            })
            .collect(),
    }
}

/// One log line and one uniform `server_error`, whichever source failed. The wire response never
/// says which lookup broke; the log always does.
fn refuse(mapper: &ClaimMapper, err: &lightbridge_authz_core::error::Error) -> TokenErrorResponse {
    tracing::error!(
        error = %err,
        claim = %mapper.claim,
        source = ?mapper.source,
        "claim mapper source resolution failed; refusing to mint rather than stamping an empty \
         claim, which would be indistinguishable from a legitimately unprivileged user"
    );
    oauth_err("server_error", "claim resolution failed")
}
