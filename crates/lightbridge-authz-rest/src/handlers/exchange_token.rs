use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use lightbridge_authz_core::{
    Project, ResourceStatus,
    error::{Error, Result},
};
use serde::Deserialize;
use serde_json::Value;
use tracing::instrument;

use crate::OpaState;

/// The claims a native RFC 8693 token-exchange access token (`oauth2_op::store`,
/// `TokenExchangeOpStore::handle_token_exchange`/`handle_refresh_token`) carries that
/// introspection needs to re-resolve current project authorization data. Deliberately narrow:
/// this is NOT a general-purpose claims type, only the fields this module reads.
///
/// `account_id` is intentionally NOT modelled here even though the token carries one
/// (`access_token_extra` in `crate::signing`). It was the value `resolve_context` returned at
/// MINT time; trusting it again at introspection time would mean serving a stale answer on
/// exactly the case that matters (a project reassigned to a different account since the token was
/// issued -- see the `ai-helm-values` "Default account/project" reassignment escape hatch).
/// [`resolve_exchange_token_context`] re-derives the current account id fresh from `sub` +
/// `project_id` on every call instead, via the same `resolve_context` the mint path itself uses.
#[derive(Debug, Deserialize)]
struct ExchangeClaims {
    /// The external IdP subject (e.g. Keycloak `sub`) this token was minted for. Never rewritten
    /// by this service (ADR-0011, Context) -- an identity assertion this service is allowed to
    /// trust once the signature below is verified.
    sub: String,
    /// Present on every exchange-derived access token (`access_token_extra`), absent on an
    /// `id_token` (`id_token_extra` never sets it) -- the positive signal that this token is
    /// tenant-scoped at all, distinct from any other self-issued token shape this service's keys
    /// might sign.
    project_id: Option<String>,
    /// A freshly-minted session CUID2 on an exchange-derived token (`access_token_extra` receives
    /// `session_id` in the parameter this struct field shares a name with), NEVER a real
    /// `api_keys.id` -- see this module's doc comment on why a token reaching this function can
    /// only be exchange-derived in the first place. Surfaced on the introspection response as
    /// `sub` (the "subject of the credential"), not as `api_key_id` (there is no `api_keys` row).
    api_key_id: Option<String>,
}

/// Verifies `token` was signed by one of THIS service's own signing keys (`signing_keys`, the
/// same key material `signing::well_known_router`'s `/.well-known/jwks.json` handler serves) and
/// decodes it. Returns `Ok(None)` for anything that fails verification -- malformed token, no
/// `kid`, unknown `kid`, bad signature, expired -- never an `Err` for those cases, so a forged or
/// stale bearer collapses to the same `{"active": false}` shape as "not found" rather than a 500.
///
/// **This is a different trust root than `BearerTokenServiceTrait`/`oauth2.jwks_url`.** That
/// service validates a token against the EXTERNAL IdP's JWKS (Keycloak). This function validates
/// against THIS service's OWN JWKS -- the `signing_keys` table -- which is what
/// `ApiKeyJwtSigner::sign` (self-signed API-key JWTs) and `TokenExchangeOpStore`
/// (`oauth2_op/store.rs`, the RFC 8693 exchange/refresh grants) both sign through, via the same
/// `ApiKeyJwtSigner::token_manager()` key material. Only `authz-opa`'s own `StoreRepo` (shared
/// Postgres, per AGENTS.md) is consulted -- no outbound HTTP call to `authz-idp`'s own
/// `/.well-known/jwks.json`, so this has no runtime dependency on that service being reachable.
///
/// **Why a token reaching this function can only be exchange-derived, never a real (even revoked)
/// API key.** Every self-signed API-key JWT is hashed and inserted into `api_keys.key_hash` at
/// the moment it is minted (`handlers::mod::AuthzStoreImpl::issue_api_key_secret` ->
/// `hash_api_key(&issued.secret)`), and that row is never deleted, only status-flipped on
/// revocation. So `find_api_key_validation_by_hash(hash_api_key(token))` finding NO row for this
/// exact token string is proof this token was never minted by `ApiKeyJwtSigner::sign` -- it can
/// only be a forged token (rejected below: an attacker without our private key cannot produce a
/// signature `DecodingKey::from_jwk` accepts) or a genuine RFC 8693 exchange/refresh access token.
/// This function's caller (`resolve_exchange_token_context`, via `introspect_api_key`) MUST only
/// be reached after that hash lookup has already returned `None` -- see `introspect_api_key`'s own
/// doc comment for why the hash check always runs first and unconditionally short-circuits when a
/// row exists, active or not.
#[instrument(skip(state, token))]
async fn verify_self_issued_token(
    state: &Arc<OpaState>,
    token: &str,
) -> Result<Option<ExchangeClaims>> {
    let Ok(header) = decode_header(token) else {
        return Ok(None);
    };
    let Some(kid) = header.kid else {
        tracing::debug!("self-issued token verification failed: missing kid header");
        return Ok(None);
    };

    let jwks = state.repo.list_verification_jwks().await?;
    let Some(matching_jwk) = jwks
        .into_iter()
        .find(|raw| raw.get("kid").and_then(Value::as_str) == Some(kid.as_str()))
    else {
        tracing::debug!(kid = %kid, "self-issued token verification failed: no matching signing key");
        return Ok(None);
    };

    let Ok(jwk) = serde_json::from_value::<Jwk>(matching_jwk) else {
        tracing::warn!(kid = %kid, "stored signing key JWK failed to parse");
        return Ok(None);
    };
    let Ok(decoding_key) = DecodingKey::from_jwk(&jwk) else {
        tracing::warn!(kid = %kid, "stored signing key JWK is not a usable decoding key");
        return Ok(None);
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = vec![Algorithm::RS256];
    validation.validate_aud = false;

    match decode::<ExchangeClaims>(token, &decoding_key, &validation) {
        Ok(data) => Ok(Some(data.claims)),
        Err(err) => {
            tracing::debug!(error = %err, "self-issued token signature/claims verification failed");
            Ok(None)
        }
    }
}

/// Re-resolved authorization context for a native RFC 8693 exchange session, everything
/// [`crate::handlers::introspect::introspect_api_key`] needs to build an
/// [`crate::models::IntrospectResponse`] for it. `project` doubles as the source of
/// `allowed_models`/`model_policy`/`project_quota`/`billing_plan` -- the same fields
/// `ValidatedApiKeyContext` reads off a project row on the API-key plane.
pub struct ExchangeTokenContext {
    /// The session id this token was minted with (`access_token_extra`'s `api_key_id` claim) --
    /// there is no `api_keys` row, so this is surfaced as the introspection response's `sub`
    /// (this credential's own identifier), never as `api_key_id`.
    pub session_id: Option<String>,
    pub account_id: String,
    pub project: Project,
    pub role: Option<String>,
    pub quota_tier: Option<String>,
}

/// Resolves current authorization data for a presented exchange token, or `Ok(None)` for
/// anything that fails closed: bad/expired signature, no tenant claim, subject no longer a member
/// of the claimed project, or the project/account suspended since the token was minted. Never
/// widens `active` -- every branch below either returns a fully-populated `Some` or `None`, no
/// partial state escapes this function.
///
/// **What `active: true` means for the token this builds a response for.** Unlike an API key
/// (revocable by flipping `api_keys.status`), a token-exchange access token has no per-token
/// revocation list -- it is a short-lived, stateless JWT (`oauth2.token_exchange.access_ttl_seconds`),
/// exactly like a Keycloak-issued access token, and this service has never had a way to revoke one
/// mid-lifetime (see the disabled `keycloakintrospection` AuthConfig step in `ai-helm-values` for
/// the same accepted tradeoff on the Keycloak plane). What this function DOES re-verify, live, on
/// every call: the subject is still currently a member/owner of the claimed project
/// (`resolve_context`, the same check `TokenExchangeOpStore::handle_refresh_token` re-runs on
/// every rotation), and neither the project nor its account has been suspended since mint time.
/// So `active: true` here means "signature-valid, unexpired, AND still currently authorized" --
/// strictly stronger than "signature-valid, unexpired" alone, though it cannot instantly revoke
/// the bearer JWT itself before its `exp`.
#[instrument(skip(state, token))]
pub async fn resolve_exchange_token_context(
    state: &Arc<OpaState>,
    token: &str,
) -> Result<Option<ExchangeTokenContext>> {
    let Some(claims) = verify_self_issued_token(state, token).await? else {
        return Ok(None);
    };
    let Some(project_id) = claims.project_id.filter(|s| !s.trim().is_empty()) else {
        tracing::info!(
            active = false,
            reason = "no_project_claim",
            "self-issued token introspection resolved inactive"
        );
        return Ok(None);
    };

    let context = match state.repo.resolve_context(&claims.sub, &project_id).await {
        Ok(context) => context,
        Err(Error::NotFound) => {
            tracing::info!(
                active = false,
                reason = "not_a_member",
                sub = %claims.sub,
                project_id = %project_id,
                "exchange token introspection resolved inactive"
            );
            return Ok(None);
        }
        Err(err) => return Err(err),
    };

    let Some(project) = state.repo.get_project_by_id(&context.project_id).await? else {
        tracing::info!(
            active = false,
            reason = "project_not_found",
            project_id = %context.project_id,
            "exchange token introspection resolved inactive"
        );
        return Ok(None);
    };
    if project.status != ResourceStatus::Active {
        tracing::info!(
            active = false,
            reason = "project_suspended",
            project_id = %project.id,
            "exchange token introspection resolved inactive"
        );
        return Ok(None);
    }

    let Some(account) = state.repo.get_account_by_id(&context.account_id).await? else {
        tracing::info!(
            active = false,
            reason = "account_not_found",
            account_id = %context.account_id,
            "exchange token introspection resolved inactive"
        );
        return Ok(None);
    };
    if account.status != ResourceStatus::Active {
        tracing::info!(
            active = false,
            reason = "account_suspended",
            account_id = %account.id,
            "exchange token introspection resolved inactive"
        );
        return Ok(None);
    }

    let role = state
        .repo
        .project_member_role(&context.project_id, &claims.sub)
        .await?;
    let quota_tier = state
        .repo
        .project_member_quota_tier(&context.project_id, &claims.sub)
        .await?;

    tracing::info!(
        active = true,
        account_id = %context.account_id,
        project_id = %project.id,
        sub = %claims.sub,
        "exchange token introspection resolved active"
    );

    Ok(Some(ExchangeTokenContext {
        session_id: claims.api_key_id,
        account_id: context.account_id,
        project,
        role,
        quota_tier,
    }))
}
