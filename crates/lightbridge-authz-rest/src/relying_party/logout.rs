//! RP-initiated logout's back-channel leg (`KeycloakRelyingParty::end_upstream_session`) and the
//! discovery-document plumbing it alone needs.
//!
//! A CHILD module of [`super`] (`relying_party.rs`), not a top-level sibling -- precisely so these
//! methods keep reaching `KeycloakRelyingParty`'s private fields directly, the same reason
//! `handlers/accounts.rs` is a child of `handlers/mod.rs` rather than a separate type. Split out
//! because `relying_party.rs` sits exactly on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown -- this cluster (back-channel
//! logout plus the discovery document it alone reads) was the most self-contained one available.

use serde::Deserialize;

use lightbridge_authz_core::error::{Error, Result};

use super::{KeycloakRelyingParty, KeycloakTokenSet, discovery_document_url};

/// The one OIDC discovery field this codebase needs that `authkestra_engine`'s
/// [`ProviderMetadata`] does not model: as of authkestra-engine 0.6.3 that struct is
/// `#[non_exhaustive]` and carries no `end_session_endpoint`, so the RP-initiated-logout leg
/// parses the same document itself rather than hand-building a Keycloak-shaped URL. `issuer` is
/// carried along for exactly one reason -- so this fetch performs the SAME identity-vs-location
/// check [`KeycloakRelyingParty::discover`] does: dial `discovery_url` (LOCATION), trust only a
/// document that names [`KeycloakRelyingParty::issuer`] (IDENTITY).
#[derive(Deserialize)]
struct LogoutMetadata {
    issuer: String,
    end_session_endpoint: Option<String>,
}

/// What [`KeycloakRelyingParty::end_upstream_session`] actually managed to do. Two outcomes rather
/// than a bare `()` because the caller (`end_session.rs`) treats them differently: "there was
/// nothing to log out with" is the ordinary state of a subject whose stored envelope predates a
/// `token_encryption_key` rotation or who never had a refresh token, and saying so at `info`
/// keeps a real upstream fault -- which is a `warn` -- legible in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamLogout {
    /// Keycloak accepted the back-channel logout: the upstream SSO session is terminated.
    Terminated,
    /// No usable stored refresh token for this subject -- no `federated_identities` row, no sealed
    /// envelope, an envelope that would not open (rotated `token_encryption_key`), or a stored
    /// token set that never carried a refresh token. Per `lightbridge_authz_core::crypto`'s
    /// documented `open()` contract every one of those is "no stored credential", never an error.
    NoStoredCredential,
}

impl KeycloakRelyingParty {
    /// Back-channel-terminates the upstream Keycloak SSO session held by `subject`. ADR-0024's
    /// follow-up 4: the first production consumer of a sealed `federated_identities.token_envelope`,
    /// and the reason [`StoreRepo::find_federated_identity`] was written ahead of a caller.
    ///
    /// **A `POST` to the discovered `end_session_endpoint`, never a browser redirect to it.**
    /// [`KeycloakTokenSet`] deliberately stores no raw ID token (it would be replayable as a
    /// `subject_token` into this service's own RFC 8693 endpoint -- see that type's doc comment),
    /// so there is no `id_token_hint` to redirect with; and a redirect *without* a hint makes
    /// Keycloak render a confirmation interstitial on every single logout. The back-channel form
    /// carries `client_id` + `refresh_token`, plus `client_secret` when this deployment registered
    /// a confidential client, and Keycloak ends the SSO session server-side with no user
    /// interaction at all.
    ///
    /// **Every failure here is the caller's to swallow.** Local revocation has already happened by
    /// the time this runs (`end_session.rs`), and an unreachable Keycloak must never turn a
    /// completed local logout into a `500`. The two directions are split accordingly: anything
    /// meaning "there is nothing to log out with" is `Ok(UpstreamLogout::NoStoredCredential)`,
    /// and only a real upstream fault (discovery down, logout endpoint refusing) is an `Err`.
    ///
    /// Bounded by `oauth2.relying_party.timeout_ms`: `self.client` was built with it as a request
    /// timeout, so a slow Keycloak cannot hang logout.
    pub async fn end_upstream_session(&self, subject: &str) -> Result<UpstreamLogout> {
        let Some(refresh_token) = self.stored_refresh_token(subject).await? else {
            return Ok(UpstreamLogout::NoStoredCredential);
        };
        let endpoint = self.discover_end_session_endpoint().await?;
        let mut form = vec![
            ("client_id", self.config.client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ];
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        let response = self
            .client
            .post(endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|_| Error::Server("Keycloak logout endpoint unavailable".to_string()))?;
        if !response.status().is_success() {
            // Status only. The body is never read into the error: this request carried a refresh
            // token, and Keycloak's error documents are free to echo request detail back.
            return Err(Error::Server(format!(
                "Keycloak logout endpoint refused back-channel logout: {}",
                response.status()
            )));
        }
        Ok(UpstreamLogout::Terminated)
    }

    /// The refresh token sealed for `(self.issuer, subject)`, or `None` for every shape of "no
    /// usable stored credential" (see [`UpstreamLogout::NoStoredCredential`]). Only the lookup
    /// itself failing is an `Err`: a query that could not run is not the same answer as one that
    /// found nothing, and the caller's log line should not claim it was.
    async fn stored_refresh_token(&self, subject: &str) -> Result<Option<String>> {
        let Some(identity) = self
            .repo
            .find_federated_identity(&self.issuer, subject)
            .await?
        else {
            return Ok(None);
        };
        let Some(envelope) = identity.token_envelope.as_deref() else {
            return Ok(None);
        };
        // The SAME AAD `persist_federated_identity` sealed under -- the federation key, not the
        // row id (see `lightbridge_authz_core::crypto::seal`'s doc comment for why).
        let aad = format!("{}\u{1f}{}", identity.issuer, identity.subject);
        let Ok(plaintext) = lightbridge_authz_core::crypto::open(&self.token_key, &aad, envelope)
        else {
            // `lightbridge_authz_core::crypto`'s module doc states this contract for the first
            // production caller, which is this one: treat any open failure as "no stored
            // credential", log at most the AAD components, and never touch the row. A rotated
            // `token_encryption_key` makes every older envelope permanently unopenable BY DESIGN;
            // the row sits inert until the next login re-seals it.
            tracing::warn!(
                issuer = %identity.issuer,
                subject = %identity.subject,
                "stored Keycloak token envelope could not be opened; upstream logout skipped"
            );
            return Ok(None);
        };
        let Ok(token_set) = serde_json::from_slice::<KeycloakTokenSet>(&plaintext) else {
            tracing::warn!(
                issuer = %identity.issuer,
                subject = %identity.subject,
                "stored Keycloak token set is not in the expected format; upstream logout skipped"
            );
            return Ok(None);
        };
        Ok(token_set.refresh_token)
    }

    /// Reads `end_session_endpoint` off the provider's own discovery document rather than
    /// composing a Keycloak-shaped URL by hand -- a hand-built path silently rots the moment the
    /// upstream realm base, or the upstream product, changes.
    async fn discover_end_session_endpoint(&self) -> Result<String> {
        let url = discovery_document_url(&self.discovery_url)?;
        let metadata = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| Error::Server("Keycloak discovery unavailable".to_string()))?
            .json::<LogoutMetadata>()
            .await
            .map_err(|_| {
                Error::Server("Keycloak discovery returned an unreadable document".to_string())
            })?;
        // Identical to `discover()`'s check, and for the identical reason: never relax this to
        // compare against `discovery_url`, or a deployment's internal dial target silently
        // becomes the trusted issuer.
        if metadata.issuer != self.issuer {
            return Err(Error::Server(
                "Keycloak discovery issuer mismatch".to_string(),
            ));
        }
        metadata.end_session_endpoint.ok_or_else(|| {
            Error::Server("Keycloak discovery advertises no end_session_endpoint".to_string())
        })
    }
}
