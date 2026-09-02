//! Builds the `reqwest::Client` used to fetch a JWKS, optionally trusting a private CA
//! (`oauth2.jwks_ca_bundle_path`, lightbridge-authz#625) in addition to the platform trust store.
//!
//! Kept as its own module so [`trust_ca_bundle`] is reusable at BOTH production JWKS-fetching
//! sites -- [`crate::BearerTokenService`] here, and `KeycloakRelyingParty` in
//! `lightbridge-authz-rest` (which already depends on this crate) -- without duplicating the
//! read-PEM-add-root-certificate logic a second time.

use anyhow::{anyhow, ensure};

/// Adds `ca_bundle_path`'s PEM certificate(s) as additional trusted roots on `builder`, if set;
/// returns `builder` untouched when `ca_bundle_path` is `None` (the common case), which keeps the
/// resulting client byte-identical to the default -- platform trust store only.
///
/// This ADDS to the trust store (`reqwest::ClientBuilder::add_root_certificate`), it never
/// replaces it -- unlike `SSL_CERT_FILE`, which would swap out the trust store for every outbound
/// connection the process makes. That distinction is the whole point: the JWKS client trusting an
/// in-cluster private CA must not also change what Keycloak discovery (or anything else in the
/// same process) trusts.
///
/// An unreadable path, or a bundle containing zero parseable PEM certificates, is a hard error
/// naming the offending path -- never a silent fallback to the default (unmodified) builder. Per
/// this codebase's fail-closed rule, a misconfigured trust anchor must refuse to start rather than
/// quietly trust less than the operator configured.
pub fn trust_ca_bundle(
    mut builder: reqwest::ClientBuilder,
    ca_bundle_path: Option<&str>,
) -> anyhow::Result<reqwest::ClientBuilder> {
    let Some(path) = ca_bundle_path else {
        return Ok(builder);
    };
    let pem = std::fs::read(path)
        .map_err(|e| anyhow!("failed to read jwks_ca_bundle_path '{path}': {e}"))?;
    // `from_pem_bundle` (not `from_pem`) so a bundle containing zero certificates is
    // distinguishable from "one valid cert" -- reqwest's rustls backend parses PEM lazily, so
    // neither call alone fails on content with no certificate blocks in it.
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|e| anyhow!("failed to parse jwks_ca_bundle_path '{path}' as PEM: {e}"))?;
    ensure!(
        !certs.is_empty(),
        "jwks_ca_bundle_path '{path}' contains no PEM certificates"
    );
    for cert in certs {
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder)
}
