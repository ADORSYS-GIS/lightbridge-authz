//! Per-resource source resolution (governance#358), split out of `ingest.rs` (LoC gate).
//!
//! Resource attribute a multi-source collector's own trusted forwarder can stamp with a more
//! specific source than the collector-wide `X-Source` header carries. Same key
//! `payload_identity::IDENTITY_ATTRIBUTE_KEYS` checks for a mismatch against the trusted source;
//! that check is unaffected by this (it already runs against whichever source this resolves).

use std::collections::HashMap;

use serde_json::Value;

const RESOURCE_SOURCE_ATTRIBUTE: &str = "governance.source";

/// Whether a resource's own [`RESOURCE_SOURCE_ATTRIBUTE`] may refine the `source` [`ingest`]'s
/// callers pass in, or whether that `source` is already final and a resource-level claim must be
/// ignored (though still cross-checked by `check_identity_mismatch`, unaffected by this type).
///
/// [`ingest`]: super::ingest
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceTrust {
    /// The unauthenticated `/v1/otel/*` path (ADR-0028 D8): no per-request credential exists, so
    /// `source` is only ever a collector-wide default. A single collector can carry more than one
    /// client's traffic behind one shared credential once `governance-auth`'s local collector
    /// daemon (ADR-0016) is involved -- it derives a trustworthy per-resource source from each
    /// resource's own `event.name` before forwarding, which is safe to prefer here.
    ResourceMayRefine,
    /// The authenticated `/auth/v1/otel/*` path (#585): a per-request machine credential already
    /// maps 1:1 to exactly one `source` (`authenticate_and_authorize`). Trusting a resource-level
    /// claim here would let a valid credential for one source forge attribution to another --
    /// exactly the forgery `check_identity_mismatch`'s "alert, never overwrite" rule exists to
    /// deny, so `source` is returned unconditionally.
    CredentialIsFinal,
}

/// Resolves the trusted source for ONE resource group. See [`SourceTrust`] for when
/// `resource_attrs`'s own claim may apply at all; when it may, an unrecognised claim (one outside
/// [`crate::normalizer::KNOWN_SOURCES`]) is never trusted either, same rule `resolve_source`
/// already applies to the `X-Source` header itself. Either way this is a resource-level
/// REFINEMENT of the already-authenticated channel's source, never an escape from it -- nothing
/// here accepts a source `resolve_source` would have rejected for the request as a whole.
pub(super) fn resolve_event_source<'a>(
    resource_attrs: &HashMap<String, Value>,
    default_source: &'a str,
    trust: SourceTrust,
) -> &'a str {
    if trust == SourceTrust::CredentialIsFinal {
        return default_source;
    }
    let Some(Value::String(claimed)) = resource_attrs.get(RESOURCE_SOURCE_ATTRIBUTE) else {
        return default_source;
    };
    crate::normalizer::KNOWN_SOURCES
        .iter()
        .find(|&&known| known == claimed)
        .map_or(default_source, |&known| known)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs_with_source(source: &str) -> HashMap<String, Value> {
        HashMap::from([(
            RESOURCE_SOURCE_ATTRIBUTE.to_owned(),
            Value::String(source.to_owned()),
        )])
    }

    #[test]
    fn a_recognised_resource_level_source_wins_when_refinement_is_allowed() {
        assert_eq!(
            resolve_event_source(
                &attrs_with_source("codex"),
                "ai-cli",
                SourceTrust::ResourceMayRefine
            ),
            "codex"
        );
        assert_eq!(
            resolve_event_source(
                &attrs_with_source("claude-code"),
                "ai-cli",
                SourceTrust::ResourceMayRefine
            ),
            "claude-code"
        );
    }

    #[test]
    fn a_credential_bound_source_is_never_overridden_by_the_resource() {
        // The exact forgery this type exists to deny: a request authenticated for one source
        // must not be relabelled by anything the payload's resource attributes claim.
        assert_eq!(
            resolve_event_source(
                &attrs_with_source("codex"),
                "eaig",
                SourceTrust::CredentialIsFinal
            ),
            "eaig"
        );
    }

    #[test]
    fn no_resource_level_attribute_falls_back_to_the_default() {
        assert_eq!(
            resolve_event_source(&HashMap::new(), "ai-cli", SourceTrust::ResourceMayRefine),
            "ai-cli"
        );
    }

    #[test]
    fn an_unrecognised_resource_level_claim_is_never_trusted() {
        // Registry-shaped-looking but not actually in KNOWN_SOURCES -- must fall back exactly
        // like `resolve_source` refuses an unknown `X-Source` header, never invent a new source.
        assert_eq!(
            resolve_event_source(
                &attrs_with_source("not-a-real-source"),
                "ai-cli",
                SourceTrust::ResourceMayRefine
            ),
            "ai-cli"
        );
    }

    #[test]
    fn a_non_string_resource_level_value_is_ignored() {
        let attrs = HashMap::from([(RESOURCE_SOURCE_ATTRIBUTE.to_owned(), Value::Bool(true))]);
        assert_eq!(
            resolve_event_source(&attrs, "ai-cli", SourceTrust::ResourceMayRefine),
            "ai-cli"
        );
    }
}
