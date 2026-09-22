//! #585 AC4, the "alert, never overwrite" half: cross-check the source identity a payload
//! *asserts* against the source identity the *credential* established.
//!
//! The trusted source is resolved from the authenticated channel (a `client_credentials` token's
//! mapped principal on `/auth/v1/otel/*`, the `X-Source` header on the legacy gateway path) --
//! never from anything the payload says. This module is the other direction of that rule: when a
//! payload nonetheless carries its own idea of who it is, that disagreement must be *visible* and
//! must never be *applied*. The stored event always carries the trusted source; the payload's
//! value is left exactly as it arrived and is never written over it.
//!
//! Deliberately **not** a refusal. A payload-asserted identity is attacker-controlled input on a
//! path that is otherwise authenticated, and rejecting the batch would let a caller who can craft
//! a payload attribute deny service to an honest collector's real telemetry. Alerting keeps the
//! signal without handing over a lever. ADR-0027 decision 4 and ADR-0028 D8 leg 1 both state this
//! explicitly ("a payload-asserted identity remains a cross-check that alerts on mismatch and
//! never overwrites").
//!
//! **Why this lives in its own file, and why it reads `attrs` rather than a `UsageEvent`:** #549
//! (`7c7eea3`) deleted `UsageEvent::attributes` outright -- the field was 60% of a
//! 100 MB/day table and was never read back. The check used to run over the *persisted* event,
//! which is why it silently became a no-op the moment that field went away. It now runs
//! **upstream of extraction**, on the merged OTLP attribute map that `handlers::ingest`'s
//! extractors build in memory before constructing a `UsageEvent` -- the last point where the
//! payload's own assertion still exists. Splitting it out of `handlers/ingest.rs` (which is at
//! its grandfathered LoC-gate ceiling) keeps that file from growing for this.

use std::collections::HashMap;

use serde_json::Value;
use tracing::warn;

/// Payload attribute names that carry a self-asserted source identity.
///
/// `governance.source` is what this platform's own tooling stamps; `service.namespace` is the
/// OpenTelemetry resource convention. Both are checked because either one showing up disagreeing
/// with the credential-derived source is the same fact.
pub const IDENTITY_ATTRIBUTE_KEYS: [&str; 2] = ["governance.source", "service.namespace"];

/// Returns the first payload-asserted identity that disagrees with `trusted_source`, as
/// `(attribute name, asserted value)`.
///
/// `None` covers both "the payload made no assertion" and "the payload agreed" -- the two cases
/// that need no warning. Split out from [`check_identity_mismatch`] so the decision is a pure
/// function a test can drive directly, rather than something only observable in a log sink.
pub fn find_identity_mismatch<'a>(
    attrs: &'a HashMap<String, Value>,
    trusted_source: &str,
) -> Option<(&'static str, &'a str)> {
    for key in IDENTITY_ATTRIBUTE_KEYS {
        if let Some(Value::String(asserted)) = attrs.get(key)
            && asserted != trusted_source
        {
            return Some((key, asserted.as_str()));
        }
    }
    None
}

/// Warns when a payload asserts an identity other than `trusted_source`. Never mutates `attrs`,
/// and never causes the record to be rejected or dropped -- see the module doc comment.
///
/// Emits at most one warning per *record*: [`find_identity_mismatch`] returns on the first
/// disagreement. (Before the move upstream this was once per *batch*, because the old caller
/// returned out of a loop over every event; per-record is the honest granularity now that the
/// input is one record's attributes.)
pub fn check_identity_mismatch(attrs: &HashMap<String, Value>, trusted_source: &str) {
    if let Some((key, asserted)) = find_identity_mismatch(attrs, trusted_source) {
        warn!(
            attribute = key,
            asserted,
            trusted_source,
            "payload-asserted source identity differs from the trusted source; storing the \
             trusted source and leaving the payload attribute unmodified"
        );
    }
}
