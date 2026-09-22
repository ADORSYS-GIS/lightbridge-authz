//! Trusted-vs-payload attribute merge (governance#358), split out of `ingest.rs` (LoC gate).

use std::collections::HashMap;

use serde_json::Value;

/// Merges two OTLP attribute maps. On a key collision, **`additional` wins** -- it is applied
/// last, over a clone of `base`.
///
/// Every call site in `ingest.rs` passes the identity-carrying side (resource attributes, or a
/// less-granular signal level already resource-prioritized) as `additional`, and the more
/// attacker-reachable side (log-record / span / per-point attributes, straight from the request
/// body) as `base`. That is deliberate, not incidental: resource attributes on the public IDE
/// collectors carry `user.id`/`user.email`/`account_id` derived from the claims of the bearer
/// token the collector's OIDC extension already verified (`governance-auth`'s
/// `identity_attributes()`), while per-record attributes are fully caller-controlled JSON with no
/// verification at all. Before this ordering, a single forged `user_id` in one log record's
/// attributes silently overrode the verified identity for that record -- an impersonation path,
/// not a hypothetical one, since nothing about the OTLP wire format stops a client from setting
/// arbitrary per-record attributes. Putting the verified side last means a record without its own
/// value still falls back to whatever the merge produced (unchanged for every non-identity field,
/// since resource attributes essentially never carry model/cost/token keys), but a record that
/// tries to assert its own identity can no longer win.
pub(crate) fn merge_attr_maps(
    base: &HashMap<String, Value>,
    additional: &HashMap<String, Value>,
) -> HashMap<String, Value> {
    let mut merged = base.clone();
    for (key, value) in additional {
        merged.insert(key.clone(), value.clone());
    }
    merged
}

#[cfg(test)]
mod tests {
    use opentelemetry_proto::tonic::collector::{
        logs::v1::ExportLogsServiceRequest, trace::v1::ExportTraceServiceRequest,
    };
    use serde_json::json;

    use crate::handlers::{
        ingest::{extract_log_events, extract_trace_events},
        source_resolution::SourceTrust,
    };

    #[test]
    fn extract_trace_events_should_refuse_record_level_identity_spoofing() {
        // governance#358: resource attributes carry the identity `governance-auth` derived from
        // the collector's own verified bearer token; span attributes are the request BODY, fully
        // caller-controlled. A span asserting a different account/user than the verified resource
        // must never win -- see `merge_attr_maps`'s doc comment.
        let payload: ExportTraceServiceRequest = serde_json::from_value(json!({
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "account_id", "value": {"stringValue": "trusted-account"}},
                            {"key": "lc_user_id", "value": {"stringValue": "trusted-user"}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "00000000000000000000000000000001",
                                    "spanId": "0000000000000001",
                                    "name": "chat.completion",
                                    "startTimeUnixNano": "1735689600000000000",
                                    "endTimeUnixNano": "1735689601000000000",
                                    "attributes": [
                                        {"key": "account_id", "value": {"stringValue": "attacker-account"}},
                                        {"key": "lc_user_id", "value": {"stringValue": "attacker-user"}},
                                        {"key": "model", "value": {"stringValue": "gpt-4.1"}}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }))
        .expect("valid trace payload");

        let events = extract_trace_events(payload, "claude-code", SourceTrust::ResourceMayRefine);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.account_id.as_deref(), Some("trusted-account"));
        assert_eq!(event.user_id.as_deref(), Some("trusted-user"));
        // Non-colliding payload fields are unaffected by the precedence change.
        assert_eq!(event.model.as_deref(), Some("gpt-4.1"));
    }

    #[test]
    fn extract_log_events_should_fall_back_to_record_identity_when_resource_has_none() {
        // The precedence fix must not regress internal/legacy senders that carry no resource-level
        // identity at all (e.g. EAIG's access-log export) -- a record's own value is still used
        // when the resource genuinely has nothing to say about identity.
        let payload: ExportLogsServiceRequest = serde_json::from_value(json!({
            "resourceLogs": [
                {
                    "resource": {"attributes": []},
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": "1735689600000000000",
                                    "attributes": [
                                        {"key": "account_id", "value": {"stringValue": "acct_only_on_record"}}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }))
        .expect("valid log payload");

        let events = extract_log_events(payload, "eaig", SourceTrust::ResourceMayRefine);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].account_id.as_deref(), Some("acct_only_on_record"));
    }
}
