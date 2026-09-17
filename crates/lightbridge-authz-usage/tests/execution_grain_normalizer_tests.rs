//! Unit tests for the execution-grain normalizer (#588, AC2): parsing OTLP trace spans into
//! `usage_executions` / `usage_model_calls` / `usage_tool_calls` rows, with stub-before-parent
//! and identity extraction.
//!
//! These run in CI unconditionally — no database needed.

use lightbridge_authz_usage_rest::normalizer::execution_grain::parse_execution_grain;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use serde_json::json;

const TRACE: &str = "00000000000000000000000000000001";
const EXEC_SPAN: &str = "0000000000000001";
const MC_SPAN: &str = "0000000000000002";
const TC_SPAN: &str = "0000000000000003";

fn span(
    span_id: &str,
    parent_span_id: &str,
    name: &str,
    start: &str,
    end: &str,
    attrs: serde_json::Value,
) -> serde_json::Value {
    json!({
        "traceId": TRACE,
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "name": name,
        "startTimeUnixNano": start,
        "endTimeUnixNano": end,
        "attributes": attrs
    })
}

fn payload(spans: serde_json::Value) -> ExportTraceServiceRequest {
    serde_json::from_value(json!({
        "resourceSpans": [{ "scopeSpans": [{ "spans": spans }] }]
    }))
    .expect("valid trace payload")
}

#[test]
fn classifies_an_execution_span() {
    let p = payload(json!([span(
        EXEC_SPAN,
        "",
        "agent.run",
        "1735689600000000000",
        "1735689605000000000",
        json!([
            {"key":"user_id","value":{"stringValue":"user-1"}},
            {"key":"provider","value":{"stringValue":"anthropic"}}
        ])
    )]));
    let batch = parse_execution_grain(p, "claude-code").expect("ok");
    assert_eq!(batch.executions.len(), 1);
    assert!(batch.model_calls.is_empty());
    assert!(batch.tool_calls.is_empty());

    let e = &batch.executions[0];
    assert_eq!(e.source, "claude-code");
    assert_eq!(e.trace_id, TRACE);
    assert_eq!(e.span_id, EXEC_SPAN);
    assert_eq!(e.provider.as_deref(), Some("anthropic"));
    assert_eq!(e.provider_user_id.as_deref(), Some("user-1"));
    assert_eq!(e.duration_ms, Some(5000));
}

#[test]
fn classifies_a_model_call_and_mints_a_stub_parent() {
    let p = payload(json!([span(
        MC_SPAN,
        EXEC_SPAN,
        "chat.completion",
        "1735689600000000000",
        "1735689601000000000",
        json!([
            {"key":"model","value":{"stringValue":"gpt-4.1"}},
            {"key":"input_tokens","value":{"intValue":"10"}},
            {"key":"output_tokens","value":{"intValue":"5"}}
        ])
    )]));
    let batch = parse_execution_grain(p, "claude-code").expect("ok");
    assert!(!batch.executions.is_empty());
    assert_eq!(batch.model_calls.len(), 1);

    let m = &batch.model_calls[0];
    assert_eq!(m.model, "gpt-4.1");
    assert_eq!(m.input_tokens, Some(10));
    assert_eq!(m.output_tokens, Some(5));
    assert_eq!(
        m.execution_id,
        format!("exec_claude-code_{TRACE}_{EXEC_SPAN}")
    );

    let stub = batch
        .executions
        .iter()
        .find(|e| e.span_id == EXEC_SPAN)
        .expect("a stub execution for the missing parent");
    assert_eq!(stub.provider, None);
    assert_eq!(stub.duration_ms, None);
    assert_eq!(stub.provider_user_id, None);
}

#[test]
fn classifies_a_tool_call() {
    let p = payload(json!([span(
        TC_SPAN,
        EXEC_SPAN,
        "tool.use",
        "1735689600000000000",
        "1735689600200000000",
        json!([{"key":"tool_name","value":{"stringValue":"bash"}}])
    )]));
    let batch = parse_execution_grain(p, "claude-code").expect("ok");
    assert_eq!(batch.tool_calls.len(), 1);
    let t = &batch.tool_calls[0];
    assert_eq!(t.tool_name, "bash");
    assert_eq!(t.duration_ms, 200);
    assert_eq!(
        t.execution_id,
        format!("exec_claude-code_{TRACE}_{EXEC_SPAN}")
    );
}

#[test]
fn no_stub_when_parent_execution_is_in_the_same_batch() {
    let p = payload(json!([
        span(
            EXEC_SPAN,
            "",
            "agent.run",
            "1735689600000000000",
            "1735689605000000000",
            json!([{"key":"user_id","value":{"stringValue":"user-1"}}])
        ),
        span(
            MC_SPAN,
            EXEC_SPAN,
            "chat.completion",
            "1735689600000000000",
            "1735689601000000000",
            json!([{"key":"model","value":{"stringValue":"gpt-4.1"}}])
        )
    ]));
    let batch = parse_execution_grain(p, "claude-code").expect("ok");
    assert_eq!(batch.executions.len(), 1, "parent in batch means no stub");
    assert_eq!(batch.model_calls.len(), 1);
}

#[test]
fn refuses_a_tool_call_with_no_duration() {
    // A valid timestamp pair that is non-monotonic (end < start) yields no duration, so the
    // tool-call branch must refuse rather than fabricate a zero.
    let p = payload(json!([span(
        TC_SPAN,
        EXEC_SPAN,
        "tool.use",
        "1735689605000000000",
        "1735689600000000000",
        json!([{"key":"tool_name","value":{"stringValue":"bash"}}])
    )]));
    let err = parse_execution_grain(p, "claude-code").expect_err("no duration must be refused");
    assert!(err.to_string().contains("no duration"));
}

#[test]
fn refuses_a_span_with_no_timestamp() {
    // Fail-loud on a missing timestamp (P2): `usage_executions.observed_at` is NOT NULL and built
    // from new code, so a zero timestamp must be refused, never silently replaced with wall-clock
    // ingest time.
    let p = payload(json!([span(
        EXEC_SPAN,
        "",
        "agent.run",
        "0",
        "0",
        json!([{"key":"user_id","value":{"stringValue":"user-1"}}])
    )]));
    let err = parse_execution_grain(p, "claude-code").expect_err("no timestamp must be refused");
    assert!(err.to_string().contains("no timestamp"));
}
