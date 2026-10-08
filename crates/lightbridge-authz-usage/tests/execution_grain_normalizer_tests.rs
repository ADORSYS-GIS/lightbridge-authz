//! Unit tests for the execution-grain normalizer (#588, AC2): parsing OTLP trace spans into
//! `usage_executions` / `usage_model_calls` / `usage_tool_calls` rows, with stub-before-parent
//! and identity extraction.
//!
//! These run in CI unconditionally — no database needed.

use lightbridge_authz_usage_rest::normalizer::execution_grain::{
    parse_execution_grain, parse_execution_grain_counted,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use serde_json::json;

/// The classifier's mechanics (placement, stubs, refusals) are tested under a VERIFIED source,
/// where they still apply unchanged. Unverified sources are strict -- see the `#769` block below.
const SOURCE: &str = "opencode";
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
    let batch = parse_execution_grain(p, SOURCE).expect("ok");
    assert_eq!(batch.executions.len(), 1);
    assert!(batch.model_calls.is_empty());
    assert!(batch.tool_calls.is_empty());

    let e = &batch.executions[0];
    assert_eq!(e.source, SOURCE);
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
            {"key":"gen_ai.request.model","value":{"stringValue":"gpt-4.1"}},
            {"key":"gen_ai.usage.input_tokens","value":{"intValue":"10"}},
            {"key":"gen_ai.usage.output_tokens","value":{"intValue":"5"}}
        ])
    )]));
    let batch = parse_execution_grain(p, SOURCE).expect("ok");
    assert!(!batch.executions.is_empty());
    assert_eq!(batch.model_calls.len(), 1);

    let m = &batch.model_calls[0];
    assert_eq!(m.model, "gpt-4.1");
    assert_eq!(m.input_tokens, Some(10));
    assert_eq!(m.output_tokens, Some(5));
    assert_eq!(m.execution_id, format!("exec_{SOURCE}_{TRACE}_{EXEC_SPAN}"));

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
        json!([{"key":"gen_ai.tool.name","value":{"stringValue":"bash"}}])
    )]));
    let batch = parse_execution_grain(p, SOURCE).expect("ok");
    assert_eq!(batch.tool_calls.len(), 1);
    let t = &batch.tool_calls[0];
    assert_eq!(t.tool_name, "bash");
    assert_eq!(t.duration_ms, 200);
    assert_eq!(t.execution_id, format!("exec_{SOURCE}_{TRACE}_{EXEC_SPAN}"));
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
            json!([{"key":"gen_ai.request.model","value":{"stringValue":"gpt-4.1"}}])
        )
    ]));
    let batch = parse_execution_grain(p, SOURCE).expect("ok");
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
        json!([{"key":"gen_ai.tool.name","value":{"stringValue":"bash"}}])
    )]));
    let err = parse_execution_grain(p, SOURCE).expect_err("no duration must be refused");
    assert!(err.to_string().contains("no duration"));
}

#[test]
fn refuses_a_tool_call_with_no_parent_execution() {
    // A tool call with an empty parent span id would otherwise mint a phantom stub execution
    // for the empty parent (`exec_{source}_{trace}_{}`) — refuse instead of fabricating a row.
    let p = payload(json!([span(
        TC_SPAN,
        "",
        "tool.use",
        "1735689600000000000",
        "1735689600200000000",
        json!([{"key":"gen_ai.tool.name","value":{"stringValue":"bash"}}])
    )]));
    let err = parse_execution_grain(p, SOURCE).expect_err("no parent must be refused");
    assert!(err.to_string().contains("no parent"));
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
    let err = parse_execution_grain(p, SOURCE).expect_err("no timestamp must be refused");
    assert!(err.to_string().contains("no timestamp"));
}

// ---------------------------------------------------------------------------------------------
// #769: unverified sources are strict
// ---------------------------------------------------------------------------------------------

fn attr(key: &str, value: &str) -> serde_json::Value {
    json!({"key": key, "value": {"stringValue": value}})
}

/// One VS Code Copilot Chat agent turn, as it reached production labelled `claude-code`.
///
/// SHAPE from a real capture (Copilot Chat 0.68.0, VS Code file exporter, 2026-10-08): the span
/// names, parent structure and attribute KEYS are as captured. Every VALUE is synthetic, and the
/// identifying keys (session, repository, conversation ids) are omitted rather than faked.
fn copilot_agent_turn() -> ExportTraceServiceRequest {
    const AGENT: &str = "00000000000000a1";
    let t = |s: &str, e: &str| (s.to_string(), e.to_string());
    let (s0, e0) = t("1735689600000000000", "1735689609000000000");
    payload(json!([
        span(
            AGENT,
            "",
            "invoke_agent GitHub Copilot Chat",
            &s0,
            &e0,
            json!([
                attr("gen_ai.operation.name", "invoke_agent"),
                attr("gen_ai.request.model", "model-x")
            ])
        ),
        span(
            "00000000000000a2",
            AGENT,
            "execute_tool list_dir",
            &s0,
            &e0,
            json!([
                attr("gen_ai.operation.name", "execute_tool"),
                attr("gen_ai.tool.name", "list_dir")
            ])
        ),
        span(
            "00000000000000a3",
            AGENT,
            "embeddings text-embedding-x",
            &s0,
            &e0,
            json!([
                attr("gen_ai.operation.name", "embeddings"),
                attr("gen_ai.request.model", "text-embedding-x")
            ])
        ),
        span(
            "00000000000000a4",
            "",
            "chat model-y",
            &s0,
            &e0,
            json!([
                attr("gen_ai.operation.name", "chat"),
                attr("gen_ai.request.model", "model-y")
            ])
        ),
        span(
            "00000000000000a5",
            "",
            "vscode.chat.user_perceived_time_to_first_progress",
            &s0,
            &e0,
            json!([attr("vscode.chat.user_interaction.result", "success")])
        )
    ]))
}

#[test]
fn a_copilot_turn_labelled_claude_code_stores_no_spurious_execution_and_is_not_rejected() {
    let (batch, dropped) =
        parse_execution_grain_counted(copilot_agent_turn(), "claude-code").expect("never rejected");

    // Dropped: the execute_tool span (gen_ai.tool.name is not a recognised tool key), the UI
    // timing span, and the two parentless model-bearing spans (invoke_agent, chat) -- each of
    // which used to reject the WHOLE batch.
    assert_eq!(dropped.count(), 4);
    let names: Vec<&str> = dropped.names().collect();
    assert!(names.contains(&"execute_tool list_dir"), "{names:?}");
    assert!(
        names.contains(&"vscode.chat.user_perceived_time_to_first_progress"),
        "{names:?}"
    );

    // Kept: the one model call that has a parent, under a stub of that parent. One stub per agent
    // turn is the most this shape can create -- not one execution per span.
    assert_eq!(batch.model_calls.len(), 1);
    assert_eq!(batch.executions.len(), 1, "only the stub parent");
    assert!(
        batch.executions[0].provider.is_none(),
        "a stub, not a real execution"
    );
    assert!(batch.tool_calls.is_empty());
}

#[test]
fn an_unverified_source_never_stores_an_unclassified_span_as_an_execution() {
    for source in ["claude-code", "codex", "microsoft-foundry"] {
        let p = payload(json!([span(
            EXEC_SPAN,
            "",
            "agent.run",
            "1735689600000000000",
            "1735689605000000000",
            json!([attr("provider", "anthropic")])
        )]));
        let (batch, dropped) = parse_execution_grain_counted(p, source).expect("ok");
        assert!(batch.executions.is_empty(), "{source}");
        assert_eq!(dropped.count(), 1, "{source}");
    }
}

#[test]
fn a_verified_source_keeps_the_original_behaviour_exactly() {
    // The same span opencode has always stored as a real execution, with nothing dropped.
    let p = payload(json!([span(
        EXEC_SPAN,
        "",
        "agent.run",
        "1735689600000000000",
        "1735689605000000000",
        json!([attr("provider", "anthropic")])
    )]));
    let (batch, dropped) = parse_execution_grain_counted(p, "opencode").expect("ok");
    assert_eq!(batch.executions.len(), 1);
    assert_eq!(dropped.count(), 0);
}

#[test]
fn drop_reports_carry_a_bounded_set_of_names_never_attributes() {
    let spans: Vec<_> = (0..20)
        .map(|i| {
            span(
                &format!("{:016x}", i + 1),
                "",
                &format!("span-{i}"),
                "1735689600000000000",
                "1735689605000000000",
                json!([attr("user_id", "someone@example.com")]),
            )
        })
        .collect();
    let (_, dropped) =
        parse_execution_grain_counted(payload(json!(spans)), "claude-code").expect("ok");
    assert_eq!(dropped.count(), 20);
    let names: Vec<&str> = dropped.names().collect();
    assert_eq!(names.len(), 5, "bounded");
    assert!(
        names.iter().all(|n| !n.contains('@')),
        "names only, never attribute values"
    );
}
