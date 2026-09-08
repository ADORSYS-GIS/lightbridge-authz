use lightbridge_authz_usage_rest::normalizer::{REGISTRY, SpanMeta, usd_to_micros};
use serde_json::{Value, json};
use std::collections::HashMap;

#[test]
fn test_opencode_normalizer_cost_conversion() {
    let normalizer = REGISTRY
        .get("opencode")
        .expect("opencode normalizer should exist");

    let mut attrs = HashMap::new();
    attrs.insert(
        "gen_ai.usage.input_tokens".to_string(),
        Value::Number(100.into()),
    );
    attrs.insert(
        "gen_ai.usage.output_tokens".to_string(),
        Value::Number(50.into()),
    );
    attrs.insert(
        "gen_ai.request.model".to_string(),
        Value::String("meta-llama/llama-3.1-405b-instruct".to_string()),
    );

    let span_meta = SpanMeta {
        trace_id: None,
        span_id: None,
        start_time_unix_nano: 0,
        end_time_unix_nano: 0,
        name: "gen_ai.client.token.usage".to_string(),
    };

    let record = normalizer(&attrs, &span_meta);

    assert_eq!(record.prompt_tokens, Some(100));
    assert_eq!(record.completion_tokens, Some(50));
    assert_eq!(record.total_tokens, Some(150));
    assert_eq!(
        record.model.as_deref(),
        Some("meta-llama/llama-3.1-405b-instruct")
    );

    // Expected cost:
    // Input cost per million: $2.75 -> 2.75 * 100 / 1,000,000 = $0.000275
    // Output cost per million: $2.75 -> 2.75 * 50 / 1,000,000 = $0.0001375
    // Total cost = $0.0004125
    // Micro-dollars: 0.0004125 * 1,000,000 = 412.5 -> rounds to 413
    assert_eq!(record.cost_micros, Some(413));
}

#[test]
fn test_opencode_normalizer_cost_conversion_deepseek() {
    let normalizer = REGISTRY
        .get("opencode")
        .expect("opencode normalizer should exist");

    let mut attrs = HashMap::new();
    attrs.insert(
        "gen_ai.usage.input_tokens".to_string(),
        Value::Number(100.into()),
    );
    attrs.insert(
        "gen_ai.usage.output_tokens".to_string(),
        Value::Number(50.into()),
    );
    attrs.insert(
        "gen_ai.request.model".to_string(),
        Value::String("deepseek-ai/deepseek-coder-33b-instruct".to_string()),
    );

    let span_meta = SpanMeta {
        trace_id: None,
        span_id: None,
        start_time_unix_nano: 0,
        end_time_unix_nano: 0,
        name: "gen_ai.client.token.usage".to_string(),
    };

    let record = normalizer(&attrs, &span_meta);

    // Deepseek Coder 33b: input $0.14/1M, output $0.28/1M
    // Input cost: 0.14 * 100 / 1,000,000 = $0.000014
    // Output cost: 0.28 * 50 / 1,000,000 = $0.000014
    // Total cost = $0.000028 -> 28 micro-dollars
    assert_eq!(record.cost_micros, Some(28));
}

#[test]
fn test_opencode_normalizer_unknown_model_fallback() {
    let normalizer = REGISTRY
        .get("opencode")
        .expect("opencode normalizer should exist");

    let mut attrs = HashMap::new();
    attrs.insert(
        "gen_ai.usage.input_tokens".to_string(),
        Value::Number(100.into()),
    );
    attrs.insert(
        "gen_ai.usage.output_tokens".to_string(),
        Value::Number(50.into()),
    );
    attrs.insert(
        "gen_ai.request.model".to_string(),
        Value::String("unknown/model".to_string()),
    );

    let span_meta = SpanMeta {
        trace_id: None,
        span_id: None,
        start_time_unix_nano: 0,
        end_time_unix_nano: 0,
        name: "gen_ai.client.token.usage".to_string(),
    };

    let record = normalizer(&attrs, &span_meta);

    assert_eq!(record.prompt_tokens, Some(100));
    assert_eq!(record.completion_tokens, Some(50));
    assert_eq!(record.total_tokens, Some(150));
    assert_eq!(record.cost_micros, None);
}

#[test]
fn test_registry_unknown_source_is_none() {
    let normalizer = REGISTRY.get("unknown_source");
    assert!(normalizer.is_none());
}

fn span_meta() -> SpanMeta {
    SpanMeta {
        trace_id: None,
        span_id: None,
        start_time_unix_nano: 0,
        end_time_unix_nano: 0,
        name: "test".to_string(),
    }
}

fn attrs(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn test_claude_code_normalizer_ports_governance_contract() {
    let normalizer = REGISTRY
        .get("claude-code")
        .expect("claude-code should exist");
    let record = normalizer(
        &attrs(&[
            ("model.name", json!("claude-3-5-sonnet")),
            ("tokens.input", json!(100)),
            ("tokens.output", json!(50)),
            ("cost_usd", json!(0.0004125)),
            ("duration_ms", json!(412.0)),
            ("tool.name", json!("bash")),
        ]),
        &span_meta(),
    );

    assert_eq!(record.model.as_deref(), Some("claude-3-5-sonnet"));
    assert_eq!(record.prompt_tokens, Some(100));
    assert_eq!(record.completion_tokens, Some(50));
    assert_eq!(record.total_tokens, Some(150));
    assert_eq!(record.cost_micros, Some(413));
    assert_eq!(record.latency_ms, Some(412.0));
    assert_eq!(record.tool_name.as_deref(), Some("bash"));
}

#[test]
fn test_codex_normalizer_ports_governance_contract() {
    let normalizer = REGISTRY.get("codex").expect("codex should exist");
    let record = normalizer(
        &attrs(&[
            ("model.name", json!("gpt-4.1")),
            ("tokens.input", json!(10)),
            ("tokens.output", json!(5)),
            ("tool.name", json!("read")),
        ]),
        &span_meta(),
    );

    assert_eq!(record.model.as_deref(), Some("gpt-4.1"));
    assert_eq!(record.prompt_tokens, Some(10));
    assert_eq!(record.completion_tokens, Some(5));
    assert_eq!(record.total_tokens, Some(15));
    assert_eq!(record.cost_micros, None);
    assert_eq!(record.latency_ms, None);
    assert_eq!(record.tool_name.as_deref(), Some("read"));
}

#[test]
fn test_microsoft_foundry_normalizer_ports_governance_contract() {
    let normalizer = REGISTRY
        .get("microsoft-foundry")
        .expect("microsoft-foundry should exist");
    let record = normalizer(
        &attrs(&[
            ("model.name", json!("phi-4")),
            ("tokens.input", json!(8)),
            ("tokens.output", json!(2)),
            ("cost_usd", json!(0.00001)),
            ("duration_ms", json!(33.0)),
            ("tool.name", json!("edit")),
        ]),
        &span_meta(),
    );

    assert_eq!(record.model.as_deref(), Some("phi-4"));
    assert_eq!(record.prompt_tokens, Some(8));
    assert_eq!(record.completion_tokens, Some(2));
    assert_eq!(record.total_tokens, Some(10));
    assert_eq!(record.cost_micros, Some(10));
    assert_eq!(record.latency_ms, Some(33.0));
    assert_eq!(record.tool_name.as_deref(), Some("edit"));
}

#[test]
fn test_eaig_normalizer_ports_governance_contract() {
    let normalizer = REGISTRY.get("eaig").expect("eaig should exist");
    let record = normalizer(
        &attrs(&[
            ("model", json!("gpt-4")),
            ("llm.usage.prompt_tokens", json!(100)),
            ("llm.usage.completion_tokens", json!(50)),
            ("io.envoy.ai_gateway.llm_custom_total_cost", json!(0.001)),
            ("duration", json!(25.0)),
        ]),
        &span_meta(),
    );

    assert_eq!(record.model.as_deref(), Some("gpt-4"));
    assert_eq!(record.prompt_tokens, Some(100));
    assert_eq!(record.completion_tokens, Some(50));
    assert_eq!(record.total_tokens, Some(150));
    assert_eq!(record.cost_micros, Some(1000));
    assert_eq!(record.latency_ms, Some(25.0));
}

#[test]
fn test_usd_to_micros_rounds_half_away_from_zero() {
    assert_eq!(usd_to_micros(0.0004125), Some(413));
    assert_eq!(usd_to_micros(0.0), Some(0));
    assert_eq!(usd_to_micros(1.0), Some(1_000_000));
}

#[test]
fn test_usd_to_micros_refuses_nan_negative_and_overflow() {
    assert_eq!(usd_to_micros(f64::NAN), None);
    assert_eq!(usd_to_micros(f64::NEG_INFINITY), None);
    assert_eq!(usd_to_micros(f64::INFINITY), None);
    assert_eq!(usd_to_micros(-0.01), None);
    assert_eq!(usd_to_micros(1e20), None);
}
