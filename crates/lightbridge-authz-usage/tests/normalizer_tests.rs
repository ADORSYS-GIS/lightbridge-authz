use lightbridge_authz_usage_rest::normalizer::{REGISTRY, SpanMeta};
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
