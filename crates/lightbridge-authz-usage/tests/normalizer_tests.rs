use std::collections::HashMap;

use lightbridge_authz_usage_rest::normalizer::{KNOWN_SOURCES, REGISTRY, SpanMeta, usd_to_micros};
use serde_json::{Value, json};

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
fn test_opencode_normalizer_missing_token_counts_yield_unknown_cost_not_zero() {
    // A data point can carry `model` without carrying token counts -- e.g. OpenCode's
    // gen_ai.client.operation.duration histogram (latency signal) does not also carry
    // gen_ai.usage.input_tokens/output_tokens (those live on the separate
    // gen_ai.client.token.usage metric). The model-based cost estimator must report cost as
    // unknown (None) here, not silently compute 0 * rate = $0.00 and claim the run was free.
    let normalizer = REGISTRY
        .get("opencode")
        .expect("opencode normalizer should exist");

    let mut attrs = HashMap::new();
    attrs.insert(
        "gen_ai.request.model".to_string(),
        Value::String("meta-llama/llama-3.1-405b-instruct".to_string()),
    );

    let span_meta = SpanMeta {
        trace_id: None,
        span_id: None,
        start_time_unix_nano: 0,
        end_time_unix_nano: 0,
        name: "gen_ai.client.operation.duration".to_string(),
    };

    let record = normalizer(&attrs, &span_meta);

    assert_eq!(record.prompt_tokens, None);
    assert_eq!(record.completion_tokens, None);
    assert_eq!(
        record.cost_micros, None,
        "missing token counts must yield unknown cost, never a $0.00 default"
    );
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
    // Real claude_code.api_request/tool_result attribute names
    // (docs/research/2026-08-25-genai-usage-ingestion.md lines 229-231): `model`,
    // `input_tokens`, `output_tokens`, `cost_usd`, `duration_ms`, `tool_name` -- not the dotted
    // forms this normalizer used before review (`model.name`/`tokens.input`/`tokens.output`/
    // `tool.name`), which don't match the real event schema at all.
    let normalizer = REGISTRY
        .get("claude-code")
        .expect("claude-code should exist");
    let record = normalizer(
        &attrs(&[
            ("model", json!("claude-3-5-sonnet")),
            ("input_tokens", json!(100)),
            ("output_tokens", json!(50)),
            ("cost_usd", json!(0.0004125)),
            ("duration_ms", json!(412.0)),
            ("tool_name", json!("bash")),
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
fn test_claude_code_normalizer_prefers_cost_usd_micros_over_cost_usd() {
    // cost_usd_micros is already integer micro-USD; cost_usd is dollars. They must never be
    // folded into the same extraction path (that would treat one of them as the wrong unit).
    // When both are present, the already-correct-unit field wins.
    let normalizer = REGISTRY
        .get("claude-code")
        .expect("claude-code should exist");
    let record = normalizer(
        &attrs(&[
            ("model", json!("claude-3-5-sonnet")),
            ("cost_usd", json!(999.0)), // must be ignored: cost_usd_micros takes precedence
            ("cost_usd_micros", json!(413)),
        ]),
        &span_meta(),
    );

    assert_eq!(
        record.cost_micros,
        Some(413),
        "cost_usd_micros must win over cost_usd when both are present"
    );
}

#[test]
fn test_claude_code_normalizer_cost_usd_micros_only_is_read_as_micros_not_dollars() {
    // A claude_code.api_request event whose cost_usd rounds away/is absent but whose
    // cost_usd_micros is populated must not lose the cost entirely (the bug: only cost_usd was
    // ever read before review).
    let normalizer = REGISTRY
        .get("claude-code")
        .expect("claude-code should exist");
    let record = normalizer(
        &attrs(&[
            ("model", json!("claude-3-5-sonnet")),
            ("cost_usd_micros", json!(7)),
        ]),
        &span_meta(),
    );

    assert_eq!(record.cost_micros, Some(7));
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
    // io.envoy.ai_gateway.llm_custom_total_cost is ALREADY micro-USD on the wire (ai-helm
    // ADR-0051/ADR-0058; docs/research/2026-08-25-genai-usage-ingestion.md "F1: Cost is off by
    // 1,000,000x") -- 1000 here means $0.001, not $1000. The normalizer must read it verbatim,
    // never multiply it by 1_000_000 again.
    let normalizer = REGISTRY.get("eaig").expect("eaig should exist");
    let record = normalizer(
        &attrs(&[
            ("model", json!("gpt-4")),
            ("llm.usage.prompt_tokens", json!(100)),
            ("llm.usage.completion_tokens", json!(50)),
            ("io.envoy.ai_gateway.llm_custom_total_cost", json!(1000)),
            ("duration", json!(25.0)),
        ]),
        &span_meta(),
    );

    assert_eq!(record.model.as_deref(), Some("gpt-4"));
    assert_eq!(record.prompt_tokens, Some(100));
    assert_eq!(record.completion_tokens, Some(50));
    assert_eq!(record.total_tokens, Some(150));
    assert_eq!(
        record.cost_micros,
        Some(1000),
        "llm_custom_total_cost is already micro-USD -- must pass through unchanged, not be \
         multiplied by 1_000_000 again (F1)"
    );
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

#[test]
fn test_every_known_source_has_a_registered_normalizer() {
    // KNOWN_SOURCES (resolve_source's header allowlist) and NormalizerRegistry::build() (the
    // actual dispatch table) are two independently hand-maintained lists with nothing at
    // compile time forcing them to agree. If a future source is added to KNOWN_SOURCES but the
    // registry insert is forgotten, resolve_source accepts the header as "known" while
    // REGISTRY.get() silently returns None -- ingest.rs's `norm = normalizer.map(|f|
    // f(&attrs, &meta)).unwrap_or_default()` then falls back to an all-`None` record instead of
    // refusing the request, exactly the "unavailable branch becomes the permissive branch"
    // failure class. This test makes that drift a compile-time-adjacent, always-run failure
    // instead of a silent data-quality bug discovered downstream.
    for source in KNOWN_SOURCES {
        assert!(
            REGISTRY.get(source).is_some(),
            "{source} is in KNOWN_SOURCES but has no registered normalizer -- \
             NormalizerRegistry::build() is missing an insert for it"
        );
    }
}
