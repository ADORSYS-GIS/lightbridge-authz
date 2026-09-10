use std::collections::HashMap;

use serde_json::Value;

use super::{
    NormalizedRecord, SpanMeta, extract_f64, extract_i64, extract_string, extract_token_triple,
};

// This is already micro-USD on the wire (docs/research/2026-08-25-genai-usage-ingestion.md
// "F1: Cost is off by 1,000,000x" -- the gateway's llm_custom_total_cost CEL emits micro-USD,
// ai-helm ADR-0051/ADR-0058), NOT dollars. Read it as an integer directly -- do NOT run it
// through usd_to_micros, which would reproduce F1 by multiplying an already-micro value by
// 1,000,000 a second time.
//
// The attribute this deployment actually sends is `gen_ai.usage.custom_total_cost`: the Envoy
// AI Gateway access-log mapping (research doc §2.1/§3.2) maps the raw `io.envoy.ai_gateway`
// dynamic-metadata operator into that OTel semconv attribute. The raw key is kept as a
// fallback, but the real wire key must lead or the micro-USD read never engages on the live
// path and the generic COST_KEYS fallback re-treats the micro-USD value as dollars (F1).
pub const EAIG_COST_KEYS: [&str; 2] = [
    "gen_ai.usage.custom_total_cost",
    "io.envoy.ai_gateway.llm_custom_total_cost",
];
pub const EAIG_MODEL_KEYS: [&str; 3] = ["model", "llm.model", "gen_ai.request.model"];
pub const EAIG_PROMPT_TOKENS_KEYS: [&str; 4] = [
    "prompt_tokens",
    "llm.usage.prompt_tokens",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.prompt_tokens",
];
pub const EAIG_COMPLETION_TOKENS_KEYS: [&str; 4] = [
    "completion_tokens",
    "llm.usage.completion_tokens",
    "gen_ai.usage.output_tokens",
    "gen_ai.usage.completion_tokens",
];
pub const EAIG_TOTAL_TOKENS_KEYS: [&str; 3] = [
    "total_tokens",
    "llm.usage.total_tokens",
    "gen_ai.usage.total_tokens",
];
pub const EAIG_LATENCY_MS_KEYS: [&str; 2] = ["duration", "x-envoy-upstream-service-time"];

pub fn normalize(attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    // The micro-USD cost can arrive as an integer OR as an integral double (CEL-computed costs
    // are float-backed), so try the integer read first and fall back to an integral double read
    // rather than leaving `cost_micros` None. If we left it None, merge_norm_tokens_and_cost
    // would fall back to the generic dollar-interpreted COST_KEYS and re-treat the micro-USD
    // value as dollars (F1, off by 1,000,000x).
    let cost_micros = extract_i64(attrs, &EAIG_COST_KEYS).or_else(|| {
        extract_f64(attrs, &EAIG_COST_KEYS)
            .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
            .map(|value| value as i64)
    });

    let (prompt_tokens, completion_tokens, total_tokens) = extract_token_triple(
        attrs,
        &EAIG_PROMPT_TOKENS_KEYS,
        &EAIG_COMPLETION_TOKENS_KEYS,
        &EAIG_TOTAL_TOKENS_KEYS,
    );

    let latency_ms = extract_f64(attrs, &EAIG_LATENCY_MS_KEYS)
        .filter(|value| value.is_finite() && *value >= 0.0);

    NormalizedRecord {
        trace_id: meta.trace_id.clone(),
        span_id: meta.span_id.clone(),
        model: extract_string(attrs, &EAIG_MODEL_KEYS),
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cost_micros,
        latency_ms,
        tool_name: None,
    }
}
