use super::{
    NormalizedRecord, SpanMeta, combine_token_total, extract_f64, extract_i64, extract_string,
    usd_to_micros,
};
use serde_json::Value;
use std::collections::HashMap;

pub const EAIG_COST_KEYS: [&str; 1] = ["io.envoy.ai_gateway.llm_custom_total_cost"];
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
    let cost_usd = extract_f64(attrs, &EAIG_COST_KEYS);
    let cost_micros = cost_usd.and_then(usd_to_micros);

    let prompt_tokens = extract_i64(attrs, &EAIG_PROMPT_TOKENS_KEYS);
    let completion_tokens = extract_i64(attrs, &EAIG_COMPLETION_TOKENS_KEYS);
    let total_tokens = extract_i64(attrs, &EAIG_TOTAL_TOKENS_KEYS)
        .or_else(|| combine_token_total(prompt_tokens, completion_tokens));

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
