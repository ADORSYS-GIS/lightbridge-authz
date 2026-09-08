use super::{
    NormalizedRecord, SpanMeta, combine_token_total, extract_f64, extract_i64, extract_string,
    usd_to_micros,
};
use serde_json::Value;
use std::collections::HashMap;

pub const CLAUDE_CODE_MODEL_KEYS: [&str; 2] = ["model.name", "gen_ai.request.model"];
pub const CLAUDE_CODE_PROMPT_TOKENS_KEYS: [&str; 1] = ["tokens.input"];
pub const CLAUDE_CODE_COMPLETION_TOKENS_KEYS: [&str; 1] = ["tokens.output"];
pub const CLAUDE_CODE_COST_KEYS: [&str; 1] = ["cost_usd"];
pub const CLAUDE_CODE_LATENCY_MS_KEYS: [&str; 1] = ["duration_ms"];
pub const CLAUDE_CODE_TOOL_KEYS: [&str; 1] = ["tool.name"];

pub fn normalize(attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    let cost_usd = extract_f64(attrs, &CLAUDE_CODE_COST_KEYS);
    let cost_micros = cost_usd.and_then(usd_to_micros);

    let prompt_tokens = extract_i64(attrs, &CLAUDE_CODE_PROMPT_TOKENS_KEYS);
    let completion_tokens = extract_i64(attrs, &CLAUDE_CODE_COMPLETION_TOKENS_KEYS);
    let total_tokens = combine_token_total(prompt_tokens, completion_tokens);

    let latency_ms = extract_f64(attrs, &CLAUDE_CODE_LATENCY_MS_KEYS)
        .filter(|value| value.is_finite() && *value >= 0.0);

    NormalizedRecord {
        trace_id: meta.trace_id.clone(),
        span_id: meta.span_id.clone(),
        model: extract_string(attrs, &CLAUDE_CODE_MODEL_KEYS),
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cost_micros,
        latency_ms,
        tool_name: extract_string(attrs, &CLAUDE_CODE_TOOL_KEYS),
    }
}
