use super::{
    NormalizedRecord, SpanMeta, combine_token_total, extract_f64, extract_i64, extract_string,
    usd_to_micros,
};
use serde_json::Value;
use std::collections::HashMap;

pub const OPENCODE_MODEL_KEYS: [&str; 1] = ["gen_ai.request.model"];
pub const OPENCODE_PROMPT_TOKENS_KEYS: [&str; 1] = ["gen_ai.usage.input_tokens"];
pub const OPENCODE_COMPLETION_TOKENS_KEYS: [&str; 1] = ["gen_ai.usage.output_tokens"];
pub const OPENCODE_TOTAL_TOKENS_KEYS: [&str; 1] = ["gen_ai.usage.total_tokens"]; // from histogram sum
pub const OPENCODE_COST_KEYS: [&str; 1] = ["opencode.cost.usage"];
pub const OPENCODE_LATENCY_SECONDS_KEYS: [&str; 1] = ["gen_ai.client.operation.duration"];
pub const OPENCODE_TOOL_KEYS: [&str; 1] = ["gen_ai.tool.name"];

pub fn normalize(attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    let model = extract_string(attrs, &OPENCODE_MODEL_KEYS);

    let prompt_tokens = extract_i64(attrs, &OPENCODE_PROMPT_TOKENS_KEYS);
    let completion_tokens = extract_i64(attrs, &OPENCODE_COMPLETION_TOKENS_KEYS);
    let total_tokens = extract_i64(attrs, &OPENCODE_TOTAL_TOKENS_KEYS)
        .or_else(|| combine_token_total(prompt_tokens, completion_tokens));

    let cost_usd = extract_f64(attrs, &OPENCODE_COST_KEYS).or_else(|| {
        let m = model.as_deref()?;
        let p_tok = prompt_tokens.unwrap_or(0) as f64;
        let c_tok = completion_tokens.unwrap_or(0) as f64;

        let (in_cost, out_cost) = match m {
            "meta-llama/llama-3.1-405b-instruct" => (2.75, 2.75),
            "deepseek-ai/deepseek-coder-33b-instruct" => (0.14, 0.28),
            _ => return None, // unknown model, no default
        };
        Some((p_tok * in_cost / 1_000_000.0) + (c_tok * out_cost / 1_000_000.0))
    });
    let cost_micros = cost_usd.and_then(usd_to_micros);

    // OpenCode duration is seconds (gen_ai.client.operation.duration)
    let latency_ms = extract_f64(attrs, &OPENCODE_LATENCY_SECONDS_KEYS)
        .map(|seconds| seconds * 1_000.0)
        .filter(|value| value.is_finite() && *value >= 0.0);

    NormalizedRecord {
        trace_id: meta.trace_id.clone(),
        span_id: meta.span_id.clone(),
        model,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cost_micros,
        latency_ms,
        tool_name: extract_string(attrs, &OPENCODE_TOOL_KEYS),
    }
}
