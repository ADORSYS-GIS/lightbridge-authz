use std::collections::HashMap;

use serde_json::Value;

use super::{
    NormalizedRecord, SpanMeta, extract_f64, extract_string, extract_token_triple, usd_to_micros,
};

pub const OPENCODE_MODEL_KEYS: [&str; 1] = ["gen_ai.request.model"];
pub const OPENCODE_PROMPT_TOKENS_KEYS: [&str; 1] = ["gen_ai.usage.input_tokens"];
pub const OPENCODE_COMPLETION_TOKENS_KEYS: [&str; 1] = ["gen_ai.usage.output_tokens"];
pub const OPENCODE_TOTAL_TOKENS_KEYS: [&str; 1] = ["gen_ai.usage.total_tokens"];
pub const OPENCODE_COST_KEYS: [&str; 1] = ["opencode.cost.usage"];
pub const OPENCODE_LATENCY_SECONDS_KEYS: [&str; 1] = ["gen_ai.client.operation.duration"];
pub const OPENCODE_TOOL_KEYS: [&str; 1] = ["gen_ai.tool.name"];

pub fn normalize(attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    let model = extract_string(attrs, &OPENCODE_MODEL_KEYS);

    let (prompt_tokens, completion_tokens, total_tokens) = extract_token_triple(
        attrs,
        &OPENCODE_PROMPT_TOKENS_KEYS,
        &OPENCODE_COMPLETION_TOKENS_KEYS,
        &OPENCODE_TOTAL_TOKENS_KEYS,
    );

    let cost_usd = extract_f64(attrs, &OPENCODE_COST_KEYS).or_else(|| {
        let m = model.as_deref()?;
        // Missing token counts mean "cost unknown", not "cost zero" -- a data point that
        // carries `model` but not the usage metric (e.g. the `gen_ai.client.operation.duration`
        // histogram, which OpenCode emits on a separate metric from
        // `gen_ai.client.token.usage`) must not fall through to `0 * rate = 0.0` and be
        // reported as a free run. Mirrors the `_ => return None` unknown-model branch below.
        let (Some(prompt_tokens), Some(completion_tokens)) = (prompt_tokens, completion_tokens)
        else {
            return None;
        };
        let p_tok = prompt_tokens as f64;
        let c_tok = completion_tokens as f64;

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
