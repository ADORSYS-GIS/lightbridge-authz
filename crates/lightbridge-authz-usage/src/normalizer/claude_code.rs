use std::collections::HashMap;

use serde_json::Value;

use super::{
    NormalizedRecord, SpanMeta, combine_token_total, extract_f64, extract_i64, extract_string,
    usd_to_micros,
};

// Real claude_code.api_request/tool_result attribute names (docs/research/2026-08-25-genai-usage-ingestion.md
// lines 229-231): `model`, `input_tokens`, `output_tokens`, `cost_usd`, `cost_usd_micros`,
// `duration_ms` (api_request); `tool_name` (tool_result). The dotted forms below
// (`model.name`/`tokens.input`/`tokens.output`/`tool.name`) do not match the real event schema --
// keep `gen_ai.request.model` as a secondary OTel-semconv fallback, but `model` must lead.
pub const CLAUDE_CODE_MODEL_KEYS: [&str; 2] = ["model", "gen_ai.request.model"];
pub const CLAUDE_CODE_PROMPT_TOKENS_KEYS: [&str; 1] = ["input_tokens"];
pub const CLAUDE_CODE_COMPLETION_TOKENS_KEYS: [&str; 1] = ["output_tokens"];
// `cost_usd` (dollars) and `cost_usd_micros` (already integer micro-USD) are two different units
// on the same event -- see normalize() below, which tries the micros field first rather than
// folding both keys into one extract_f64 list (that would silently treat a micros value as
// dollars, reproducing the same class of bug as F1).
pub const CLAUDE_CODE_COST_USD_KEYS: [&str; 1] = ["cost_usd"];
pub const CLAUDE_CODE_COST_USD_MICROS_KEYS: [&str; 1] = ["cost_usd_micros"];
pub const CLAUDE_CODE_LATENCY_MS_KEYS: [&str; 1] = ["duration_ms"];
pub const CLAUDE_CODE_TOOL_KEYS: [&str; 1] = ["tool_name"];

pub fn normalize(attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    // Prefer the already-micro-USD field when present; only convert cost_usd (dollars) when
    // cost_usd_micros is absent. Reading both into the same extract_f64/usd_to_micros pipeline
    // would treat cost_usd_micros as dollars and multiply it by 1_000_000 a second time.
    let cost_micros = extract_i64(attrs, &CLAUDE_CODE_COST_USD_MICROS_KEYS)
        .or_else(|| extract_f64(attrs, &CLAUDE_CODE_COST_USD_KEYS).and_then(usd_to_micros));

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
