use std::collections::HashMap;

use serde_json::Value;

use super::{
    NormalizedRecord, SpanMeta, combine_token_total, extract_f64, extract_i64, extract_string,
    usd_to_micros,
};

// ⚠️ UNVERIFIED against a real Foundry integration -- these keys are byte-identical to
// claude_code.rs's, which review found do NOT match Claude Code's actual event schema
// (docs/research/2026-08-25-genai-usage-ingestion.md documents `model`/`input_tokens`/
// `output_tokens`/`tool_name`, not the dotted forms below). lightbridge-governance's
// RFC-0002 (docs/rfc/0002-microsoft-foundry-otlp-ingestion.md) explicitly punts on this:
// "Do not couple the product to raw OpenTelemetry GenAI attribute names -- those conventions
// are still moving" -- i.e. Foundry's real attribute names were not settled when this
// normalizer was written, and this file looks like an uncustomized copy of claude_code.rs
// rather than a verified mapping. Do not trust this as ground truth; confirm against real
// Foundry OTLP telemetry (or RFC-0002's eventual normalization decision) before relying on it,
// and prefer the generic ingest.rs fallback keys over these dotted forms in the meantime.
pub const FOUNDRY_MODEL_KEYS: [&str; 2] = ["model.name", "gen_ai.request.model"];
pub const FOUNDRY_PROMPT_TOKENS_KEYS: [&str; 1] = ["tokens.input"];
pub const FOUNDRY_COMPLETION_TOKENS_KEYS: [&str; 1] = ["tokens.output"];
pub const FOUNDRY_COST_KEYS: [&str; 1] = ["cost_usd"];
pub const FOUNDRY_LATENCY_MS_KEYS: [&str; 1] = ["duration_ms"];
pub const FOUNDRY_TOOL_KEYS: [&str; 1] = ["tool.name"];

pub fn normalize(attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    let cost_usd = extract_f64(attrs, &FOUNDRY_COST_KEYS);
    let cost_micros = cost_usd.and_then(usd_to_micros);

    let prompt_tokens = extract_i64(attrs, &FOUNDRY_PROMPT_TOKENS_KEYS);
    let completion_tokens = extract_i64(attrs, &FOUNDRY_COMPLETION_TOKENS_KEYS);
    let total_tokens = combine_token_total(prompt_tokens, completion_tokens);

    let latency_ms = extract_f64(attrs, &FOUNDRY_LATENCY_MS_KEYS)
        .filter(|value| value.is_finite() && *value >= 0.0);

    NormalizedRecord {
        trace_id: meta.trace_id.clone(),
        span_id: meta.span_id.clone(),
        model: extract_string(attrs, &FOUNDRY_MODEL_KEYS),
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cost_micros,
        latency_ms,
        tool_name: extract_string(attrs, &FOUNDRY_TOOL_KEYS),
    }
}
