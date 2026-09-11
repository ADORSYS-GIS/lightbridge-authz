// ⚠️ UNVERIFIED against a real Codex integration -- these keys use dotted forms
// (`model.name`/`tokens.input`/`tokens.output`/`tool.name`) which review noted may not match
// actual event schemas. Confirm against real Codex telemetry before relying on it.

use std::collections::HashMap;

use serde_json::Value;

use super::{NormalizedRecord, SpanMeta, combine_token_total, extract_i64, extract_string};

pub const CODEX_MODEL_KEYS: [&str; 2] = ["model.name", "gen_ai.request.model"];
pub const CODEX_PROMPT_TOKENS_KEYS: [&str; 1] = ["tokens.input"];
pub const CODEX_COMPLETION_TOKENS_KEYS: [&str; 1] = ["tokens.output"];
pub const CODEX_TOOL_KEYS: [&str; 1] = ["tool.name"];

pub fn normalize(attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    let prompt_tokens = extract_i64(attrs, &CODEX_PROMPT_TOKENS_KEYS);
    let completion_tokens = extract_i64(attrs, &CODEX_COMPLETION_TOKENS_KEYS);
    let total_tokens = combine_token_total(prompt_tokens, completion_tokens);

    NormalizedRecord {
        trace_id: meta.trace_id.clone(),
        span_id: meta.span_id.clone(),
        model: extract_string(attrs, &CODEX_MODEL_KEYS),
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cost_micros: None,
        latency_ms: None,
        tool_name: extract_string(attrs, &CODEX_TOOL_KEYS),
    }
}
