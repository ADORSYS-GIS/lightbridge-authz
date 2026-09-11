use std::collections::HashMap;

use serde_json::Value;

use super::{NormalizedRecord, SpanMeta};

pub fn normalize(_attrs: &HashMap<String, Value>, meta: &SpanMeta) -> NormalizedRecord {
    // Copilot data arrives via the day-grain pull path, not the push OTLP path.
    // This stub normalizer exists only to prevent `github-copilot` from being an
    // "unknown source" rejection if its token ever appears on the push path.
    NormalizedRecord {
        trace_id: meta.trace_id.clone(),
        span_id: meta.span_id.clone(),
        model: None,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        cost_micros: None,
        latency_ms: None,
        tool_name: None,
    }
}
