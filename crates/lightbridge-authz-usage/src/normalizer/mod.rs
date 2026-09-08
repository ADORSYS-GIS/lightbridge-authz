use axum::http::HeaderMap;
use lightbridge_authz_core::{Error, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;

pub mod claude_code;
pub mod codex;
pub mod eaig;
pub mod github_copilot;
pub mod microsoft_foundry;
pub mod opencode;

/// The canonical source vocabulary (ADR-0028 D4).
pub const KNOWN_SOURCES: [&str; 6] = [
    "eaig",
    "claude-code",
    "codex",
    "opencode",
    "microsoft-foundry",
    "github-copilot",
];

/// Metadata from the OTLP envelope, passed to the normalizer.
#[derive(Debug, Clone)]
pub struct SpanMeta {
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub name: String,
}

/// The normalized output from a source-specific normalizer.
#[derive(Debug, Clone, Default)]
pub struct NormalizedRecord {
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub model: Option<String>,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    /// BIGINT µUSD -- the integer invariant.
    pub cost_micros: Option<i64>,
    pub latency_ms: Option<f64>,
    pub tool_name: Option<String>,
}

pub type NormalizerFn = fn(&HashMap<String, Value>, &SpanMeta) -> NormalizedRecord;

pub struct NormalizerRegistry {
    normalizers: HashMap<&'static str, NormalizerFn>,
}

impl NormalizerRegistry {
    fn build() -> Self {
        let mut normalizers = HashMap::new();
        normalizers.insert("eaig", eaig::normalize as NormalizerFn);
        normalizers.insert("claude-code", claude_code::normalize as NormalizerFn);
        normalizers.insert("codex", codex::normalize as NormalizerFn);
        normalizers.insert("opencode", opencode::normalize as NormalizerFn);
        normalizers.insert(
            "microsoft-foundry",
            microsoft_foundry::normalize as NormalizerFn,
        );
        normalizers.insert("github-copilot", github_copilot::normalize as NormalizerFn);
        Self { normalizers }
    }

    pub fn get(&self, source: &str) -> Option<NormalizerFn> {
        self.normalizers.get(source).copied()
    }
}

pub static REGISTRY: LazyLock<NormalizerRegistry> = LazyLock::new(NormalizerRegistry::build);

/// Extracts and validates the trusted source from the authenticated channel.
/// Currently reads `X-Source` as a provisional implementation pending #585.
pub fn resolve_source(headers: &HeaderMap) -> Result<&'static str> {
    let source_header = headers
        .get("x-source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim());

    match source_header {
        Some(s) => {
            if let Some(known) = KNOWN_SOURCES.iter().find(|&&k| k == s) {
                Ok(*known)
            } else {
                Err(Error::BadRequest(format!("unknown source: {}", s)))
            }
        }
        None => Err(Error::BadRequest("missing x-source header".to_string())),
    }
}

/// Converts float USD to integer µUSD with half-away-from-zero rounding.
pub fn usd_to_micros(usd: f64) -> Option<i64> {
    if !usd.is_finite() || usd < 0.0 || usd > (i64::MAX as f64 / 1_000_000.0) {
        return None;
    }
    Some((usd * 1_000_000.0).round() as i64)
}

pub fn extract_string(attrs: &HashMap<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|&key| {
        attrs.get(key).and_then(|value| match value {
            Value::String(v) if !v.is_empty() => Some(v.clone()),
            Value::Number(v) => Some(v.to_string()),
            Value::Bool(v) => Some(v.to_string()),
            _ => None,
        })
    })
}

pub fn extract_i64(attrs: &HashMap<String, Value>, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|&key| {
        attrs.get(key).and_then(|value| match value {
            Value::Number(v) => v
                .as_i64()
                .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok())),
            Value::String(v) => v.parse::<i64>().ok(),
            _ => None,
        })
    })
}

pub fn extract_f64(attrs: &HashMap<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|&key| {
        attrs.get(key).and_then(|value| match value {
            Value::Number(v) => v.as_f64(),
            Value::String(v) => v.parse::<f64>().ok(),
            _ => None,
        })
    })
}

pub fn combine_token_total(
    prompt_tokens: Option<i64>,
    completion_tokens: Option<i64>,
) -> Option<i64> {
    match (prompt_tokens, completion_tokens) {
        (Some(prompt), Some(completion)) => prompt.checked_add(completion),
        (Some(prompt), None) => Some(prompt),
        (None, Some(completion)) => Some(completion),
        (None, None) => None,
    }
}
