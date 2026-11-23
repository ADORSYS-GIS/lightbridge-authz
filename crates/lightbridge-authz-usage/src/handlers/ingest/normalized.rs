//! Normalizer merge, extracted to keep ingest within its existing size ceiling.
use super::*;

pub struct MergedNorm {
    pub(super) model: Option<String>,
    pub(super) prompt_tokens: Option<i64>,
    pub(super) completion_tokens: Option<i64>,
    pub(super) total_tokens: Option<i64>,
    pub(super) cached_tokens: Option<i64>,
    pub(super) reasoning_tokens: Option<i64>,
    pub total_cost: Option<f64>,
    pub(super) latency_ms: Option<f64>,
}

/// # `total_cost` is MICRO-USD, from every branch, always (#745)
///
/// This function is the ONLY writer of `usage_events.total_cost`, and both of its branches must
/// agree on the unit. They did not, twice, and each time it was an incident:
///
/// * `norm.cost_micros` is micro-USD by its own name. It used to be divided by `1_000_000.0`
///   here, silently making the column dollars for normalizer-backed sources only.
/// * `extract_f64(attrs, &COST_KEYS)` is the gateway's `llm_custom_total_cost` CEL value, which
///   is micro-USD and is stored verbatim.
///
/// With one branch scaling and the other not, the column held two units distinguished only by
/// which writer produced the row, and `validate_total_cost_micros` on the budget side cannot tell
/// them apart — it sees one `f64`. #488 read the column as micro-USD, #737 read it as dollars,
/// and both were half right. Neither is recoverable by choosing a different constant on the
/// reading side: the fix is that there is only ever ONE unit written.
///
/// If a future normalizer reports cost in anything but micro-USD, convert it INSIDE that
/// normalizer, not here. `usage_events_total_cost_is_micro_usd_from_every_branch`
/// (`tests/normalizer_tests.rs`) fails if this branch starts scaling again.
pub fn apply_normalizer(
    normalizer: Option<crate::normalizer::NormalizerFn>,
    attrs: &HashMap<String, Value>,
    span_meta: &crate::normalizer::SpanMeta,
) -> MergedNorm {
    let norm = normalizer.map(|f| f(attrs, span_meta)).unwrap_or_default();

    let prompt_tokens = norm
        .prompt_tokens
        .or_else(|| extract_i64(attrs, &PROMPT_TOKENS_KEYS));
    let completion_tokens = norm
        .completion_tokens
        .or_else(|| extract_i64(attrs, &COMPLETION_TOKENS_KEYS));
    let total_tokens = norm
        .total_tokens
        .or_else(|| extract_i64(attrs, &TOTAL_TOKENS_KEYS))
        .or_else(|| crate::normalizer::combine_token_total(prompt_tokens, completion_tokens));

    let total_cost = norm
        .cost_micros
        .map(|c| c as f64)
        .or_else(|| extract_f64(attrs, &COST_KEYS));

    let model = norm.model.or_else(|| extract_string(attrs, &MODEL_KEYS));

    MergedNorm {
        model,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cached_tokens: extract_i64(attrs, &["gen_ai.usage.cache_read.input_tokens"]),
        reasoning_tokens: extract_i64(attrs, &["gen_ai.usage.reasoning.output_tokens"]),
        total_cost,
        latency_ms: norm.latency_ms,
    }
}
