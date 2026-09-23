//! Wire types for the execution-grain ingest (#588, AC2): the normalized rows the
//! execution-grain receiver produces from OTLP trace spans, and the repo upserts into
//! `usage_executions` / `usage_model_calls` / `usage_tool_calls` (plus `usage_identities`).
//!
//! These are the ingest-side counterparts to the query-side types in [`super::execution`].
//! The column shapes mirror the migrations in `migrations-usage/2026090700000{1,2,3,4}_*.sql`
//! (ADR-0027/0028, #582): `source` is the origin dimension, ids are derived from
//! `source` + `trace_id` + `span_id`, and `NULL` means *unknown, never zero*.

use chrono::{DateTime, Utc};

/// One normalized `usage_executions` row — either a real execution span or a stub minted on
/// first sight of a child (see the `20260907000002_usage_executions.sql` header for the
/// stub-before-parent contract).
#[derive(Debug, Clone)]
pub struct ExecutionRecord {
    pub source: String,
    pub trace_id: String,
    pub span_id: String,
    pub observed_at: DateTime<Utc>,
    /// `None` for a stub (a tool-call-first stub has no model provider to set).
    pub provider: Option<String>,
    /// The provider-scoped user id, preserved verbatim (AC3 — no shape validation). The repo
    /// mints a `usage_identities` row for it and resolves `identity_id`; `None` for a stub.
    pub provider_user_id: Option<String>,
    /// `None` for a stub (the real execution span fills it via the upsert).
    pub duration_ms: Option<i64>,
    /// `None` = cost unknown (never a zero a dashboard would read as "free").
    pub estimated_cost_micro_usd: Option<i64>,
    pub raw_backend: Option<String>,
    /// `None` for a stub (the real execution span fills it).
    pub raw_schema_version: Option<i64>,
}

/// One normalized `usage_model_calls` row. `span_id` is the model call's OWN span, not the
/// parent execution's; `execution_id` is the derived parent id.
#[derive(Debug, Clone)]
pub struct ModelCallRecord {
    pub source: String,
    pub trace_id: String,
    pub span_id: String,
    pub execution_id: String,
    pub observed_at: DateTime<Utc>,
    pub model: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cost_micro_usd: Option<i64>,
}

/// One normalized `usage_tool_calls` row. `span_id` is the tool call's OWN span;
/// `execution_id` is the derived parent id. `duration_ms` is `NOT NULL` in the schema.
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    pub source: String,
    pub trace_id: String,
    pub span_id: String,
    pub execution_id: String,
    pub observed_at: DateTime<Utc>,
    pub tool_name: String,
    pub duration_ms: i64,
}

/// The full set of rows one OTLP trace export normalizes to. `executions` already includes any
/// stubs the normalizer minted for children whose parent execution is not in the same batch.
#[derive(Debug, Clone)]
pub struct ExecutionGrainBatch {
    pub executions: Vec<ExecutionRecord>,
    pub model_calls: Vec<ModelCallRecord>,
    pub tool_calls: Vec<ToolCallRecord>,
}

/// The derived `usage_executions.id` — `exec_{source}_{trace_id}_{span_id}` (see the
/// `20260907000002_usage_executions.sql` header for why the `_` separator is unambiguous).
pub(crate) fn execution_id(source: &str, trace_id: &str, span_id: &str) -> String {
    format!("exec_{source}_{trace_id}_{span_id}")
}

/// The derived `usage_model_calls.id` — `{source}_{trace_id}_{span_id}:mc`.
pub(crate) fn model_call_id(source: &str, trace_id: &str, span_id: &str) -> String {
    format!("{source}_{trace_id}_{span_id}:mc")
}

/// The derived `usage_tool_calls.id` — `{source}_{trace_id}_{span_id}:tc`.
pub(crate) fn tool_call_id(source: &str, trace_id: &str, span_id: &str) -> String {
    format!("{source}_{trace_id}_{span_id}:tc")
}
