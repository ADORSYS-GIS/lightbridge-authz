//! The execution-grain receiver's normalizer (#588, AC2): parses OTLP trace spans into
//! `usage_executions` / `usage_model_calls` / `usage_tool_calls` rows (plus `usage_identities`),
//! minting a STUB execution for a child whose parent is not in the same batch (stub-before-parent).

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Error, Result};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;

use crate::handlers::payload_identity::check_identity_mismatch;
use crate::models::execution_ingest::{
    ExecutionGrainBatch, ExecutionRecord, ModelCallRecord, ToolCallRecord, execution_id,
};
use crate::normalizer::{REGISTRY, SpanMeta, extract_string};
/// The sources whose OTLP traces are execution-grain (ADR-0027): the agent tools. The gateway
/// (`eaig`) stays request-grain; `github-copilot` is day-grain (RFC-0001).
pub const EXECUTION_GRAIN_SOURCES: [&str; 4] =
    ["claude-code", "codex", "opencode", "microsoft-foundry"];

/// Whether a source's traces belong to the execution grain.
pub fn is_execution_grain_source(source: &str) -> bool {
    EXECUTION_GRAIN_SOURCES.contains(&source)
}

/// Attribute names carrying the provider-scoped user id (AC3 — preserved verbatim, no shape
/// validation). Mirrors the request-grain `USER_KEYS` in `handlers::ingest`.
const PROVIDER_USER_KEYS: [&str; 6] = [
    "user_id",
    "user.id",
    "end_user.id",
    "lc_user_id",
    "x-user-id",
    "authz.user_id",
];

const PROVIDER_KEYS: [&str; 3] = ["provider", "gen_ai.provider.name", "gen_ai.provider"];
const RAW_BACKEND_KEYS: [&str; 2] = ["raw_backend", "backend"];

/// Parse an OTLP trace export into an execution-grain batch (real + stub executions, model
/// calls, tool calls).
pub fn parse_execution_grain(
    payload: ExportTraceServiceRequest,
    source: &str,
) -> Result<ExecutionGrainBatch> {
    let normalizer = REGISTRY.get(source);
    let mut executions = Vec::new();
    let mut model_calls = Vec::new();
    let mut tool_calls = Vec::new();
    let mut real_execution_ids = HashSet::new();
    let mut stubs: HashMap<String, ExecutionRecord> = HashMap::new();

    for resource_spans in payload.resource_spans {
        let resource_attrs = resource_spans
            .resource
            .map(|r| crate::handlers::ingest::key_values_to_map(&r.attributes))
            .unwrap_or_default();
        for scope_spans in resource_spans.scope_spans {
            for span in scope_spans.spans {
                let attrs = crate::handlers::ingest::merge_attr_maps(
                    &resource_attrs,
                    &crate::handlers::ingest::key_values_to_map(&span.attributes),
                );
                check_identity_mismatch(&attrs, source);
                let trace_id = hex::encode(&span.trace_id);
                let span_id = hex::encode(&span.span_id);
                let parent_span_id = hex::encode(&span.parent_span_id);
                let span_meta = SpanMeta {
                    trace_id: Some(trace_id.clone()),
                    span_id: Some(span_id.clone()),
                    start_time_unix_nano: span.start_time_unix_nano,
                    end_time_unix_nano: span.end_time_unix_nano,
                    name: span.name.clone(),
                };
                let norm = normalizer
                    .map(|f| f(&attrs, &span_meta))
                    .unwrap_or_default();
                let observed_at = nanos_to_datetime(if span.end_time_unix_nano > 0 {
                    span.end_time_unix_nano
                } else {
                    span.start_time_unix_nano
                })?;
                let duration_ms =
                    span_duration_ms(span.start_time_unix_nano, span.end_time_unix_nano)
                        .or(norm.latency_ms.map(|v| v as i64));

                if let Some(tool_name) = norm.tool_name {
                    if parent_span_id.is_empty() {
                        return Err(Error::BadRequest(format!(
                            "tool-call span {trace_id}/{span_id} has no parent execution"
                        )));
                    }
                    let duration_ms = duration_ms.ok_or_else(|| {
                        Error::BadRequest(format!(
                            "tool-call span {trace_id}/{span_id} has no duration"
                        ))
                    })?;
                    let parent_id = execution_id(source, &trace_id, &parent_span_id);
                    stubs.entry(parent_id.clone()).or_insert_with(|| {
                        stub_execution(source, &trace_id, &parent_span_id, observed_at)
                    });
                    tool_calls.push(ToolCallRecord {
                        source: source.to_string(),
                        trace_id: trace_id.clone(),
                        span_id: span_id.clone(),
                        execution_id: parent_id,
                        observed_at,
                        tool_name,
                        duration_ms,
                    });
                } else if let Some(model) = norm.model {
                    if parent_span_id.is_empty() {
                        return Err(Error::BadRequest(format!(
                            "model-call span {trace_id}/{span_id} has no parent execution"
                        )));
                    }
                    let parent_id = execution_id(source, &trace_id, &parent_span_id);
                    stubs.entry(parent_id.clone()).or_insert_with(|| {
                        stub_execution(source, &trace_id, &parent_span_id, observed_at)
                    });
                    model_calls.push(ModelCallRecord {
                        source: source.to_string(),
                        trace_id: trace_id.clone(),
                        span_id: span_id.clone(),
                        execution_id: parent_id,
                        observed_at,
                        model,
                        input_tokens: norm.prompt_tokens,
                        output_tokens: norm.completion_tokens,
                        cost_micro_usd: norm.cost_micros,
                    });
                } else {
                    let id = execution_id(source, &trace_id, &span_id);
                    real_execution_ids.insert(id);
                    executions.push(ExecutionRecord {
                        source: source.to_string(),
                        trace_id: trace_id.clone(),
                        span_id: span_id.clone(),
                        observed_at,
                        provider: extract_string(&attrs, &PROVIDER_KEYS),
                        provider_user_id: extract_string(&attrs, &PROVIDER_USER_KEYS),
                        duration_ms,
                        estimated_cost_micro_usd: norm.cost_micros,
                        raw_backend: extract_string(&attrs, &RAW_BACKEND_KEYS),
                        raw_schema_version: None,
                    });
                }
            }
        }
    }

    for (id, stub) in stubs {
        if !real_execution_ids.contains(&id) {
            executions.push(stub);
        }
    }

    Ok(ExecutionGrainBatch {
        executions,
        model_calls,
        tool_calls,
    })
}

fn stub_execution(
    source: &str,
    trace_id: &str,
    span_id: &str,
    observed_at: DateTime<Utc>,
) -> ExecutionRecord {
    ExecutionRecord {
        source: source.to_string(),
        trace_id: trace_id.to_string(),
        span_id: span_id.to_string(),
        observed_at,
        provider: None,
        provider_user_id: None,
        duration_ms: None,
        estimated_cost_micro_usd: None,
        raw_backend: None,
        raw_schema_version: None,
    }
}

fn nanos_to_datetime(nanos: u64) -> Result<DateTime<Utc>> {
    if nanos == 0 {
        return Err(Error::BadRequest("span has no timestamp".into()));
    }
    let secs = (nanos / 1_000_000_000) as i64;
    let sub_nanos = (nanos % 1_000_000_000) as u32;
    DateTime::from_timestamp(secs, sub_nanos)
        .ok_or_else(|| Error::BadRequest("span timestamp out of range".into()))
}

fn span_duration_ms(start_time_unix_nano: u64, end_time_unix_nano: u64) -> Option<i64> {
    if start_time_unix_nano == 0 || end_time_unix_nano < start_time_unix_nano {
        return None;
    }
    Some(((end_time_unix_nano - start_time_unix_nano) / 1_000_000) as i64)
}
