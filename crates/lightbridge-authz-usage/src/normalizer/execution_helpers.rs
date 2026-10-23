//! Span helpers for the execution-grain normalizer (stub executions, timestamps). Moved verbatim out of
//! `execution_grain.rs` to satisfy the LoC gate (lightbridge-governance#172) when #769 added the
//! verified-source policy; behaviour unchanged.

use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Error, Result};

use crate::models::execution_ingest::ExecutionRecord;

pub(super) fn nanos_to_datetime(nanos: u64) -> Result<DateTime<Utc>> {
    if nanos == 0 {
        return Err(Error::BadRequest("span has no timestamp".into()));
    }
    let secs = (nanos / 1_000_000_000) as i64;
    let sub_nanos = (nanos % 1_000_000_000) as u32;
    DateTime::from_timestamp(secs, sub_nanos)
        .ok_or_else(|| Error::BadRequest("span timestamp out of range".into()))
}

pub(super) fn span_duration_ms(start_time_unix_nano: u64, end_time_unix_nano: u64) -> Option<i64> {
    if start_time_unix_nano == 0 || end_time_unix_nano < start_time_unix_nano {
        return None;
    }
    Some(((end_time_unix_nano - start_time_unix_nano) / 1_000_000) as i64)
}

pub(super) fn stub_execution(
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
