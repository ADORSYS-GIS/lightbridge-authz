use crate::UsageState;
use crate::models::IngestResponse;
use crate::repo::UsageEvent;
use axum::http::header::CONTENT_ENCODING;
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Error, Result};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::metrics::v1::{
    ExponentialHistogramDataPoint, HistogramDataPoint, NumberDataPoint, SummaryDataPoint,
    metric::Data, number_data_point,
};
use prost::Message;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use tracing::{info, instrument, warn};

const ACCOUNT_KEYS: [&str; 5] = [
    "account_id",
    "account.id",
    "x-account-id",
    "authz.account_id",
    "lb.account_id",
];
const PROJECT_KEYS: [&str; 5] = [
    "project_id",
    "project.id",
    "x-project-id",
    "authz.project_id",
    "lb.project_id",
];
const API_KEY_KEYS: [&str; 5] = [
    "api_key_id",
    "api_key.id",
    "x-api-key-id",
    "authz.api_key_id",
    "lb.api_key_id",
];
const USER_KEYS: [&str; 6] = [
    "user_id",
    "user.id",
    "end_user.id",
    "lc_user_id",
    "x-user-id",
    "authz.user_id",
];
const USER_NAME_KEYS: [&str; 6] = [
    "user_name",
    "user.name",
    "end_user.name",
    "lc_user_name",
    "x-user-name",
    "authz.user_name",
];
const MODEL_KEYS: [&str; 5] = [
    "model",
    "llm.model",
    "ai.model",
    "gen_ai.request.model",
    "genai.request.model",
];
const PROMPT_TOKENS_KEYS: [&str; 6] = [
    "prompt_tokens",
    "input_tokens",
    "usage.prompt_tokens",
    "gen_ai.usage.prompt_tokens",
    "genai.usage.prompt_tokens",
    "gen_ai.usage.input_tokens",
];
const COMPLETION_TOKENS_KEYS: [&str; 6] = [
    "completion_tokens",
    "output_tokens",
    "usage.completion_tokens",
    "gen_ai.usage.completion_tokens",
    "genai.usage.completion_tokens",
    "gen_ai.usage.output_tokens",
];
const TOTAL_TOKENS_KEYS: [&str; 5] = [
    "total_tokens",
    "usage.total_tokens",
    "tokens",
    "gen_ai.usage.total_tokens",
    "genai.usage.total_tokens",
];
const USAGE_VALUE_KEYS: [&str; 3] = ["usage_value", "usage", "gen_ai.usage.total_tokens"];
const COST_KEYS: [&str; 4] = [
    "io.envoy.ai_gateway.llm_custom_total_cost",
    "custom_total_cost",
    "cost",
    "gen_ai.usage.custom_total_cost",
];

#[utoipa::path(
    post,
    path = "/v1/otel/traces",
    request_body(content = String, content_type = "application/x-protobuf" ),
    responses(
        (status = 202, body = IngestResponse),
        (status = 400)
    ),
    tag = "ingest"
)]
#[instrument(skip(state, headers))]
pub async fn ingest_traces(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<IngestResponse>)> {
    let payload = decode_trace_request(&headers, &body)?;
    let events = extract_trace_events(payload);
    let accepted_events = persist_events(&state, "trace", &events).await?;

    info!("accepted {} trace events", accepted_events);

    Ok((
        StatusCode::ACCEPTED,
        Json(IngestResponse { accepted_events }),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/otel/metrics",
    request_body(content = String, content_type = "application/x-protobuf"),
    responses(
        (status = 202, body = IngestResponse),
        (status = 400)
    ),
    tag = "ingest"
)]
#[instrument(skip(state, headers))]
pub async fn ingest_metrics(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<IngestResponse>)> {
    let payload = decode_metrics_request(&headers, &body)?;
    let events = extract_metric_events(payload);
    let accepted_events = persist_events(&state, "metric", &events).await?;

    info!("accepted {} metric events", accepted_events);

    Ok((
        StatusCode::ACCEPTED,
        Json(IngestResponse { accepted_events }),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/otel/logs",
    request_body(content = String, content_type = "application/x-protobuf"),
    responses(
        (status = 202, body = IngestResponse),
        (status = 400)
    ),
    tag = "ingest"
)]
#[instrument(skip(state, headers))]
pub async fn ingest_logs(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<IngestResponse>)> {
    let payload = decode_logs_request(&headers, &body)?;
    let events = extract_log_events(payload);
    let accepted_events = persist_events(&state, "log", &events).await?;

    info!("accepted {} log events", accepted_events);

    Ok((
        StatusCode::ACCEPTED,
        Json(IngestResponse { accepted_events }),
    ))
}

fn decode_logs_request(headers: &HeaderMap, body: &[u8]) -> Result<ExportLogsServiceRequest> {
    let body = decode_maybe_gzip(headers, body)?;
    if is_json_content(headers) {
        serde_json::from_slice(&body).map_err(|e| {
            warn!("invalid OTLP logs JSON payload: {e}");
            Error::BadRequest(format!("invalid OTLP logs JSON payload: {e}"))
        })
    } else {
        ExportLogsServiceRequest::decode(body.as_slice()).map_err(|e| {
            warn!("invalid OTLP logs protobuf payload: {e}");
            Error::BadRequest(format!("invalid OTLP logs protobuf payload: {e}"))
        })
    }
}

fn decode_maybe_gzip(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>> {
    let encoding = headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let is_gzip = encoding
        .split(',')
        .any(|e| e.trim().eq_ignore_ascii_case("gzip"));

    if !is_gzip {
        return Ok(body.to_vec());
    }

    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| {
        warn!("invalid gzip body: {e}");
        Error::BadRequest(format!("invalid gzip body: {e}"))
    })?;
    Ok(out)
}

async fn persist_events(
    state: &UsageState,
    signal_type: &str,
    events: &[UsageEvent],
) -> Result<usize> {
    validate_events(events)?;
    let persisted_events = state.repo.insert_usage_events(events).await?;

    if persisted_events < events.len() {
        warn!(
            "usage {signal_type} insert persisted {} of {} decoded events; treating remaining events as accepted",
            persisted_events,
            events.len()
        );
        Ok(events.len())
    } else {
        Ok(persisted_events)
    }
}

fn validate_events(events: &[UsageEvent]) -> Result<()> {
    for event in events {
        if event.signal_type.trim().is_empty() {
            return Err(Error::BadRequest("signal_type is required".to_string()));
        }

        if !event.usage_value.is_finite() {
            return Err(Error::BadRequest("usage_value must be finite".to_string()));
        }

        if event.total_cost.is_some_and(|value| !value.is_finite()) {
            return Err(Error::BadRequest("total_cost must be finite".to_string()));
        }

        if event.request_count < 0 {
            return Err(Error::BadRequest(
                "request_count cannot be negative".to_string(),
            ));
        }

        if [
            event.prompt_tokens,
            event.completion_tokens,
            event.total_tokens,
        ]
        .into_iter()
        .flatten()
        .any(|value| value < 0)
        {
            return Err(Error::BadRequest(
                "token counts cannot be negative".to_string(),
            ));
        }
    }

    Ok(())
}

fn extract_log_events(payload: ExportLogsServiceRequest) -> Vec<UsageEvent> {
    let mut events = Vec::new();

    for resource_logs in payload.resource_logs {
        let resource_attrs = resource_logs
            .resource
            .map(|resource| key_values_to_map(&resource.attributes))
            .unwrap_or_default();

        for scope_logs in resource_logs.scope_logs {
            for log_record in scope_logs.log_records {
                let attrs =
                    merge_attr_maps(&resource_attrs, &key_values_to_map(&log_record.attributes));

                let observed_nanos = if log_record.time_unix_nano > 0 {
                    log_record.time_unix_nano
                } else if log_record.observed_time_unix_nano > 0 {
                    log_record.observed_time_unix_nano
                } else {
                    0
                };

                let prompt_tokens = extract_i64(&attrs, &PROMPT_TOKENS_KEYS);
                let completion_tokens = extract_i64(&attrs, &COMPLETION_TOKENS_KEYS);
                let total_tokens = extract_i64(&attrs, &TOTAL_TOKENS_KEYS)
                    .or_else(|| combine_token_total(prompt_tokens, completion_tokens));

                let usage_value = extract_f64(&attrs, &USAGE_VALUE_KEYS)
                    .or_else(|| total_tokens.map(|v| v as f64))
                    .unwrap_or(1.0);

                let total_cost = extract_f64(&attrs, &COST_KEYS);

                events.push(UsageEvent {
                    observed_at: nanos_to_datetime(observed_nanos),
                    signal_type: "log".to_string(),
                    account_id: extract_string(&attrs, &ACCOUNT_KEYS),
                    project_id: extract_string(&attrs, &PROJECT_KEYS),
                    api_key_id: extract_string(&attrs, &API_KEY_KEYS),
                    user_id: extract_string(&attrs, &USER_KEYS),
                    user_name: extract_string(&attrs, &USER_NAME_KEYS),
                    model: extract_string(&attrs, &MODEL_KEYS),
                    metric_name: non_empty(Some(log_record.severity_text)),
                    usage_value,
                    request_count: 1,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    total_cost,
                    attributes: Value::Object(attrs.into_iter().collect()),
                });
            }
        }
    }

    events
}

fn decode_trace_request(headers: &HeaderMap, body: &[u8]) -> Result<ExportTraceServiceRequest> {
    if is_json_content(headers) {
        serde_json::from_slice(body).map_err(|e| {
            warn!("invalid OTLP trace JSON payload: {e}");
            Error::BadRequest(format!("invalid OTLP trace JSON payload: {e}"))
        })
    } else {
        ExportTraceServiceRequest::decode(body).map_err(|e| {
            warn!("invalid OTLP trace protobuf payload: {e}");
            Error::BadRequest(format!("invalid OTLP trace protobuf payload: {e}"))
        })
    }
}

fn decode_metrics_request(headers: &HeaderMap, body: &[u8]) -> Result<ExportMetricsServiceRequest> {
    if is_json_content(headers) {
        serde_json::from_slice(body).map_err(|e| {
            warn!("invalid OTLP metrics JSON payload: {e}");
            Error::BadRequest(format!("invalid OTLP metrics JSON payload: {e}"))
        })
    } else {
        ExportMetricsServiceRequest::decode(body).map_err(|e| {
            warn!("invalid OTLP metrics protobuf payload: {e}");
            Error::BadRequest(format!("invalid OTLP metrics protobuf payload: {e}"))
        })
    }
}

fn is_json_content(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| value.contains("json"))
}

fn extract_trace_events(payload: ExportTraceServiceRequest) -> Vec<UsageEvent> {
    let mut events = Vec::new();

    for resource_spans in payload.resource_spans {
        let resource_attrs = resource_spans
            .resource
            .map(|resource| key_values_to_map(&resource.attributes))
            .unwrap_or_default();

        for scope_spans in resource_spans.scope_spans {
            for span in scope_spans.spans {
                let attrs = merge_attr_maps(&resource_attrs, &key_values_to_map(&span.attributes));

                let prompt_tokens = extract_i64(&attrs, &PROMPT_TOKENS_KEYS);
                let completion_tokens = extract_i64(&attrs, &COMPLETION_TOKENS_KEYS);
                let total_tokens = extract_i64(&attrs, &TOTAL_TOKENS_KEYS)
                    .or_else(|| combine_token_total(prompt_tokens, completion_tokens));

                let usage_value = extract_f64(&attrs, &USAGE_VALUE_KEYS)
                    .or_else(|| total_tokens.map(|v| v as f64))
                    .unwrap_or(1.0);

                let total_cost = extract_f64(&attrs, &COST_KEYS);

                let observed_nanos = if span.end_time_unix_nano > 0 {
                    span.end_time_unix_nano
                } else {
                    span.start_time_unix_nano
                };

                events.push(UsageEvent {
                    observed_at: nanos_to_datetime(observed_nanos),
                    signal_type: "trace".to_string(),
                    account_id: extract_string(&attrs, &ACCOUNT_KEYS),
                    project_id: extract_string(&attrs, &PROJECT_KEYS),
                    api_key_id: extract_string(&attrs, &API_KEY_KEYS),
                    user_id: extract_string(&attrs, &USER_KEYS),
                    user_name: extract_string(&attrs, &USER_NAME_KEYS),
                    model: extract_string(&attrs, &MODEL_KEYS),
                    metric_name: non_empty(Some(span.name)),
                    usage_value,
                    total_cost,
                    request_count: 1,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    attributes: Value::Object(attrs.into_iter().collect()),
                });
            }
        }
    }

    events
}

fn extract_metric_events(payload: ExportMetricsServiceRequest) -> Vec<UsageEvent> {
    let mut events = Vec::new();

    for resource_metrics in payload.resource_metrics {
        let resource_attrs = resource_metrics
            .resource
            .map(|resource| key_values_to_map(&resource.attributes))
            .unwrap_or_default();

        for scope_metrics in resource_metrics.scope_metrics {
            for metric in scope_metrics.metrics {
                let metric_name = non_empty(Some(metric.name.clone()));
                let metric_attrs =
                    merge_attr_maps(&resource_attrs, &key_values_to_map(&metric.metadata));

                if let Some(data) = metric.data {
                    match data {
                        Data::Gauge(gauge) => {
                            for point in gauge.data_points {
                                events.push(number_data_point_to_event(
                                    &metric_attrs,
                                    metric_name.clone(),
                                    point,
                                ));
                            }
                        }
                        Data::Sum(sum) => {
                            for point in sum.data_points {
                                events.push(number_data_point_to_event(
                                    &metric_attrs,
                                    metric_name.clone(),
                                    point,
                                ));
                            }
                        }
                        Data::Histogram(histogram) => {
                            for point in histogram.data_points {
                                events.push(histogram_data_point_to_event(
                                    &metric_attrs,
                                    metric_name.clone(),
                                    point,
                                ));
                            }
                        }
                        Data::ExponentialHistogram(exp_histogram) => {
                            for point in exp_histogram.data_points {
                                events.push(exponential_histogram_data_point_to_event(
                                    &metric_attrs,
                                    metric_name.clone(),
                                    point,
                                ));
                            }
                        }
                        Data::Summary(summary) => {
                            for point in summary.data_points {
                                events.push(summary_data_point_to_event(
                                    &metric_attrs,
                                    metric_name.clone(),
                                    point,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    events
}

fn number_data_point_to_event(
    metric_attrs: &HashMap<String, Value>,
    metric_name: Option<String>,
    point: NumberDataPoint,
) -> UsageEvent {
    let attrs = merge_attr_maps(metric_attrs, &key_values_to_map(&point.attributes));

    let value = match point.value {
        Some(number_data_point::Value::AsDouble(v)) => v,
        Some(number_data_point::Value::AsInt(v)) => v as f64,
        None => 0.0,
    };

    let total_cost = extract_f64(&attrs, &COST_KEYS);
    let prompt_tokens = extract_i64(&attrs, &PROMPT_TOKENS_KEYS);
    let completion_tokens = extract_i64(&attrs, &COMPLETION_TOKENS_KEYS);
    let total_tokens = extract_i64(&attrs, &TOTAL_TOKENS_KEYS)
        .or_else(|| combine_token_total(prompt_tokens, completion_tokens));

    UsageEvent {
        observed_at: nanos_to_datetime(point.time_unix_nano),
        signal_type: "metric".to_string(),
        account_id: extract_string(&attrs, &ACCOUNT_KEYS),
        project_id: extract_string(&attrs, &PROJECT_KEYS),
        api_key_id: extract_string(&attrs, &API_KEY_KEYS),
        user_id: extract_string(&attrs, &USER_KEYS),
        user_name: extract_string(&attrs, &USER_NAME_KEYS),
        model: extract_string(&attrs, &MODEL_KEYS),
        metric_name,
        usage_value: value,
        request_count: request_count_from_metric_value(value),
        prompt_tokens,
        completion_tokens,
        total_tokens,
        total_cost,
        attributes: Value::Object(attrs.into_iter().collect()),
    }
}

fn histogram_data_point_to_event(
    metric_attrs: &HashMap<String, Value>,
    metric_name: Option<String>,
    point: HistogramDataPoint,
) -> UsageEvent {
    let attrs = merge_attr_maps(metric_attrs, &key_values_to_map(&point.attributes));
    let count = u64_to_i64(point.count);
    let usage_value = point.sum.unwrap_or(count as f64);
    let total_cost = extract_f64(&attrs, &COST_KEYS);

    UsageEvent {
        observed_at: nanos_to_datetime(point.time_unix_nano),
        signal_type: "metric".to_string(),
        account_id: extract_string(&attrs, &ACCOUNT_KEYS),
        project_id: extract_string(&attrs, &PROJECT_KEYS),
        api_key_id: extract_string(&attrs, &API_KEY_KEYS),
        user_id: extract_string(&attrs, &USER_KEYS),
        user_name: extract_string(&attrs, &USER_NAME_KEYS),
        model: extract_string(&attrs, &MODEL_KEYS),
        metric_name,
        usage_value,
        total_cost,
        request_count: count.max(1),
        prompt_tokens: extract_i64(&attrs, &PROMPT_TOKENS_KEYS),
        completion_tokens: extract_i64(&attrs, &COMPLETION_TOKENS_KEYS),
        total_tokens: extract_i64(&attrs, &TOTAL_TOKENS_KEYS),
        attributes: Value::Object(attrs.into_iter().collect()),
    }
}

fn exponential_histogram_data_point_to_event(
    metric_attrs: &HashMap<String, Value>,
    metric_name: Option<String>,
    point: ExponentialHistogramDataPoint,
) -> UsageEvent {
    let attrs = merge_attr_maps(metric_attrs, &key_values_to_map(&point.attributes));
    let count = u64_to_i64(point.count);
    let usage_value = point.sum.unwrap_or(count as f64);
    let total_cost = extract_f64(&attrs, &COST_KEYS);

    UsageEvent {
        observed_at: nanos_to_datetime(point.time_unix_nano),
        signal_type: "metric".to_string(),
        account_id: extract_string(&attrs, &ACCOUNT_KEYS),
        project_id: extract_string(&attrs, &PROJECT_KEYS),
        api_key_id: extract_string(&attrs, &API_KEY_KEYS),
        user_id: extract_string(&attrs, &USER_KEYS),
        user_name: extract_string(&attrs, &USER_NAME_KEYS),
        model: extract_string(&attrs, &MODEL_KEYS),
        metric_name,
        usage_value,
        total_cost,
        request_count: count.max(1),
        prompt_tokens: extract_i64(&attrs, &PROMPT_TOKENS_KEYS),
        completion_tokens: extract_i64(&attrs, &COMPLETION_TOKENS_KEYS),
        total_tokens: extract_i64(&attrs, &TOTAL_TOKENS_KEYS),
        attributes: Value::Object(attrs.into_iter().collect()),
    }
}

fn summary_data_point_to_event(
    metric_attrs: &HashMap<String, Value>,
    metric_name: Option<String>,
    point: SummaryDataPoint,
) -> UsageEvent {
    let attrs = merge_attr_maps(metric_attrs, &key_values_to_map(&point.attributes));
    let count = u64_to_i64(point.count);
    let total_cost = extract_f64(&attrs, &COST_KEYS);

    UsageEvent {
        observed_at: nanos_to_datetime(point.time_unix_nano),
        signal_type: "metric".to_string(),
        account_id: extract_string(&attrs, &ACCOUNT_KEYS),
        project_id: extract_string(&attrs, &PROJECT_KEYS),
        api_key_id: extract_string(&attrs, &API_KEY_KEYS),
        user_id: extract_string(&attrs, &USER_KEYS),
        user_name: extract_string(&attrs, &USER_NAME_KEYS),
        model: extract_string(&attrs, &MODEL_KEYS),
        metric_name,
        total_cost,
        usage_value: point.sum,
        request_count: count.max(1),
        prompt_tokens: extract_i64(&attrs, &PROMPT_TOKENS_KEYS),
        completion_tokens: extract_i64(&attrs, &COMPLETION_TOKENS_KEYS),
        total_tokens: extract_i64(&attrs, &TOTAL_TOKENS_KEYS),
        attributes: Value::Object(attrs.into_iter().collect()),
    }
}

fn combine_token_total(prompt_tokens: Option<i64>, completion_tokens: Option<i64>) -> Option<i64> {
    match (prompt_tokens, completion_tokens) {
        (Some(prompt), Some(completion)) => prompt.checked_add(completion),
        (Some(prompt), None) => Some(prompt),
        (None, Some(completion)) => Some(completion),
        (None, None) => None,
    }
}

fn request_count_from_metric_value(value: f64) -> i64 {
    if value.is_finite() && value >= 1.0 {
        let rounded = value.round();
        if rounded > i64::MAX as f64 {
            i64::MAX
        } else {
            rounded as i64
        }
    } else {
        1
    }
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn nanos_to_datetime(nanos: u64) -> DateTime<Utc> {
    if nanos == 0 {
        return Utc::now();
    }

    let secs = (nanos / 1_000_000_000) as i64;
    let sub_nanos = (nanos % 1_000_000_000) as u32;

    DateTime::from_timestamp(secs, sub_nanos).unwrap_or_else(Utc::now)
}

fn key_values_to_map(values: &[KeyValue]) -> HashMap<String, Value> {
    let mut map = HashMap::new();
    for kv in values {
        let value = kv
            .value
            .as_ref()
            .map(any_value_to_json)
            .unwrap_or(Value::Null);
        map.insert(kv.key.clone(), value);
    }
    map
}

fn merge_attr_maps(
    base: &HashMap<String, Value>,
    additional: &HashMap<String, Value>,
) -> HashMap<String, Value> {
    let mut merged = base.clone();
    for (key, value) in additional {
        merged.insert(key.clone(), value.clone());
    }
    merged
}

fn any_value_to_json(any: &AnyValue) -> Value {
    match &any.value {
        Some(any_value::Value::StringValue(v)) => Value::String(v.clone()),
        Some(any_value::Value::BoolValue(v)) => Value::Bool(*v),
        Some(any_value::Value::IntValue(v)) => json!(*v),
        Some(any_value::Value::DoubleValue(v)) => json!(*v),
        Some(any_value::Value::ArrayValue(v)) => {
            Value::Array(v.values.iter().map(any_value_to_json).collect())
        }
        Some(any_value::Value::KvlistValue(v)) => {
            let mut object = Map::new();
            for entry in &v.values {
                let value = entry
                    .value
                    .as_ref()
                    .map(any_value_to_json)
                    .unwrap_or(Value::Null);
                object.insert(entry.key.clone(), value);
            }
            Value::Object(object)
        }
        Some(any_value::Value::BytesValue(v)) => Value::String(hex::encode(v)),
        Some(any_value::Value::StringValueStrindex(_)) => Value::Null,
        None => Value::Null,
    }
}

fn extract_string(attrs: &HashMap<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        attrs.get(*key).and_then(|value| match value {
            Value::String(v) if !v.is_empty() => Some(v.clone()),
            Value::Number(v) => Some(v.to_string()),
            Value::Bool(v) => Some(v.to_string()),
            _ => None,
        })
    })
}

fn extract_i64(attrs: &HashMap<String, Value>, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        attrs.get(*key).and_then(|value| match value {
            Value::Number(v) => v
                .as_i64()
                .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok())),
            Value::String(v) => v.parse::<i64>().ok(),
            _ => None,
        })
    })
}

fn extract_f64(attrs: &HashMap<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        attrs.get(*key).and_then(|value| match value {
            Value::Number(v) => v.as_f64(),
            Value::String(v) => v.parse::<f64>().ok(),
            _ => None,
        })
    })
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_trace_events_should_capture_dimensions_and_tokens() {
        let payload: ExportTraceServiceRequest = serde_json::from_value(json!({
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "account_id", "value": {"stringValue": "acct_1"}},
                            {"key": "project_id", "value": {"stringValue": "proj_1"}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "00000000000000000000000000000001",
                                    "spanId": "0000000000000001",
                                    "name": "chat.completion",
                                    "startTimeUnixNano": "1735689600000000000",
                                    "endTimeUnixNano": "1735689601000000000",
                                    "attributes": [
                                        {"key": "api_key_id", "value": {"stringValue": "key_1"}},
                                        {"key": "lc_user_id", "value": {"stringValue": "user_1"}},
                                        {"key": "lc_user_name", "value": {"stringValue": "Ada Lovelace"}},
                                        {"key": "model", "value": {"stringValue": "gpt-4.1"}},
                                        {"key": "gen_ai.usage.prompt_tokens", "value": {"intValue": "10"}},
                                        {"key": "gen_ai.usage.completion_tokens", "value": {"intValue": "5"}}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }))
        .expect("valid trace payload");

        let events = extract_trace_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.account_id.as_deref(), Some("acct_1"));
        assert_eq!(event.project_id.as_deref(), Some("proj_1"));
        assert_eq!(event.api_key_id.as_deref(), Some("key_1"));
        assert_eq!(event.user_id.as_deref(), Some("user_1"));
        assert_eq!(event.user_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(event.model.as_deref(), Some("gpt-4.1"));
        assert_eq!(event.prompt_tokens, Some(10));
        assert_eq!(event.completion_tokens, Some(5));
        assert_eq!(event.total_tokens, Some(15));
        assert_eq!(event.usage_value, 15.0);
        assert_eq!(event.request_count, 1);
    }

    #[test]
    fn extract_metric_events_should_capture_number_data_points() {
        use opentelemetry_proto::tonic::common::v1::InstrumentationScope;
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueValue;
        use opentelemetry_proto::tonic::metrics::v1::{
            AggregationTemporality, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
            metric,
        };
        use opentelemetry_proto::tonic::resource::v1::Resource;

        let payload = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "account_id".to_string(),
                        value: Some(AnyValue {
                            value: Some(AnyValueValue::StringValue("acct_1".to_string())),
                        }),
                        key_strindex: 0,
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        name: "tests".to_string(),
                        version: "1.0".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    }),
                    metrics: vec![Metric {
                        name: "gen_ai.usage.total_tokens".to_string(),
                        description: String::new(),
                        unit: String::new(),
                        metadata: vec![],
                        data: Some(metric::Data::Sum(Sum {
                            data_points: vec![NumberDataPoint {
                                attributes: vec![
                                    KeyValue {
                                        key: "project_id".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(AnyValueValue::StringValue(
                                                "proj_1".to_string(),
                                            )),
                                        }),
                                        key_strindex: 0,
                                    },
                                    KeyValue {
                                        key: "api_key_id".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(AnyValueValue::StringValue(
                                                "key_1".to_string(),
                                            )),
                                        }),
                                        key_strindex: 0,
                                    },
                                    KeyValue {
                                        key: "lc_user_id".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(AnyValueValue::StringValue(
                                                "user_1".to_string(),
                                            )),
                                        }),
                                        key_strindex: 0,
                                    },
                                    KeyValue {
                                        key: "lc_user_name".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(AnyValueValue::StringValue(
                                                "Ada Lovelace".to_string(),
                                            )),
                                        }),
                                        key_strindex: 0,
                                    },
                                    KeyValue {
                                        key: "model".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(AnyValueValue::StringValue(
                                                "gpt-4.1".to_string(),
                                            )),
                                        }),
                                        key_strindex: 0,
                                    },
                                ],
                                start_time_unix_nano: 0,
                                time_unix_nano: 1_735_689_601_000_000_000,
                                exemplars: vec![],
                                flags: 0,
                                value: Some(number_data_point::Value::AsInt(99)),
                            }],
                            aggregation_temporality: AggregationTemporality::Delta as i32,
                            is_monotonic: true,
                        })),
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let events = extract_metric_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.signal_type, "metric");
        assert_eq!(event.account_id.as_deref(), Some("acct_1"));
        assert_eq!(event.project_id.as_deref(), Some("proj_1"));
        assert_eq!(event.api_key_id.as_deref(), Some("key_1"));
        assert_eq!(event.user_id.as_deref(), Some("user_1"));
        assert_eq!(event.user_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(event.model.as_deref(), Some("gpt-4.1"));
        assert_eq!(
            event.metric_name.as_deref(),
            Some("gen_ai.usage.total_tokens")
        );
        assert_eq!(event.usage_value, 99.0);
        assert_eq!(event.request_count, 99);
    }

    #[test]
    fn extract_log_events_should_capture_dimensions_and_tokens() {
        use opentelemetry_proto::tonic::common::v1::InstrumentationScope;
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueValue;
        use opentelemetry_proto::tonic::logs::v1::{
            LogRecord, ResourceLogs, ScopeLogs, SeverityNumber,
        };
        use opentelemetry_proto::tonic::resource::v1::Resource;

        let payload = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![
                        KeyValue {
                            key: "account_id".to_string(),
                            value: Some(AnyValue {
                                value: Some(AnyValueValue::StringValue("acct_1".to_string())),
                            }),
                            key_strindex: 0,
                        },
                        KeyValue {
                            key: "project_id".to_string(),
                            value: Some(AnyValue {
                                value: Some(AnyValueValue::StringValue("proj_1".to_string())),
                            }),
                            key_strindex: 0,
                        },
                    ],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "test-logger".to_string(),
                        version: "1.0".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    }),
                    log_records: vec![LogRecord {
                        event_name: String::new(),
                        time_unix_nano: 1_735_689_601_000_000_000,
                        observed_time_unix_nano: 0,
                        severity_number: SeverityNumber::Info as i32,
                        severity_text: "INFO".to_string(),
                        body: None,
                        attributes: vec![
                            KeyValue {
                                key: "api_key_id".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::StringValue("key_1".to_string())),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "lc_user_id".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::StringValue("user_1".to_string())),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "lc_user_name".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::StringValue(
                                        "Ada Lovelace".to_string(),
                                    )),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "model".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::StringValue("gpt-4.1".to_string())),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "gen_ai.usage.prompt_tokens".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::IntValue(15)),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "gen_ai.usage.completion_tokens".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::IntValue(10)),
                                }),
                                key_strindex: 0,
                            },
                        ],
                        dropped_attributes_count: 0,
                        flags: 0,
                        trace_id: vec![],
                        span_id: vec![],
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let events = extract_log_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.signal_type, "log");
        assert_eq!(event.account_id.as_deref(), Some("acct_1"));
        assert_eq!(event.project_id.as_deref(), Some("proj_1"));
        assert_eq!(event.api_key_id.as_deref(), Some("key_1"));
        assert_eq!(event.user_id.as_deref(), Some("user_1"));
        assert_eq!(event.user_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(event.model.as_deref(), Some("gpt-4.1"));
        assert_eq!(event.metric_name.as_deref(), Some("INFO"));
        assert_eq!(event.prompt_tokens, Some(15));
        assert_eq!(event.completion_tokens, Some(10));
        assert_eq!(event.total_tokens, Some(25));
        assert_eq!(event.usage_value, 25.0);
        assert_eq!(event.request_count, 1);
    }

    #[test]
    fn extract_log_events_should_read_envoy_ai_gateway_custom_cost() {
        use opentelemetry_proto::tonic::common::v1::InstrumentationScope;
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueValue;
        use opentelemetry_proto::tonic::logs::v1::{
            LogRecord, ResourceLogs, ScopeLogs, SeverityNumber,
        };
        use opentelemetry_proto::tonic::resource::v1::Resource;

        // This test verifies that the cost written by the Envoy AI Gateway extproc
        // (io.envoy.ai_gateway.llm_custom_total_cost) is correctly extracted.
        let payload = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "account_id".to_string(),
                        value: Some(AnyValue {
                            value: Some(AnyValueValue::StringValue("acct_1".to_string())),
                        }),
                        key_strindex: 0,
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "test-logger".to_string(),
                        version: "1.0".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    }),
                    log_records: vec![LogRecord {
                        event_name: String::new(),
                        time_unix_nano: 1_735_689_601_000_000_000,
                        observed_time_unix_nano: 0,
                        severity_number: SeverityNumber::Info as i32,
                        severity_text: "INFO".to_string(),
                        body: None,
                        attributes: vec![
                            KeyValue {
                                key: "user_id".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::StringValue("user_1".to_string())),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "model".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::StringValue("gpt-4.1".to_string())),
                                }),
                                key_strindex: 0,
                            },
                            // The key written by Envoy AI Gateway extproc
                            KeyValue {
                                key: "io.envoy.ai_gateway.llm_custom_total_cost".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::DoubleValue(123.45)),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "gen_ai.usage.prompt_tokens".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::IntValue(100)),
                                }),
                                key_strindex: 0,
                            },
                            KeyValue {
                                key: "gen_ai.usage.completion_tokens".to_string(),
                                value: Some(AnyValue {
                                    value: Some(AnyValueValue::IntValue(50)),
                                }),
                                key_strindex: 0,
                            },
                        ],
                        dropped_attributes_count: 0,
                        flags: 0,
                        trace_id: vec![],
                        span_id: vec![],
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let events = extract_log_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        // This is the key assertion - the custom cost should now be extracted
        assert_eq!(event.total_cost, Some(123.45));
        assert_eq!(event.prompt_tokens, Some(100));
        assert_eq!(event.completion_tokens, Some(50));
        assert_eq!(event.total_tokens, Some(150));
    }

    fn string_kv(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(value.to_string())),
            }),
            key_strindex: 0,
        }
    }

    #[test]
    fn extract_log_events_should_capture_real_envoy_access_log_json_keys() {
        // Field names copied verbatim from ai-helm's
        // charts/core-gateway/templates/envoy-proxy.yaml accessLog JSON format
        // block (api_key_id/project_id/account_id/user_id/gen_ai.request.model),
        // NOT from this file's own PROJECT_KEYS/ACCOUNT_KEYS/etc. lists.
        let payload: ExportLogsServiceRequest = serde_json::from_value(json!({
            "resourceLogs": [
                {
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": "1735689601000000000",
                                    "attributes": [
                                        {"key": "account_id", "value": {"stringValue": "acct_1"}},
                                        {"key": "project_id", "value": {"stringValue": "proj_1"}},
                                        {"key": "api_key_id", "value": {"stringValue": "key_1"}},
                                        {"key": "user_id", "value": {"stringValue": "user_1"}},
                                        {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4.1"}}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }))
        .expect("valid log payload");

        let events = extract_log_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.account_id.as_deref(), Some("acct_1"));
        assert_eq!(event.project_id.as_deref(), Some("proj_1"));
        assert_eq!(event.api_key_id.as_deref(), Some("key_1"));
        assert_eq!(event.user_id.as_deref(), Some("user_1"));
        assert_eq!(event.model.as_deref(), Some("gpt-4.1"));
    }

    #[test]
    fn extract_log_events_should_capture_real_envoy_access_log_keys_over_protobuf_wire() {
        // Same as the JSON probe above, but goes through an actual protobuf
        // encode -> decode -> extract_log_events roundtrip, exactly like
        // production traffic (Content-Type: application/x-protobuf), to rule
        // out any serde_json-specific artifact in the JSON probe above.
        let request = ExportLogsServiceRequest {
            resource_logs: vec![opentelemetry_proto::tonic::logs::v1::ResourceLogs {
                resource: None,
                scope_logs: vec![opentelemetry_proto::tonic::logs::v1::ScopeLogs {
                    scope: None,
                    log_records: vec![opentelemetry_proto::tonic::logs::v1::LogRecord {
                        time_unix_nano: 1_735_689_601_000_000_000,
                        severity_text: "INFO".to_string(),
                        attributes: vec![
                            string_kv("account_id", "acct_1"),
                            string_kv("project_id", "proj_1"),
                            string_kv("api_key_id", "key_1"),
                            string_kv("user_id", "user_1"),
                            string_kv("gen_ai.request.model", "gpt-4.1"),
                        ],
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let mut encoded = Vec::new();
        request.encode(&mut encoded).expect("should encode");

        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).expect("should decode");
        let events = extract_log_events(decoded);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.account_id.as_deref(), Some("acct_1"));
        assert_eq!(event.project_id.as_deref(), Some("proj_1"));
        assert_eq!(event.api_key_id.as_deref(), Some("key_1"));
        assert_eq!(event.user_id.as_deref(), Some("user_1"));
        assert_eq!(event.model.as_deref(), Some("gpt-4.1"));
    }

    fn base_usage_event() -> UsageEvent {
        UsageEvent {
            observed_at: Utc::now(),
            signal_type: "trace".to_string(),
            account_id: None,
            project_id: None,
            api_key_id: None,
            user_id: None,
            user_name: None,
            model: None,
            metric_name: None,
            usage_value: 1.0,
            request_count: 1,
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            total_cost: None,
            attributes: Value::Null,
        }
    }

    #[test]
    fn extract_trace_events_should_fall_back_to_start_time_when_end_time_is_missing() {
        let payload: ExportTraceServiceRequest = serde_json::from_value(json!({
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": "chat.completion",
                                    "startTimeUnixNano": "1735689600000000000",
                                    "endTimeUnixNano": "0"
                                }
                            ]
                        }
                    ]
                }
            ]
        }))
        .expect("valid trace payload");

        let events = extract_trace_events(payload);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].observed_at,
            nanos_to_datetime(1_735_689_600_000_000_000)
        );
        assert_eq!(events[0].usage_value, 1.0);
        assert_eq!(events[0].account_id, None);
    }

    #[test]
    fn extract_log_events_should_fall_back_to_observed_time_and_default_usage_value() {
        let payload: ExportLogsServiceRequest = serde_json::from_value(json!({
            "resourceLogs": [
                {
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": "0",
                                    "observedTimeUnixNano": "1735689600000000000",
                                    "severityText": ""
                                }
                            ]
                        }
                    ]
                }
            ]
        }))
        .expect("valid log payload");

        let events = extract_log_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(
            event.observed_at,
            nanos_to_datetime(1_735_689_600_000_000_000)
        );
        assert_eq!(event.metric_name, None);
        assert_eq!(event.usage_value, 1.0);
    }

    #[test]
    fn extract_metric_events_should_capture_gauge_data_points() {
        use opentelemetry_proto::tonic::metrics::v1::{
            Gauge, Metric, ResourceMetrics, ScopeMetrics, metric,
        };

        let payload = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "queue.depth".to_string(),
                        data: Some(metric::Data::Gauge(Gauge {
                            data_points: vec![NumberDataPoint {
                                time_unix_nano: 1_735_689_601_000_000_000,
                                value: Some(number_data_point::Value::AsDouble(3.5)),
                                ..Default::default()
                            }],
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let events = extract_metric_events(payload);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].usage_value, 3.5);
        assert_eq!(events[0].metric_name.as_deref(), Some("queue.depth"));
        assert_eq!(events[0].request_count, 4);
    }

    #[test]
    fn extract_metric_events_should_capture_histogram_data_points() {
        use opentelemetry_proto::tonic::metrics::v1::{
            Histogram, HistogramDataPoint, Metric, ResourceMetrics, ScopeMetrics, metric,
        };

        let payload = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "request.latency".to_string(),
                        data: Some(metric::Data::Histogram(Histogram {
                            data_points: vec![HistogramDataPoint {
                                time_unix_nano: 1_735_689_601_000_000_000,
                                count: 7,
                                sum: Some(42.0),
                                attributes: vec![string_kv("model", "gpt-4.1")],
                                ..Default::default()
                            }],
                            aggregation_temporality: 0,
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let events = extract_metric_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.usage_value, 42.0);
        assert_eq!(event.request_count, 7);
        assert_eq!(event.model.as_deref(), Some("gpt-4.1"));
    }

    #[test]
    fn extract_metric_events_should_capture_exponential_histogram_data_points() {
        use opentelemetry_proto::tonic::metrics::v1::{
            ExponentialHistogram, ExponentialHistogramDataPoint, Metric, ResourceMetrics,
            ScopeMetrics, metric,
        };

        let payload = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "token.distribution".to_string(),
                        data: Some(metric::Data::ExponentialHistogram(ExponentialHistogram {
                            data_points: vec![ExponentialHistogramDataPoint {
                                time_unix_nano: 1_735_689_601_000_000_000,
                                count: 5,
                                sum: Some(15.0),
                                ..Default::default()
                            }],
                            aggregation_temporality: 0,
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let events = extract_metric_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.usage_value, 15.0);
        assert_eq!(event.request_count, 5);
    }

    #[test]
    fn extract_metric_events_should_capture_summary_data_points() {
        use opentelemetry_proto::tonic::metrics::v1::{
            Metric, ResourceMetrics, ScopeMetrics, Summary, SummaryDataPoint, metric,
        };

        let payload = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "latency.summary".to_string(),
                        data: Some(metric::Data::Summary(Summary {
                            data_points: vec![SummaryDataPoint {
                                time_unix_nano: 1_735_689_601_000_000_000,
                                count: 9,
                                sum: 27.0,
                                ..Default::default()
                            }],
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let events = extract_metric_events(payload);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.usage_value, 27.0);
        assert_eq!(event.request_count, 9);
    }

    #[test]
    fn extract_metric_events_should_skip_metrics_without_data() {
        use opentelemetry_proto::tonic::metrics::v1::{Metric, ResourceMetrics, ScopeMetrics};

        let payload = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "no.data".to_string(),
                        data: None,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let events = extract_metric_events(payload);

        assert!(events.is_empty());
    }

    #[test]
    fn any_value_to_json_should_convert_bool_double_array_kvlist_and_bytes() {
        use opentelemetry_proto::tonic::common::v1::{ArrayValue, KeyValueList};

        assert_eq!(
            any_value_to_json(&AnyValue {
                value: Some(any_value::Value::BoolValue(true)),
            }),
            Value::Bool(true)
        );
        assert_eq!(
            any_value_to_json(&AnyValue {
                value: Some(any_value::Value::DoubleValue(1.5)),
            }),
            json!(1.5)
        );
        assert_eq!(
            any_value_to_json(&AnyValue {
                value: Some(any_value::Value::ArrayValue(ArrayValue {
                    values: vec![AnyValue {
                        value: Some(any_value::Value::StringValue("a".to_string())),
                    }],
                })),
            }),
            Value::Array(vec![Value::String("a".to_string())])
        );

        let kvlist = any_value_to_json(&AnyValue {
            value: Some(any_value::Value::KvlistValue(KeyValueList {
                values: vec![string_kv("nested", "value")],
            })),
        });
        assert_eq!(kvlist["nested"], Value::String("value".to_string()));

        assert_eq!(
            any_value_to_json(&AnyValue {
                value: Some(any_value::Value::BytesValue(vec![0xDE, 0xAD])),
            }),
            Value::String("dead".to_string())
        );
        assert_eq!(any_value_to_json(&AnyValue { value: None }), Value::Null);
    }

    #[test]
    fn extract_string_should_read_numbers_and_booleans_and_ignore_other_types() {
        let mut attrs = HashMap::new();
        attrs.insert("num".to_string(), json!(42));
        attrs.insert("flag".to_string(), json!(true));
        attrs.insert("nullish".to_string(), Value::Null);

        assert_eq!(extract_string(&attrs, &["num"]), Some("42".to_string()));
        assert_eq!(extract_string(&attrs, &["flag"]), Some("true".to_string()));
        assert_eq!(extract_string(&attrs, &["nullish"]), None);
        assert_eq!(extract_string(&attrs, &["missing"]), None);
    }

    #[test]
    fn extract_i64_should_parse_numeric_strings_and_reject_out_of_range_values() {
        let mut attrs = HashMap::new();
        attrs.insert("str_tokens".to_string(), json!("128"));
        attrs.insert("big".to_string(), json!(18_446_744_073_709_551_615u64));
        attrs.insert("not_a_number".to_string(), json!("nope"));

        assert_eq!(extract_i64(&attrs, &["str_tokens"]), Some(128));
        assert_eq!(extract_i64(&attrs, &["big"]), None);
        assert_eq!(extract_i64(&attrs, &["not_a_number"]), None);
    }

    #[test]
    fn extract_f64_should_parse_numeric_strings() {
        let mut attrs = HashMap::new();
        attrs.insert("cost".to_string(), json!("12.5"));
        attrs.insert("bad".to_string(), json!("abc"));

        assert_eq!(extract_f64(&attrs, &["cost"]), Some(12.5));
        assert_eq!(extract_f64(&attrs, &["bad"]), None);
    }

    #[test]
    fn non_empty_should_trim_and_reject_blank_values() {
        assert_eq!(
            non_empty(Some("  hello  ".to_string())),
            Some("hello".to_string())
        );
        assert_eq!(non_empty(Some("   ".to_string())), None);
        assert_eq!(non_empty(None), None);
    }

    #[test]
    fn combine_token_total_should_cover_every_combination() {
        assert_eq!(combine_token_total(Some(3), Some(4)), Some(7));
        assert_eq!(combine_token_total(Some(3), None), Some(3));
        assert_eq!(combine_token_total(None, Some(4)), Some(4));
        assert_eq!(combine_token_total(None, None), None);
        assert_eq!(combine_token_total(Some(i64::MAX), Some(1)), None);
    }

    #[test]
    fn request_count_from_metric_value_should_default_to_one_for_small_or_non_finite_values() {
        assert_eq!(request_count_from_metric_value(0.4), 1);
        assert_eq!(request_count_from_metric_value(-5.0), 1);
        assert_eq!(request_count_from_metric_value(f64::NAN), 1);
    }

    #[test]
    fn request_count_from_metric_value_should_cap_at_i64_max_for_huge_values() {
        assert_eq!(request_count_from_metric_value(f64::MAX), i64::MAX);
        assert_eq!(request_count_from_metric_value(5.0), 5);
    }

    #[test]
    fn u64_to_i64_should_cap_at_i64_max_on_overflow() {
        assert_eq!(u64_to_i64(u64::MAX), i64::MAX);
        assert_eq!(u64_to_i64(10), 10);
    }

    #[test]
    fn nanos_to_datetime_should_fall_back_to_now_when_nanos_is_zero() {
        let before = Utc::now();
        let observed = nanos_to_datetime(0);
        let after = Utc::now();

        assert!(observed >= before && observed <= after);
    }

    #[test]
    fn decode_logs_request_should_accept_json_payload() {
        let body = json!({"resourceLogs": []}).to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let payload =
            decode_logs_request(&headers, body.as_bytes()).expect("json payload should decode");

        assert!(payload.resource_logs.is_empty());
    }

    #[test]
    fn decode_logs_request_should_reject_invalid_json_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let err = decode_logs_request(&headers, b"{not json")
            .expect_err("invalid json should be rejected");

        assert!(
            matches!(err, Error::BadRequest(m) if m.contains("invalid OTLP logs JSON payload"))
        );
    }

    #[test]
    fn decode_trace_request_should_accept_json_payload() {
        let body = json!({"resourceSpans": []}).to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let payload =
            decode_trace_request(&headers, body.as_bytes()).expect("json payload should decode");

        assert!(payload.resource_spans.is_empty());
    }

    #[test]
    fn decode_trace_request_should_reject_invalid_json_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let err = decode_trace_request(&headers, b"{not json")
            .expect_err("invalid json should be rejected");

        assert!(
            matches!(err, Error::BadRequest(m) if m.contains("invalid OTLP trace JSON payload"))
        );
    }

    #[test]
    fn decode_trace_request_should_reject_invalid_protobuf_payload() {
        let err = decode_trace_request(&HeaderMap::new(), b"not protobuf")
            .expect_err("invalid protobuf should be rejected");

        assert!(
            matches!(err, Error::BadRequest(m) if m.contains("invalid OTLP trace protobuf payload"))
        );
    }

    #[test]
    fn decode_metrics_request_should_accept_json_payload() {
        let body = json!({"resourceMetrics": []}).to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let payload =
            decode_metrics_request(&headers, body.as_bytes()).expect("json payload should decode");

        assert!(payload.resource_metrics.is_empty());
    }

    #[test]
    fn decode_metrics_request_should_reject_invalid_json_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let err = decode_metrics_request(&headers, b"{not json")
            .expect_err("invalid json should be rejected");

        assert!(
            matches!(err, Error::BadRequest(m) if m.contains("invalid OTLP metrics JSON payload"))
        );
    }

    #[test]
    fn decode_metrics_request_should_reject_invalid_protobuf_payload() {
        let err = decode_metrics_request(&HeaderMap::new(), b"not protobuf")
            .expect_err("invalid protobuf should be rejected");

        assert!(
            matches!(err, Error::BadRequest(m) if m.contains("invalid OTLP metrics protobuf payload"))
        );
    }

    #[test]
    fn decode_maybe_gzip_should_passthrough_uncompressed_bodies() {
        let headers = HeaderMap::new();

        let out =
            decode_maybe_gzip(&headers, b"plain body").expect("uncompressed body should pass");

        assert_eq!(out, b"plain body");
    }

    #[test]
    fn decode_maybe_gzip_should_decompress_gzip_encoded_bodies() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"compressed body")
            .expect("write should succeed");
        let compressed = encoder.finish().expect("gzip encoding should succeed");

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());

        let out = decode_maybe_gzip(&headers, &compressed).expect("gzip body should decompress");

        assert_eq!(out, b"compressed body");
    }

    #[test]
    fn decode_maybe_gzip_should_reject_invalid_gzip_bodies() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());

        let err = decode_maybe_gzip(&headers, b"not gzip")
            .expect_err("invalid gzip body should be rejected");

        assert!(matches!(err, Error::BadRequest(m) if m.contains("invalid gzip body")));
    }

    #[test]
    fn is_json_content_should_detect_json_and_non_json_content_types() {
        let mut json_headers = HeaderMap::new();
        json_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        assert!(is_json_content(&json_headers));

        let mut proto_headers = HeaderMap::new();
        proto_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-protobuf".parse().unwrap(),
        );
        assert!(!is_json_content(&proto_headers));

        assert!(!is_json_content(&HeaderMap::new()));
    }

    #[test]
    fn validate_events_should_reject_empty_signal_type() {
        let event = UsageEvent {
            signal_type: "   ".to_string(),
            ..base_usage_event()
        };

        let err = validate_events(&[event]).expect_err("blank signal_type must be rejected");

        assert!(matches!(err, Error::BadRequest(m) if m == "signal_type is required"));
    }

    #[test]
    fn validate_events_should_reject_non_finite_usage_value() {
        let event = UsageEvent {
            usage_value: f64::NAN,
            ..base_usage_event()
        };

        let err = validate_events(&[event]).expect_err("non-finite usage_value must be rejected");

        assert!(matches!(err, Error::BadRequest(m) if m == "usage_value must be finite"));
    }

    #[test]
    fn validate_events_should_reject_non_finite_total_cost() {
        let event = UsageEvent {
            total_cost: Some(f64::INFINITY),
            ..base_usage_event()
        };

        let err = validate_events(&[event]).expect_err("non-finite total_cost must be rejected");

        assert!(matches!(err, Error::BadRequest(m) if m == "total_cost must be finite"));
    }

    #[test]
    fn validate_events_should_reject_negative_request_count() {
        let event = UsageEvent {
            request_count: -1,
            ..base_usage_event()
        };

        let err = validate_events(&[event]).expect_err("negative request_count must be rejected");

        assert!(matches!(err, Error::BadRequest(m) if m == "request_count cannot be negative"));
    }

    #[test]
    fn validate_events_should_reject_negative_token_counts() {
        let event = UsageEvent {
            prompt_tokens: Some(-1),
            ..base_usage_event()
        };

        let err = validate_events(&[event]).expect_err("negative token counts must be rejected");

        assert!(matches!(err, Error::BadRequest(m) if m == "token counts cannot be negative"));
    }

    #[test]
    fn validate_events_should_accept_a_well_formed_event() {
        assert!(validate_events(&[base_usage_event()]).is_ok());
    }

    #[tokio::test]
    async fn persist_events_should_treat_a_partial_insert_as_fully_accepted() {
        struct PartialInsertRepo {
            persisted: usize,
        }

        #[lightbridge_authz_core::async_trait]
        impl crate::UsageRepoTrait for PartialInsertRepo {
            async fn insert_usage_events(&self, _events: &[UsageEvent]) -> Result<usize> {
                Ok(self.persisted)
            }

            async fn query_usage(
                &self,
                _input: &crate::models::UsageQueryRequest,
            ) -> Result<Vec<crate::models::UsageSeriesPoint>> {
                Ok(vec![])
            }

            async fn spend_for_account(
                &self,
                _account_id: &str,
                _start: chrono::DateTime<chrono::Utc>,
                _end: chrono::DateTime<chrono::Utc>,
            ) -> Result<Option<f64>> {
                Ok(None)
            }
        }

        let state = crate::UsageState {
            repo: Arc::new(PartialInsertRepo { persisted: 1 }),
        };
        let events = vec![base_usage_event(), base_usage_event()];

        let accepted = persist_events(&state, "trace", &events)
            .await
            .expect("partial insert should still be treated as accepted");

        assert_eq!(accepted, 2);
    }
}
