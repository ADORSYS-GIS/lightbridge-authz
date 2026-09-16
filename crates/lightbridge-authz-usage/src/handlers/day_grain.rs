//! The day-grain ingest handler (#588): receives the RFC-0001 OTLP log records governance-ctl
//! emits and upserts them into `usage_day_facts` / `usage_seat_snapshots`.
//!
//! This handler is dispatched to from the OTLP log ingest paths (`/v1/otel/logs` and
//! `/auth/v1/otel/logs`) when the request's source is `github-copilot` — Copilot data arrives via
//! the day-grain pull path, never the request-grain push path (see the `github_copilot` normalizer
//! stub). Authentication/source resolution happens in the caller; this handler only decodes,
//! parses the RFC-0001 contract, and upserts.
//!
//! Fail-loud: a malformed day-grain record aborts the whole request (`Err`), never a silent drop —
//! the cutover's count assertions depend on every emitted record landing or the run failing.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use lightbridge_authz_core::Result;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;

use crate::{
    UsageState,
    handlers::ingest::{decode_otlp_request_async, key_values_to_map, merge_attr_maps},
    models::IngestResponse,
    models::day_seat::{DayFact, SeatSnapshot},
    normalizer::day_grain::{DayGrainRecord, parse_day_grain},
};

/// Decode an OTLP logs request, parse every day-grain record, and upsert into the day/seat tables.
pub async fn ingest_day_grain_logs(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<IngestResponse>)> {
    let payload =
        decode_otlp_request_async::<ExportLogsServiceRequest>(headers, body, "logs").await?;
    let (facts, seats) = extract_day_grain(payload)?;

    let accepted = state.repo.upsert_day_facts(&facts).await?
        + state.repo.upsert_seat_snapshots(&seats).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(IngestResponse {
            accepted_events: accepted,
        }),
    ))
}

/// Split an OTLP logs payload into day facts and seat snapshots.
///
/// Records without a `report` attribute are not day-grain and are skipped (a `github-copilot`
/// source emits only day-grain records per RFC-0001). A record that IS day-grain but malformed
/// returns `Err` — the whole request is refused rather than partially applied.
fn extract_day_grain(
    payload: ExportLogsServiceRequest,
) -> Result<(Vec<DayFact>, Vec<SeatSnapshot>)> {
    let mut facts = Vec::new();
    let mut seats = Vec::new();

    for resource_logs in payload.resource_logs {
        let resource_attrs = resource_logs
            .resource
            .map(|r| key_values_to_map(&r.attributes))
            .unwrap_or_default();
        for scope_logs in resource_logs.scope_logs {
            for log_record in scope_logs.log_records {
                let attrs =
                    merge_attr_maps(&resource_attrs, &key_values_to_map(&log_record.attributes));
                match parse_day_grain(&attrs)? {
                    Some(DayGrainRecord::DayFact(f)) => facts.push(f),
                    Some(DayGrainRecord::SeatSnapshot(s)) => seats.push(s),
                    None => {}
                }
            }
        }
    }

    Ok((facts, seats))
}
