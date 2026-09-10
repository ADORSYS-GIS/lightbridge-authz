//! Source-agnostic replay of the raw OTLP archive through the real ingest endpoint (#693).
//!
//! The archive leg (#589) writes raw OTLP objects to S3 under `<source>/<yyyy>/<mm>/<dd>/…`
//! (the exporter lives in the governance repo, on the edge collector). This module is the
//! replay half: it takes archived OTLP objects and POSTs each one through the *real*
//! authenticated ingest endpoint (`/v1/otel/{traces,metrics,logs}`), so a field promoted to a
//! column gets a historical backfill for every source.
//!
//! It is deliberately source-agnostic — no per-vendor code. The only thing it knows about a
//! source is which OTLP signal an object carries (which route to POST it to) and the object's
//! original content type (proto vs OTLP-JSON), both of which the archive object itself carries.
//!
//! Idempotency is NOT this module's job. A re-run changes no counts because the ingest path
//! writes to the grain tables whose dedup keys (`UNIQUE (source, trace_id, span_id)` for the
//! execution grain, the natural-key PKs for the day/seat grains — #582/#583) absorb a redelivery
//! via `ON CONFLICT`. This module's contract is narrower and stricter: **fail loud, never
//! silently drop.** A non-2xx ingest response, an unreachable ingest, or an unreadable archive
//! object is an error that aborts the run — an outage must never look like a successful replay.
//!
//! `replay_batch` replays with bounded concurrency. The first error aborts the whole batch and
//! is returned; a partially-replayed batch is therefore possible (objects already accepted before
//! the failure), which is exactly why idempotency matters — the operator re-runs the job and the
//! grain-table dedup keys absorb the already-replayed objects, changing no counts. With
//! `concurrency = 1` the batch replays strictly in order.

use lightbridge_authz_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Which OTLP signal an archived object carries, and therefore which ingest route it replays
/// into. The archive object's key encodes this (the governance-side exporter writes one object
/// per signal), so the replay job never has to sniff the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    Traces,
    Metrics,
    Logs,
}

impl Signal {
    /// The ingest route this signal replays into.
    pub fn ingest_path(self) -> &'static str {
        match self {
            Signal::Traces => "/v1/otel/traces",
            Signal::Metrics => "/v1/otel/metrics",
            Signal::Logs => "/v1/otel/logs",
        }
    }
}

/// One archived OTLP object read from the S3 archive.
///
/// `content_type` is preserved from the archive so the ingest handler's `is_json_content`
/// branch (OTLP-JSON) and its proto branch both see what the original exporter sent — replaying
/// a JSON object as proto would corrupt it.
#[derive(Debug, Clone)]
pub struct ArchiveObject {
    /// The object's S3 key (e.g. `claude_code/2026/09/07/…`). Used only for error messages and
    /// the summary; never parsed for routing.
    pub key: String,
    pub signal: Signal,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// The result of replaying a batch of archive objects.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ReplaySummary {
    pub objects: usize,
    pub traces: usize,
    pub metrics: usize,
    pub logs: usize,
}

/// POSTs one archived object through the real ingest endpoint.
///
/// Takes the object by value so the body is moved into the request rather than cloned — a replay
/// job can process a large archive, and cloning every body doubles the memory traffic for no
/// reason.
///
/// Fail-loud: a non-2xx response, an unreachable ingest, or a transport error is returned as an
/// `Err`, never swallowed. The caller decides whether to abort the whole run; this function
/// surfaces the first failure so a broken archive or a broken ingest is seen, not skipped.
pub async fn replay_object(
    client: &reqwest::Client,
    ingest_base_url: &str,
    object: ArchiveObject,
) -> Result<()> {
    let url = format!(
        "{}{}",
        ingest_base_url.trim_end_matches('/'),
        object.signal.ingest_path()
    );

    let response = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, &object.content_type)
        .body(object.body)
        .send()
        .await
        .map_err(|e| {
            Error::Server(format!(
                "replay of {} failed: ingest POST to {url} could not be sent: {e}",
                object.key
            ))
        })?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(Error::Server(format!(
            "replay of {} failed: ingest rejected {url} ({status}): {body}",
            object.key
        )));
    }

    Ok(())
}

/// Replays a batch of archive objects through the real ingest endpoint with bounded concurrency.
///
/// `concurrency` bounds how many objects are in flight at once; `1` replays strictly in order.
/// Fail-loud: the first error aborts the whole batch (in-flight tasks are cancelled) and is
/// returned. A partially-replayed batch is therefore possible, which is exactly why idempotency
/// matters — the operator re-runs the job and the grain-table dedup keys absorb the
/// already-replayed objects, changing no counts.
pub async fn replay_batch(
    client: &reqwest::Client,
    ingest_base_url: &str,
    objects: Vec<ArchiveObject>,
    concurrency: usize,
) -> Result<ReplaySummary> {
    let concurrency = concurrency.max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut summary = ReplaySummary::default();
    let mut set = JoinSet::new();
    let mut iter = objects.into_iter();

    // Seed the first `concurrency` objects so the pipeline stays full.
    for _ in 0..concurrency {
        if let Some(object) = iter.next() {
            spawn_replay(&mut set, client, ingest_base_url, object, &semaphore);
        }
    }

    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(signal)) => {
                summary.objects += 1;
                match signal {
                    Signal::Traces => summary.traces += 1,
                    Signal::Metrics => summary.metrics += 1,
                    Signal::Logs => summary.logs += 1,
                }
                // Refill the slot with the next object.
                if let Some(object) = iter.next() {
                    spawn_replay(&mut set, client, ingest_base_url, object, &semaphore);
                }
            }
            Ok(Err(e)) => {
                set.abort_all();
                return Err(e);
            }
            Err(e) => {
                set.abort_all();
                return Err(Error::Server(format!("replay task failed: {e}")));
            }
        }
    }

    Ok(summary)
}

fn spawn_replay(
    set: &mut JoinSet<Result<Signal>>,
    client: &reqwest::Client,
    ingest_base_url: &str,
    object: ArchiveObject,
    semaphore: &Arc<Semaphore>,
) {
    let client = client.clone();
    let url = ingest_base_url.to_string();
    let semaphore = Arc::clone(semaphore);
    set.spawn(async move {
        let _permit = semaphore
            .acquire_owned()
            .await
            .map_err(|_| Error::Server("replay semaphore closed".to_string()))?;
        let signal = object.signal;
        replay_object(&client, &url, object).await?;
        Ok(signal)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_ingest_paths_match_the_ingest_router() {
        assert_eq!(Signal::Traces.ingest_path(), "/v1/otel/traces");
        assert_eq!(Signal::Metrics.ingest_path(), "/v1/otel/metrics");
        assert_eq!(Signal::Logs.ingest_path(), "/v1/otel/logs");
    }
}
