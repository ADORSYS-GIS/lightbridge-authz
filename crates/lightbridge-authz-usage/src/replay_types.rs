//! The data types the replay module POSTs through the ingest endpoint (#693).
//!
//! Split out of `replay.rs` rather than left beside `replay_object`/`replay_batch` purely because
//! that file sits on the LoC-gate ceiling (`.github/loc-baseline.json`) and may be touched but
//! not grown. Moved verbatim, and `replay` re-exports all three, so every existing
//! `lightbridge_authz_usage_rest::replay::{Signal, ArchiveObject, ReplaySummary}` path still
//! resolves. The pairing with `replay_object`/`replay_batch` is unchanged.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    /// Path to the archived object's body on disk. Read lazily just before the POST so memory is
    /// bounded by concurrency, not by the size of the whole archive window.
    pub body_path: PathBuf,
}

/// The result of replaying a batch of archive objects.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ReplaySummary {
    pub objects: usize,
    pub traces: usize,
    pub metrics: usize,
    pub logs: usize,
}
