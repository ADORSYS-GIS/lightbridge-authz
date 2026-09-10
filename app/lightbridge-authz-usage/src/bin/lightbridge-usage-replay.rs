//! `lightbridge-usage-replay` — the source-agnostic replay job for the raw OTLP archive (#693).
//!
//! Reads archived OTLP objects and POSTs each one through the real ingest endpoint
//! (`/v1/otel/{traces,metrics,logs}`), so a field promoted to a column gets a historical
//! backfill for every source. A re-run changes no counts because the ingest path writes to the
//! grain tables whose dedup keys (#582/#583) absorb a redelivery via `ON CONFLICT`.
//!
//! The archive leg (#589) writes raw OTLP to S3 under `<source>/<yyyy>/<mm>/<dd>/…`; the
//! exporter lives in the governance repo, on the edge collector. This binary is deliberately
//! source-agnostic and does not talk to S3 itself — it consumes a **manifest** (JSON) that lists
//! the objects to replay and where each object's body lives on disk. The S3 listing driver
//! (a small script or the governance-side archive tooling) turns a prefix/date-range read into
//! that manifest. Keeping S3 out of this binary keeps it testable and free of per-vendor code.
//!
//! Fail-loud: a non-2xx ingest response, an unreachable ingest, or an unreadable archive object
//! aborts the run with a non-zero exit — an outage never looks like a successful replay.
//!
//! Manifest shape:
//! ```json
//! {
//!   "ingest_base_url": "http://usage:3000",
//!   "objects": [
//!     { "key": "claude_code/2026/09/07/traces-1",
//!       "signal": "traces",
//!       "content_type": "application/x-protobuf",
//!       "body_path": "/archive/claude_code/2026/09/07/traces-1" }
//!   ]
//! }
//! ```
//! `signal` is one of `traces` | `metrics` | `logs`. `content_type` is preserved so the ingest
//! handler's OTLP-JSON branch sees what the exporter originally sent.

use clap::Parser;
use lightbridge_authz_core::Result;
use lightbridge_authz_usage_rest::replay::{ArchiveObject, Signal, replay_batch};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "lightbridge-usage-replay",
    about = "Replay the raw OTLP archive through the real ingest endpoint"
)]
struct Cli {
    /// Path to the JSON manifest of archive objects to replay.
    #[arg(long)]
    manifest: PathBuf,

    /// Override the ingest base URL from the manifest (e.g. for a local test server).
    #[arg(long)]
    ingest_base_url: Option<String>,

    /// Per-request timeout for each ingest POST, in seconds. A hung ingest must not hang the
    /// replay job forever.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,

    /// How many archive objects to replay concurrently. `1` replays strictly in order.
    #[arg(long, default_value_t = 1)]
    concurrency: usize,
}

#[derive(Deserialize)]
struct Manifest {
    ingest_base_url: String,
    objects: Vec<ManifestObject>,
}

#[derive(Deserialize)]
struct ManifestObject {
    key: String,
    signal: String,
    content_type: String,
    body_path: PathBuf,
}

fn parse_signal(raw: &str) -> Result<Signal> {
    match raw {
        "traces" => Ok(Signal::Traces),
        "metrics" => Ok(Signal::Metrics),
        "logs" => Ok(Signal::Logs),
        other => Err(lightbridge_authz_core::Error::BadRequest(format!(
            "unknown signal `{other}` in manifest (expected traces|metrics|logs)"
        ))),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let manifest_text = std::fs::read_to_string(&cli.manifest).map_err(|e| {
        lightbridge_authz_core::Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read manifest {}: {e}", cli.manifest.display()),
        ))
    })?;
    let manifest: Manifest = serde_json::from_str(&manifest_text).map_err(|e| {
        lightbridge_authz_core::Error::BadRequest(format!(
            "failed to parse manifest {}: {e}",
            cli.manifest.display()
        ))
    })?;

    let ingest_base_url = cli.ingest_base_url.unwrap_or(manifest.ingest_base_url);

    let mut objects = Vec::with_capacity(manifest.objects.len());
    for entry in manifest.objects {
        let body = std::fs::read(&entry.body_path).map_err(|e| {
            lightbridge_authz_core::Error::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to read archive object {}: {e}",
                    entry.body_path.display()
                ),
            ))
        })?;
        objects.push(ArchiveObject {
            key: entry.key,
            signal: parse_signal(&entry.signal)?,
            content_type: entry.content_type,
            body,
        });
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cli.timeout_secs))
        .build()
        .map_err(|e| {
            lightbridge_authz_core::Error::Server(format!("failed to build HTTP client: {e}"))
        })?;

    let summary = replay_batch(&client, &ingest_base_url, objects, cli.concurrency).await?;

    println!(
        "replayed {} objects ({} traces, {} metrics, {} logs) through {}",
        summary.objects, summary.traces, summary.metrics, summary.logs, ingest_base_url
    );
    Ok(())
}
