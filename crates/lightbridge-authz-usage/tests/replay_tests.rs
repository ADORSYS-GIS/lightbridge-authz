#![cfg(feature = "it-tests")]

//! Replay-job tests (#693): the source-agnostic POST-through-ingest core.
//!
//! These prove the replay module's contract against a mock ingest server (httpmock):
//!   * an archived object is POSTed to the correct `/v1/otel/{traces,metrics,logs}` route;
//!   * the object's original content type (proto vs OTLP-JSON) is preserved, so the ingest
//!     handler's `is_json_content` branch sees what the exporter originally sent;
//!   * a non-2xx ingest response is an error, never silently dropped (fail loud);
//!   * an unreachable ingest is an error, never silently dropped (fail loud);
//!   * a batch replays and reports per-signal counts, both sequentially and concurrently;
//!   * a batch aborts on the first failure, even under concurrency;
//!   * an unreadable archive object is an error, never silently dropped (fail loud);
//!   * a re-run re-sends every object — the module does NOT dedup, and the ingest path writes
//!     `usage_events` via a plain INSERT with no dedup key, so re-run safety must come from the
//!     ingest path absorbing redelivery, which does not exist today (see `src/replay.rs`).

use httpmock::prelude::*;
use lightbridge_authz_usage_rest::replay::{
    ArchiveObject, ReplaySummary, Signal, replay_batch, replay_object,
};
use std::path::PathBuf;
use tempfile::TempDir;

/// Writes `body` to a file under `dir` and returns an `ArchiveObject` pointing at it.
fn object(
    dir: &TempDir,
    name: &str,
    key: &str,
    signal: Signal,
    content_type: &str,
    body: &[u8],
) -> ArchiveObject {
    let body_path: PathBuf = dir.path().join(name);
    std::fs::write(&body_path, body).expect("write archive body");
    ArchiveObject {
        key: key.to_string(),
        signal,
        content_type: content_type.to_string(),
        body_path,
    }
}

#[test]
fn signal_ingest_paths_match_the_ingest_router() {
    assert_eq!(Signal::Traces.ingest_path(), "/v1/otel/traces");
    assert_eq!(Signal::Metrics.ingest_path(), "/v1/otel/metrics");
    assert_eq!(Signal::Logs.ingest_path(), "/v1/otel/logs");
}

#[tokio::test]
async fn replay_object_posts_to_the_signal_route_with_original_content_type() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/otel/traces")
            .header("content-type", "application/x-protobuf")
            .body("raw-trace-bytes");
        then.status(200);
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let obj = object(
        &dir,
        "traces-1",
        "claude_code/2026/09/07/traces-1",
        Signal::Traces,
        "application/x-protobuf",
        b"raw-trace-bytes",
    );

    replay_object(&client, &server.base_url(), obj)
        .await
        .expect("replay should succeed");

    mock.assert();
}

#[tokio::test]
async fn replay_object_preserves_otlp_json_content_type() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/otel/logs")
            .header("content-type", "application/json")
            .body("{\"resourceLogs\":[]}");
        then.status(200);
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let obj = object(
        &dir,
        "logs-1",
        "gateway/2026/09/07/logs-1",
        Signal::Logs,
        "application/json",
        br#"{"resourceLogs":[]}"#,
    );

    replay_object(&client, &server.base_url(), obj)
        .await
        .expect("replay should succeed");

    mock.assert();
}

#[tokio::test]
async fn replay_object_fails_loud_on_non_2xx_ingest_response() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/otel/metrics");
        then.status(500).body("boom");
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let obj = object(
        &dir,
        "metrics-1",
        "codex/2026/09/07/metrics-1",
        Signal::Metrics,
        "application/x-protobuf",
        b"metrics",
    );

    let err = replay_object(&client, &server.base_url(), obj)
        .await
        .expect_err("a 500 must be an error, never silently dropped");
    let msg = err.to_string();
    assert!(
        msg.contains("ingest rejected") && msg.contains("500"),
        "error should name the rejection and status, got: {msg}"
    );
}

#[tokio::test]
async fn replay_object_fails_loud_on_unreachable_ingest() {
    // A port that is not listening: connection refused surfaces as a transport error.
    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let obj = object(
        &dir,
        "traces-1",
        "opencode/2026/09/07/traces-1",
        Signal::Traces,
        "application/x-protobuf",
        b"traces",
    );

    let err = replay_object(&client, "http://127.0.0.1:1", obj)
        .await
        .expect_err("an unreachable ingest must be an error, never silently dropped");
    assert!(
        err.to_string().contains("could not be sent"),
        "error should name the transport failure, got: {err}"
    );
}

#[tokio::test]
async fn replay_object_fails_loud_on_unreadable_archive_object() {
    let server = MockServer::start();
    let client = reqwest::Client::new();
    let obj = ArchiveObject {
        key: "s1/2026/09/07/traces-1".to_string(),
        signal: Signal::Traces,
        content_type: "application/x-protobuf".to_string(),
        body_path: PathBuf::from("/nonexistent/archive/object"),
    };

    let err = replay_object(&client, &server.base_url(), obj)
        .await
        .expect_err("an unreadable archive object must be an error, never silently dropped");
    assert!(
        err.to_string().contains("could not read archive object"),
        "error should name the unreadable object, got: {err}"
    );
}

#[tokio::test]
async fn replay_batch_replays_in_order_and_reports_per_signal_counts() {
    let server = MockServer::start();
    let traces = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/traces");
        then.status(200);
    });
    let metrics = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/metrics");
        then.status(200);
    });
    let logs = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/logs");
        then.status(200);
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let objects = vec![
        object(
            &dir,
            "t-1",
            "s1/2026/09/07/t-1",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            &dir,
            "m-1",
            "s1/2026/09/07/m-1",
            Signal::Metrics,
            "application/x-protobuf",
            b"m",
        ),
        object(
            &dir,
            "l-1",
            "s2/2026/09/07/l-1",
            Signal::Logs,
            "application/json",
            b"{}",
        ),
    ];

    let summary: ReplaySummary = replay_batch(&client, &server.base_url(), objects, 1)
        .await
        .expect("batch succeeds");

    traces.assert();
    metrics.assert();
    logs.assert();
    assert_eq!(summary.objects, 3);
    assert_eq!(summary.traces, 1);
    assert_eq!(summary.metrics, 1);
    assert_eq!(summary.logs, 1);
}

#[tokio::test]
async fn replay_batch_replays_all_objects_with_concurrency() {
    let server = MockServer::start();
    let traces = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/traces");
        then.status(200);
    });
    let logs = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/logs");
        then.status(200);
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let objects = vec![
        object(
            &dir,
            "t-1",
            "s1/2026/09/07/t-1",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            &dir,
            "t-2",
            "s1/2026/09/07/t-2",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            &dir,
            "t-3",
            "s1/2026/09/07/t-3",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            &dir,
            "l-1",
            "s2/2026/09/07/l-1",
            Signal::Logs,
            "application/json",
            b"{}",
        ),
        object(
            &dir,
            "l-2",
            "s2/2026/09/07/l-2",
            Signal::Logs,
            "application/json",
            b"{}",
        ),
    ];

    let summary: ReplaySummary = replay_batch(&client, &server.base_url(), objects, 4)
        .await
        .expect("batch succeeds");

    traces.assert_calls(3);
    logs.assert_calls(2);
    assert_eq!(summary.objects, 5);
    assert_eq!(summary.traces, 3);
    assert_eq!(summary.logs, 2);
}

#[tokio::test]
async fn replay_batch_aborts_on_first_failure() {
    let server = MockServer::start();
    // First object succeeds, second fails — the batch must abort at the failure.
    let ok = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/traces");
        then.status(200);
    });
    let fail = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/logs");
        then.status(503);
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let objects = vec![
        object(
            &dir,
            "t-1",
            "s1/2026/09/07/t-1",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            &dir,
            "l-1",
            "s1/2026/09/07/l-1",
            Signal::Logs,
            "application/json",
            b"{}",
        ),
    ];

    let err = replay_batch(&client, &server.base_url(), objects, 1)
        .await
        .expect_err("a failing object must abort the batch");
    assert!(err.to_string().contains("503"), "got: {err}");
    ok.assert();
    fail.assert();
}

#[tokio::test]
async fn replay_batch_aborts_on_first_failure_under_concurrency() {
    let server = MockServer::start();
    // A mix of successes and a failure; the batch must abort with the failure and not report a
    // successful summary.
    let ok = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/traces");
        then.status(200);
    });
    let fail = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/logs");
        then.status(503);
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let objects = vec![
        object(
            &dir,
            "t-1",
            "s1/2026/09/07/t-1",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            &dir,
            "t-2",
            "s1/2026/09/07/t-2",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            &dir,
            "l-1",
            "s1/2026/09/07/l-1",
            Signal::Logs,
            "application/json",
            b"{}",
        ),
        object(
            &dir,
            "l-2",
            "s1/2026/09/07/l-2",
            Signal::Logs,
            "application/json",
            b"{}",
        ),
    ];

    let err = replay_batch(&client, &server.base_url(), objects, 4)
        .await
        .expect_err("a failing object must abort the batch under concurrency");
    assert!(err.to_string().contains("503"), "got: {err}");
    // Both trace objects succeed; at least one log object hits the failing route before the
    // batch aborts (how many is nondeterministic under concurrency).
    ok.assert_calls(2);
    assert!(
        fail.calls() >= 1,
        "the failing route must be hit at least once"
    );
}

#[tokio::test]
async fn replay_batch_resends_every_object_on_rerun() {
    // Documents the current reality: the replay module does NOT dedup, and the ingest path
    // writes `usage_events` via a plain INSERT with no dedup key, so re-running the job re-sends
    // every object and double-counts. Re-run safety must come from the ingest path absorbing
    // redelivery, which does not exist today — see `src/replay.rs`.
    let server = MockServer::start();
    let traces = server.mock(|when, then| {
        when.method(POST).path("/v1/otel/traces");
        then.status(200);
    });

    let dir = TempDir::new().unwrap();
    let client = reqwest::Client::new();
    let obj = object(
        &dir,
        "t-1",
        "s1/2026/09/07/t-1",
        Signal::Traces,
        "application/x-protobuf",
        b"t",
    );

    let first = replay_batch(&client, &server.base_url(), vec![obj.clone()], 1)
        .await
        .expect("first run succeeds");
    let second = replay_batch(&client, &server.base_url(), vec![obj], 1)
        .await
        .expect("second run succeeds");

    assert_eq!(first.objects, 1);
    assert_eq!(second.objects, 1);
    // The module re-sends the object on every run — it does not dedup.
    traces.assert_calls(2);
}
