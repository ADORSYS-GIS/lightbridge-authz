#![cfg(feature = "it-tests")]

//! Replay-job tests (#693): the source-agnostic POST-through-ingest core.
//!
//! These prove the replay module's contract against a mock ingest server (httpmock):
//!   * an archived object is POSTed to the correct `/v1/otel/{traces,metrics,logs}` route;
//!   * the object's original content type (proto vs OTLP-JSON) is preserved, so the ingest
//!     handler's `is_json_content` branch sees what the exporter originally sent;
//!   * a non-2xx ingest response is an error, never silently dropped (fail loud);
//!   * an unreachable ingest is an error, never silently dropped (fail loud);
//!   * a batch replays in order and reports per-signal counts.
//!
//! Idempotency (replay twice → counts unchanged) is a property of the grain-table dedup keys
//! (#582/#583) that the ingest path writes to, not of this module — it is exercised by the
//! grain-table it-tests. This module's job is the fail-loud POST, which is what these tests pin.

use httpmock::prelude::*;
use lightbridge_authz_usage_rest::replay::{
    ArchiveObject, ReplaySummary, Signal, replay_batch, replay_object,
};

fn object(key: &str, signal: Signal, content_type: &str, body: &[u8]) -> ArchiveObject {
    ArchiveObject {
        key: key.to_string(),
        signal,
        content_type: content_type.to_string(),
        body: body.to_vec(),
    }
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

    let client = reqwest::Client::new();
    let obj = object(
        "claude_code/2026/09/07/traces-1",
        Signal::Traces,
        "application/x-protobuf",
        b"raw-trace-bytes",
    );

    replay_object(&client, &server.base_url(), &obj)
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

    let client = reqwest::Client::new();
    let obj = object(
        "gateway/2026/09/07/logs-1",
        Signal::Logs,
        "application/json",
        br#"{"resourceLogs":[]}"#,
    );

    replay_object(&client, &server.base_url(), &obj)
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

    let client = reqwest::Client::new();
    let obj = object(
        "codex/2026/09/07/metrics-1",
        Signal::Metrics,
        "application/x-protobuf",
        b"metrics",
    );

    let err = replay_object(&client, &server.base_url(), &obj)
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
    let client = reqwest::Client::new();
    let obj = object(
        "opencode/2026/09/07/traces-1",
        Signal::Traces,
        "application/x-protobuf",
        b"traces",
    );

    let err = replay_object(&client, "http://127.0.0.1:1", &obj)
        .await
        .expect_err("an unreachable ingest must be an error, never silently dropped");
    assert!(
        err.to_string().contains("could not be sent"),
        "error should name the transport failure, got: {err}"
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

    let client = reqwest::Client::new();
    let objects = vec![
        object(
            "s1/2026/09/07/t-1",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object(
            "s1/2026/09/07/m-1",
            Signal::Metrics,
            "application/x-protobuf",
            b"m",
        ),
        object("s2/2026/09/07/l-1", Signal::Logs, "application/json", b"{}"),
    ];

    let summary: ReplaySummary = replay_batch(&client, &server.base_url(), &objects)
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

    let client = reqwest::Client::new();
    let objects = vec![
        object(
            "s1/2026/09/07/t-1",
            Signal::Traces,
            "application/x-protobuf",
            b"t",
        ),
        object("s1/2026/09/07/l-1", Signal::Logs, "application/json", b"{}"),
    ];

    let err = replay_batch(&client, &server.base_url(), &objects)
        .await
        .expect_err("a failing object must abort the batch");
    assert!(err.to_string().contains("503"), "got: {err}");
    ok.assert();
    fail.assert();
}
