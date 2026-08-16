//! Exercises `UsageServiceSpendReader` against a mock HTTP server (`httpmock`), never a real
//! usage service or database -- these tests are about the HTTP client's own behavior: does it
//! parse a correct response the way the removed `TimescaleSpendReader` parsed a direct SQL
//! result, and does every way the HTTP call can fail route to `Spend::Unavailable` rather than
//! propagating an error or silently reporting zero. The endpoint's own SQL semantics (matching
//! the direct-SQL figure, half-open interval boundaries, Basic-auth rejection) are covered
//! end-to-end against a real database in
//! `crates/lightbridge-authz-usage/tests/spend_query_it_tests.rs`.

use base64::Engine;
use httpmock::Method::POST;
use httpmock::MockServer;
use lightbridge_authz_budget::{Period, Spend, SpendReader, UsageServiceSpendReader};
use lightbridge_authz_core::config::BasicAuth;
use std::time::Duration;

const USERNAME: &str = "usage-internal";
const PASSWORD: &str = "change-me";

fn basic_auth() -> BasicAuth {
    BasicAuth {
        username: USERNAME.to_string(),
        password: PASSWORD.to_string(),
    }
}

fn reader_for(base_url: &str) -> UsageServiceSpendReader {
    UsageServiceSpendReader::new(base_url, basic_auth(), false, Duration::from_secs(5))
        .expect("reader construction must succeed")
}

fn period() -> Period {
    Period::parse("2026-08").expect("valid period")
}

/// Test 1 (minimum test list, client-side half): a known, non-null `total_cost` is converted to
/// `Spend::Known` in the same micro-USD units `cost_to_micros` always used.
#[tokio::test]
async fn known_nonzero_total_cost_becomes_spend_known_in_micros() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": 3.75 }));
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(spend, Spend::Known(3_750_000));
}

/// Test 5 (minimum test list): a genuinely-zero spend must be `Spend::Known(0)`, not
/// `Unavailable` -- the whole point of keeping `total_cost` nullable on the wire.
#[tokio::test]
async fn known_zero_total_cost_becomes_spend_known_zero_not_unavailable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": 0.0 }));
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(spend, Spend::Known(0));
}

/// A `null` `total_cost` (SQL `SUM` over zero matching rows) must be `Spend::Unavailable`.
#[tokio::test]
async fn null_total_cost_becomes_spend_unavailable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": null }));
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(spend, Spend::Unavailable);
}

/// The reader must send the configured Basic-auth credentials on every request -- proves the
/// client-side half of "mirror `server.opa.basic_auth`'s mechanism."
#[tokio::test]
async fn reader_sends_the_configured_basic_auth_credentials() {
    let server = MockServer::start();
    let expected_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"))
    );
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/usage/v1/spend/query")
            .header("authorization", &expected_header);
        then.status(200)
            .json_body(serde_json::json!({ "total_cost": 1.0 }));
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    mock.assert();
    assert_eq!(spend, Spend::Known(1_000_000));
}

/// Fail-closed mode 1/5 (minimum test list): the usage service is unreachable (nothing listening
/// on the target port). Prove-fail-first: before this test's assertion existed, an unreachable
/// server produced a `reqwest::Error` that this reader's caller (`RefillService::load_facts`)
/// propagated with `?` -- a hard `Err`, not `Spend::Unavailable` -- exactly the bug this reader
/// is written to not have.
#[tokio::test]
async fn usage_service_unreachable_yields_spend_unavailable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("must bind an ephemeral port");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local addr");
    drop(listener);
    let base_url = format!("http://{addr}");

    let reader = reader_for(&base_url);
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("connection failure must not surface as Err");

    assert_eq!(spend, Spend::Unavailable);
}

/// Fail-closed mode 2/5: the request times out.
#[tokio::test]
async fn usage_service_timeout_yields_spend_unavailable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .delay(Duration::from_millis(300))
            .json_body(serde_json::json!({ "total_cost": 1.0 }));
    });

    let reader = UsageServiceSpendReader::new(
        server.base_url(),
        basic_auth(),
        false,
        Duration::from_millis(20),
    )
    .expect("reader construction must succeed");

    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("a timeout must not surface as Err");

    assert_eq!(spend, Spend::Unavailable);
}

/// Fail-closed mode 3/5: the usage service returns a `500`.
#[tokio::test]
async fn usage_service_returns_500_yields_spend_unavailable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(500).body("internal error");
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("a 500 must not surface as Err");

    assert_eq!(spend, Spend::Unavailable);
}

/// Fail-closed mode 4/5: the usage service returns a `401` (credential mismatch).
#[tokio::test]
async fn usage_service_returns_401_yields_spend_unavailable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(401).body("Unauthorized");
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("a 401 must not surface as Err");

    assert_eq!(spend, Spend::Unavailable);
}

/// Fail-closed mode 5/5: the usage service returns a `200` with a body that is not the expected
/// JSON shape.
#[tokio::test]
async fn usage_service_returns_malformed_json_yields_spend_unavailable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .body("{not valid json");
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("a malformed body must not surface as Err");

    assert_eq!(spend, Spend::Unavailable);
}

/// A response that parses as JSON but carries a nonsensical `total_cost` (negative, here) must
/// also fail closed -- an untrusted network boundary gets the same treatment as a malformed body.
#[tokio::test]
async fn usage_service_returns_negative_total_cost_yields_spend_unavailable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": -5.0 }));
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("an unusable total_cost must not surface as Err");

    assert_eq!(spend, Spend::Unavailable);
}
