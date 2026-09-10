//! Exercises `UsageServiceSpendReader` against a mock HTTP server (`httpmock`), never a real
//! usage service or database -- these tests are about the HTTP client's own behavior: does it
//! parse a correct response the way the removed `TimescaleSpendReader` parsed a direct SQL
//! result, and does every way the HTTP call can fail route to `Spend::Unavailable` rather than
//! propagating an error or silently reporting zero. The endpoint's own SQL semantics (matching
//! the direct-SQL figure, half-open interval boundaries) are covered end-to-end against a real
//! database in `crates/lightbridge-authz-usage/tests/spend_query_it_tests.rs`.
//!
//! Every reader built here presents no client identity and no CA bundle (all `None`) -- mTLS
//! client-identity/CA-bundle behavior has its own dedicated test files
//! (`usage_service_ca_bundle_tests.rs`, `usage_service_client_identity_tests.rs`), since neither
//! can be exercised against `httpmock`'s plain (non-TLS) mock server.
//! `usage_service_returns_401_yields_spend_unavailable` below is kept regardless: the reader must
//! not assume `2xx` just because it isn't authenticating -- an unexpected `401` (or any other
//! non-2xx) from the usage service is still "unknown", not "assume success".

use httpmock::Method::POST;
use httpmock::MockServer;
use lightbridge_authz_budget::{
    Period, Spend, SpendObservation, SpendReader, UsageServiceSpendReader,
};
use std::time::Duration;

fn reader_for(base_url: &str) -> UsageServiceSpendReader {
    UsageServiceSpendReader::new(base_url, false, None, None, None, Duration::from_secs(5))
        .expect("reader construction must succeed")
}

fn period() -> Period {
    Period::parse("2026-08").expect("valid period")
}

/// Test 1 (minimum test list, client-side half): a known, non-null `total_cost` -- already
/// micro-USD on the wire (#488) -- is passed through into `Spend::Known` unscaled. Realistic
/// gateway figure: a request costing 1,234 micro-USD (~$0.001234). Prove-fail: reintroducing
/// `validate_total_cost_micros`'s old `* 1_000_000.0` makes this assert `1_234_000_000` instead.
#[tokio::test]
async fn known_nonzero_total_cost_becomes_spend_known_in_micros() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": 1234.0 }));
    });

    let reader = reader_for(&server.base_url());
    let spend = reader
        .spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(spend, Spend::Known(1_234));
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
        false,
        None,
        None,
        None,
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

/// Fail-closed mode 4/5: the usage service returns a `401`. The reader sends no credential, so
/// this isn't a real credential mismatch on this endpoint today -- but the reader must not
/// special-case "unauthenticated, so any response must be fine": any non-2xx, including this one,
/// is still "unknown" and must still fail closed, not be silently treated as `Known`.
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

// ── ADR-0034: `observe_spend_for_account` splits the two halves `Spend::Unavailable` merges ──
//
// `spend_for_account` above must keep its contract exactly: a `NULL` sum and an unreachable
// service are both `Unavailable`, because a refill must never be decided on unverified spend.
// The gateway's remaining-budget read is the one caller that needs them apart -- an account with
// no rows this period is the ordinary state of EVERY account until its first request completes,
// and collapsing it into "unknown" would fail-close the whole fleet at every month boundary.

/// The distinguishing case. `spend_for_account` says `Unavailable` (asserted above);
/// `observe_spend_for_account` says `Empty`, which the remaining endpoint reads as zero spend.
#[tokio::test]
async fn null_total_cost_observes_as_empty_not_unreachable() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": null }));
    });

    let reader = reader_for(&server.base_url());
    let observation = reader
        .observe_spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(observation, SpendObservation::Empty);
}

/// The case that must NOT be confused with the one above: nothing answered at all.
#[tokio::test]
async fn an_unreachable_usage_service_observes_as_unreachable_never_empty() {
    // Port 1 is reserved and nothing listens on it: a connection refusal, not a timeout.
    let reader = reader_for("http://127.0.0.1:1");
    let observation = reader
        .observe_spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(observation, SpendObservation::Unreachable);
}

#[tokio::test]
async fn a_non_success_status_observes_as_unreachable_never_empty() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(500);
    });

    let reader = reader_for(&server.base_url());
    let observation = reader
        .observe_spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(observation, SpendObservation::Unreachable);
}

/// A real, non-null total is reported as itself on both methods -- the split changed nothing for
/// the ordinary path.
#[tokio::test]
async fn a_known_total_observes_as_answered_with_the_same_micros() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": 1234.0 }));
    });

    let reader = reader_for(&server.base_url());
    assert_eq!(
        reader
            .observe_spend_for_account("acct_1", &period())
            .await
            .expect("reader never returns Err"),
        SpendObservation::Answered(1_234)
    );
    assert_eq!(
        reader
            .spend_for_account("acct_1", &period())
            .await
            .expect("reader never returns Err"),
        Spend::Known(1_234)
    );
}

/// A genuine zero-cost total is `Answered(0)`, NOT `Empty`: the usage store has rows for this
/// account and they summed to nothing. The two are different facts and the enum keeps them apart.
#[tokio::test]
async fn a_genuine_zero_total_observes_as_answered_zero_not_empty() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/usage/v1/spend/query");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "total_cost": 0.0 }));
    });

    let reader = reader_for(&server.base_url());
    let observation = reader
        .observe_spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(observation, SpendObservation::Answered(0));
}

/// The default trait method collapses conservatively: a reader that cannot see the transport
/// boundary reports `Unreachable`, never a permissive `Empty`.
#[tokio::test]
async fn the_default_observation_for_a_reader_without_a_transport_is_unreachable() {
    use lightbridge_authz_budget::UnavailableSpendReader;

    let observation = UnavailableSpendReader
        .observe_spend_for_account("acct_1", &period())
        .await
        .expect("reader never returns Err");

    assert_eq!(observation, SpendObservation::Unreachable);
}
