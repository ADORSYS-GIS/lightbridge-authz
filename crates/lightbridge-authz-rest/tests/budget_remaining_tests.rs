//! HTTP contract for `GET /budget/v1/remaining` (ADR-0034, lightbridge-authz#658), driving the
//! REAL handler over a stand-in [`RemainingReader`].
//!
//! `RemainingReader` is a trait precisely so this can be done: the two outcomes that matter most
//! here — an unreachable spend source and an unreadable ledger — cannot be produced on demand
//! against a live Postgres, and they are exactly the ones that must never render as "you have
//! nothing left". The arithmetic behind a *known* answer is covered against a real ledger in
//! `lightbridge-authz-budget`'s `remaining_service_it_tests.rs`.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderName, Request, StatusCode, header};
use chrono::{DateTime, Utc};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::{BudgetRemaining, Period, Remaining, RemainingReader};
use lightbridge_authz_rest::budget_remaining::{
    BUDGET_REMAINING_PATH, BudgetInternalState, ERROR_BUDGET_UNAVAILABLE, budget_remaining_router,
};
use lightbridge_authz_rest::budget_remaining_auth::ERROR_UNAUTHORIZED;
use tower::ServiceExt;

/// Drives the REAL handler. `RemainingReader` exists precisely so this can be done: the two
/// outcomes that matter most here -- an unreachable spend source and an unreadable ledger --
/// cannot be produced on demand against a live Postgres, and they are exactly the ones that
/// must never render as "you have nothing left".
#[derive(Debug, Clone)]
enum StubReader {
    Known(BudgetRemaining),
    Unavailable,
    LedgerFailed,
}

#[lightbridge_authz_core::async_trait]
impl RemainingReader for StubReader {
    async fn remaining_for_account(
        &self,
        _budget_account_id: &str,
        _period: &Period,
        _now: DateTime<Utc>,
    ) -> Result<Remaining, BudgetError> {
        match self {
            Self::Known(remaining) => Ok(Remaining::Known(Box::new(remaining.clone()))),
            Self::Unavailable => Ok(Remaining::Unavailable),
            Self::LedgerFailed => Err(BudgetError::StorageFailed(
                "connection pool timed out".to_string(),
            )),
        }
    }
}

/// The shipped path constant, asserted once so the literal URIs below cannot drift from it.
#[test]
fn the_route_is_mounted_at_the_documented_path() {
    assert_eq!(BUDGET_REMAINING_PATH, "/budget/v1/remaining");
}

/// The secret every authorized call below presents, and the header it rides in. Both are values
/// in `server.budget_internal`; the AuthConfig's `sharedSecretRef` +
/// `credentials.customHeader.name` are the other end of exactly these two.
const SECRET: &str = "shared-secret-under-test";
const SECRET_HEADER: &str = "x-lightbridge-budget-token";

fn app(reader: StubReader) -> Router {
    let state = Arc::new(BudgetInternalState {
        remaining: Arc::new(reader),
        shared_secret: SECRET.to_string(),
        shared_secret_header: HeaderName::from_static(SECRET_HEADER),
    });
    budget_remaining_router(state.clone()).with_state(state)
}

fn known() -> BudgetRemaining {
    BudgetRemaining {
        budget_account_id: "acct_1".to_string(),
        period: Period::parse("2026-09").expect("valid period"),
        ceiling_micros: 24_000_000,
        spent_micros: 3_210_000,
        remaining_micros: 20_790_000,
        next_reset_at: "2026-10-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("valid timestamp"),
        source_lag_seconds: None,
    }
}

/// Every call presents the shared secret unless a test is specifically about the credential --
/// the middleware runs in front of the handler, so an unauthenticated call can never reach the
/// behaviour the other tests are about.
async fn call(app: Router, uri: &str, auth: bool) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri(uri).header(SECRET_HEADER, SECRET);
    if auth {
        builder = builder.header(header::AUTHORIZATION, "Bearer nope");
    }
    let response = app
        .oneshot(builder.body(Body::empty()).expect("request builds"))
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn a_known_balance_is_reported_verbatim() {
    let (status, body) = call(
        app(StubReader::Known(known())),
        "/budget/v1/remaining?account_id=acct_1",
        false,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["remaining_micros"], 20_790_000);
    assert_eq!(body["ceiling_micros"], 24_000_000);
    assert_eq!(body["spent_micros"], 3_210_000);
    assert_eq!(body["period"], "2026-09");
    assert_eq!(body["budget_account_id"], "acct_1");
    assert_eq!(body["next_reset_at"], "2026-10-01T00:00:00Z");
    assert!(
        body["source_lag_seconds"].is_null(),
        "unknown lag must serialize as null, never 0: {body}"
    );
}

/// The load-bearing test for this whole endpoint. An unreadable spend source must never look
/// like an exhausted budget -- see the module doc comment.
#[tokio::test]
async fn an_unreachable_spend_source_is_503_and_never_a_zero_balance() {
    let (status, body) = call(
        app(StubReader::Unavailable),
        "/budget/v1/remaining?account_id=acct_1",
        false,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], ERROR_BUDGET_UNAVAILABLE);
    assert!(
        body.get("remaining_micros").is_none(),
        "a 503 must not carry a balance at all: {body}"
    );
}

/// Same rule for the other half of the computation: a ledger fault is a 503, not a zero.
#[tokio::test]
async fn an_unreadable_ledger_is_503_and_never_a_zero_balance() {
    let (status, body) = call(
        app(StubReader::LedgerFailed),
        "/budget/v1/remaining?account_id=acct_1",
        false,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], ERROR_BUDGET_UNAVAILABLE);
    assert!(body.get("remaining_micros").is_none());
}

/// Mirrors `/usage/v1/spend/query`'s #570 rule: a cross-account service read has no business
/// ever receiving a user's bearer token, and a misrouted proxy must fail loudly.
#[tokio::test]
async fn a_bearer_token_is_refused_outright() {
    let (status, body) = call(
        app(StubReader::Known(known())),
        "/budget/v1/remaining?account_id=acct_1",
        true,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "forbidden");
}

#[tokio::test]
async fn a_blank_account_id_is_a_bad_request_not_a_zero_balance() {
    let (status, body) = call(
        app(StubReader::Known(known())),
        "/budget/v1/remaining?account_id=%20",
        false,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "bad_request");
}

#[tokio::test]
async fn a_missing_account_id_parameter_is_a_bad_request() {
    let (status, _) = call(
        app(StubReader::Known(known())),
        "/budget/v1/remaining",
        false,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_malformed_period_is_a_bad_request() {
    let (status, body) = call(
        app(StubReader::Known(known())),
        "/budget/v1/remaining?account_id=acct_1&period=2026-13",
        false,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "bad_request");
}

/// An omitted period is the current calendar period, not an error -- the gateway never sends
/// one, because the ledger and the gateway's own `x-billing-period` marker agree on it.
#[tokio::test]
async fn an_omitted_period_is_accepted() {
    let (status, _) = call(
        app(StubReader::Known(known())),
        "/budget/v1/remaining?account_id=acct_1",
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// A negative remaining balance is a real, reachable state (the gateway charges
/// `llm_custom_total_cost` only after the response completes), and it must survive
/// serialization unclamped so overspend stays visible to dashboards.
#[tokio::test]
async fn an_overspent_account_reports_a_negative_remaining() {
    let mut overspent = known();
    overspent.spent_micros = 25_000_000;
    overspent.remaining_micros = -1_000_000;

    let (status, body) = call(
        app(StubReader::Known(overspent)),
        "/budget/v1/remaining?account_id=acct_1",
        false,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["remaining_micros"], -1_000_000);
}

/// ADR-0034's 2026-09-03 amendment. The shared secret replaced mTLS because Authorino v0.24.0's
/// `metadata.http` cannot present a client certificate -- which makes THIS check, and not the TLS
/// handshake, the only thing standing in front of a cross-account balance read.
#[tokio::test]
async fn a_request_without_the_shared_secret_is_refused() {
    let response = app(StubReader::Known(known()))
        .oneshot(
            Request::builder()
                .uri("/budget/v1/remaining?account_id=acct_1")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    assert_eq!(body["error"], ERROR_UNAUTHORIZED);
    assert!(
        body.get("remaining_micros").is_none(),
        "an unauthenticated call must never carry a balance: {body}"
    );
}

/// A wrong secret and a missing one are the same answer, deliberately: telling them apart would
/// confirm to a prober that it guessed the header NAME correctly.
#[tokio::test]
async fn a_wrong_shared_secret_is_refused_the_same_way() {
    let response = app(StubReader::Known(known()))
        .oneshot(
            Request::builder()
                .uri("/budget/v1/remaining?account_id=acct_1")
                .header(SECRET_HEADER, "not-the-secret")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The secret must not be accepted in the `Authorization` header even when it is the right value:
/// that header is refused before the credential is looked at (403, not 401), so a proxy that
/// forwards a user's bearer token here fails loudly rather than being silently ignored.
#[tokio::test]
async fn the_authorization_header_is_refused_before_the_credential_is_checked() {
    let response = app(StubReader::Known(known()))
        .oneshot(
            Request::builder()
                .uri("/budget/v1/remaining?account_id=acct_1")
                .header(SECRET_HEADER, SECRET)
                .header(header::AUTHORIZATION, format!("Bearer {SECRET}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
