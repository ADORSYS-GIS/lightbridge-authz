//! Reads actual spend (`SUM(usage_events.total_cost)`) for a given account/period from
//! `lightbridge-authz-usage`'s `/usage/v1/spend/query` endpoint, so the budget domain's
//! self-service augmentation logic (Phase 5) can compare spend against a grant balance. This
//! call presents a client certificate for mTLS (#347) when configured -- see
//! `UsageServiceSpendReader`'s own doc comment for the full security posture.
//!
//! Until this module was inverted (see the PR that introduced `UsageServiceSpendReader`), this
//! crate opened its own connection directly to the usage-events database and ran
//! `SELECT SUM(total_cost) ...` against `usage_events` itself -- two services querying one
//! service's tables. `lightbridge-authz-usage` owns `usage_events`; it now owns the query too.
//! `UsageServiceSpendReader` runs the identical SQL (`StoreRepo::spend_for_account` in
//! `crates/lightbridge-authz-usage/src/repo.rs`) on the other side of that HTTP call, so this
//! module's contract is unchanged -- only the transport is.
//!
//! The one rule this module exists to enforce: an aggregate `SUM` over zero matching rows is SQL
//! `NULL`, not zero. `lightbridge-authz-usage`'s own dashboard-facing query code
//! (`crates/lightbridge-authz-usage/src/repo.rs`) collapses that `NULL` into `0.0` via
//! `unwrap_or(0.0)`, which is a defensible default for a chart but not for a budget decision: an
//! account with no rows (broken ingest, retention rollout, or simply new) must never be
//! indistinguishable from an account that provably spent nothing. `Spend` keeps those two cases
//! as distinct variants so a caller deciding whether to grant more budget is forced to handle
//! "we don't know" separately from "zero" -- and routes the former to the strictest branch. That
//! same fail-closed rule now also covers every way the HTTP call itself can go wrong: an
//! unreachable usage service, a timeout, a non-2xx status, or a response body that doesn't parse
//! are all "we don't know", exactly like a `NULL` sum -- see `UsageServiceSpendReader` below.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::error::BudgetError;
use crate::period::Period;

/// The result of summing `total_cost` for a scope/period.
///
/// ## Wire shape (`Serialize`/`Deserialize`)
///
/// Adjacently tagged (`#[serde(tag = "status", content = "amount_micros")]`), matching the
/// snake_case convention `rule_data.rs`'s own hand-editable JSON already uses (this crate has no
/// camelCase JSON anywhere -- that convention belongs to the RPC schema layer, not this domain's
/// own rule-data/scenario JSON). A `Known` value round-trips as:
///
/// ```json
/// { "status": "known", "amount_micros": 5000000 }
/// ```
///
/// and `Unavailable` as:
///
/// ```json
/// { "status": "unavailable" }
/// ```
///
/// An internally tagged representation (`#[serde(tag = "status")]` alone) was considered and
/// rejected: like `rule_data.rs`'s `Condition::All`/`Condition::Any` (see that module's doc
/// comment), internal tagging requires every variant's payload to serialize as a map, and a bare
/// `i64` does not. Adjacently tagged is the smallest change that keeps `Known`/`Unavailable` as
/// plain Rust tuple/unit variants (so every existing `match`/`matches!` call site in this crate
/// is untouched) while still producing a shape a human can write by hand for `simulateBudgetPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "amount_micros", rename_all = "snake_case")]
pub enum Spend {
    /// `SUM(total_cost)` over at least one matching row, validated as non-negative micro-USD.
    /// Zero is a legitimate, common value here (e.g. an account whose only logged events cost
    /// nothing) -- it is NOT the same thing as `Unavailable` below, and callers must not
    /// conflate them.
    Known(i64),
    /// No matching rows for this scope/period (broken ingest, data aged past retention, or a
    /// brand-new account with no traffic yet), OR the usage service could not be asked (network
    /// failure, timeout, non-2xx response, unparseable body) -- deliberately NOT represented as
    /// `Known(0)` in either case. A caller deciding whether to grant or trigger something MUST
    /// treat this as "we don't know", routing to the strictest branch, never as "spent nothing,
    /// go ahead".
    Unavailable,
}

/// Reads summed spend for an account over a budget period. Implementations must preserve the
/// `Known`/`Unavailable` distinction described on [`Spend`] -- never collapse "no rows" or "the
/// spend source could not be reached" into `Known(0)`.
#[lightbridge_authz_core::async_trait]
pub trait SpendReader: Send + Sync + std::fmt::Debug {
    async fn spend_for_account(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<Spend, BudgetError>;
}

/// Validates and losslessly narrows a `total_cost` value -- **already micro-USD**, as stored in
/// `usage_events.total_cost` -- into `i64`.
///
/// ## Unit contract (#488)
///
/// `usage_events.total_cost` is micro-USD, not US dollars. The gateway's `llm_custom_total_cost`
/// CEL is the only production writer of this column (via
/// `crates/lightbridge-authz-usage/src/handlers/ingest.rs`'s `COST_KEYS` extraction, landed
/// verbatim, no scaling applied on the way in) and it emits micro-USD -- see the ai-helm
/// cost-tracking doc (`docs/models-chart-docs/cost-tracking.md`, *"Micro-USD ... the chart stores
/// request cost in this unit"*) in the `ADORSYS-GIS/ai-helm` repo. This function used to multiply
/// by `1_000_000.0` here, which was correct only if the stored value were US dollars -- it is
/// not, so that multiplication inflated every reported spend figure by roughly 10^6 and drove
/// self-service refill decisions to the fail-closed floor. See
/// https://github.com/ADORSYS-GIS/lightbridge-authz/issues/488.
///
/// This function therefore does not scale its input at all -- it only validates. The value still
/// arrives as `f64` over the wire (`SpendQueryResponse::total_cost`, a SQL `double precision`
/// `SUM`), so it must still be checked for the same three failure modes as before: non-finite
/// (`NaN`/`±inf`), negative (a cost can never be negative), and too large to round-trip into
/// `i64` exactly. All three are treated as an unusable response from the usage service by
/// `UsageServiceSpendReader` (see its doc comment), which routes them to `Spend::Unavailable`
/// rather than propagating an error.
///
/// Rounding: `f64` cannot represent every integer micro-USD value exactly (float summation drift
/// from `SUM(total_cost)` over many rows), so this rounds to the nearest whole micro-USD using
/// `f64::round` -- ties round away from zero (e.g. `1234.5` -> `1235`), not round-half-even. This
/// is the same rounding semantics the pre-#488 code already used for its (wrong-unit) conversion;
/// only the scaling factor changed, not the rounding rule.
fn validate_total_cost_micros(total_cost: f64) -> Result<i64, BudgetError> {
    if !total_cost.is_finite() {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost is not finite: {total_cost}"
        )));
    }
    if total_cost < 0.0 {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost is negative: {total_cost}"
        )));
    }

    let micros = total_cost.round();
    if micros > i64::MAX as f64 {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost overflows i64 micro-USD: {total_cost}"
        )));
    }

    Ok(micros as i64)
}

/// Computes `[start of calendar month, start of next calendar month)` in UTC for `period`.
fn period_bounds_utc(period: &Period) -> (DateTime<Utc>, DateTime<Utc>) {
    let year = period.year();
    let month = period.month();

    // Safe: `Period` only ever holds a string that already passed `Period::parse`'s validation
    // (4-digit year, 2-digit month in 1..=12), so `year`/`month` here always form a valid
    // calendar date on the 1st of the month.
    let start_date = NaiveDate::from_ymd_opt(year as i32, u32::from(month), 1)
        .expect("Period invariant: year/month always form a valid calendar date");

    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let end_date = NaiveDate::from_ymd_opt(next_year as i32, u32::from(next_month), 1)
        .expect("Period invariant: year/month always form a valid calendar date");

    let start = start_date
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always a valid time")
        .and_utc();
    let end = end_date
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always a valid time")
        .and_utc();

    (start, end)
}

/// Wire request body for `POST {base_url}/usage/v1/spend/query`, matching
/// `lightbridge_authz_usage_rest::models::SpendQueryRequest` field-for-field. No shared crate
/// backs this contract (the usage and budget crates are siblings, not layered -- see
/// `AGENTS.md`), so the two sides are kept in sync by convention and by
/// `usage_service_spend_reader_tests.rs`/`spend_query_it_tests.rs` exercising both ends.
#[derive(Debug, Serialize)]
struct SpendQueryRequest {
    account_id: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

/// Wire response body for `/usage/v1/spend/query`, matching
/// `lightbridge_authz_usage_rest::models::SpendQueryResponse`. `total_cost` stays the raw,
/// nullable SQL `SUM` result -- see that type's doc comment for why.
#[derive(Debug, Deserialize)]
struct SpendQueryResponse {
    total_cost: Option<f64>,
}

/// Reads spend by calling `lightbridge-authz-usage`'s `/usage/v1/spend/query` endpoint over
/// HTTPS, instead of opening a direct database connection (see this module's doc comment for
/// why).
///
/// ## Security posture: mTLS (#347)
///
/// This reader presents a client certificate (`client_cert_path`/`client_key_path`) when the
/// usage service's listener requires one -- see `crate::config::Tls::client_ca_bundle_path` on
/// the server side and `lightbridge_authz_core::server::serve_tls`'s `build_mtls_config`. A
/// deployment that has not wired up `client_cert_path`/`client_key_path` presents no client
/// certificate at all, exactly as before #347; whether that is acceptable depends entirely on
/// whether the usage service's own listener is configured to require one, which is the actual
/// enforcement point -- this reader has no independent opinion about it. Every deployment that
/// enables `Tls::client_ca_bundle_path` on the usage service's listener MUST also configure this
/// reader's client identity, or every spend read fails closed to `Spend::Unavailable` (see "Fail-
/// closed contract" below) once that flip happens -- see the deploy-ordering note in the PR that
/// introduced this.
///
/// A per-endpoint Basic-auth credential was deliberately not added as interim scaffolding before
/// mTLS landed: mTLS is the intended mechanism, and a Basic-auth credential would just have been
/// more surface to retire later.
///
/// ## Fail-closed contract
///
/// Every way this HTTP call can fail is treated as "we don't know", never as an error that
/// propagates out of [`SpendReader::spend_for_account`] and never as `Spend::Known(0)`. This
/// holds regardless of the endpoint being unauthenticated -- an unexpected response (including a
/// `401`/`403` the usage service might return for reasons unrelated to credentials, since none
/// are sent) is still "unknown", not "assume success":
///
/// - the request itself fails (DNS failure, connection refused, TLS handshake failure, the
///   request timing out)
/// - the response status is not `2xx` (any non-2xx, including `401`/`403`/`5xx`)
/// - the response body cannot be decoded as the expected JSON shape
/// - the decoded `total_cost` value is itself unusable (`validate_total_cost_micros` rejects non-finite,
///   negative, or overflowing values)
///
/// All four map to `Ok(Spend::Unavailable)`. This is a deliberate strengthening over the old
/// `TimescaleSpendReader`, which let a SQL query error propagate as `Err(BudgetError::
/// StorageFailed)` -- an HTTP boundary has strictly more ways to fail than a trusted in-process
/// database connection did, and every one of them is "unknown", which per this codebase's
/// stated failure-mode rule (`AGENTS.md`, "Failure modes") must route to the strictest branch,
/// not abort the caller's request with a different error shape. See `rule_data.rs`'s
/// `EvalAbort::FieldUnavailable` handling for what a caller does with `Spend::Unavailable`: it
/// routes to `Effect::ManualReview`, never `auto_approve`.
#[derive(Debug)]
pub struct UsageServiceSpendReader {
    client: reqwest::Client,
    base_url: String,
}

impl UsageServiceSpendReader {
    /// Builds a reader against `base_url` (e.g. `https://authz-usage:3002`, no trailing slash
    /// required). `insecure_skip_verify` should only ever be `true` in local Compose, where every
    /// authz service serves a self-signed certificate with no shared CA bundle available to
    /// mount (see `AGENTS.md`'s Security Notes) -- production deployments must leave it `false`
    /// and set `ca_bundle_path` instead.
    ///
    /// `ca_bundle_path`, when `Some`, names a PEM file the client adds as a trusted root so it
    /// verifies the usage service's certificate against that specific CA (e.g. the
    /// cert-manager-issued `ca.crt` production mounts at `/etc/lightbridge/tls/ca.crt` -- see
    /// `Config::usage_service`'s doc comment). An unreadable path or a bundle that fails to parse
    /// as PEM is a hard error naming the path: per this codebase's fail-closed rule, a
    /// misconfigured trust anchor must refuse to start, never silently fall back to
    /// `insecure_skip_verify` or to the platform's default trust store -- either would turn a
    /// configuration mistake into weaker verification than the operator asked for.
    ///
    /// `client_cert_path`/`client_key_path` (#347), when both `Some`, name a PEM certificate and
    /// its matching PEM private key this reader presents as its own identity for mTLS -- e.g. the
    /// same `/etc/lightbridge/tls/tls.crt`/`tls.key` this pod already mounts for its own server
    /// listener, since that certificate already carries `clientAuth` in its EKU. Setting exactly
    /// one of the two is a hard construction error naming which one is missing -- never a silent
    /// "connect without an identity" fallback. Both unset means this reader presents no client
    /// certificate, which is only safe when the usage service's listener does not require one
    /// (`Tls::client_ca_bundle_path` unset there).
    pub fn new(
        base_url: impl Into<String>,
        insecure_skip_verify: bool,
        ca_bundle_path: Option<&str>,
        client_cert_path: Option<&str>,
        client_key_path: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<Self, BudgetError> {
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(insecure_skip_verify);

        if let Some(path) = ca_bundle_path {
            let pem = std::fs::read(path).map_err(|err| {
                BudgetError::StorageFailed(format!(
                    "failed to read usage-service CA bundle at '{path}': {err}"
                ))
            })?;
            // `from_pem_bundle` (rather than `from_pem`) so an empty result -- zero
            // `-----BEGIN CERTIFICATE-----` blocks found -- is distinguishable from "one valid
            // cert": reqwest's rustls backend parses PEM/DER lazily (bytes are only actually
            // decoded once the client is built), so neither this call nor `from_pem` alone would
            // otherwise fail on content that merely contains no certificates.
            let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|err| {
                BudgetError::StorageFailed(format!(
                    "failed to parse usage-service CA bundle at '{path}' as PEM: {err}"
                ))
            })?;
            if certs.is_empty() {
                return Err(BudgetError::StorageFailed(format!(
                    "usage-service CA bundle at '{path}' contains no PEM certificates"
                )));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        if let Some(identity) = load_client_identity(client_cert_path, client_key_path)? {
            builder = builder.identity(identity);
        }

        let client = builder.build().map_err(|err| {
            let bundle_context = ca_bundle_path
                .map(|path| format!(" (CA bundle '{path}')"))
                .unwrap_or_default();
            BudgetError::StorageFailed(format!(
                "failed to build usage-service HTTP client{bundle_context}: {err}"
            ))
        })?;

        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }
}

/// Loads the mTLS client identity named by `client_cert_path`/`client_key_path`, or returns
/// `None` when both are unset. Setting exactly one is a hard construction error: a half-configured
/// identity must never silently degrade to "present no certificate", since that would turn a
/// configuration mistake into a weaker guarantee than the operator asked for (this codebase's
/// fail-closed rule).
fn load_client_identity(
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> Result<Option<reqwest::Identity>, BudgetError> {
    let (cert_path, key_path) = match (client_cert_path, client_key_path) {
        (None, None) => return Ok(None),
        (Some(cert_path), Some(key_path)) => (cert_path, key_path),
        (Some(cert_path), None) => {
            return Err(BudgetError::StorageFailed(format!(
                "usage-service client_cert_path '{cert_path}' is set but client_key_path is \
                 missing -- both must be set together"
            )));
        }
        (None, Some(key_path)) => {
            return Err(BudgetError::StorageFailed(format!(
                "usage-service client_key_path '{key_path}' is set but client_cert_path is \
                 missing -- both must be set together"
            )));
        }
    };

    let mut pem = std::fs::read(cert_path).map_err(|err| {
        BudgetError::StorageFailed(format!(
            "failed to read usage-service client cert at '{cert_path}': {err}"
        ))
    })?;
    let key_pem = std::fs::read(key_path).map_err(|err| {
        BudgetError::StorageFailed(format!(
            "failed to read usage-service client key at '{key_path}': {err}"
        ))
    })?;
    pem.push(b'\n');
    pem.extend_from_slice(&key_pem);

    let identity = reqwest::Identity::from_pem(&pem).map_err(|err| {
        BudgetError::StorageFailed(format!(
            "failed to parse usage-service client identity from cert '{cert_path}' / key \
             '{key_path}': {err}"
        ))
    })?;

    Ok(Some(identity))
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for UsageServiceSpendReader {
    async fn spend_for_account(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<Spend, BudgetError> {
        let (start, end) = period_bounds_utc(period);
        let url = format!("{}/usage/v1/spend/query", self.base_url);
        let request = SpendQueryRequest {
            account_id: account_id.to_string(),
            start,
            end,
        };

        let response = match self.client.post(&url).json(&request).send().await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "usage-service spend query request failed; treating spend as unavailable"
                );
                return Ok(Spend::Unavailable);
            }
        };

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "usage-service spend query returned a non-success status; treating spend as unavailable"
            );
            return Ok(Spend::Unavailable);
        }

        let body: SpendQueryResponse = match response.json().await {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "usage-service spend query returned a body that did not parse; treating spend as unavailable"
                );
                return Ok(Spend::Unavailable);
            }
        };

        match body.total_cost {
            None => Ok(Spend::Unavailable),
            Some(total_cost) => match validate_total_cost_micros(total_cost) {
                Ok(micros) => Ok(Spend::Known(micros)),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "usage-service spend query returned an unusable total_cost value; treating spend as unavailable"
                    );
                    Ok(Spend::Unavailable)
                }
            },
        }
    }
}

/// A [`SpendReader`] that always reports [`Spend::Unavailable`], never touching the network.
///
/// Used by `lightbridge-authz-rest`'s `start_api_server` when `Config.usage_service` is not
/// configured for a given deployment. `RefillService` genuinely needs *some* `SpendReader` to
/// construct (see its constructor), but the usage service integration is documented as optional
/// (`crates/lightbridge-authz-core/src/config/mod.rs`'s `usage_service` doc comment) -- a
/// deployment that has not wired it up yet should not be unable to start the self-service refill
/// RPC surface at all. This degrades instead of failing startup: every spend-dependent rule-data
/// fact resolves to `Unavailable`, and per this module's own "never collapse no rows / no
/// connection into `Known(0)`" rule (and `rule_data.rs`'s `EvalAbort::FieldUnavailable`
/// handling), any policy rule that reads `spend_this_period`/`spend_last_period` already fails
/// closed on `Unavailable` -- routing to `manual_review`, never to `auto_approve`. So the missing
/// configuration narrows what self-service refill can decide automatically; it does not silently
/// grant more than a correctly-configured deployment would.
#[derive(Debug, Clone, Default)]
pub struct UnavailableSpendReader;

#[lightbridge_authz_core::async_trait]
impl SpendReader for UnavailableSpendReader {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(Spend::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_spend_reader_always_reports_unavailable() {
        let reader = UnavailableSpendReader;
        let period = Period::parse("2026-08").expect("valid period");
        let spend = reader
            .spend_for_account("acct_1", &period)
            .await
            .expect("unavailable reader never errors");
        assert_eq!(spend, Spend::Unavailable);
    }

    #[test]
    fn validate_total_cost_micros_zero_is_zero() {
        assert_eq!(validate_total_cost_micros(0.0).unwrap(), 0);
    }

    /// #488 prove-fail (test 1): a realistic gateway payload figure -- a request costing 1,234
    /// micro-USD (~$0.001234) -- passes through unchanged as 1,234 micro-USD. Break the fix by
    /// reintroducing `* 1_000_000.0` in `validate_total_cost_micros` and this fails with
    /// `1_234_000_000` instead.
    #[test]
    fn validate_total_cost_micros_passes_gateway_micro_usd_through_unscaled() {
        assert_eq!(validate_total_cost_micros(1234.0).unwrap(), 1_234);
    }

    /// #488 prove-fail (test 3): fractional micro-USD (float summation drift from `SUM` over many
    /// rows) rounds to the nearest whole micro-USD, ties away from zero -- `f64::round`'s
    /// semantics, documented on `validate_total_cost_micros` and unchanged by this fix (only the
    /// scaling factor was removed, not the rounding rule).
    #[test]
    fn validate_total_cost_micros_rounds_fractional_micro_usd_half_away_from_zero() {
        assert_eq!(validate_total_cost_micros(1234.6).unwrap(), 1_235);
        assert_eq!(validate_total_cost_micros(0.5).unwrap(), 1);
    }

    #[test]
    fn validate_total_cost_micros_rejects_negative() {
        assert!(validate_total_cost_micros(-0.01).is_err());
    }

    #[test]
    fn validate_total_cost_micros_rejects_nan_and_infinite() {
        assert!(validate_total_cost_micros(f64::NAN).is_err());
        assert!(validate_total_cost_micros(f64::INFINITY).is_err());
        assert!(validate_total_cost_micros(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn validate_total_cost_micros_rejects_i64_overflow() {
        assert!(validate_total_cost_micros(1e19).is_err());
    }

    #[test]
    fn period_bounds_utc_covers_a_calendar_month() {
        let period = Period::parse("2026-08").expect("valid period");
        let (start, end) = period_bounds_utc(&period);
        assert_eq!(start.to_rfc3339(), "2026-08-01T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-09-01T00:00:00+00:00");
    }

    #[test]
    fn period_bounds_utc_rolls_over_december_into_january() {
        let period = Period::parse("2026-12").expect("valid period");
        let (start, end) = period_bounds_utc(&period);
        assert_eq!(start.to_rfc3339(), "2026-12-01T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2027-01-01T00:00:00+00:00");
    }

    #[test]
    fn spend_known_round_trips_through_json_with_the_documented_shape() {
        let spend = Spend::Known(5_000_000);
        let json = serde_json::to_string(&spend).expect("spend must serialize");
        assert_eq!(json, r#"{"status":"known","amount_micros":5000000}"#);
        let parsed: Spend = serde_json::from_str(&json).expect("spend must deserialize");
        assert_eq!(parsed, spend);
    }

    #[test]
    fn spend_unavailable_round_trips_through_json_with_the_documented_shape() {
        let spend = Spend::Unavailable;
        let json = serde_json::to_string(&spend).expect("spend must serialize");
        assert_eq!(json, r#"{"status":"unavailable"}"#);
        let parsed: Spend = serde_json::from_str(&json).expect("spend must deserialize");
        assert_eq!(parsed, spend);
    }

    #[test]
    fn usage_service_spend_reader_constructs_with_only_a_base_url() {
        let reader = UsageServiceSpendReader::new(
            "https://authz-usage:3002",
            false,
            None,
            None,
            None,
            std::time::Duration::from_secs(1),
        );
        assert!(
            reader.is_ok(),
            "constructing the reader must not require a credential"
        );
    }
}
