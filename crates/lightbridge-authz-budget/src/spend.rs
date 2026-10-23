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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::BudgetError;
use crate::period::Period;
use crate::spend_units::{period_bounds_utc, validate_total_cost_micros};

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

/// A spend reading that keeps the two halves of [`Spend::Unavailable`] apart: "the spend source
/// answered, and it has no rows for this account/period" versus "the spend source could not be
/// asked at all".
///
/// [`Spend`] deliberately collapses those two, and that is the correct, conservative reading for
/// a **refill decision** — handing out budget on unverified spend is exactly the mistake that
/// enum exists to prevent, and a broken ingest pipeline is indistinguishable from a quiet account
/// when all you have is an empty `SUM`.
///
/// It is the wrong reading for the **gateway's remaining-budget read** (ADR-0034,
/// lightbridge-authz#658), which is on the critical path of every model request. There, "no rows"
/// is the normal state of every account at the start of every period: collapsing it to "unknown"
/// would fail-close the entire fleet at 00:00 UTC on the 1st of each month, every month, until
/// each account's first request happened to complete. So that one caller — and only that one —
/// reads spend through [`SpendReader::observe_spend_for_account`] instead.
///
/// The distinction is only *recoverable* at the transport boundary: a `200` carrying
/// `{"total_cost": null}` is an answer, a timeout or a `503` is not. Every reader that cannot see
/// that boundary keeps the conservative collapse via the default method below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendObservation {
    /// The spend source answered with a `SUM` over at least one matching row. `Answered(0)` is a
    /// real zero -- an account whose logged events happened to cost nothing -- and is NOT the
    /// same thing as [`Self::Empty`].
    Answered(i64),
    /// The spend source answered, and it holds no matching rows at all (SQL `NULL` sum). For a
    /// refill decision this is indistinguishable from a broken ingest pipeline and must fail
    /// closed; for the gateway's remaining-budget read it is the ordinary state of every account
    /// at the start of every period and counts as zero spend. Keeping it as its own variant is
    /// what lets each caller make that choice explicitly instead of inheriting the other's.
    Empty,
    /// The spend source could not be asked, or answered something unusable. Every caller must
    /// route this to its strictest branch; it is never zero.
    Unreachable,
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

    /// The same reading, with "answered but empty" separated from "could not ask" -- see
    /// [`SpendObservation`] for which caller needs that and why.
    ///
    /// The default implementation derives it from [`Self::spend_for_account`], which means it
    /// reports `Unreachable` for both cases: an implementation that cannot see the transport
    /// boundary genuinely cannot tell them apart, and guessing in the permissive direction here
    /// would silently turn a broken spend source into "spent nothing, go ahead". Only
    /// [`UsageServiceSpendReader`], which does see the boundary, overrides this.
    async fn observe_spend_for_account(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        Ok(match self.spend_for_account(account_id, period).await? {
            Spend::Known(micros) => SpendObservation::Answered(micros),
            Spend::Unavailable => SpendObservation::Unreachable,
        })
    }
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

impl UsageServiceSpendReader {
    /// The single HTTP round-trip behind both [`SpendReader`] methods, returning the finer-
    /// grained [`SpendObservation`]. `spend_for_account` collapses `Answered(0)`-from-no-rows
    /// back into `Spend::Unavailable` so its documented contract is bit-for-bit unchanged; only
    /// `observe_spend_for_account` sees the distinction.
    async fn observe(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
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
                return Ok(SpendObservation::Unreachable);
            }
        };

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "usage-service spend query returned a non-success status; treating spend as unavailable"
            );
            return Ok(SpendObservation::Unreachable);
        }

        let body: SpendQueryResponse = match response.json().await {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "usage-service spend query returned a body that did not parse; treating spend as unavailable"
                );
                return Ok(SpendObservation::Unreachable);
            }
        };

        match body.total_cost {
            // A `200` carrying a SQL `NULL` sum: the usage service ANSWERED, and it holds no rows
            // for this account/period. `spend_for_account` below still collapses this into
            // `Spend::Unavailable` -- a refill must never be decided on an unverified zero -- but
            // the gateway's remaining-budget read needs the distinction (see `SpendObservation`).
            None => Ok(SpendObservation::Empty),
            Some(total_cost) => match validate_total_cost_micros(total_cost) {
                Ok(micros) => Ok(SpendObservation::Answered(micros)),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "usage-service spend query returned an unusable total_cost value; treating spend as unavailable"
                    );
                    Ok(SpendObservation::Unreachable)
                }
            },
        }
    }
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for UsageServiceSpendReader {
    /// Unchanged contract: an empty `SUM` and an unreachable usage service are BOTH
    /// `Spend::Unavailable` here, exactly as before `observe` was split out -- see this type's
    /// "Fail-closed contract" section, which still describes this method exactly.
    async fn spend_for_account(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(match self.observe(account_id, period).await? {
            SpendObservation::Answered(micros) => Spend::Known(micros),
            // The two halves collapse here, and only here: this method's documented contract is
            // "no rows and no answer are both `Unavailable`", and it is unchanged by the split.
            SpendObservation::Empty | SpendObservation::Unreachable => Spend::Unavailable,
        })
    }

    async fn observe_spend_for_account(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        self.observe(account_id, period).await
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
