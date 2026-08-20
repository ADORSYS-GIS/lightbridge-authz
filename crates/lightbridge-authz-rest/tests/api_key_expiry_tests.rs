// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests` (clippy.toml) does
// not reach their free helper functions -- mirrors `rpc_it_tests.rs`'s identical header.
#![allow(clippy::unwrap_used)]

//! lightbridge-authz#395: "all api-keys created from our system MUST have an expiry date...
//! custom should be about around max 90 days." Covers `AuthzStoreImpl::create_api_key`'s and
//! `rotate_api_key`'s `expires_at` validation (`validate_expires_at` in
//! `crates/lightbridge-authz-rest/src/handlers/mod.rs`, private to that module -- exercised here
//! through the `pub` `create_api_key`/`rotate_api_key` methods instead, per AGENTS.md's "new tests
//! go in `tests/`, not `src/`").
//!
//! Every case here uses `lazy_pool()` (a dead Postgres connection with a short acquire timeout),
//! exactly like the existing billing-plan/quota-tier validation tests in
//! `crates/lightbridge-authz-rest/src/handlers/mod.rs`'s own `#[cfg(test)]` module: a case that
//! should be REJECTED must fail with `BadRequest` *before* ever touching the (unreachable) DB,
//! proving the check runs first. A case that should be ACCEPTED is expected to instead fail with a
//! connection error once validation lets it through -- that failure is the proof the validation
//! layer did not itself reject it.

use chrono::{Duration, Utc};
use lightbridge_authz_core::config::{ApiKeyExpiry, Billing, BillingPlan};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{CreateApiKey, RotateApiKey};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

fn lazy_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/x")
        .unwrap();
    Arc::new(DbPool::from_pool(pool))
}

/// `Billing::is_allowed` (unlike `QuotaTiers`/`ApiKeyExpiry`) has no "empty catalogue accepts
/// anything" fallback -- an empty catalogue rejects every plan id. `create_input` below always
/// requests the `"free"` plan, and `create_api_key` checks `billing_plan` before `expires_at`, so
/// every store built here needs a real catalogue or every case in this file would fail on the
/// billing check instead of the expiry check it's actually testing.
fn configured_billing() -> Billing {
    Billing {
        plans: vec![BillingPlan {
            id: "free".to_string(),
            name: "Free".to_string(),
            limits: None,
        }],
    }
}

fn store_with_cap(max_lifetime_days: u32) -> AuthzStoreImpl {
    AuthzStoreImpl::with_pool(lazy_pool())
        .with_billing(configured_billing())
        .with_api_key_expiry(ApiKeyExpiry { max_lifetime_days })
}

fn create_input(expires_at: Option<chrono::DateTime<Utc>>) -> CreateApiKey {
    CreateApiKey {
        name: "k".to_string(),
        expires_at,
        billing_plan: "free".to_string(),
    }
}

fn assert_rejected_before_db(err: &Error, needle: &str) {
    assert!(
        matches!(err, Error::BadRequest(m) if m.contains(needle)),
        "expected a BadRequest containing {needle:?} (proving rejection happened before any DB \
         access), got: {err}"
    );
}

/// A case that clears validation must fail differently -- via the dead DB connection, not via
/// `BadRequest` -- proving validation did not itself block it.
fn assert_accepted_by_validation(err: &Error) {
    assert!(
        !matches!(err, Error::BadRequest(_)),
        "a compliant expiresAt must not be rejected by validate_expires_at, got: {err}"
    );
}

// ---------------------------------------------------------------------------------------------
// createApiKey
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn create_api_key_rejects_missing_expiry() {
    let store = store_with_cap(90);
    let err = store
        .create_api_key("subject", None, "proj", create_input(None))
        .await
        .unwrap_err();
    assert_rejected_before_db(&err, "expiresAt is required");
}

#[tokio::test]
async fn create_api_key_rejects_a_past_expiry() {
    let store = store_with_cap(90);
    let past = Utc::now() - Duration::minutes(5);
    let err = store
        .create_api_key("subject", None, "proj", create_input(Some(past)))
        .await
        .unwrap_err();
    assert_rejected_before_db(&err, "must be in the future");
}

#[tokio::test]
async fn create_api_key_rejects_an_expiry_beyond_the_configured_cap() {
    let store = store_with_cap(90);
    let beyond_cap = Utc::now() + Duration::days(91);
    let err = store
        .create_api_key("subject", None, "proj", create_input(Some(beyond_cap)))
        .await
        .unwrap_err();
    assert_rejected_before_db(&err, "exceeds the configured maximum");
}

#[tokio::test]
async fn create_api_key_accepts_an_expiry_within_the_cap() {
    let store = store_with_cap(90);
    let within_cap = Utc::now() + Duration::days(30);
    let err = store
        .create_api_key("subject", None, "proj", create_input(Some(within_cap)))
        .await
        .unwrap_err();
    assert_accepted_by_validation(&err);
}

/// The boundary itself: `now + max_lifetime_days` exactly must be accepted, not rejected --
/// `validate_expires_at` uses `>` (strictly beyond), not `>=`, for the cap comparison.
#[tokio::test]
async fn create_api_key_accepts_an_expiry_exactly_at_the_cap() {
    let store = store_with_cap(90);
    // A few seconds of slack for the gap between this `now` and the one `validate_expires_at`
    // computes internally -- without it, a slow CI run could tip `at_cap` a hair below the
    // server's own `now + 90d`, spuriously failing this boundary assertion.
    let at_cap = Utc::now() + Duration::days(90) - Duration::seconds(5);
    let err = store
        .create_api_key("subject", None, "proj", create_input(Some(at_cap)))
        .await
        .unwrap_err();
    assert_accepted_by_validation(&err);
}

// ---------------------------------------------------------------------------------------------
// rotateApiKey
// ---------------------------------------------------------------------------------------------

/// `rotate_api_key` looks the existing key up first (`repo.get_api_key`), which fails against the
/// dead pool before `validate_expires_at` ever runs -- so rotate's own expiry validation cannot be
/// isolated the same "before any DB access" way `create_api_key`'s can with only `lazy_pool()`.
/// This asserts the one thing observable without a real key to rotate: a caller-supplied
/// `expires_at` that fails validation must not silently reach `resolve_rotated_expires_at` and
/// beyond -- confirmed indirectly by the fact any rejection surfaces at all as `NotFound` (the
/// lookup), not by a different, later error shape a validation bug might have introduced. The
/// real "rotate enforces the cap" coverage lives in `rpc_it_tests.rs` against a real database.
#[tokio::test]
async fn rotate_api_key_reaches_the_lookup_first() {
    let store = store_with_cap(90);
    let err = store
        .rotate_api_key(
            "subject",
            None,
            "key_1",
            RotateApiKey {
                name: None,
                expires_at: None,
                grace_period_seconds: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        !matches!(err, Error::BadRequest(_)),
        "rotate's lookup should fail (dead pool) before expiry validation ever runs, got: {err}"
    );
}

// ---------------------------------------------------------------------------------------------
// ApiKeyExpiry config plumbing
// ---------------------------------------------------------------------------------------------

/// `AuthzStoreImpl::with_pool`'s default `ApiKeyExpiry` must be the real 90-day ceiling, not
/// "unlimited" -- otherwise a server built without threading real config through (a bug, not a
/// supported mode) would silently accept unbounded expiries instead of failing loudly.
#[tokio::test]
async fn default_store_enforces_the_default_ninety_day_cap() {
    let store = AuthzStoreImpl::with_pool(lazy_pool()).with_billing(configured_billing());
    let beyond_default_cap = Utc::now() + Duration::days(91);
    let err = store
        .create_api_key(
            "subject",
            None,
            "proj",
            create_input(Some(beyond_default_cap)),
        )
        .await
        .unwrap_err();
    assert_rejected_before_db(&err, "exceeds the configured maximum");
}

#[tokio::test]
async fn a_lower_configured_cap_is_honored() {
    let store = store_with_cap(30);
    let beyond_thirty_days = Utc::now() + Duration::days(31);
    let err = store
        .create_api_key(
            "subject",
            None,
            "proj",
            create_input(Some(beyond_thirty_days)),
        )
        .await
        .unwrap_err();
    assert_rejected_before_db(&err, "exceeds the configured maximum");
}
