//! Per-client refresh-token TTL overrides (repo owner request: "the duration of a refresh token
//! should be configurable on the client entry in the .yaml config file").
//!
//! Covers `OauthClient::refresh_ttl_seconds`/`refresh_absolute_ttl_seconds` end to end at the two
//! seams that matter:
//! - [`ConfigClientStore::refresh_ttls`] (`oauth2_op::client_store`), the per-request resolution
//!   `TokenExchangeOpStore`'s minting paths read instead of `Oauth2TokenExchange` directly.
//! - [`validate_client_refresh_ttls`] (`oauth2_op::refresh_ttl`), the `start_idp_server` startup
//!   gate that refuses to start when a client's EFFECTIVE per-token TTL is non-positive or
//!   exceeds its EFFECTIVE absolute chain cap.
//!
//! Fully offline: no Postgres, no Redis, no Docker -- both seams are pure config resolution.

use lightbridge_authz_core::config::{Oauth2TokenExchange, OauthClient, OauthClientType};
use lightbridge_authz_rest::oauth2_op::client_store::ConfigClientStore;
use lightbridge_authz_rest::oauth2_op::refresh_ttl::validate_client_refresh_ttls;

fn global_cfg() -> Oauth2TokenExchange {
    Oauth2TokenExchange {
        enabled: true,
        access_ttl_seconds: 900,
        authorization_code_ttl_seconds: 300,
        refresh_ttl_seconds: 2_592_000,
        allowed_scopes: vec!["openid".to_string(), "offline_access".to_string()],
        refresh_absolute_ttl_seconds: 7_776_000,
        refresh_reuse_grace_seconds: 30,
        device_code_ttl_seconds: 600,
        device_poll_interval_seconds: 5,
        device_verification_uri: "https://authz.example.test/device/verify".to_string(),
        client_credentials_ttl_seconds: 900,
    }
}

fn client(client_id: &str) -> OauthClient {
    OauthClient {
        client_id: client_id.to_string(),
        client_type: OauthClientType::Public,
        scopes: vec!["openid".to_string(), "offline_access".to_string()],
        grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
        allowed_audiences: vec![client_id.to_string()],
        jwks: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

/// No override: `ConfigClientStore::refresh_ttls` falls back to the global pair.
#[tokio::test]
async fn absence_falls_back_to_the_global_ttls() {
    let store = ConfigClientStore::from_config(&[client("lightbridge-ss")], &global_cfg());
    assert_eq!(store.refresh_ttls("lightbridge-ss"), (2_592_000, 7_776_000));
}

/// A client override is honoured for BOTH values -- not just `refresh_ttl_seconds` alone (the
/// half-working-feature config trap the task description calls out).
#[tokio::test]
async fn a_client_override_is_honoured_for_both_values() {
    let mut overridden = client("long-lived-client");
    overridden.refresh_ttl_seconds = Some(15_552_000); // 180 days
    overridden.refresh_absolute_ttl_seconds = Some(31_536_000); // 365 days
    let store =
        ConfigClientStore::from_config(&[overridden, client("lightbridge-ss")], &global_cfg());
    assert_eq!(
        store.refresh_ttls("long-lived-client"),
        (15_552_000, 31_536_000)
    );
    // A different, non-overriding client in the same config still gets the global pair.
    assert_eq!(store.refresh_ttls("lightbridge-ss"), (2_592_000, 7_776_000));
}

/// A client may override just one of the two fields; the other still falls back to global.
#[tokio::test]
async fn a_partial_override_falls_back_only_for_the_unset_field() {
    let mut ttl_only = client("ttl-only-client");
    ttl_only.refresh_ttl_seconds = Some(60);
    let store = ConfigClientStore::from_config(&[ttl_only], &global_cfg());
    assert_eq!(store.refresh_ttls("ttl-only-client"), (60, 7_776_000));
}

/// An unknown client id (never expected in production -- see `refresh_ttls`' own doc comment)
/// still resolves to the global pair rather than panicking.
#[tokio::test]
async fn unknown_client_id_falls_back_to_the_global_ttls() {
    let store = ConfigClientStore::from_config(&[client("lightbridge-ss")], &global_cfg());
    assert_eq!(store.refresh_ttls("nope"), (2_592_000, 7_776_000));
}

/// The success path: every client's effective TTLs are valid (override or global), so startup
/// validation passes.
#[tokio::test]
async fn validation_passes_when_every_effective_ttl_is_sound() {
    let mut overridden = client("long-lived-client");
    overridden.refresh_ttl_seconds = Some(15_552_000);
    overridden.refresh_absolute_ttl_seconds = Some(31_536_000);
    assert!(
        validate_client_refresh_ttls(&[overridden, client("lightbridge-ss")], &global_cfg())
            .is_ok()
    );
}

/// THE config trap this ticket exists to prevent: a client configured for a longer per-token TTL
/// than its (here, still-global) absolute chain cap must refuse startup, naming the client id and
/// both values -- see house rule "Startup validation, fail loudly" in the task description.
#[tokio::test]
async fn startup_is_refused_when_a_clients_per_token_ttl_exceeds_its_absolute_cap() {
    let mut overridden = client("misconfigured-client");
    // Global refresh_absolute_ttl_seconds is 7_776_000 (90 days); this client asks for a
    // 180-day-long individual token -- every token minted for it would be killed by the still-90-
    // day chain cap before its own expiry ever took effect.
    overridden.refresh_ttl_seconds = Some(15_552_000);
    let Err(err) = validate_client_refresh_ttls(&[overridden], &global_cfg()) else {
        panic!(
            "expected an error: misconfigured-client's effective refresh_ttl_seconds \
             (15552000) exceeds its effective refresh_absolute_ttl_seconds (7776000)"
        );
    };
    let message = format!("{err}");
    assert!(message.contains("misconfigured-client"));
    assert!(message.contains("15552000"));
    assert!(message.contains("7776000"));
}

/// The boundary case: an effective per-token TTL EQUAL to the absolute cap is accepted (the task
/// description's own boundary condition is `<=`, not strict `<`).
#[tokio::test]
async fn an_effective_ttl_equal_to_the_absolute_cap_is_accepted() {
    let mut overridden = client("boundary-client");
    overridden.refresh_ttl_seconds = Some(7_776_000);
    overridden.refresh_absolute_ttl_seconds = Some(7_776_000);
    assert!(validate_client_refresh_ttls(&[overridden], &global_cfg()).is_ok());
}

/// A non-positive effective per-token TTL is refused even when the absolute cap is fine.
#[tokio::test]
async fn a_non_positive_effective_ttl_is_refused() {
    let mut overridden = client("zero-ttl-client");
    overridden.refresh_ttl_seconds = Some(0);
    let Err(err) = validate_client_refresh_ttls(&[overridden], &global_cfg()) else {
        panic!("expected an error for a non-positive effective refresh_ttl_seconds");
    };
    assert!(format!("{err}").contains("zero-ttl-client"));
}

/// A non-positive effective absolute cap is refused even when the per-token TTL is fine.
#[tokio::test]
async fn a_non_positive_effective_absolute_ttl_is_refused() {
    let mut overridden = client("zero-absolute-client");
    overridden.refresh_absolute_ttl_seconds = Some(0);
    let Err(err) = validate_client_refresh_ttls(&[overridden], &global_cfg()) else {
        panic!("expected an error for a non-positive effective refresh_absolute_ttl_seconds");
    };
    assert!(format!("{err}").contains("zero-absolute-client"));
}

/// A config declaring no clients at all still gets the global pair validated -- the check this
/// module subsumed from `build_token_exchange_state`'s own former inline global-only check.
#[tokio::test]
async fn no_clients_configured_still_validates_the_bare_global_pair() {
    let mut bad_global = global_cfg();
    bad_global.refresh_absolute_ttl_seconds = 100;
    bad_global.refresh_ttl_seconds = 200;
    let Err(err) = validate_client_refresh_ttls(&[], &bad_global) else {
        panic!(
            "expected an error: the global refresh_ttl_seconds exceeds refresh_absolute_ttl_seconds"
        );
    };
    assert!(format!("{err}").contains("<global>"));
}
