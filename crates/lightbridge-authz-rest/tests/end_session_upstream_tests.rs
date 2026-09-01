// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! The upstream half of RP-initiated logout: `/oauth2/end_session` must terminate the *Keycloak*
//! SSO session, not merely the local one.
//!
//! The bug this file exists for was reported from production: logout revoked every local session
//! and cleared the cookie, but never touched Keycloak, so the user's next `/authorize` silently
//! re-authenticated with no prompt. From the user's seat they had not logged out at all.
//!
//! Two properties, pulling in opposite directions, and the second is the one that is easy to
//! regress into a worse bug than the one being fixed:
//!
//! 1. **A healthy Keycloak is actually told.** A back-channel `POST` to the discovered
//!    `end_session_endpoint` carrying `client_id` + the stored `refresh_token` (+ `client_secret`
//!    for a confidential client).
//! 2. **Nothing upstream can block local logout.** Keycloak unreachable, Keycloak refusing, no
//!    stored refresh token, an envelope sealed under a since-rotated `token_encryption_key`, no
//!    federated identity at all -- every one of those must still leave the local session revoked.
//!    A logout that fails because a third party is down leaves the user *more* signed in than if
//!    it had never been attempted.
//!
//! Plus the standing credential rule: the refresh token now flows through a new code path, so
//! `KeycloakTokenSet`'s redacting `Debug` is asserted here too.
//!
//! Mutation-checked -- each mutation below was applied to the fixed code, the named tests were
//! watched go red for the predicted reason, and the code was restored before the next one:
//!
//! - Deleting the `end_upstream_session(relying_party, &subject).await` call from
//!   `revoke_sessions_for_cookie` -- i.e. reinstating the reported production bug -- turns
//!   `logout_ends_the_upstream_keycloak_sso_session`,
//!   `a_confidential_client_authenticates_its_back_channel_logout` and
//!   `a_keycloak_that_refuses_the_logout_does_not_block_local_logout` red on a mock call count of
//!   0 against an expected 1.
//! - Making the upstream leg fatal (`relying_party.end_upstream_session(..).await.map_err(|_| ())?`
//!   in place of the swallowing call) turns `an_unreachable_keycloak_does_not_block_local_logout`
//!   and `a_keycloak_that_refuses_the_logout_does_not_block_local_logout` red:
//!   `Err(LocalRevocationFailed)` where
//!   `Ok(true)` was expected, which at the router is the hard `500`.
//! - Propagating `crypto::open`'s failure with `?` instead of degrading to "no stored credential"
//!   turns `an_envelope_under_a_rotated_key_is_treated_as_no_stored_credential` red on its
//!   `UpstreamLogout::NoStoredCredential` assertion. Note this mutation is invisible to the
//!   side-effect assertions alone -- `revoke_sessions_for_cookie` swallows an `Err` too -- which
//!   is exactly why that test asserts the classification directly.
//! - Dropping the `client_secret` form field turns
//!   `a_confidential_client_authenticates_its_back_channel_logout` red, and nothing else: a
//!   deployment with a public client would never have noticed.
//! - Sealing/opening under the row id instead of the `(issuer, subject)` AAD turns the same three
//!   call-count tests red -- the envelope simply stops opening.
//! - Swapping `KeycloakTokenSet`'s hand-written `Debug` for a derived one turns
//!   `keycloak_token_set_debug_never_leaks_the_refresh_token` red, printing the token in full.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine;
use chrono::{Duration, Utc};
use cratestack_axum::ratelimit::{InMemoryRateLimitStore, RateLimitStore};
use httpmock::Method::{GET, POST};
use httpmock::MockServer;
use lightbridge_authz_api_key::entities::federated_identity_row::UpsertFederatedIdentity;
use lightbridge_authz_api_key::entities::session_row::NewSession;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::OidcRelyingParty;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::dto::{CreateAccount, CreateProject};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_rest::end_session::revoke_sessions_for_cookie;
use lightbridge_authz_rest::relying_party::{
    IdTokenClaimsSnapshot, KeycloakRelyingParty, KeycloakTokenSet, UpstreamLogout,
};
use lightbridge_authz_rest::session_cookie::SESSION_COOKIE_NAME;
use sqlx::PgPool;

const STATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// Deliberately distinct from [`STATE_KEY`] -- `KeycloakRelyingParty::new` rejects a config where
/// the two are equal (ADR-0024).
const TOKEN_KEY: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
/// A *third* valid key, standing in for the operator having rotated `token_encryption_key` since
/// the envelope at rest was sealed. ADR-0024's documented posture: there is no key history, so
/// every older envelope becomes permanently unopenable.
const ROTATED_TOKEN_KEY: &str = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M";

const SUBJECT: &str = "keycloak-subject";
const REFRESH_TOKEN: &str = "keycloak-refresh-token-value";

fn repo(pool: PgPool) -> Arc<StoreRepo> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(pool))
}

fn rate_limiter() -> Arc<dyn RateLimitStore> {
    Arc::new(InMemoryRateLimitStore::new())
}

fn rp_config(client_secret: Option<&str>) -> OidcRelyingParty {
    OidcRelyingParty {
        client_id: "authz-idp-rp".to_string(),
        callback_url: "https://authz.example.test/idp/callback".to_string(),
        client_secret: client_secret.map(str::to_string),
        state_encryption_key: STATE_KEY.to_string(),
        token_encryption_key: TOKEN_KEY.to_string(),
        timeout_ms: 500,
        browser_session_ttl_seconds: 28_800,
    }
}

fn key_bytes(encoded: &str) -> [u8; 32] {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .unwrap()
        .try_into()
        .unwrap()
}

/// A discovery document that advertises `end_session_endpoint` -- the field the logout leg reads.
/// `issuer` is the mock's own base URL because the relying party validates the fetched document's
/// issuer against the IDENTITY issuer it was constructed with.
async fn mock_discovery(keycloak: &MockServer) {
    keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(serde_json::json!({
                "issuer": keycloak.base_url(),
                "authorization_endpoint": keycloak.url("/authorize"),
                "token_endpoint": keycloak.url("/token"),
                "jwks_uri": keycloak.url("/jwks"),
                "end_session_endpoint": keycloak.url("/logout"),
            }));
        })
        .await;
}

fn relying_party(
    config: OidcRelyingParty,
    issuer: String,
    discovery_url: String,
    repo: Arc<StoreRepo>,
) -> KeycloakRelyingParty {
    KeycloakRelyingParty::new(
        config,
        issuer,
        discovery_url,
        "https://keycloak.example.test/jwks".to_string(),
        repo,
        rate_limiter(),
    )
    .unwrap()
}

fn token_set(refresh_token: Option<&str>, issuer: &str) -> KeycloakTokenSet {
    KeycloakTokenSet {
        refresh_token: refresh_token.map(str::to_string),
        id_token_claims: IdTokenClaimsSnapshot {
            sub: SUBJECT.to_string(),
            iss: issuer.to_string(),
            email: Some("subject@example.test".to_string()),
            email_verified: Some(true),
            preferred_username: Some("subject".to_string()),
            name: Some("A Subject".to_string()),
            auth_time: Some(Utc::now().timestamp()),
            sid: Some("keycloak-sid".to_string()),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        token_type: Some("Bearer".to_string()),
        session_state: Some("session-state-value".to_string()),
    }
}

/// Seals `set` exactly as `persist_federated_identity` does -- same AAD (`issuer \u{1f} subject`,
/// the federation key, never the row id) -- and persists it, so the logout leg reads a row
/// indistinguishable from one a real login wrote.
async fn store_federated_identity(
    repo: &StoreRepo,
    issuer: &str,
    key: &str,
    set: &KeycloakTokenSet,
) {
    let plaintext = serde_json::to_vec(set).unwrap();
    let aad = format!("{issuer}\u{1f}{SUBJECT}");
    let envelope = lightbridge_authz_core::crypto::seal(&key_bytes(key), &aad, &plaintext).unwrap();
    repo.upsert_federated_identity(
        UpsertFederatedIdentity {
            issuer: issuer.to_string(),
            subject: SUBJECT.to_string(),
            token_envelope: Some(envelope),
            token_sealed_at: Some(Utc::now()),
            access_expires_at: Some(Utc::now() + Duration::minutes(5)),
            refresh_expires_at: Some(Utc::now() + Duration::minutes(30)),
            scope: Some("openid profile email".to_string()),
            email: None,
            email_verified: None,
            preferred_username: None,
            name: None,
        },
        issuer,
    )
    .await
    .unwrap();
}

/// An account, its default project, and one active browser session bound to [`SUBJECT`] as the
/// real acting subject -- the exact shape `KeycloakRelyingParty::complete`'s browser arm creates.
/// Returns the session id, which the cookie below carries.
async fn seed_browser_session(repo: &StoreRepo) -> String {
    repo.create_account(
        &AccountId::assert_already_resolved(SUBJECT),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .unwrap();
    let account = AccountId::assert_already_resolved(SUBJECT);
    repo.create_project(
        &account,
        SUBJECT,
        CreateProject {
            name: "logout project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "logout-binding".to_string(),
            project_quota: None,
        },
        "logout-project".to_string(),
    )
    .await
    .unwrap();
    let project_id = repo
        .find_default_project_id(&account)
        .await
        .unwrap()
        .unwrap();
    let session = repo
        .create_session(NewSession {
            id: cuid2(),
            account_id: SUBJECT.to_string(),
            project_id,
            client_id: None,
            kind: "browser".to_string(),
            expires_at: Utc::now() + Duration::hours(8),
            subject: Some(SUBJECT.to_string()),
        })
        .await
        .unwrap();
    session.id
}

fn cookie_headers(session_id: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{SESSION_COOKIE_NAME}={session_id}")).unwrap(),
    );
    headers
}

/// The property the whole endpoint is judged on, asserted directly against the database rather
/// than inferred from a status code: after logout there is no active browser session left for
/// this id.
async fn assert_locally_revoked(repo: &StoreRepo, session_id: &str) {
    assert!(
        repo.find_active_browser_session(session_id, Utc::now())
            .await
            .unwrap()
            .is_none(),
        "local logout must have revoked the browser session regardless of what Keycloak did"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn logout_ends_the_upstream_keycloak_sso_session(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    mock_discovery(&keycloak).await;
    // The assertion that closes the reported bug: a back-channel POST carrying the client and the
    // stored refresh token. `body_includes` on both, so a request missing either does not match
    // and the hit count below stays 0.
    let logout = keycloak
        .mock_async(|when, then| {
            when.method(POST)
                .path("/logout")
                .body_includes("client_id=authz-idp-rp")
                .body_includes(format!("refresh_token={REFRESH_TOKEN}"));
            then.status(204);
        })
        .await;
    let repo = repo(pool);
    let session_id = seed_browser_session(&repo).await;
    store_federated_identity(
        &repo,
        &keycloak.base_url(),
        TOKEN_KEY,
        &token_set(Some(REFRESH_TOKEN), &keycloak.base_url()),
    )
    .await;
    let rp = relying_party(
        rp_config(None),
        keycloak.base_url(),
        keycloak.base_url(),
        repo.clone(),
    );

    let ended = revoke_sessions_for_cookie(&repo, &rp, &cookie_headers(&session_id)).await;

    assert_eq!(ended, Ok(true));
    logout.assert_calls_async(1).await;
    assert_locally_revoked(&repo, &session_id).await;
    assert_eq!(
        rp.end_upstream_session(SUBJECT).await.unwrap(),
        UpstreamLogout::Terminated,
        "a Keycloak that accepted the back-channel logout must be reported as terminated, not as \
         a missing credential -- the log line an operator reads on 'why am I still signed in' \
         depends on the difference"
    );
}

/// A confidential client must authenticate its back-channel logout, or Keycloak rejects it and
/// the SSO session survives -- the original bug with an extra step.
#[sqlx::test(migrations = "../../migrations")]
async fn a_confidential_client_authenticates_its_back_channel_logout(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    mock_discovery(&keycloak).await;
    let logout = keycloak
        .mock_async(|when, then| {
            when.method(POST)
                .path("/logout")
                .body_includes("client_secret=rp-client-secret");
            then.status(204);
        })
        .await;
    let repo = repo(pool);
    let session_id = seed_browser_session(&repo).await;
    store_federated_identity(
        &repo,
        &keycloak.base_url(),
        TOKEN_KEY,
        &token_set(Some(REFRESH_TOKEN), &keycloak.base_url()),
    )
    .await;
    let rp = relying_party(
        rp_config(Some("rp-client-secret")),
        keycloak.base_url(),
        keycloak.base_url(),
        repo.clone(),
    );

    assert_eq!(
        revoke_sessions_for_cookie(&repo, &rp, &cookie_headers(&session_id)).await,
        Ok(true)
    );
    logout.assert_calls_async(1).await;
}

/// Keycloak entirely unreachable -- discovery dialled at a port nothing is listening on. This is
/// the outage case, and it must be indistinguishable from a normal logout as far as the user's
/// own session is concerned.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreachable_keycloak_does_not_block_local_logout(pool: PgPool) {
    let repo = repo(pool);
    let session_id = seed_browser_session(&repo).await;
    let issuer = "https://keycloak.example.test/realms/dev".to_string();
    store_federated_identity(
        &repo,
        &issuer,
        TOKEN_KEY,
        &token_set(Some(REFRESH_TOKEN), &issuer),
    )
    .await;
    let rp = relying_party(
        rp_config(None),
        issuer,
        "http://127.0.0.1:1".to_string(),
        repo.clone(),
    );

    assert_eq!(
        revoke_sessions_for_cookie(&repo, &rp, &cookie_headers(&session_id)).await,
        Ok(true),
        "an unreachable Keycloak must never surface as logout's hard 500"
    );
    assert_locally_revoked(&repo, &session_id).await;
}

/// Keycloak reachable but refusing (an expired or already-used refresh token is the common cause).
#[sqlx::test(migrations = "../../migrations")]
async fn a_keycloak_that_refuses_the_logout_does_not_block_local_logout(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    mock_discovery(&keycloak).await;
    let logout = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/logout");
            then.status(400)
                .json_body(serde_json::json!({ "error": "invalid_grant" }));
        })
        .await;
    let repo = repo(pool);
    let session_id = seed_browser_session(&repo).await;
    store_federated_identity(
        &repo,
        &keycloak.base_url(),
        TOKEN_KEY,
        &token_set(Some(REFRESH_TOKEN), &keycloak.base_url()),
    )
    .await;
    let rp = relying_party(
        rp_config(None),
        keycloak.base_url(),
        keycloak.base_url(),
        repo.clone(),
    );

    assert_eq!(
        revoke_sessions_for_cookie(&repo, &rp, &cookie_headers(&session_id)).await,
        Ok(true),
        "a refused back-channel logout must never surface as logout's hard 500"
    );
    logout.assert_calls_async(1).await;
    assert_locally_revoked(&repo, &session_id).await;
}

/// A stored token set that never carried a refresh token (Keycloak omits one when the client is
/// not permitted them). There is nothing to send, so nothing is sent -- and logout still works.
#[sqlx::test(migrations = "../../migrations")]
async fn an_absent_refresh_token_means_no_upstream_call_at_all(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    mock_discovery(&keycloak).await;
    let logout = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/logout");
            then.status(204);
        })
        .await;
    let repo = repo(pool);
    let session_id = seed_browser_session(&repo).await;
    store_federated_identity(
        &repo,
        &keycloak.base_url(),
        TOKEN_KEY,
        &token_set(None, &keycloak.base_url()),
    )
    .await;
    let rp = relying_party(
        rp_config(None),
        keycloak.base_url(),
        keycloak.base_url(),
        repo.clone(),
    );

    assert_eq!(
        revoke_sessions_for_cookie(&repo, &rp, &cookie_headers(&session_id)).await,
        Ok(true)
    );
    assert_eq!(
        logout.calls_async().await,
        0,
        "with no stored refresh token there is nothing to authenticate a logout with; calling \
         anyway would be a guaranteed 400"
    );
    assert_locally_revoked(&repo, &session_id).await;
    assert_eq!(
        rp.end_upstream_session(SUBJECT).await.unwrap(),
        UpstreamLogout::NoStoredCredential
    );
}

/// `oauth2.relying_party.token_encryption_key` has been rotated since this envelope was sealed.
/// ADR-0024's documented posture is that such a row is permanently unopenable and must be treated
/// as "no stored token" -- never as an error, and never as a row to erase.
#[sqlx::test(migrations = "../../migrations")]
async fn an_envelope_under_a_rotated_key_is_treated_as_no_stored_credential(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    mock_discovery(&keycloak).await;
    let logout = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/logout");
            then.status(204);
        })
        .await;
    let repo = repo(pool);
    let session_id = seed_browser_session(&repo).await;
    store_federated_identity(
        &repo,
        &keycloak.base_url(),
        ROTATED_TOKEN_KEY,
        &token_set(Some(REFRESH_TOKEN), &keycloak.base_url()),
    )
    .await;
    let rp = relying_party(
        rp_config(None),
        keycloak.base_url(),
        keycloak.base_url(),
        repo.clone(),
    );

    assert_eq!(
        revoke_sessions_for_cookie(&repo, &rp, &cookie_headers(&session_id)).await,
        Ok(true)
    );
    assert_eq!(logout.calls_async().await, 0);
    assert_locally_revoked(&repo, &session_id).await;
    assert!(
        repo.find_federated_identity(&keycloak.base_url(), SUBJECT)
            .await
            .unwrap()
            .is_some(),
        "an unopenable envelope is not a corrupt row to be deleted -- the next login re-seals it"
    );
    // The classification itself, not just its side effects: `crypto`'s documented `open()`
    // contract says a rotated key is a MISSING credential, not an error. Asserted directly
    // because `revoke_sessions_for_cookie` swallows both alike, so nothing above would notice a
    // regression that started propagating the decrypt failure instead.
    assert_eq!(
        rp.end_upstream_session(SUBJECT).await.unwrap(),
        UpstreamLogout::NoStoredCredential
    );
}

/// No `federated_identities` row at all: a session that predates ADR-0024's persistence, or one
/// whose account was adopted through some other path. Logout is still a success.
#[sqlx::test(migrations = "../../migrations")]
async fn a_subject_with_no_federated_identity_still_logs_out(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    mock_discovery(&keycloak).await;
    let logout = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/logout");
            then.status(204);
        })
        .await;
    let repo = repo(pool);
    let session_id = seed_browser_session(&repo).await;
    let rp = relying_party(
        rp_config(None),
        keycloak.base_url(),
        keycloak.base_url(),
        repo.clone(),
    );

    assert_eq!(
        revoke_sessions_for_cookie(&repo, &rp, &cookie_headers(&session_id)).await,
        Ok(true)
    );
    assert_eq!(logout.calls_async().await, 0);
    assert_locally_revoked(&repo, &session_id).await;
}

/// The refresh token is now read back out of storage and put on the wire, so the one thing that
/// must never happen is it landing in a log line via an incidental `{:?}`. Same rule, and the same
/// hand-written `Debug`, as `TokenResponse`'s in `relying_party_tests.rs`.
#[test]
fn keycloak_token_set_debug_never_leaks_the_refresh_token() {
    let rendered = format!(
        "{:?}",
        token_set(
            Some(REFRESH_TOKEN),
            "https://keycloak.example.test/realms/dev"
        )
    );
    assert!(
        !rendered.contains(REFRESH_TOKEN),
        "KeycloakTokenSet's Debug must redact the refresh token, got {rendered}"
    );
    assert!(rendered.contains("<redacted>"));
    assert!(
        rendered.contains("session-state-value"),
        "the non-credential fields must still be printable, or the redaction is untestable noise"
    );
}
