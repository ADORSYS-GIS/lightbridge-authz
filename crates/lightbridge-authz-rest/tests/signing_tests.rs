// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::signing::{ApiKeyJwtSigner, capped_expiry, generate_rs256_key};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

const ISSUER: &str = "https://authz.example.test";

fn signing_cfg(ttl: i64) -> JwtSigning {
    JwtSigning {
        issuer: ISSUER.to_string(),
        audience: Some("lightbridge-api-key".to_string()),
        ttl_seconds: ttl,
        max_key_age_days: 30,
    }
}

fn lazy_repo() -> Arc<lightbridge_authz_api_key::repo::StoreRepo> {
    let pool = PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool");
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(lightbridge_authz_api_key::repo::StoreRepo::new(pool))
}

#[derive(Serialize, Deserialize)]
struct Probe {
    sub: String,
    exp: i64,
}

/// Verifies the generated keypair is matched and its JWK is usable: sign with the PEM, verify
/// with the JWK's RSA components.
#[test]
fn keygen_produces_matched_keypair_and_jwk() {
    let key = generate_rs256_key().expect("keygen");
    assert_eq!(key.public_jwk["kid"], key.kid);
    assert_eq!(key.public_jwk["alg"], "RS256");

    let encoding = EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).expect("encoding key");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let token = encode(
        &header,
        &Probe {
            sub: "s".to_string(),
            exp: 4102444800,
        },
        &encoding,
    )
    .expect("sign");

    let decoding = DecodingKey::from_rsa_components(
        key.public_jwk["n"].as_str().unwrap(),
        key.public_jwk["e"].as_str().unwrap(),
    )
    .expect("decoding key");
    let data = decode::<Probe>(&token, &decoding, &Validation::new(Algorithm::RS256))
        .expect("verify against jwk");
    assert_eq!(data.claims.sub, "s");
}

#[tokio::test]
async fn from_config_builds_signer_for_valid_config() {
    assert!(ApiKeyJwtSigner::from_config(&signing_cfg(3600), lazy_repo()).is_ok());
}

#[tokio::test]
async fn debug_impl_omits_private_key_material() {
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), lazy_repo()).unwrap();
    let debug = format!("{signer:?}");
    assert!(debug.contains(ISSUER));
    assert!(
        !debug.to_lowercase().contains("private"),
        "Debug output must not expose private key material: {debug}"
    );
}

#[tokio::test]
async fn from_config_rejects_empty_issuer() {
    let mut cfg = signing_cfg(3600);
    cfg.issuer = "   ".to_string();
    let err = ApiKeyJwtSigner::from_config(&cfg, lazy_repo()).unwrap_err();
    assert!(format!("{err}").contains("issuer is required"));
}

#[tokio::test]
async fn from_config_rejects_non_positive_ttl() {
    let err = ApiKeyJwtSigner::from_config(&signing_cfg(0), lazy_repo()).unwrap_err();
    assert!(format!("{err}").contains("ttl_seconds must be positive"));
}

#[tokio::test]
async fn well_known_serves_cors_headers() {
    use axum::body::Body;
    use axum::http::{Request, header};
    use lightbridge_authz_rest::signing::well_known_router;
    use tower::ServiceExt;

    let response = well_known_router::<()>(ISSUER, lazy_repo(), None)
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("well-known responses must carry a CORS allow-origin header"),
        "*"
    );
}

#[tokio::test]
async fn jwks_endpoint_returns_server_error_when_repo_is_unreachable() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use lightbridge_authz_rest::signing::well_known_router;
    use serde_json::Value;
    use tower::ServiceExt;

    let response = well_known_router::<()>(ISSUER, lazy_repo(), None)
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["keys"].as_array().unwrap().len(), 0);
}

const CAP_TTL_SECONDS: i64 = 7_776_000;

#[test]
fn capped_expiry_honors_requested_within_cap() {
    let now = chrono::Utc::now();
    let requested = now + chrono::Duration::days(30);
    assert_eq!(
        capped_expiry(now, CAP_TTL_SECONDS, Some(requested)),
        requested
    );
}

#[test]
fn capped_expiry_clamps_requested_beyond_cap() {
    let now = chrono::Utc::now();
    let requested = now + chrono::Duration::days(365);
    let cap = now + chrono::Duration::seconds(CAP_TTL_SECONDS);
    assert_eq!(capped_expiry(now, CAP_TTL_SECONDS, Some(requested)), cap);
}

#[test]
fn capped_expiry_defaults_to_ttl_when_unrequested() {
    let now = chrono::Utc::now();
    let cap = now + chrono::Duration::seconds(CAP_TTL_SECONDS);
    assert_eq!(capped_expiry(now, CAP_TTL_SECONDS, None), cap);
}

#[test]
fn capped_expiry_ignores_past_request_to_avoid_dead_token() {
    let now = chrono::Utc::now();
    let cap = now + chrono::Duration::seconds(CAP_TTL_SECONDS);
    let past = now - chrono::Duration::days(1);
    assert_eq!(capped_expiry(now, CAP_TTL_SECONDS, Some(past)), cap);
}

/// OIDC Core §3.1.3.6 `at_hash`: SHA-256 the access token octets, take the left-most half, base64url
/// (no padding) encode it. Independently computed via Python (NOT this crate's implementation) so
/// this is a real known-vector test, not a self-check:
///
/// ```python
/// import hashlib, base64
/// d = hashlib.sha256(b"hello-world-access-token").digest()
/// base64.urlsafe_b64encode(d[:16]).rstrip(b"=").decode()
/// # => "7bwQYIKkMUJvb0oGYN1JlA"
/// ```
#[test]
fn at_hash_matches_independently_computed_vector() {
    use lightbridge_authz_rest::signing::compute_at_hash;
    assert_eq!(
        compute_at_hash("hello-world-access-token"),
        "7bwQYIKkMUJvb0oGYN1JlA"
    );
}

#[test]
fn at_hash_changes_with_the_access_token() {
    use lightbridge_authz_rest::signing::compute_at_hash;
    assert_ne!(
        compute_at_hash("token-a"),
        compute_at_hash("token-b"),
        "at_hash must actually bind to the access token, not return a constant"
    );
}

#[cfg(feature = "it-tests")]
mod db {
    use super::*;
    use chrono::{Duration, Utc};
    use lightbridge_authz_api_key::repo::StoreRepo;
    // `Billing`/`BillingPlan` are imported HERE, not at file scope: they are used only by this
    // `it-tests`-gated module, so a file-level import reads as unused on a build without the
    // feature (which is what `cargo fix` acted on) while being required with it.
    use lightbridge_authz_core::config::{Billing, BillingPlan, Oauth2};
    use lightbridge_authz_core::cuid::cuid2;
    use lightbridge_authz_core::{CreateAccount, CreateApiKey, CreateProject};
    use lightbridge_authz_rest::handlers::AuthzStoreImpl;
    use lightbridge_authz_rest::signing::{KeyOwner, bootstrap_signing_key};
    use serde_json::Value;
    use sqlx::PgPool;

    #[derive(Debug, Deserialize)]
    struct ApiKeyClaims {
        iss: String,
        sub: String,
        api_key_id: String,
        project_id: String,
        account_id: String,
        allowed_models: Option<Vec<String>>,
        email: Option<String>,
        email_verified: Option<bool>,
        typ: Option<String>,
        scope: Option<String>,
        #[serde(rename = "lightbridge_caller_kind")]
        caller_kind: Option<String>,
    }

    fn repo(pool: PgPool) -> Arc<StoreRepo> {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        Arc::new(StoreRepo::new(pool))
    }

    fn verify_against(jwk: &Value, token: &str) -> ApiKeyClaims {
        let decoding = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["lightbridge-api-key"]);
        validation.set_issuer(&[ISSUER]);
        decode::<ApiKeyClaims>(token, &decoding, &validation)
            .expect("verify")
            .claims
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn bootstrap_creates_active_key_and_is_idempotent(pool: PgPool) {
        let repo = repo(pool);
        assert!(repo.get_active_signing_key().await.unwrap().is_none());

        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let first = repo
            .get_active_signing_key()
            .await
            .unwrap()
            .expect("active");

        // Second boot must not create a second active key.
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let second = repo
            .get_active_signing_key()
            .await
            .unwrap()
            .expect("active");
        assert_eq!(first.kid, second.kid, "boot should be idempotent");
        assert_eq!(repo.list_verification_jwks().await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotation_stales_old_key_and_publishes_both(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let old = repo.get_active_signing_key().await.unwrap().unwrap();

        // Force rotation: cutoff after the current key's creation.
        let candidate = generate_rs256_key().unwrap();
        let new = repo
            .ensure_active_signing_key(
                lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey {
                    kid: candidate.kid,
                    algorithm: "RS256".to_string(),
                    private_key_pem: candidate.private_key_pem,
                    public_jwk: candidate.public_jwk,
                    created_at: Utc::now(),
                },
                Utc::now() + Duration::minutes(1),
            )
            .await
            .unwrap();

        assert_ne!(old.kid, new.kid);
        assert_eq!(new.status, "active");
        // Both keys remain published so tokens from the old key still verify.
        assert_eq!(repo.list_verification_jwks().await.unwrap().len(), 2);
        assert_eq!(
            repo.get_active_signing_key().await.unwrap().unwrap().kid,
            new.kid
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn signer_signs_verifiable_against_active_jwk(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = repo.get_active_signing_key().await.unwrap().unwrap();

        let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), repo.clone()).unwrap();
        let owner = KeyOwner {
            subject: "kc-user-123".to_string(),
            email: Some("dev@example.test".to_string()),
            email_verified: Some(true),
        };
        let signed = signer
            .sign(
                &owner,
                "key_1",
                "proj_1",
                "acct_1",
                Some(vec!["gpt-4.1-mini".to_string()]),
                Utc::now(),
                None,
            )
            .await
            .unwrap();

        let claims = verify_against(&active.public_jwk, &signed.token);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.sub, "kc-user-123");
        assert_eq!(claims.api_key_id, "key_1");
        assert_eq!(claims.project_id, "proj_1");
        assert_eq!(claims.account_id, "acct_1");
        assert_eq!(claims.email.as_deref(), Some("dev@example.test"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.typ.as_deref(), Some("Bearer"));
        assert_eq!(claims.scope.as_deref(), Some("profile email"));
        assert_eq!(
            claims.allowed_models,
            Some(vec!["gpt-4.1-mini".to_string()])
        );
        // #191/#216: every self-signed API-key JWT must carry this claim so
        // `requestBudgetRefill` can refuse API-key-derived callers by a real, intentional
        // signal rather than by JWKS separation happening to reject the token first.
        assert_eq!(
            claims.caller_kind.as_deref(),
            Some(lightbridge_authz_bearer::API_KEY_CALLER_KIND)
        );
    }

    /// The exact claim shape `signing.rs`'s hand-rolled `jsonwebtoken::encode` produced before
    /// ADR-0011 replaced it with `TokenManager` -- reconstructed here (not imported: the real
    /// struct is gone) so this test is a genuine diff against the old wire contract, not a
    /// description of it written after the fact.
    #[derive(serde::Serialize)]
    struct OldApiKeyClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        jti: String,
        iat: i64,
        exp: i64,
        typ: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        azp: Option<&'a str>,
        #[serde(rename = "lightbridge_caller_kind")]
        caller_kind: &'static str,
        sid: String,
        scope: &'static str,
        api_key_id: &'a str,
        project_id: &'a str,
        account_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email_verified: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allowed_models: Option<Vec<String>>,
    }

    #[allow(clippy::too_many_arguments)]
    fn old_signer_token(
        active_key_pem: &str,
        kid: &str,
        owner: &KeyOwner,
        api_key_id: &str,
        project_id: &str,
        account_id: &str,
        allowed_models: Option<Vec<String>>,
        now: chrono::DateTime<Utc>,
        expires_at: chrono::DateTime<Utc>,
    ) -> String {
        let encoding_key = EncodingKey::from_rsa_pem(active_key_pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let claims = OldApiKeyClaims {
            iss: ISSUER,
            sub: &owner.subject,
            jti: format!("lgbr:{}", cuid2()),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            typ: "Bearer",
            aud: Some("lightbridge-api-key"),
            azp: Some("lightbridge-api-key"),
            caller_kind: lightbridge_authz_bearer::API_KEY_CALLER_KIND,
            sid: cuid2(),
            scope: "profile email",
            api_key_id,
            project_id,
            account_id,
            email: owner.email.as_deref(),
            email_verified: owner.email_verified,
            allowed_models,
        };
        encode(&header, &claims, &encoding_key).unwrap()
    }

    /// Decodes a JWT's full claim set into an untyped `serde_json::Value`, verifying its
    /// signature against `jwk` -- unlike the typed `ApiKeyClaims` test helper above, this sees
    /// every key on the wire, not just the ones a fixed struct happens to declare.
    fn decode_untyped(jwk: &Value, token: &str) -> Value {
        let decoding = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["lightbridge-api-key"]);
        validation.set_issuer(&[ISSUER]);
        decode::<Value>(token, &decoding, &validation)
            .expect("verify")
            .claims
    }

    /// ADR-0011 Decision 2 non-regression requirement: the access token's claim set produced
    /// through the new `TokenManager` path must be EQUIVALENT to the old hand-rolled
    /// `jsonwebtoken::encode` path -- same claim names, same values, same omissions -- with any
    /// deviation stated explicitly rather than silently shipped.
    ///
    /// Verified finding (not assumed): `TokenManager::issue_user_token_with_extra` is not a
    /// drop-in replacement at the wire level. It unconditionally adds two claims this signer never
    /// emitted before (`nbf`, and a nested `identity` object duplicating `sub`/`email`), and it
    /// mints `jti` as a UUIDv4 rather than this repo's `lgbr:`-prefixed CUID2 -- with no clean way
    /// to override it (an `extra["jti"]` entry collides with `Claims`' own top-level `jti` field
    /// and produces a JWT payload with a duplicate `jti` key on the wire, which is
    /// technically-malformed JSON that only happens to decode via `serde_json`'s last-wins
    /// behavior; not something to rely on). This test pins that finding precisely rather than
    /// letting it silently drift, per this repo's "stop and report, don't silently change the wire
    /// contract" rule.
    #[sqlx::test(migrations = "../../migrations")]
    async fn new_signer_claim_set_is_a_documented_superset_of_the_old_signer(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = repo.get_active_signing_key().await.unwrap().unwrap();

        let owner = KeyOwner {
            subject: "kc-user-old-vs-new".to_string(),
            email: Some("dev@example.test".to_string()),
            email_verified: Some(true),
        };
        let allowed_models = Some(vec!["gpt-4.1-mini".to_string()]);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(3600);

        let old_token = old_signer_token(
            &active.private_key_pem,
            &active.kid,
            &owner,
            "key_1",
            "proj_1",
            "acct_1",
            allowed_models.clone(),
            now,
            expires_at,
        );
        let old_claims = decode_untyped(&active.public_jwk, &old_token);

        let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), repo.clone()).unwrap();
        let signed = signer
            .sign(
                &owner,
                "key_1",
                "proj_1",
                "acct_1",
                allowed_models,
                now,
                None,
            )
            .await
            .unwrap();
        let new_claims = decode_untyped(&active.public_jwk, &signed.token);

        let old_obj = old_claims.as_object().unwrap();
        let new_obj = new_claims.as_object().unwrap();

        for (key, value) in old_obj {
            // `jti`/`sid` are freshly random per call by design (a session identifier and a
            // token identifier respectively), so an exact-value comparison across two independent
            // signing calls would always fail regardless of this signer swap; `iat`/`exp` differ
            // because `TokenManager` stamps its own internal `now()` (documented above).
            if matches!(key.as_str(), "jti" | "sid" | "iat" | "exp") {
                continue;
            }
            assert_eq!(
                new_obj.get(key),
                Some(value),
                "claim `{key}` regressed: old={value:?} new={:?}",
                new_obj.get(key)
            );
        }

        let old_keys: std::collections::BTreeSet<&str> =
            old_obj.keys().map(String::as_str).collect();
        let new_keys: std::collections::BTreeSet<&str> =
            new_obj.keys().map(String::as_str).collect();
        let added: std::collections::BTreeSet<&str> =
            new_keys.difference(&old_keys).copied().collect();
        assert_eq!(
            added,
            std::collections::BTreeSet::from(["identity", "nbf"]),
            "the new signer must add exactly `identity` + `nbf` and nothing else beyond the old \
             claim set -- any other addition/removal is an undocumented wire-contract change"
        );

        assert!(
            new_obj["sid"].is_string() && !new_obj["sid"].as_str().unwrap().is_empty(),
            "sid must still be present and non-empty on the new signer"
        );

        let old_jti = old_obj["jti"].as_str().unwrap();
        let new_jti = new_obj["jti"].as_str().unwrap();
        assert!(
            old_jti.starts_with("lgbr:"),
            "sanity check on the reconstructed old shape"
        );
        assert!(
            !new_jti.starts_with("lgbr:")
                && new_jti.len() == 36
                && new_jti.matches('-').count() == 4,
            "new jti must be authkestra's own UUIDv4 (documented deviation from the AGENTS.md \
             \"every minted id is CUID2\" rule -- see the doc comment on this test): {new_jti}"
        );

        // The nested `identity` object mirrors `sub`/`email`, not new authority.
        assert_eq!(new_obj["identity"]["external_id"], "kc-user-old-vs-new");
        assert_eq!(new_obj["identity"]["email"], "dev@example.test");
    }

    /// ADR-0011, Decision 7: the id_token carries upstream identity snapshots + `at_hash`/`azp`,
    /// and never tenant context or role/quota data (that stays access-token-only, matching
    /// `docs/governance-model-and-enforcement.md`).
    #[sqlx::test(migrations = "../../migrations")]
    async fn sign_id_token_carries_upstream_claims_and_no_tenant_context(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = repo.get_active_signing_key().await.unwrap().unwrap();

        let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), repo.clone()).unwrap();
        let owner = KeyOwner {
            subject: "kc-user-id-token".to_string(),
            email: Some("dev@example.test".to_string()),
            email_verified: Some(true),
        };
        let now = Utc::now();
        let expires_at = now + Duration::seconds(900);
        let access_token = "fake-access-token-for-at-hash-binding".to_string();

        let id_token = signer
            .sign_id_token(
                &owner,
                &access_token,
                Some(1_700_000_000),
                Some("nonce-abc".to_string()),
                now,
                expires_at,
            )
            .await
            .unwrap();

        let claims = decode_untyped(&active.public_jwk, &id_token);
        assert_eq!(claims["sub"], "kc-user-id-token");
        assert_eq!(claims["email"], "dev@example.test");
        assert_eq!(claims["email_verified"], true);
        assert_eq!(claims["auth_time"], 1_700_000_000);
        assert_eq!(claims["nonce"], "nonce-abc");
        assert_eq!(claims["azp"], "lightbridge-api-key");
        assert_eq!(
            claims["at_hash"],
            lightbridge_authz_rest::signing::compute_at_hash(&access_token)
        );
        for tenant_claim in [
            "api_key_id",
            "project_id",
            "account_id",
            "lightbridge_caller_kind",
        ] {
            assert!(
                claims.get(tenant_claim).is_none(),
                "id_token must never carry tenant context ({tenant_claim}): {claims}"
            );
        }
    }

    /// `auth_time`/`nonce` must be OMITTED, never a fabricated value, when the upstream token
    /// carried none -- the failure mode this repo's rules explicitly call out ("a fabricated
    /// value is the failure mode").
    #[sqlx::test(migrations = "../../migrations")]
    async fn sign_id_token_omits_auth_time_and_nonce_when_absent(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = repo.get_active_signing_key().await.unwrap().unwrap();

        let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), repo.clone()).unwrap();
        let owner = KeyOwner {
            subject: "kc-user-no-auth-time".to_string(),
            email: None,
            email_verified: None,
        };
        let now = Utc::now();
        let id_token = signer
            .sign_id_token(&owner, "tok", None, None, now, now + Duration::seconds(900))
            .await
            .unwrap();

        let claims = decode_untyped(&active.public_jwk, &id_token);
        assert!(
            claims.get("auth_time").is_none(),
            "auth_time must be omitted, not null/fabricated, when absent upstream: {claims}"
        );
        assert!(
            claims.get("nonce").is_none(),
            "nonce must be omitted, not null/fabricated, when absent upstream: {claims}"
        );
    }

    /// Failure mode: this phase has no real per-client audience (ADR-0011 Decision 5 is phase 2),
    /// so `id_token.aud` falls back to `oauth2.signing.audience`. When that is unconfigured there
    /// is no value to stamp as `aud` -- refusing to mint a spec-invalid id_token (no `aud` at all)
    /// is the fail-closed answer, not silently omitting the claim.
    #[sqlx::test(migrations = "../../migrations")]
    async fn sign_id_token_refuses_when_audience_is_not_configured(pool: PgPool) {
        let mut cfg = signing_cfg(3600);
        cfg.audience = None;
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &cfg).await.unwrap();
        let signer = ApiKeyJwtSigner::from_config(&cfg, repo.clone()).unwrap();
        let owner = KeyOwner {
            subject: "kc-user-no-aud".to_string(),
            email: None,
            email_verified: None,
        };
        let now = Utc::now();

        let err = signer
            .sign_id_token(&owner, "tok", None, None, now, now + Duration::seconds(60))
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("audience"),
            "must refuse (fail closed), not issue an id_token missing `aud`: {err}"
        );
    }

    fn signing_oauth2() -> Oauth2 {
        Oauth2 {
            oauth2_type: lightbridge_authz_core::config::Oauth2Type::SelfSigned,
            jwks_url: "http://unused".to_string(),
            oauth2_url: None,
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            issuance: None,
            audience: None,
            signing: Some(signing_cfg(3600)),
            token_exchange: None,
            rbac: Default::default(),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_api_key_emits_verifiable_signed_jwt(pool: PgPool) {
        let key_repo = repo(pool.clone());
        bootstrap_signing_key(&key_repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = key_repo.get_active_signing_key().await.unwrap().unwrap();

        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let store = AuthzStoreImpl::with_pool_and_oauth2(
            db_pool,
            &signing_oauth2(),
            &Billing {
                plans: vec![BillingPlan {
                    id: "free".to_string(),
                    name: "Free".to_string(),
                    limits: None,
                }],
            },
        )
        .unwrap();
        let subject = "owner-sign";

        let account = store
            .create_account(
                subject,
                CreateAccount {
                    default_quota: None,
                },
            )
            .await
            .unwrap();
        // Project creation left `AuthzStoreImpl` in the cratestack migration (the CRUD verbs now run
        // through the generated client). Seed the project row directly via the surviving
        // hand-written `StoreRepo::create_project` (membership already seeded by `create_account`);
        // this test only needs a project to exist so `create_api_key` can sign against it.
        let project = key_repo
            .create_project(
                subject,
                &account.id,
                CreateProject {
                    name: "p".to_string(),
                    allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
                    default_limits: None,
                    billing_plan: "free".to_string(),
                    billing_identity: format!("bill-{}", cuid2()),
                    project_quota: None,
                },
                cuid2(),
            )
            .await
            .unwrap();
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"email":"owner@example.test","email_verified":true}"#);
        let bearer = format!("h.{payload}.s");
        let created = store
            .create_api_key(
                subject,
                Some(&bearer),
                &project.id,
                CreateApiKey {
                    name: "k".to_string(),
                    expires_at: None,
                    billing_plan: "free".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(created.secret.split('.').count(), 3, "must be a JWT");
        let claims = verify_against(&active.public_jwk, &created.secret);
        assert_eq!(claims.sub, subject);
        assert_eq!(claims.api_key_id, created.api_key.id);
        assert_eq!(claims.project_id, project.id);
        assert_eq!(claims.account_id, account.id);
        assert_eq!(claims.email.as_deref(), Some("owner@example.test"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn jwks_and_discovery_endpoints_serve_db_keys(pool: PgPool) {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use lightbridge_authz_rest::signing::well_known_router;
        use tower::ServiceExt;

        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        // Rotate so both an active and a stale key are published.
        let candidate = generate_rs256_key().unwrap();
        repo.ensure_active_signing_key(
            lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey {
                kid: candidate.kid,
                algorithm: "RS256".to_string(),
                private_key_pem: candidate.private_key_pem,
                public_jwk: candidate.public_jwk,
                created_at: Utc::now(),
            },
            Utc::now() + Duration::minutes(1),
        )
        .await
        .unwrap();

        let jwks = well_known_router::<()>(ISSUER, repo.clone(), None)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwks.status(), StatusCode::OK);
        let body = to_bytes(jwks.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["keys"].as_array().unwrap().len(),
            2,
            "active + stale keys should both be published"
        );
        assert_eq!(payload["keys"][0]["alg"], "RS256");

        let scopes = vec!["openid".to_string(), "offline_access".to_string()];
        let discovery = well_known_router::<()>(ISSUER, repo, Some(scopes))
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(discovery.status(), StatusCode::OK);
        let body = to_bytes(discovery.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["issuer"], ISSUER);
        assert_eq!(
            payload["jwks_uri"],
            format!("{ISSUER}/.well-known/jwks.json")
        );
        assert_eq!(
            payload["token_endpoint"],
            format!("{ISSUER}/oauth2/token"),
            "token_endpoint must be advertised when token-exchange is enabled"
        );
        let grants = payload["grant_types_supported"].as_array().unwrap();
        assert!(
            grants
                .iter()
                .any(|g| g == "urn:ietf:params:oauth:grant-type:token-exchange"),
            "discovery must advertise the token-exchange grant"
        );
        let scopes_supported = payload["scopes_supported"].as_array().unwrap();
        assert!(scopes_supported.iter().any(|s| s == "openid"));
        assert!(scopes_supported.iter().any(|s| s == "offline_access"));
        let auth_methods = payload["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap();
        assert_eq!(
            auth_methods,
            &[Value::String("none".to_string())],
            "must never advertise client_secret_basic/client_secret_post -- \
             this service never accepts secret-based client auth"
        );
        let claims_supported = payload["claims_supported"].as_array().unwrap();
        for claim in ["sub", "email", "email_verified", "auth_time", "at_hash"] {
            assert!(
                claims_supported.iter().any(|c| c == claim),
                "claims_supported must list {claim}: {claims_supported:?}"
            );
        }
    }

    /// ADR-0011, Decision 9: `OidcDiscovery`'s `token_endpoint`/`grant_types_supported`/
    /// `response_types_supported` fields are required (not `Option`), unlike the previous
    /// hand-built document which omitted them entirely when token-exchange was disabled. This
    /// replaces `discovery_omits_token_endpoint_when_exchange_disabled`, which asserted the old,
    /// now-impossible-to-preserve behavior -- see `discovery_document`'s doc comment in
    /// `signing.rs` for why.
    #[tokio::test]
    async fn discovery_advertises_no_grants_when_exchange_disabled() {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use lightbridge_authz_rest::signing::well_known_router;
        use tower::ServiceExt;

        let discovery = well_known_router::<()>(ISSUER, lazy_repo(), None)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(discovery.status(), StatusCode::OK);
        let body = to_bytes(discovery.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            payload["grant_types_supported"]
                .as_array()
                .unwrap()
                .is_empty(),
            "no grants must be advertised when token-exchange is disabled: {payload}"
        );
        assert!(
            payload["response_types_supported"]
                .as_array()
                .unwrap()
                .is_empty(),
            "no response types must be advertised when token-exchange is disabled: {payload}"
        );
        assert!(
            payload["scopes_supported"].as_array().unwrap().is_empty(),
            "no scopes must be advertised when token-exchange is disabled: {payload}"
        );
    }
}
