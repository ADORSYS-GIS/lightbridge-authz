#![expect(
    clippy::unwrap_used,
    reason = "test setup and assertions intentionally unwrap expected database results"
)]

use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use chrono::{Duration, Utc};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::oauth2_op::authorization_code_store::DbAuthorizationCodeStore;
use sqlx::PgPool;

fn code(value: &str, expires_at: chrono::DateTime<Utc>) -> AuthorizationCode {
    AuthorizationCode {
        code: value.to_string(),
        client_id: "browser-client".to_string(),
        redirect_uri: "https://dashboard.example.test/oauth/callback".to_string(),
        scope: "openid profile".to_string(),
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: Some("nonce".to_string()),
        identity: Identity {
            provider_id: "keycloak".to_string(),
            external_id: "subject".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        },
        expires_at,
        used: false,
    }
}

fn store(pool: PgPool) -> DbAuthorizationCodeStore {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    DbAuthorizationCodeStore::new(Arc::new(StoreRepo::new(pool)))
}

#[sqlx::test(migrations = "../../migrations")]
async fn authorization_code_is_exactly_bound_and_consumed_once(pool: PgPool) {
    let store = store(pool);
    store
        .store_code(code("opaque-code", Utc::now() + Duration::minutes(5)))
        .await
        .unwrap();

    assert!(
        store
            .matches_binding(
                "opaque-code",
                "browser-client",
                "https://dashboard.example.test/oauth/callback"
            )
            .await
            .unwrap()
    );
    assert!(
        !store
            .matches_binding(
                "opaque-code",
                "browser-client",
                "https://dashboard.example.test/oauth/callback/"
            )
            .await
            .unwrap()
    );
    assert!(
        !store
            .matches_binding(
                "opaque-code",
                "other-client",
                "https://dashboard.example.test/oauth/callback"
            )
            .await
            .unwrap()
    );

    let (first, second) = tokio::join!(
        store.consume_code("opaque-code"),
        store.consume_code("opaque-code")
    );
    assert_eq!(
        usize::from(first.unwrap().is_some()) + usize::from(second.unwrap().is_some()),
        1
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn expired_authorization_code_cannot_be_consumed(pool: PgPool) {
    let store = store(pool);
    store
        .store_code(code("expired-code", Utc::now() - Duration::seconds(1)))
        .await
        .unwrap();
    assert!(store.consume_code("expired-code").await.unwrap().is_none());
}
