//! Permanent no-op `AuthorizationCodeStore` implementation (ADR-0011 Decision 3, reaffirmed by
//! ADR-0012 Decision 3). `/authorize` requires a client-supplied `redirect_uri` and a real
//! consent/redirect dance this service deliberately does not build (see ADR-0012 Decision 3's
//! full argument for why authorization-code and device-code are NOT symmetric here, despite both
//! originally being grouped under this same stub) -- there is no future version of this service
//! that implements this trait for real.
//!
//! `DeviceCodeStore` used to be a permanent stub here too, on the same original reasoning ADR-0011
//! Decision 3 gave. ADR-0012 Decision 3 superseded that half specifically: once this service hosts
//! the verification-page redirect to Keycloak, `DeviceCodeStore` stops being unreachable and needs
//! a real, persisted implementation -- see `oauth2_op::device_store::DbDeviceCodeStore` (#423),
//! which `TokenExchangeOpStore` now uses instead of a stub.
//!
//! In practice `AuthorizationCodeStore` is still never reached:
//! `authkestra_op::handlers::token::handle_token`'s `authorization_code` match arm gates on
//! `client.allows_grant_type(...)` before touching this store, and no client this service
//! registers is ever given that grant type (`oauth2_op::client_store` only ever maps
//! `urn:ietf:params:oauth:grant-type:token-exchange`/`refresh_token`). This stub exists so
//! `OpStore`'s supertrait bound is satisfiable at all, and it fails toward rejection (never
//! `Ok(Some(..))`) in case that invariant is ever violated.

use authkestra_op::OpError;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use lightbridge_authz_core::async_trait;

#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuthorizationCodeStore;

#[async_trait]
impl AuthorizationCodeStore for NoAuthorizationCodeStore {
    async fn store_code(&self, _code: AuthorizationCode) -> Result<(), OpError> {
        Err(OpError::InvalidCode)
    }

    async fn consume_code(&self, _code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authorization_code_store_never_yields_a_code() {
        let store = NoAuthorizationCodeStore;
        assert!(store.consume_code("anything").await.unwrap().is_none());
        assert!(store.store_code(dummy_code()).await.is_err());
    }

    fn dummy_code() -> AuthorizationCode {
        AuthorizationCode {
            code: "c".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.test".to_string(),
            scope: String::new(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity: authkestra_engine::auth::state::Identity {
                provider_id: "test".to_string(),
                external_id: "user".to_string(),
                email: None,
                username: None,
                attributes: Default::default(),
            },
            expires_at: chrono::Utc::now(),
            used: false,
        }
    }
}
