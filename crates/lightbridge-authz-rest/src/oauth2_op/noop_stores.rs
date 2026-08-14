//! Permanent no-op `AuthorizationCodeStore`/`DeviceCodeStore` implementations (ADR-0011, Decision
//! 3). Both flows require *running* a user-facing authentication step -- a login page for
//! authorization-code, a device-pairing prompt for the device flow -- and this service owns no
//! users and runs no login flow anywhere (ADR-0011 Context). That is the architecturally correct
//! terminus, not an expedient shortcut: there is no future version of this service that
//! implements these two traits for real, because doing so would mean authenticating a user, which
//! it structurally cannot.
//!
//! In practice neither is ever reached: `authkestra_op::handlers::token::handle_token`'s
//! `authorization_code`/device-code match arms gate on `client.allows_grant_type(...)` before
//! touching either store, and no client this service registers is ever given those grant types
//! (`oauth2_op::client_store` only ever maps `urn:ietf:params:oauth:grant-type:token-exchange`/
//! `refresh_token`). These stubs exist so `OpStore`'s supertrait bound is satisfiable at all, and
//! they fail toward rejection (never `Ok(Some(..))`) in case that invariant is ever violated.

use authkestra_op::OpError;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStore};
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

#[derive(Debug, Clone, Copy, Default)]
pub struct NoDeviceCodeStore;

#[async_trait]
impl DeviceCodeStore for NoDeviceCodeStore {
    async fn store_device_code(&self, _session: DeviceCodeSession) -> Result<(), OpError> {
        Err(OpError::Storage)
    }

    async fn get_device_code(
        &self,
        _device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        Ok(None)
    }

    async fn get_by_user_code(
        &self,
        _user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        Ok(None)
    }

    async fn update_device_code(&self, _session: DeviceCodeSession) -> Result<(), OpError> {
        Err(OpError::Storage)
    }

    async fn delete_device_code(&self, _device_code: &str) -> Result<(), OpError> {
        Ok(())
    }

    async fn consume_device_code(
        &self,
        _device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
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

    #[tokio::test]
    async fn device_code_store_never_yields_a_session() {
        let store = NoDeviceCodeStore;
        assert!(store.get_device_code("anything").await.unwrap().is_none());
        assert!(store.get_by_user_code("anything").await.unwrap().is_none());
        assert!(
            store
                .consume_device_code("anything")
                .await
                .unwrap()
                .is_none()
        );
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
