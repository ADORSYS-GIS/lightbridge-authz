//! Persisted authorization-code storage for ADR-0019's browser flow.

use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_op::OpError;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use chrono::Utc;
use lightbridge_authz_api_key::entities::authorization_code_row::NewAuthorizationCode;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::crypto::hash_api_key;
use lightbridge_authz_core::cuid::cuid2;

#[derive(Clone)]
pub struct DbAuthorizationCodeStore {
    repo: Arc<StoreRepo>,
}

impl DbAuthorizationCodeStore {
    pub fn new(repo: Arc<StoreRepo>) -> Self {
        Self { repo }
    }

    pub async fn matches_binding(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<bool, OpError> {
        self.repo
            .authorization_code_matches(&hash_api_key(code), client_id, redirect_uri, Utc::now())
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to check authorization-code binding");
                OpError::Storage
            })
    }
}

#[async_trait]
impl AuthorizationCodeStore for DbAuthorizationCodeStore {
    async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
        let identity = serde_json::to_value(&code.identity).map_err(|error| {
            tracing::error!(%error, "failed to serialize authorization-code identity");
            OpError::Storage
        })?;
        self.repo
            .create_authorization_code(NewAuthorizationCode {
                id: cuid2(),
                code_hash: hash_api_key(&code.code),
                client_id: code.client_id,
                redirect_uri: code.redirect_uri,
                scope: code.scope,
                code_challenge: code.code_challenge,
                code_challenge_method: code.code_challenge_method,
                nonce: code.nonce,
                identity,
                expires_at: code.expires_at,
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to store authorization code");
                OpError::Storage
            })
    }

    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        let row = self
            .repo
            .consume_authorization_code(&hash_api_key(code), Utc::now())
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to consume authorization code");
                OpError::Storage
            })?;
        row.map(|row| {
            serde_json::from_value::<Identity>(row.identity)
                .map(|identity| {
                    let mut consumed = AuthorizationCode::new(
                        code.to_owned(),
                        row.client_id,
                        row.redirect_uri,
                        row.scope,
                        identity,
                        row.expires_at,
                        true,
                    );
                    consumed.code_challenge = row.code_challenge;
                    consumed.code_challenge_method = row.code_challenge_method;
                    consumed.nonce = row.nonce;
                    consumed
                })
                .map_err(|error| {
                    tracing::error!(%error, "stored authorization-code identity is invalid");
                    OpError::Storage
                })
        })
        .transpose()
    }
}
