use crate::entities::schema::{acl_models, acls};
use crate::entities::{acl_model_row::AclModelRow, acl_row::AclRow, api_key_row::ApiKeyRow};
use crate::mappers::to_api_key;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use lightbridge_authz_core::api_key::{ApiKey, CreateApiKey, PatchApiKey};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::{Error, Result};
use std::sync::Arc;

#[async_trait]
pub trait ApiKeyRepository: Send + Sync {
    async fn create(&self, user_id: &str, input: CreateApiKey, key_hash: String) -> Result<ApiKey>;
    async fn find_by_id(&self, user_id: &str, id: &str) -> Result<Option<ApiKey>>;
    async fn find_by_token(&self, token: &str) -> Result<Option<ApiKey>>;
    async fn find_api_key_for_authz(&self, token: &str) -> Result<Option<ApiKey>>;
    async fn update(&self, user_id: &str, id: &str, input: PatchApiKey) -> Result<ApiKey>;
    async fn delete(&self, user_id: &str, id: &str) -> Result<()>;
    async fn list(&self, limit: i64, offset: i64) -> Result<Vec<ApiKey>>;
    async fn find_all(&self, user_id: &str, limit: i64, offset: i64) -> Result<Vec<ApiKey>>;
}

#[derive(Debug, Clone)]
pub struct ApiKeyRepo {
    pub pool: Arc<dyn DbPoolTrait>,
}

#[async_trait]
impl ApiKeyRepository for ApiKeyRepo {
    async fn create(&self, user_id: &str, input: CreateApiKey, key_hash: String) -> Result<ApiKey> {
        self.create_impl(user_id, input, key_hash).await
    }
    async fn find_by_id(&self, user_id: &str, id: &str) -> Result<Option<ApiKey>> {
        self.find_by_id_impl(user_id, id).await
    }
    async fn find_by_token(&self, token: &str) -> Result<Option<ApiKey>> {
        self.find_by_token_impl(token).await
    }
    async fn find_api_key_for_authz(&self, token: &str) -> Result<Option<ApiKey>> {
        self.find_api_key_for_authz_impl(token).await
    }
    async fn update(&self, user_id: &str, id: &str, input: PatchApiKey) -> Result<ApiKey> {
        self.update_impl(user_id, id, input).await
    }
    async fn delete(&self, user_id: &str, id: &str) -> Result<()> {
        self.delete_impl(user_id, id).await
    }
    async fn list(&self, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        self.list_impl(limit, offset).await
    }
    async fn find_all(&self, user_id: &str, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        self.find_all_impl(user_id, limit, offset).await
    }
}

impl ApiKeyRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    pub fn convert_diesel_error(e: diesel::result::Error) -> Error {
        Error::Any(anyhow::anyhow!(e))
    }

    pub async fn get_api_key_dto(
        conn: &mut diesel_async::AsyncPgConnection,
        api_key_row: ApiKeyRow,
    ) -> std::result::Result<ApiKey, diesel::result::Error> {
        let acl_row: AclRow = acls::table
            .find(&api_key_row.id)
            .first::<AclRow>(conn)
            .await?;

        let model_rows: Vec<AclModelRow> = acl_models::table
            .filter(acl_models::id.eq(&api_key_row.id))
            .load::<AclModelRow>(conn)
            .await?;

        Ok(to_api_key(&api_key_row, &acl_row, &model_rows).await)
    }
}
