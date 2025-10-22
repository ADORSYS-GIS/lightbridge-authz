use crate::entities::api_key_row::ApiKeyRow;
use crate::entities::schema::api_keys;
use crate::repositories::api_key_repository::ApiKeyRepo;
use anyhow::anyhow;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use lightbridge_authz_core::api_key::ApiKey;
use lightbridge_authz_core::error::{Error, Result};

impl ApiKeyRepo {
    pub async fn find_by_id_impl(&self, user_id: &str, id: &str) -> Result<Option<ApiKey>> {
        let mut conn = self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))?;
        let maybe_row = api_keys::table
            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()?;

        match maybe_row {
            Some(api_key_row) => {
                let dto = ApiKeyRepo::get_api_key_dto(&mut conn, api_key_row).await?;
                Ok(Some(dto))
            }
            None => Ok(None),
        }
    }

    pub async fn find_by_token_impl(&self, token: &str) -> Result<Option<ApiKey>> {
        let mut conn = self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))?;
        let maybe_row = api_keys::table
            .filter(api_keys::key_hash.eq(token))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()?;

        match maybe_row {
            Some(api_key_row) => {
                let dto = ApiKeyRepo::get_api_key_dto(&mut conn, api_key_row).await?;
                Ok(Some(dto))
            }
            None => Ok(None),
        }
    }

    pub async fn find_api_key_for_authz_impl(&self, token: &str) -> Result<Option<ApiKey>> {
        let mut conn = self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))?;
        let maybe_row = api_keys::table
            .filter(api_keys::key_hash.eq(token))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()?;

        match maybe_row {
            Some(api_key_row) => {
                let dto = ApiKeyRepo::get_api_key_dto(&mut conn, api_key_row).await?;
                Ok(Some(dto))
            }
            None => Ok(None),
        }
    }
}
