use crate::entities::api_key_row::ApiKeyRow;
use crate::entities::schema::api_keys;
use crate::repositories::api_key_repository::ApiKeyRepo;
use anyhow::anyhow;
use diesel::QueryDsl;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use lightbridge_authz_core::api_key::ApiKey;
use lightbridge_authz_core::error::{Error, Result};

impl ApiKeyRepo {
    pub async fn list_impl(&self, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        let mut conn = self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))?;

        let rows: Vec<ApiKeyRow> = api_keys::table
            .order(api_keys::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<ApiKeyRow>(&mut conn)
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let dto = ApiKeyRepo::get_api_key_dto(&mut conn, row).await?;
            out.push(dto);
        }

        Ok(out)
    }

    pub async fn find_all_impl(
        &self,
        user_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ApiKey>> {
        let mut conn = self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))?;

        let rows: Vec<ApiKeyRow> = api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .order(api_keys::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<ApiKeyRow>(&mut conn)
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let dto = ApiKeyRepo::get_api_key_dto(&mut conn, row).await?;
            out.push(dto);
        }

        Ok(out)
    }
}
