use crate::entities::schema::{acl_models, acls, api_keys};
use chrono::Utc;
use diesel::QueryDsl;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use lightbridge_authz_core::api_key::{
    Acl, ApiKey, ApiKeyStatus, CreateApiKey, PatchApiKey, RateLimit,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;

use crate::entities::*;
use crate::mappers::*;

#[derive(Debug, Clone)]
pub struct ApiKeyRepo {
    pool: Arc<DbPool>,
}

#[derive(Debug, Clone)]
pub struct AclRepo {
    pool: Arc<DbPool>,
}

impl ApiKeyRepo {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }

    /// Helper method to convert diesel errors to our error type
    fn convert_diesel_error(e: diesel::result::Error) -> Error {
        Error::Any(anyhow::anyhow!(e))
    }

    pub async fn create(
        &self,
        user_id: &str,
        input: CreateApiKey,
        key_hash: String,
    ) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;
        let now = Utc::now();

        let key_id = cuid2();
        let acl_id = cuid2();

        let (new_acl, models): (NewAclRow, Vec<NewAclModelRow>) = match input.acl.clone() {
            Some(acl) => acl_to_rows(&acl, &acl_id, now, now),
            None => {
                let default_acl = Acl {
                    allowed_models: vec![],
                    tokens_per_model: HashMap::new(),
                    rate_limit: RateLimit::default(),
                };
                acl_to_rows(&default_acl, &acl_id, now, now)
            }
        };

        let new_api_key = NewApiKeyRow {
            id: key_id.clone(),
            user_id: user_id.to_string(),
            key_hash,
            created_at: now,
            expires_at: input.expires_at,
            metadata: input.metadata,
            status: ApiKeyStatus::Active.to_string(),
            acl_id: acl_id.clone(),
        };

        conn.transaction(|tx| {
            async move {
                diesel::insert_into(acls::table)
                    .values(&new_acl)
                    .execute(tx)
                    .await?;

                if !models.is_empty() {
                    diesel::insert_into(acl_models::table)
                        .values(&models)
                        .execute(tx)
                        .await?;
                }

                diesel::insert_into(api_keys::table)
                    .values(&new_api_key)
                    .execute(tx)
                    .await?;

                let api_key_row: ApiKeyRow =
                    api_keys::table.find(&key_id).first::<ApiKeyRow>(tx).await?;
                let api_key = Self::get_api_key_dto(tx, api_key_row).await?;
                Ok::<ApiKey, diesel::result::Error>(api_key)
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| Error::Any(anyhow::anyhow!(e)))
    }

    async fn get_api_key_dto(
        conn: &mut diesel_async::AsyncPgConnection,
        api_key_row: ApiKeyRow,
    ) -> std::result::Result<ApiKey, diesel::result::Error> {
        let acl_row: AclRow = acls::table
            .find(&api_key_row.acl_id)
            .first::<AclRow>(conn)
            .await?;

        let model_rows: Vec<AclModelRow> = acl_models::table
            .filter(acl_models::acl_id.eq(&api_key_row.acl_id))
            .load::<AclModelRow>(conn)
            .await?;

        Ok(to_api_key(&api_key_row, &acl_row, &model_rows).await)
    }

    pub async fn find_by_id(&self, user_id: &str, id: &str) -> Result<Option<ApiKey>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;
        let maybe_row = api_keys::table
            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()
            .map_err(Self::convert_diesel_error)?;

        match maybe_row {
            Some(api_key_row) => {
                let dto = Self::get_api_key_dto(&mut conn, api_key_row)
                    .await
                    .map_err(Self::convert_diesel_error)?;
                Ok(Some(dto))
            }
            None => Ok(None),
        }
    }

    pub async fn find_by_token(&self, token: &str) -> Result<Option<ApiKey>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;
        let maybe_row = api_keys::table
            .filter(api_keys::key_hash.eq(token))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()
            .map_err(Self::convert_diesel_error)?;

        match maybe_row {
            Some(api_key_row) => {
                let dto = Self::get_api_key_dto(&mut conn, api_key_row)
                    .await
                    .map_err(Self::convert_diesel_error)?;
                Ok(Some(dto))
            }
            None => Ok(None),
        }
    }

    pub async fn find_api_key_for_authz(&self, token: &str) -> Result<Option<ApiKey>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;
        let maybe_row = api_keys::table
            .filter(api_keys::key_hash.eq(token))
            .filter(api_keys::status.eq(ApiKeyStatus::Active.to_string()))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()
            .map_err(Self::convert_diesel_error)?;

        match maybe_row {
            Some(api_key_row) => {
                let dto = Self::get_api_key_dto(&mut conn, api_key_row)
                    .await
                    .map_err(Self::convert_diesel_error)?;
                Ok(Some(dto))
            }
            None => Ok(None),
        }
    }

    pub async fn update(&self, user_id: &str, id: &str, input: PatchApiKey) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;

        conn.transaction(|tx| {
            async move {
                let api_key_row: ApiKeyRow = api_keys::table
                    .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
                    .first::<ApiKeyRow>(tx)
                    .await?;

                let api_key_filter =
                    api_keys::table.filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)));

                if let Some(status) = input.status {
                    diesel::update(api_key_filter)
                        .set(api_keys::status.eq(status.to_string()))
                        .execute(tx)
                        .await?;
                }

                if let Some(expires_at) = input.expires_at {
                    diesel::update(api_key_filter)
                        .set(api_keys::expires_at.eq(expires_at))
                        .execute(tx)
                        .await?;
                }

                if let Some(metadata) = input.metadata {
                    diesel::update(api_key_filter)
                        .set(api_keys::metadata.eq(metadata))
                        .execute(tx)
                        .await?;
                }

                if let Some(acl) = input.acl {
                    let updated_at = Utc::now();
                    diesel::update(acls::table.find(&api_key_row.acl_id))
                        .set((
                            acls::rate_limit_requests.eq(acl.rate_limit.requests as i32),
                            acls::rate_limit_window.eq(acl.rate_limit.window_seconds as i32),
                            acls::updated_at.eq(updated_at),
                        ))
                        .execute(tx)
                        .await?;

                    diesel::delete(
                        acl_models::table.filter(acl_models::acl_id.eq(&api_key_row.acl_id)),
                    )
                    .execute(tx)
                    .await?;

                    let (_, models) = acl_to_rows(
                        &acl,
                        &api_key_row.acl_id,
                        api_key_row.created_at,
                        updated_at,
                    );
                    if !models.is_empty() {
                        diesel::insert_into(acl_models::table)
                            .values(&models)
                            .execute(tx)
                            .await?;
                    }
                }

                let api_key_row: ApiKeyRow = api_keys::table
                    .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
                    .first::<ApiKeyRow>(tx)
                    .await?;

                let dto = Self::get_api_key_dto(tx, api_key_row).await?;
                Ok::<ApiKey, diesel::result::Error>(dto)
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| Error::Any(anyhow::anyhow!(e)))
    }

    pub async fn delete(&self, user_id: &str, id: &str) -> Result<()> {
        let mut conn = self.pool.get().await?;

        diesel::update(
            api_keys::table.filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))),
        )
        .set(api_keys::status.eq(&ApiKeyStatus::Revoked.to_string()))
        .execute(&mut conn)
        .await
        .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;
        Ok(())
    }

    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let rows: Vec<ApiKeyRow> = api_keys::table
            .order(api_keys::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<ApiKeyRow>(&mut conn)
            .await
            .map_err(Self::convert_diesel_error)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let dto = Self::get_api_key_dto(&mut conn, row)
                .await
                .map_err(Self::convert_diesel_error)?;
            out.push(dto);
        }

        Ok(out)
    }

    pub async fn find_all(&self, user_id: &str, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let rows: Vec<ApiKeyRow> = api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .order(api_keys::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<ApiKeyRow>(&mut conn)
            .await
            .map_err(Self::convert_diesel_error)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let dto = Self::get_api_key_dto(&mut conn, row)
                .await
                .map_err(Self::convert_diesel_error)?;
            out.push(dto);
        }

        Ok(out)
    }
}

impl AclRepo {
    pub async fn get(&self, id: &str) -> Result<Acl> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let acl_row: AclRow = acls::table
            .find(id)
            .first::<AclRow>(&mut conn)
            .await
            .map_err(ApiKeyRepo::convert_diesel_error)?;

        let model_rows: Vec<AclModelRow> = acl_models::table
            .filter(acl_models::acl_id.eq(id))
            .load::<AclModelRow>(&mut conn)
            .await
            .map_err(ApiKeyRepo::convert_diesel_error)?;

        Ok(rows_to_acl(&acl_row, &model_rows).await)
    }
}
