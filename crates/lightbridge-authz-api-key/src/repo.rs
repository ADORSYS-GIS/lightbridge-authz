use std::collections::HashMap;

use crate::entities::schema::{acl_models, acls, api_keys};
use chrono::Utc;
use diesel::QueryDsl;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use lightbridge_authz_core::api_key::{
    Acl, ApiKey, ApiKeyStatus, CreateApiKey, PatchApiKey, RateLimit,
};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::{Error, Result};

use crate::entities::*;
use crate::mappers::*;

pub struct ApiKeyRepo;
pub struct AclRepo;

impl ApiKeyRepo {
    pub async fn create(
        &self,
        pool: &DbPool,
        user_id: &str,
        input: CreateApiKey,
        key_plain: String,
    ) -> Result<ApiKey> {
        let mut conn = pool.get().await?;
        let now = Utc::now();

        let key_id = cuid::cuid2();
        let acl_id = cuid::cuid2();

        let key_hash = key_plain;

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
            status: api_key_status_to_str(&ApiKeyStatus::Active).to_string(),
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

                let acl_row: AclRow = acls::table.find(&acl_id).first::<AclRow>(tx).await?;

                let model_rows: Vec<AclModelRow> = acl_models::table
                    .filter(acl_models::acl_id.eq(&acl_id))
                    .load::<AclModelRow>(tx)
                    .await?;

                let api_key = to_api_key(&api_key_row, &acl_row, &model_rows);
                Ok::<ApiKey, diesel::result::Error>(api_key)
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| Error::Any(anyhow::anyhow!(e)))
    }

    pub async fn find_by_id(
        &self,
        pool: &DbPool,
        user_id: &str,
        id: &str,
    ) -> Result<Option<ApiKey>> {
        let mut conn = pool.get().await?;

        let maybe_row = api_keys::table
            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let Some(api_key_row) = maybe_row else {
            return Ok(None);
        };

        let acl_row: AclRow = acls::table
            .find(&api_key_row.acl_id)
            .first::<AclRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let model_rows: Vec<AclModelRow> = acl_models::table
            .filter(acl_models::acl_id.eq(&api_key_row.acl_id))
            .load::<AclModelRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let dto = to_api_key(&api_key_row, &acl_row, &model_rows);
        Ok(Some(dto))
    }

    pub async fn find_by_token(&self, pool: &DbPool, token: &str) -> Result<Option<ApiKey>> {
        let mut conn = pool.get().await?;

        let maybe_row = api_keys::table
            .filter(api_keys::key_hash.eq(token))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let Some(api_key_row) = maybe_row else {
            return Ok(None);
        };

        let acl_row: AclRow = acls::table
            .find(&api_key_row.acl_id)
            .first::<AclRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let model_rows: Vec<AclModelRow> = acl_models::table
            .filter(acl_models::acl_id.eq(&api_key_row.acl_id))
            .load::<AclModelRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let dto = to_api_key(&api_key_row, &acl_row, &model_rows);
        Ok(Some(dto))
    }
    pub async fn update(
        &self,
        pool: &DbPool,
        user_id: &str,
        id: &str,
        input: PatchApiKey,
    ) -> Result<ApiKey> {
        let mut conn = pool.get().await?;

        conn.transaction(|tx| {
            async move {
                let api_key_row: ApiKeyRow = api_keys::table
                    .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
                    .first::<ApiKeyRow>(tx)
                    .await?;

                if let Some(status) = input.status {
                    diesel::update(
                        api_keys::table
                            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))),
                    )
                    .set(api_keys::status.eq(api_key_status_to_str(&status)))
                    .execute(tx)
                    .await?;
                }

                if let Some(expires_at) = input.expires_at {
                    diesel::update(
                        api_keys::table
                            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))),
                    )
                    .set(api_keys::expires_at.eq(expires_at))
                    .execute(tx)
                    .await?;
                }

                if let Some(metadata) = input.metadata {
                    diesel::update(
                        api_keys::table
                            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))),
                    )
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

                let acl_row: AclRow = acls::table
                    .find(&api_key_row.acl_id)
                    .first::<AclRow>(tx)
                    .await?;

                let model_rows: Vec<AclModelRow> = acl_models::table
                    .filter(acl_models::acl_id.eq(&api_key_row.acl_id))
                    .load::<AclModelRow>(tx)
                    .await?;

                let dto = to_api_key(&api_key_row, &acl_row, &model_rows);
                Ok::<ApiKey, diesel::result::Error>(dto)
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| Error::Any(anyhow::anyhow!(e)))
    }

    pub async fn delete(&self, pool: &DbPool, user_id: &str, id: &str) -> Result<()> {
        let mut conn = pool.get().await?;
        diesel::update(
            api_keys::table.filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))),
        )
        .set(api_keys::status.eq(api_key_status_to_str(&ApiKeyStatus::Revoked)))
        .execute(&mut conn)
        .await
        .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;
        Ok(())
    }

    pub async fn list(&self, pool: &DbPool, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        let mut conn = pool.get().await?;

        let rows: Vec<ApiKeyRow> = api_keys::table
            .order(api_keys::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<ApiKeyRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let acl_row: AclRow = acls::table
                .find(&row.acl_id)
                .first::<AclRow>(&mut conn)
                .await
                .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

            let model_rows: Vec<AclModelRow> = acl_models::table
                .filter(acl_models::acl_id.eq(&row.acl_id))
                .load::<AclModelRow>(&mut conn)
                .await
                .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

            out.push(to_api_key(&row, &acl_row, &model_rows));
        }

        Ok(out)
    }

    pub async fn find_all(
        &self,
        pool: &DbPool,
        user_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ApiKey>> {
        let mut conn = pool.get().await?;

        let rows: Vec<ApiKeyRow> = api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .order(api_keys::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<ApiKeyRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let acl_row: AclRow = acls::table
                .find(&row.acl_id)
                .first::<AclRow>(&mut conn)
                .await
                .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

            let model_rows: Vec<AclModelRow> = acl_models::table
                .filter(acl_models::acl_id.eq(&row.acl_id))
                .load::<AclModelRow>(&mut conn)
                .await
                .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

            out.push(to_api_key(&row, &acl_row, &model_rows));
        }

        Ok(out)
    }
}

impl AclRepo {
    pub async fn get(&self, pool: &DbPool, id: &str) -> Result<Acl> {
        let mut conn = pool.get().await?;

        let acl_row: AclRow = acls::table
            .find(id)
            .first::<AclRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let model_rows: Vec<AclModelRow> = acl_models::table
            .filter(acl_models::acl_id.eq(id))
            .load::<AclModelRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        Ok(rows_to_acl(&acl_row, &model_rows))
    }
}
