use crate::entities::schema::{acl_models, acls, api_keys};
use crate::entities::{
    api_key_row::ApiKeyRow, new_acl_model_row::NewAclModelRow, new_acl_row::NewAclRow,
    new_api_key_row::NewApiKeyRow,
};
use crate::mappers::*;
use crate::repositories::api_key_repository::ApiKeyRepo;
use anyhow::anyhow;
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use lightbridge_authz_core::api_key::{Acl, ApiKey, CreateApiKey, RateLimit};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use std::collections::HashMap;

impl ApiKeyRepo {
    pub async fn create_impl(
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
            Some(acl) => acl_to_rows(&acl, &acl_id, &key_id, now, now),
            None => {
                let default_acl = Acl {
                    allowed_models: vec![],
                    tokens_per_model: HashMap::new(),
                    rate_limit: RateLimit::default(),
                };
                acl_to_rows(&default_acl, &acl_id, &key_id, now, now)
            }
        };

        let new_api_key = NewApiKeyRow {
            id: key_id.clone(),
            user_id: user_id.to_string(),
            name: "".to_string(),
            key_hash,
            expires_at: input.expires_at,
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

                Ok::<(), Error>(())
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| Error::Any(anyhow!(e)))?;

        let api_key_row: ApiKeyRow = api_keys::table
            .filter(api_keys::id.eq(key_id))
            .first::<ApiKeyRow>(&mut conn)
            .await?;

        let api_key = ApiKeyRepo::get_api_key_dto(&mut conn, api_key_row).await?;
        Ok(api_key)
    }
}
