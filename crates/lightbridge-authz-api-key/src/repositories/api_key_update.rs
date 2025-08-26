use crate::entities::api_key_row::ApiKeyRow;
use crate::entities::schema::api_keys;
use crate::repositories::api_key_repository::ApiKeyRepo;
use anyhow::anyhow;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use lightbridge_authz_core::api_key::{ApiKey, PatchApiKey};
use lightbridge_authz_core::error::{Error, Result};

impl ApiKeyRepo {
    #[allow(unused_variables)]
    pub async fn update_impl(&self, user_id: &str, id: &str, input: PatchApiKey) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;

        conn.transaction(|tx| {
            async move {
                let api_key_row: ApiKeyRow = api_keys::table
                    .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
                    .first::<ApiKeyRow>(tx)
                    .await?;

                // TODO: map PatchApiKey fields properly; placeholder logic removed to avoid undefined vars
                // diesel::update(api_keys::table.filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))))
                //     .set(...)
                //     .execute(tx)
                //     .await?;

                let api_key_row_after_update: ApiKeyRow = api_keys::table
                    .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
                    .first::<ApiKeyRow>(tx)
                    .await?;

                let dto = ApiKeyRepo::get_api_key_dto(tx, api_key_row_after_update).await?;
                Ok::<ApiKey, diesel::result::Error>(dto)
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| Error::Any(anyhow!(e)))
    }
}
