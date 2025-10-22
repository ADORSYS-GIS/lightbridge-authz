use crate::entities::api_key_row::ApiKeyRow;
use crate::entities::schema::api_keys;
use crate::repositories::api_key_repository::ApiKeyRepo;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use diesel::AsChangeset;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use lightbridge_authz_core::api_key::{ApiKey, ApiKeyStatus, PatchApiKey};
use lightbridge_authz_core::error::{Error, Result};

#[derive(Default, AsChangeset)]
#[diesel(table_name = api_keys)]
struct UpdateApiKeyRow {
    expires_at: Option<Option<DateTime<Utc>>>,
    revoked_at: Option<Option<DateTime<Utc>>>,
}

impl ApiKeyRepo {
    #[allow(unused_variables)]
    pub async fn update_impl(&self, user_id: &str, id: &str, input: PatchApiKey) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;

        conn.transaction(|tx| {
            async move {
                let _api_key_row: ApiKeyRow = api_keys::table
                    .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
                    .first::<ApiKeyRow>(tx)
                    .await?;

                let mut changes = UpdateApiKeyRow::default();

                if let Some(expires_at) = input.expires_at {
                    changes.expires_at = Some(Some(expires_at));
                }

                if let Some(status) = input.status {
                    changes.revoked_at = Some(match status {
                        ApiKeyStatus::Revoked => Some(Utc::now()),
                        ApiKeyStatus::Active => None,
                    });
                }

                if changes.expires_at.is_some() || changes.revoked_at.is_some() {
                    diesel::update(
                        api_keys::table
                            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))),
                    )
                    .set(&changes)
                    .execute(tx)
                    .await?;
                }

                Ok::<(), Error>(())
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| Error::Any(anyhow!(e)))?;

        let api_key_row: ApiKeyRow = api_keys::table
            .filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id)))
            .first::<ApiKeyRow>(&mut conn)
            .await?;

        let api_key = ApiKeyRepo::get_api_key_dto(&mut conn, api_key_row).await?;
        Ok(api_key)
    }
}
