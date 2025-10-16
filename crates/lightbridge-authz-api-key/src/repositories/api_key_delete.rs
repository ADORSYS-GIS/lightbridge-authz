use crate::entities::schema::api_keys;
use crate::repositories::api_key_repository::ApiKeyRepo;
use anyhow::anyhow;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use lightbridge_authz_core::error::{Error, Result};

impl ApiKeyRepo {
    pub async fn delete_impl(&self, user_id: &str, id: &str) -> Result<()> {
        let mut conn = self.pool.get().await?;

        diesel::delete(
            api_keys::table.filter(api_keys::id.eq(id).and(api_keys::user_id.eq(user_id))),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| Error::Any(anyhow!(e)))?;
        Ok(())
    }
}
