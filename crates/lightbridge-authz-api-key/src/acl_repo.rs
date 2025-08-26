// Reusable ACL repository abstractions moved to dedicated module

use crate::entities::acl_model_row::AclModelRow;
use crate::entities::acl_row::AclRow;
use crate::entities::schema::{acl_models, acls};
use crate::mappers::rows_to_acl;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use lightbridge_authz_core::api_key::Acl;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::{Error, Result};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AclRepo {
    pool: Arc<dyn DbPoolTrait>,
}

impl AclRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }
}

#[async_trait]
pub trait AclRepository: Send + Sync {
    async fn get(&self, id: &str) -> Result<Acl>;
}

#[async_trait]
impl AclRepository for AclRepo {
    async fn get(&self, id: &str) -> Result<Acl> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let acl_row: AclRow = acls::table
            .find(id)
            .first::<AclRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        let model_rows: Vec<AclModelRow> = acl_models::table
            .filter(acl_models::id.eq(id))
            .load::<AclModelRow>(&mut conn)
            .await
            .map_err(|e| Error::Any(anyhow::anyhow!(e)))?;

        Ok(rows_to_acl(&acl_row, &model_rows).await)
    }
}

// Helper macro to box errors when moving types across async boundaries
