use crate::api_key::{Acl, ApiKey, ApiKeyStatus, CreateApiKey, PatchApiKey, RateLimit};
use crate::error::{Error, Result};
use crate::schema::{acl_models, acls, api_keys};
use anyhow::anyhow;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use chrono::{DateTime, Utc};
use cuid::cuid2;
use diesel::SelectableHelper;
use diesel::prelude::*;
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::{Pool, PooledConnection};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use rand_core::OsRng;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct DbPool {
    pool: Pool<AsyncPgConnection>,
}

impl DbPool {
    pub async fn new(database_url: &str) -> Result<Self> {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(20) // Increase maximum connections
            .min_idle(Some(5)) // Maintain minimum idle connections
            .connection_timeout(std::time::Duration::from_secs(30)) // Increase connection timeout
            .build(manager)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(Self { pool })
    }

    pub async fn get(&self) -> Result<PooledConnection<'_, AsyncPgConnection>> {
        self.pool.get().await.map_err(|e| Error::Any(anyhow!(e)))
    }
}

pub struct ApiKeyRepo;
pub struct AclRepo;

#[derive(Queryable, Identifiable, Selectable, diesel::QueryableByName)]
#[diesel(table_name = api_keys)]
pub struct ApiKeyRow {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub key_hash: String,
    #[diesel(sql_type = Timestamptz)]
    pub created_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pub metadata: Option<Value>,
    #[diesel(sql_type = Text)]
    pub status: String,
    #[diesel(sql_type = Text)]
    pub acl_id: String,
}

#[derive(Insertable)]
#[diesel(table_name = api_keys)]
pub struct NewApiKeyRow {
    pub id: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: String,
    pub acl_id: String,
}

#[derive(Queryable, Identifiable, Selectable)]
#[diesel(table_name = acls)]
pub struct AclRow {
    pub id: String,
    pub rate_limit_requests: i32,
    pub rate_limit_window: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = acls)]
pub struct NewAclRow {
    pub id: String,
    pub rate_limit_requests: i32,
    pub rate_limit_window: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(AsChangeset)]
#[diesel(table_name = acls)]
pub struct PatchAclRow {
    pub rate_limit_requests: Option<i32>,
    pub rate_limit_window: Option<i32>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Queryable, Identifiable, Selectable)]
#[diesel(table_name = acl_models)]
#[diesel(primary_key(acl_id, model_name))]
pub struct AclModelRow {
    pub acl_id: String,
    pub model_name: String,
    pub token_limit: i64,
}

#[derive(Insertable)]
#[diesel(table_name = acl_models)]
pub struct NewAclModelRow {
    pub acl_id: String,
    pub model_name: String,
    pub token_limit: i64,
}

#[derive(AsChangeset)]
#[diesel(table_name = acl_models)]
#[diesel(primary_key(acl_id, model_name))]
pub struct PatchAclModelRow {
    pub token_limit: Option<i64>,
}

#[derive(AsChangeset)]
#[diesel(table_name = api_keys)]
struct PatchApiKeyChanges {
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: Option<String>,
}

impl ApiKeyRow {
    pub async fn into_api_key(self, pool: &DbPool) -> Result<ApiKey> {
        let status = match self.status.to_lowercase().as_str() {
            "active" => ApiKeyStatus::Active,
            "revoked" => ApiKeyStatus::Revoked,
            _ => ApiKeyStatus::Active,
        };

        // Fetch ACL data from database
        let acl_repo = AclRepo;
        let acl = acl_repo
            .get(pool, &self.acl_id)
            .await?
            .unwrap_or_else(Acl::default); // Use default ACL if not found

        Ok(ApiKey {
            id: self.id,
            key_hash: self.key_hash,
            created_at: self.created_at,
            expires_at: self.expires_at,
            metadata: self.metadata,
            status,
            acl,
        })
    }
}

impl ApiKeyRepo {
    pub async fn create(
        &self,
        pool: &DbPool,
        new: CreateApiKey,
        key_plain: String,
    ) -> Result<ApiKey> {
        let conn = &mut pool.get().await?;
        let id_v = cuid2();
        let now = Utc::now();

        let mut rng = OsRng;
        let salt = SaltString::try_from_rng(&mut rng)?;
        let hash = Argon2::default()
            .hash_password(key_plain.as_bytes(), &salt)
            .map_err(|e| anyhow!(e.to_string()))?
            .to_string();

        // Create ACL if provided
        let acl_id = if let Some(ref acl) = new.acl {
            let acl_repo = AclRepo;
            acl_repo.create(pool, acl).await?
        } else {
            // Create a default ACL
            let default_acl = Acl::default();
            let acl_repo = AclRepo;
            acl_repo.create(pool, &default_acl).await?
        };

        let row = NewApiKeyRow {
            id: id_v,
            key_hash: hash,
            created_at: now,
            expires_at: new.expires_at,
            metadata: new.metadata,
            status: "Active".to_string(),
            acl_id: acl_id.to_string(),
        };

        let api_key_row = diesel::insert_into(crate::schema::api_keys::table)
            .values(&row)
            .returning(ApiKeyRow::as_returning())
            .get_result::<ApiKeyRow>(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        api_key_row.into_api_key(pool).await
    }

    pub async fn patch(&self, pool: &DbPool, key_id: &str, patch: PatchApiKey) -> Result<ApiKey> {
        let conn = &mut pool.get().await?;

        let mut changes = Vec::new();
        if let Some(expires_at_val) = patch.expires_at {
            changes.push(format!("expires_at = '{}'", expires_at_val));
        }
        if let Some(metadata_val) = patch.metadata {
            changes.push(format!(
                "metadata = '{}'",
                serde_json::to_string(&metadata_val).unwrap()
            ));
        }
        if let Some(status_val) = patch.status {
            changes.push(format!(
                "status = '{}'",
                match status_val {
                    ApiKeyStatus::Active => "Active",
                    ApiKeyStatus::Revoked => "Revoked",
                }
            ));
        }

        if changes.is_empty() {
            return self
                .get_by_id(pool, key_id)
                .await?
                .ok_or_else(|| Error::Any(anyhow!("API Key not found")));
        }

        let query = format!(
            "UPDATE api_keys SET {} WHERE id = '{}' RETURNING *",
            changes.join(", "),
            key_id
        );

        let api_key_row = diesel::sql_query(query)
            .get_result::<ApiKeyRow>(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        api_key_row.into_api_key(pool).await
    }

    pub async fn get_by_id(&self, pool: &DbPool, key_id: &str) -> Result<Option<ApiKey>> {
        use crate::schema::api_keys::dsl::{api_keys, id};
        let conn = &mut pool.get().await?;
        let api_key_row = api_keys
            .filter(id.eq(key_id))
            .select(ApiKeyRow::as_select())
            .first::<ApiKeyRow>(conn)
            .await
            .optional()
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        match api_key_row {
            Some(row) => {
                let api_key = row.into_api_key(pool).await?;
                Ok(Some(api_key))
            }
            None => Ok(None),
        }
    }

    pub async fn list(&self, pool: &DbPool, limit_n: i64, offset_n: i64) -> Result<Vec<ApiKey>> {
        use crate::schema::api_keys::dsl::{api_keys, created_at};
        let conn = &mut pool.get().await?;
        let api_key_rows = api_keys
            .order_by(created_at.desc())
            .limit(limit_n)
            .offset(offset_n)
            .select(ApiKeyRow::as_select())
            .load::<ApiKeyRow>(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        let mut api_key_list = Vec::new();
        for row in api_key_rows {
            let api_key = row.into_api_key(pool).await?;
            api_key_list.push(api_key);
        }

        Ok(api_key_list)
    }

    pub async fn revoke(&self, pool: &DbPool, key_id: &str) -> Result<bool> {
        use crate::schema::api_keys::dsl::{api_keys, id, status};
        let conn = &mut pool.get().await?;
        let updated = diesel::update(api_keys.filter(id.eq(key_id)))
            .set(status.eq("Revoked"))
            .execute(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;
        Ok(updated > 0)
    }
}

impl AclRepo {
    pub async fn create(&self, pool: &DbPool, acl: &Acl) -> Result<String> {
        let conn = &mut pool.get().await?;
        let id = cuid2();
        let now = Utc::now();

        // Create the ACL record
        let new_acl = NewAclRow {
            id: id.clone(),
            rate_limit_requests: acl.rate_limit.requests as i32,
            rate_limit_window: acl.rate_limit.window_seconds as i32,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(acls::table)
            .values(&new_acl)
            .execute(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        // Create ACL model records
        for (model_name, token_limit) in &acl.tokens_per_model {
            let new_acl_model = NewAclModelRow {
                acl_id: id.clone(),
                model_name: model_name.clone(),
                token_limit: *token_limit as i64,
            };

            diesel::insert_into(acl_models::table)
                .values(&new_acl_model)
                .execute(conn)
                .await
                .map_err(anyhow::Error::from)
                .map_err(Error::Any)?;
        }

        Ok(id)
    }

    pub async fn get(&self, pool: &DbPool, acl_id: &str) -> Result<Option<Acl>> {
        let conn = &mut pool.get().await?;

        // Get the ACL record
        let acl_row = acls::table
            .filter(acls::id.eq(acl_id))
            .select(AclRow::as_select())
            .first::<AclRow>(conn)
            .await
            .optional()
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        match acl_row {
            Some(row) => {
                // Get the ACL model records
                let acl_models_rows = acl_models::table
                    .filter(acl_models::acl_id.eq(acl_id))
                    .select(AclModelRow::as_select())
                    .load::<AclModelRow>(conn)
                    .await
                    .map_err(anyhow::Error::from)
                    .map_err(Error::Any)?;

                let mut tokens_per_model = HashMap::new();
                let mut allowed_models = Vec::new();

                for model_row in acl_models_rows {
                    tokens_per_model
                        .insert(model_row.model_name.clone(), model_row.token_limit as u64);
                    allowed_models.push(model_row.model_name);
                }

                let acl = Acl {
                    allowed_models,
                    tokens_per_model,
                    rate_limit: RateLimit {
                        requests: row.rate_limit_requests as u32,
                        window_seconds: row.rate_limit_window as u32,
                    },
                };

                Ok(Some(acl))
            }
            None => Ok(None),
        }
    }

    pub async fn update(&self, pool: &DbPool, acl_id: &str, acl: &Acl) -> Result<()> {
        let conn = &mut pool.get().await?;
        let now = Utc::now();

        // Update the ACL record
        let patch_acl = PatchAclRow {
            rate_limit_requests: Some(acl.rate_limit.requests as i32),
            rate_limit_window: Some(acl.rate_limit.window_seconds as i32),
            updated_at: now,
        };

        diesel::update(acls::table.filter(acls::id.eq(acl_id)))
            .set(&patch_acl)
            .execute(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        // Delete existing ACL model records
        diesel::delete(acl_models::table.filter(acl_models::acl_id.eq(acl_id)))
            .execute(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        // Create new ACL model records
        for (model_name, token_limit) in &acl.tokens_per_model {
            let new_acl_model = NewAclModelRow {
                acl_id: acl_id.to_string(),
                model_name: model_name.clone(),
                token_limit: *token_limit as i64,
            };

            diesel::insert_into(acl_models::table)
                .values(&new_acl_model)
                .execute(conn)
                .await
                .map_err(anyhow::Error::from)
                .map_err(Error::Any)?;
        }

        Ok(())
    }

    pub async fn delete(&self, pool: &DbPool, acl_id: &str) -> Result<()> {
        let conn = &mut pool.get().await?;

        // Delete ACL model records
        diesel::delete(acl_models::table.filter(acl_models::acl_id.eq(acl_id)))
            .execute(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        // Delete the ACL record
        diesel::delete(acls::table.filter(acls::id.eq(acl_id)))
            .execute(conn)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)?;

        Ok(())
    }
}
