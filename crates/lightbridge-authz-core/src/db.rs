use crate::api_key::{ApiKey, ApiKeyStatus, CreateApiKey, PatchApiKey};
use crate::error::{Error, Result};
use crate::schema::api_keys;
use anyhow::anyhow;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use chrono::{DateTime, Utc};
use diesel::SelectableHelper;
use diesel::prelude::*;
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::{Pool, PooledConnection};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use rand_core::OsRng;
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct DbPool {
    pool: Pool<AsyncPgConnection>,
}

impl DbPool {
    pub async fn new(database_url: &str) -> Result<Self> {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool = Pool::builder()
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

#[derive(Queryable, Identifiable, Selectable, diesel::QueryableByName)]
#[diesel(table_name = api_keys)]
pub struct ApiKeyRow {
    #[diesel(sql_type = DieselUuid)]
    pub id: Uuid,
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
}

#[derive(Insertable)]
#[diesel(table_name = api_keys)]
pub struct NewApiKeyRow {
    pub id: Uuid,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: String,
}

#[derive(AsChangeset)]
#[diesel(table_name = api_keys)]
struct PatchApiKeyChanges {
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: Option<String>,
}

impl From<ApiKeyRow> for ApiKey {
    fn from(r: ApiKeyRow) -> Self {
        let status = match r.status.as_str() {
            "Active" | "active" => ApiKeyStatus::Active,
            "Revoked" | "revoked" => ApiKeyStatus::Revoked,
            _ => ApiKeyStatus::Active,
        };
        ApiKey {
            id: r.id,
            key_hash: r.key_hash,
            created_at: r.created_at,
            expires_at: r.expires_at,
            metadata: r.metadata,
            status,
        }
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
        let id_v = Uuid::new_v4();
        let now = Utc::now();

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(key_plain.as_bytes(), &salt)
            .map_err(|e| anyhow!(e.to_string()))?
            .to_string();

        let row = NewApiKeyRow {
            id: id_v,
            key_hash: hash,
            created_at: now,
            expires_at: new.expires_at,
            metadata: new.metadata,
            status: "Active".to_string(),
        };

        diesel::insert_into(crate::schema::api_keys::table)
            .values(&row)
            .returning(ApiKeyRow::as_returning())
            .get_result::<ApiKeyRow>(conn)
            .await
            .map(ApiKey::from)
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)
    }

    pub async fn patch(&self, pool: &DbPool, key_id: Uuid, patch: PatchApiKey) -> Result<ApiKey> {
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

        diesel::sql_query(query)
            .get_result::<ApiKeyRow>(conn)
            .await
            .map(ApiKey::from)
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)
    }

    pub async fn get_by_id(&self, pool: &DbPool, key_id: Uuid) -> Result<Option<ApiKey>> {
        use crate::schema::api_keys::dsl::{api_keys, id};
        let conn = &mut pool.get().await?;
        api_keys
            .filter(id.eq(key_id))
            .select(ApiKeyRow::as_select())
            .first::<ApiKeyRow>(conn)
            .await
            .optional()
            .map(|opt| opt.map(ApiKey::from))
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)
    }

    pub async fn list(&self, pool: &DbPool, limit_n: i64, offset_n: i64) -> Result<Vec<ApiKey>> {
        use crate::schema::api_keys::dsl::{api_keys, created_at};
        let conn = &mut pool.get().await?;
        api_keys
            .order_by(created_at.desc())
            .limit(limit_n)
            .offset(offset_n)
            .select(ApiKeyRow::as_select())
            .load::<ApiKeyRow>(conn)
            .await
            .map(|rows| rows.into_iter().map(ApiKey::from).collect())
            .map_err(anyhow::Error::from)
            .map_err(Error::Any)
    }

    pub async fn revoke(&self, pool: &DbPool, key_id: Uuid) -> Result<bool> {
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
