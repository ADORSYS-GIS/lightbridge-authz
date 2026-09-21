use chrono::{DateTime, Utc};
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{ApiKey, ApiKeyStatus, ApiKeyValidation, UpdateApiKey};
use tracing::instrument;

use crate::entities::api_key_row::{ApiKeyChangeset, ApiKeyRow};
use crate::entities::api_key_validation_row::ApiKeyValidationRow;
use crate::entities::new_api_key_row::NewApiKeyRow;
use crate::repo::StoreRepo;

impl StoreRepo {
    /// Lead-gated (handoff recommendation #3, ADR-0006): minting a new key requires `subject` to be
    /// either the project's account owner or hold a `project_members` row with `role = 'lead'` on
    /// `input.project_id`, checked via `authorize_project_lead` before the insert -- unlike the
    /// project-scoped read/update rule most of this file's other api-key methods use, any plain
    /// member may NOT create keys. Once authorized, the plain `INSERT` needs no further
    /// project-existence guard (`authorize_project_lead` already confirmed the project exists).
    pub async fn create_api_key(
        &self,
        account_id: &AccountId,
        input: NewApiKeyRow,
    ) -> Result<ApiKey> {
        self.authorize_project_lead(&input.project_id, account_id)
            .await?;
        let row: ApiKeyRow = sqlx::query_as(
            r#"
            INSERT INTO api_keys (
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, owner_account_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, updated_at
            "#,
        )
        .bind(input.id)
        .bind(input.project_id)
        .bind(input.name)
        .bind(input.key_prefix)
        .bind(input.key_hash)
        .bind(input.created_at)
        .bind(input.expires_at)
        .bind(input.status)
        .bind(input.last_used_at)
        .bind(input.last_ip)
        .bind(input.revoked_at)
        .bind(input.billing_plan)
        // The acting account, not the project's owning account: a lead who is not the owner may
        // mint keys, and it is THEIR per-member ceiling that should bound the key.
        .bind(account_id.as_str())
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }

    /// Project-scoped rule -- any member (not just leads) may list keys, unlike `create_api_key`.
    #[instrument(skip(self))]
    pub async fn list_api_keys(
        &self,
        account_id: &AccountId,
        project_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>> {
        let rows: Vec<ApiKeyRow> = sqlx::query_as(
            r#"
            SELECT
              api_keys.id,
              api_keys.project_id,
              api_keys.name,
              api_keys.key_prefix,
              api_keys.key_hash,
              api_keys.created_at,
              api_keys.expires_at,
              api_keys.status,
              api_keys.last_used_at,
              api_keys.last_ip,
              api_keys.revoked_at,
              api_keys.billing_plan,
              api_keys.updated_at
            FROM api_keys
            JOIN projects ON projects.id = api_keys.project_id
            WHERE api_keys.project_id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            ORDER BY api_keys.created_at DESC
            LIMIT $3
            OFFSET $4
            "#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_api_key).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_api_key(
        &self,
        account_id: &AccountId,
        key_id: &str,
    ) -> Result<Option<ApiKey>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              api_keys.id,
              api_keys.project_id,
              api_keys.name,
              api_keys.key_prefix,
              api_keys.key_hash,
              api_keys.created_at,
              api_keys.expires_at,
              api_keys.status,
              api_keys.last_used_at,
              api_keys.last_ip,
              api_keys.revoked_at,
              api_keys.billing_plan,
              api_keys.updated_at
            FROM api_keys
            JOIN projects ON projects.id = api_keys.project_id
            WHERE api_keys.id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(key_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_api_key))
    }

    #[instrument(skip(self))]
    pub async fn update_api_key(
        &self,
        account_id: &AccountId,
        key_id: &str,
        input: UpdateApiKey,
    ) -> Result<ApiKey> {
        let changes = ApiKeyChangeset {
            name: input.name,
            expires_at: input.expires_at,
            status: None,
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
        };
        let row: Option<ApiKeyRow> = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              name = COALESCE($1, api_keys.name),
              expires_at = COALESCE($2, api_keys.expires_at)
            FROM projects
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $3
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $4)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $4
                )
              )
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(changes.name)
        .bind(changes.expires_at)
        .bind(key_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    /// Project-scoped rule (not lead-gated, unlike `create_api_key`) -- this backs both direct
    /// revoke/reactivate and the "revoke the old key" half of `rotate_api_key_transaction` below.
    pub async fn set_api_key_status(
        &self,
        account_id: &AccountId,
        key_id: &str,
        status: ApiKeyStatus,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey> {
        let row: Option<ApiKeyRow> = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              status = $1,
              revoked_at = COALESCE($2, revoked_at),
              expires_at = COALESCE($3, expires_at)
            FROM projects
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $4
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $5)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $5
                )
              )
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(revoked_at)
        .bind(expires_at)
        .bind(key_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    /// Project-scoped rule for both halves (not lead-gated, unlike `create_api_key`): revoking the
    /// presented key and minting its successor both require `account_id` to own the project's
    /// account or hold ANY `project_members` row on it.
    pub async fn rotate_api_key_transaction(
        &self,
        account_id: &AccountId,
        key_id: &str,
        status: ApiKeyStatus,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
        new_key: NewApiKeyRow,
    ) -> Result<ApiKey> {
        let mut tx = self.pool().begin().await?;
        let existing_update = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            UPDATE api_keys
            SET
              status = $1,
              revoked_at = COALESCE($2, revoked_at),
              expires_at = COALESCE($3, expires_at)
            FROM projects
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $4
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $5)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $5
                )
              )
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(revoked_at)
        .bind(expires_at)
        .bind(key_id)
        .bind(account_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        existing_update.ok_or(Error::NotFound)?;
        let new_row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            WITH project_auth AS (
                SELECT projects.id AS project_id
                FROM projects
                WHERE projects.id = $1
                  AND (
                    projects.account_id IN (
                      SELECT owned.id FROM accounts owned
                      WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                    )
                    OR EXISTS (
                      SELECT 1 FROM project_members pm
                      WHERE pm.project_id = projects.id AND pm.account_id = $2
                    )
                  )
            )
            INSERT INTO api_keys (
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, owner_account_id
            )
            -- `$2` is the rotating subject, reused as the new key's owner: rotation re-mints for
            -- whoever performs it, so the per-member ceiling follows the rotator rather than being
            -- inherited from the key being replaced.
            SELECT $3, project_auth.project_id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $2
            FROM project_auth
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(new_key.project_id)
        .bind(account_id.as_str())
        .bind(new_key.id)
        .bind(new_key.name)
        .bind(new_key.key_prefix)
        .bind(new_key.key_hash)
        .bind(new_key.created_at)
        .bind(new_key.expires_at)
        .bind(new_key.status)
        .bind(new_key.last_used_at)
        .bind(new_key.last_ip)
        .bind(new_key.revoked_at)
        .bind(new_key.billing_plan)
        .fetch_optional(&mut *tx)
        .await?;
        let row = new_row.ok_or(Error::NotFound)?;
        tx.commit().await?;
        Ok(Self::to_api_key(row))
    }

    // `delete_api_key` (a hand-written hard `DELETE FROM api_keys`) was removed here (PR #429
    // follow-up): it had no production caller -- `delete-api-key`'s MCP tool and the RPC
    // `model.ApiKey.delete` verb both go through cratestack's generated soft-delete
    // (`deleted_at`), per `migrations/20260721000001_cratestack_soft_delete_audit_defaults.sql`
    // -- and its semantics were actively unsafe alongside self-issued-token introspection
    // (`handlers::exchange_token`): a hard delete leaves NO `api_keys` row behind, and
    // `verify_self_issued_token`'s `azp` check is what keeps a hard-deleted key's
    // still-cryptographically-valid JWT from being reinterpreted as an active exchange session,
    // not the row's mere absence (see that function's doc comment). A dead method whose only
    // effect, if ever wired up again, is to reopen a revocation bypass is worse than no method;
    // do not reintroduce a hand-written hard delete for `api_keys` without re-reading that
    // function's doc comment first.

    /// Read the effective validity of an API key from the `api_key_validation` view (one indexed
    /// lookup by `key_hash`), with the account -> project -> key status cascade resolved by the DB.
    #[instrument(skip(self, key_hash))]
    pub async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<ApiKeyValidation>> {
        let row: Option<ApiKeyValidationRow> = sqlx::query_as(
            r#"
            SELECT
              api_key_id,
              key_hash,
              project_id,
              account_id,
              owner_account_id,
              owner_role,
              owner_quota_tier,
              api_key_status,
              project_status,
              account_status,
              expires_at,
              effective_status
            FROM api_key_validation
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|row| ApiKeyValidation {
            api_key_id: row.api_key_id,
            key_hash: row.key_hash,
            project_id: row.project_id,
            account_id: row.account_id,
            owner_account_id: row.owner_account_id,
            owner_role: row.owner_role,
            owner_quota_tier: row.owner_quota_tier,
            api_key_status: row.api_key_status,
            project_status: row.project_status,
            account_status: row.account_status,
            expires_at: row.expires_at,
            effective_status: row.effective_status,
        }))
    }

    #[instrument(skip(self, key_hash))]
    pub async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, updated_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_api_key))
    }

    #[instrument(skip(self))]
    pub async fn record_api_key_usage(
        &self,
        key_id: &str,
        last_ip: Option<String>,
    ) -> Result<ApiKey> {
        let changes = ApiKeyChangeset {
            name: None,
            expires_at: None,
            status: None,
            last_used_at: Some(Utc::now()),
            last_ip,
            revoked_at: None,
        };
        let row: ApiKeyRow = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              last_used_at = $1,
              last_ip = $2
            WHERE id = $3
            RETURNING
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, updated_at
            "#,
        )
        .bind(changes.last_used_at)
        .bind(changes.last_ip)
        .bind(key_id)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }
}
