use chrono::{DateTime, Utc};
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use tracing::instrument;

use crate::entities::device_authorization_row::{DeviceAuthorizationRow, NewDeviceAuthorization};
use crate::repo::StoreRepo;

impl StoreRepo {
    #[instrument(skip(self, input))]
    pub async fn create_device_authorization(
        &self,
        input: NewDeviceAuthorization,
    ) -> Result<DeviceAuthorizationRow> {
        let row: DeviceAuthorizationRow = sqlx::query_as(
            r#"
            INSERT INTO device_authorizations
              (id, device_code, user_code, client_id, project_id, scope, status, interval_secs, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(input.id)
        .bind(input.device_code)
        .bind(input.user_code)
        .bind(input.client_id)
        .bind(input.project_id)
        .bind(input.scope)
        .bind(input.interval_secs)
        .bind(input.expires_at)
        .fetch_one(self.pool())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return Error::Conflict(
                    "device_code or user_code already in use, caller should retry with fresh \
                     values"
                        .to_string(),
                );
            }
            Error::from(e)
        })?;
        Ok(row)
    }

    pub async fn find_active_device_authorization_by_device_code(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            FROM device_authorizations
            WHERE device_code = $1
              AND status <> 'consumed'
              AND expires_at > $2
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            FROM device_authorizations
            WHERE device_code = $1
            "#,
        )
        .bind(device_code)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_active_device_authorization_by_user_code(
        &self,
        user_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            FROM device_authorizations
            WHERE user_code = $1
              AND status <> 'consumed'
              AND expires_at > $2
            "#,
        )
        .bind(user_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn touch_device_authorization_poll(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            UPDATE device_authorizations
            SET last_polled_at = $2
            WHERE device_code = $1
              AND status = 'pending'
              AND expires_at > $2
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn approve_device_authorization(
        &self,
        device_code: &str,
        account_id: &AccountId,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            UPDATE device_authorizations
            SET status = 'approved', subject = $2
            WHERE device_code = $1
              AND status = 'pending'
              AND expires_at > $3
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(account_id.as_str())
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn deny_device_authorization(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            UPDATE device_authorizations
            SET status = 'denied'
            WHERE device_code = $1
              AND status = 'pending'
              AND expires_at > $2
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Atomically consumes an `approved`/`denied` row exactly once (backs
    /// `authkestra_op::device::DeviceCodeStore::consume_device_code`, called from the CLI's
    /// `/oauth2/token` poll once it observes a non-`pending` status). Single-use enforcement, same
    /// CAS guard as [`Self::consume_exchange_refresh_token`] (`WHERE status IN ('approved',
    /// 'denied') ...`), so two concurrent polls presenting the same `device_code` can never both
    /// observe a claimable status and both succeed -- exactly one call ever gets `Some(..)` back;
    /// every other concurrent or later call gets `Ok(None)`.
    ///
    /// Unlike every other CAS method in this file, this one is a `WITH ... FOR UPDATE` CTE feeding
    /// an `UPDATE ... FROM`, not a plain `UPDATE ... RETURNING` -- deliberately, because the
    /// caller needs the row's PRE-consume `status`/`subject` (to know whether the device code was
    /// approved or denied, and by whom) and plain `RETURNING` only ever exposes the POST-update
    /// row, which would come back as `status = 'consumed'` -- a value
    /// `oauth2_op::device_store::row_to_session` has no way to map back onto the upstream
    /// `DeviceCodeStatus` enum (only `Pending`/`Approved`/`Denied` exist there; this was caught by
    /// this repo's own it-tests, not by inspection -- see #423's PR description). The `FOR UPDATE`
    /// inside the CTE still holds the row lock for the whole statement's duration -- the second of
    /// two concurrent callers blocks on it until the first's `UPDATE` commits, then re-evaluates
    /// the CTE's `WHERE status IN (...)` and finds nothing, so this remains a single atomic
    /// statement and the CAS property holds exactly as it does everywhere else in this file.
    ///
    /// Kept as a `status = 'consumed'` flip rather than a hard `DELETE` -- consistent with this
    /// codebase's ledger-like convention for CAS-consumed rows (`exchange_refresh_tokens` does the
    /// same) -- and every read path already treats `consumed` as absent (see
    /// [`Self::find_active_device_authorization_by_device_code`]), so the row is functionally
    /// "consumed-and-gone" per ADR-0012 Decision 7 even though the audit trail survives.
    pub async fn consume_device_authorization(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            WITH claimable AS (
                SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
                FROM device_authorizations
                WHERE device_code = $1
                  AND status IN ('approved', 'denied')
                  AND expires_at > $2
                FOR UPDATE
            )
            UPDATE device_authorizations d
            SET status = 'consumed'
            FROM claimable
            WHERE d.id = claimable.id
            RETURNING claimable.id, claimable.device_code, claimable.user_code, claimable.client_id, claimable.project_id, claimable.scope, claimable.status, claimable.subject, claimable.interval_secs, claimable.created_at, claimable.expires_at, claimable.last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn delete_device_authorization(&self, device_code: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM device_authorizations
            WHERE device_code = $1
            "#,
        )
        .bind(device_code)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}
