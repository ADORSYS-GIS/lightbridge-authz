//! **Legitimately exceeds the 200-LoC gate**: this file is one domain slice of the verbatim
//! `repo.rs` -> `repo/` split (#521), with its load-bearing comments restored move-intact
//! under the #760 review. Deeper burn-down is tracked separately, not silently re-factored
//! here (see `docs/code-size-baseline.md`'s rule for honestly-oversized modules).
use chrono::{DateTime, Utc};
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use tracing::instrument;

use crate::entities::device_authorization_row::{DeviceAuthorizationRow, NewDeviceAuthorization};
use crate::repo::StoreRepo;

impl StoreRepo {
    /// Inserts a fresh `pending` `device_authorizations` row (ADR-0012 Decision 7 / #423). A
    /// `user_code` collision (the table's unique index) surfaces as `Error::Conflict`, same
    /// convention as [`Self::create_account`]'s `23505` handling -- the caller (see
    /// `oauth2_op::device_store::create_pending_device_authorization`) is expected to regenerate
    /// the code and retry, per the ticket's own "unique index + retry-on-conflict at insert time,
    /// not a pre-check-then-insert race" risk mitigation. A `device_code` collision (astronomically
    /// unlikely given its entropy) surfaces the same way; this method does not attempt to tell the
    /// two apart, since both are handled identically by the caller (retry with fresh values).
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

    /// Looks up a still-live `device_authorizations` row by `device_code` (backs
    /// `authkestra_op::device::DeviceCodeStore::get_device_code`/`consume_device_code`'s
    /// pre-checks). "Live" means not expired AND not already `consumed` -- a consumed row is
    /// treated as gone for every read path, exactly like an expired one (ADR-0012 Decision 7: "a
    /// device code must be atomically claimed exactly once"; once claimed, later reads of the same
    /// code see nothing, matching `find_active_exchange_refresh_token`'s posture on `expires_at`).
    /// `Ok(None)` covers unknown/expired/consumed uniformly -- callers must not try to distinguish
    /// them from this call alone.
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

    /// Reads a device authorization without treating expiry or consumption as absence. The token
    /// endpoint uses this to return RFC 8628's distinct `expired_token` response while keeping all
    /// other lookup paths enumeration-safe.
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

    /// Same as [`Self::find_active_device_authorization_by_device_code`], keyed by `user_code`
    /// instead (the verification-page submission path -- RFC 8628 §6.1). Callers MUST upper-case
    /// `user_code` before calling (matching `generate_user_code`'s always-upper-case output and
    /// the migration's case-insensitive-by-convention unique index) -- this method does no
    /// normalization of its own.
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

    /// CAS-updates `last_polled_at` on a still-`pending` row (backs
    /// `authkestra_op::device::DeviceCodeStore::store_device_code`'s re-store-while-polling call
    /// site -- see `oauth2_op::device_store`'s doc comment for why that trait method is called a
    /// second time with the same `device_code` during ordinary polling). Deliberately does NOT
    /// touch `status`/`subject` -- unlike [`Self::approve_device_authorization`]/
    /// [`Self::deny_device_authorization`], this is not a state transition, just a liveness
    /// timestamp, so the `WHERE status = 'pending'` guard exists only to make this a safe no-op
    /// once the row has moved on (never to let a stale "store" call clobber an already-decided
    /// row). `Ok(None)` (not an error) when the row is gone/expired/already transitioned.
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

    /// Atomically transitions a `pending` row to `approved`, stamping `subject` (ADR-0025: the
    /// resolved acting account id, never the raw Keycloak `sub` directly) in the same statement --
    /// a single `UPDATE ... WHERE status = 'pending' ... RETURNING` is its own compare-and-swap,
    /// mirroring [`Self::consume_exchange_refresh_token`] exactly: Postgres holds the row lock for
    /// the statement's duration, so two concurrent approval attempts (or an approve racing a deny,
    /// see [`Self::deny_device_authorization`]) can never both observe `status = 'pending'` and
    /// both succeed. `Ok(None)` when the row is gone/expired/already decided -- the caller (a
    /// future verification-page ticket) must treat that as "someone already acted on this code",
    /// not a generic failure.
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

    /// The `deny` mirror of [`Self::approve_device_authorization`] -- same single-statement CAS
    /// shape, `WHERE status = 'pending'` guard, `Ok(None)` on an already-decided/gone row. Leaves
    /// `subject` `NULL` (the migration's `device_authorizations_subject_only_when_approved` CHECK
    /// constraint enforces this at the database level too).
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

    /// Unconditional hard delete, backing
    /// `authkestra_op::device::DeviceCodeStore::delete_device_code`. A no-op (not an error) when
    /// the row is already gone -- deleting something already absent is not a failure, matching
    /// every other unconditional-delete/revoke convention in this file.
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
