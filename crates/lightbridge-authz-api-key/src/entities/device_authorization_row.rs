use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Mirrors `device_authorizations` (see the migration's own doc comment for the full ADR-0012
/// Decision 7 / ADR-0038 rationale). `status` is one of `pending`/`approved`/`denied`/`consumed`
/// (the CHECK constraint also allows `expired`, reserved for a future background sweep this
/// codebase does not implement -- see [`crate::repo::StoreRepo`]'s device-authorization methods
/// for the read-time-only expiry enforcement this table relies on instead).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DeviceAuthorizationRow {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub project_id: Option<String>,
    pub scope: Option<String>,
    pub status: String,
    /// The resolved Keycloak `sub`, set only once `status = 'approved'`. Never present on a
    /// `pending` row -- see the migration's `device_authorizations_subject_only_when_approved`
    /// CHECK constraint, which enforces this at the database level too.
    pub subject: Option<String>,
    pub interval_secs: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_polled_at: Option<DateTime<Utc>>,
}

/// Input for [`crate::repo::StoreRepo::create_device_authorization`]. `id` is minted by the
/// caller via `lightbridge_authz_core::cuid::cuid2()` (ADR-0039) -- never generated here.
#[derive(Debug, Clone)]
pub struct NewDeviceAuthorization {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub project_id: Option<String>,
    pub scope: Option<String>,
    pub interval_secs: i32,
    pub expires_at: DateTime<Utc>,
}
