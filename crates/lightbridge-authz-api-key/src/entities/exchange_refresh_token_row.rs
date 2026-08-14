use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ExchangeRefreshTokenRow {
    pub id: String,
    pub subject: String,
    pub account_id: String,
    pub project_id: String,
    pub token_hash: String,
    pub scope: Option<String>,
    pub status: String,
    /// Snapshot of the upstream `subject_token`'s `email`/`email_verified` at the exchange that
    /// created this refresh-token session, so `mint_from_refresh` can re-mint symmetrically with
    /// the original exchange grant instead of dropping them (ADR-0011, Decision 1 -- the
    /// `mint_from_refresh` email-dropping bug this column set fixes).
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    /// Snapshot of the upstream `subject_token`'s `auth_time`, carried across refreshes: it
    /// describes when the original authentication happened, which does not change on refresh
    /// (unlike `nonce`, deliberately not persisted here -- see `mint_from_refresh`'s doc comment).
    pub auth_time: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewExchangeRefreshToken {
    pub id: String,
    pub subject: String,
    pub account_id: String,
    pub project_id: String,
    pub token_hash: String,
    pub scope: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub auth_time: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
