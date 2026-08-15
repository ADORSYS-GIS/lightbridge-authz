use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ExchangeRefreshTokenRow {
    pub id: String,
    pub subject: String,
    pub account_id: String,
    pub project_id: String,
    /// The registered client (ADR-0011, Decision 5) this refresh token was issued to. Checked
    /// again on every refresh -- a token presented by a different client is rejected (and burned,
    /// not silently ignored), matching `authkestra_op::handlers::token::default_handle_refresh_token`'s
    /// own `old_rt.client_id != client_id` check.
    pub client_id: String,
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
    /// The rotation-chain family this token belongs to (RFC 6819 §5.2.2.3 reuse-detection
    /// cascade): shared by every token minted across one chain, starting at the offline_access
    /// exchange grant that gave birth to it. Replaying an already-rotated token revokes every
    /// still-active row sharing this value.
    pub chain_id: String,
    /// Absolute deadline for this token's whole chain, set once when the chain was born and
    /// inherited unchanged by every rotation since -- independent of, and typically longer-lived
    /// than, this individual row's own `expires_at`.
    pub chain_expires_at: DateTime<Utc>,
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
    pub client_id: String,
    pub token_hash: String,
    pub scope: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub auth_time: Option<i64>,
    pub chain_id: String,
    pub chain_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
