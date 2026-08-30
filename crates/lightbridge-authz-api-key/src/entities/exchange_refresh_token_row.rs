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
    /// Snapshot of `KeyOwner::preferred_username`/`KeyOwner::name` at the grant that created this
    /// refresh-token chain (migration
    /// `20260830000002_exchange_refresh_tokens_add_profile_claims.sql`), carried across every
    /// rotation exactly like `email`/`email_verified` above -- otherwise a refresh would silently
    /// drop these two claims even though the initial token in the chain carried them.
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// The rotation-chain family this token belongs to (RFC 6819 §5.2.2.3 reuse-detection
    /// cascade): shared by every token minted across one chain, starting at the offline_access
    /// exchange grant that gave birth to it. Replaying an already-rotated token revokes every
    /// still-active row sharing this value.
    pub chain_id: String,
    /// Absolute deadline for this token's whole chain, set once when the chain was born and
    /// inherited unchanged by every rotation since -- independent of, and typically longer-lived
    /// than, this individual row's own `expires_at`.
    pub chain_expires_at: DateTime<Utc>,
    /// ADR-0020: the `sessions` row this refresh token is chained under -- minted once at the
    /// initial exchange grant and inherited unchanged across every rotation, the same "born once,
    /// inherited across rotation" shape `chain_id` already has (Decision 1 explicitly subsumes
    /// `chain_id`'s role into this column going forward; `chain_id`/`chain_expires_at` are kept,
    /// unchanged, for one release per that Decision's own deferral).
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Refresh-reuse grace window (migration
    /// `20260830000004_exchange_refresh_tokens_add_reuse_grace.sql`, added after the 2026-08-30
    /// console-401s incident -- see that migration's doc comment): when this row's single-use CAS
    /// consume flipped it from `active` to `rotated`. `NULL` for a row that has never been
    /// rotated, and for rows rotated before the migration ran. `TokenExchangeOpStore::
    /// classify_replayed_refresh_token` treats `NULL` as OUTSIDE the grace window -- fail closed,
    /// same as today's pre-grace cascade -- never as "always graced".
    pub rotated_at: Option<DateTime<Utc>>,
    /// The id of the row this one was rotated into, written atomically with `rotated_at`.
    /// Informational lineage only -- see the owning migration's doc comment for why it is not a
    /// foreign key, and why a graced replay's own new successor does not overwrite it.
    pub successor_id: Option<String>,
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
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    pub chain_id: String,
    pub chain_expires_at: DateTime<Utc>,
    /// See [`ExchangeRefreshTokenRow::session_id`]'s doc comment.
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
