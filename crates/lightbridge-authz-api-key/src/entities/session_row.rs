use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// ADR-0020's `sessions` table -- the row a native RFC 8693 token-exchange access token's `sid`
/// claim (and, once ADR-0021 lands its own follow-ups, a browser SSO cookie) names. This crate
/// only ever reads/writes the narrow slice each caller needs (`NewSession` for the insert,
/// [`SessionStatusRow`] for the fail-closed introspection lookup) -- this full row type exists so
/// the bulk-revoke cascade query (`StoreRepo::revoke_sessions_and_cascade`) has something to
/// `RETURNING` if a future caller needs more than a row count.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionRow {
    pub id: String,
    pub account_id: String,
    pub project_id: String,
    /// `NULL` for a `kind = 'browser'` row (ADR-0021 Decision 3) -- always set for `kind =
    /// 'token'` (ADR-0020's original scope), enforced by the `sessions_kind_client_id_check` DB
    /// constraint.
    pub client_id: Option<String>,
    /// `"token"` (ADR-0020) or `"browser"` (ADR-0021 Decision 3) -- plain `String`, this schema's
    /// established convention for closed-set values.
    pub kind: String,
    /// `"active"` / `"revoked"` -- `"expired"` is never written, only computed at read time
    /// (ADR-0020 Decision 6) by comparing `expires_at` to `now()`.
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
}

/// Everything `StoreRepo::create_session` needs to insert a new session row: `kind = "token"`
/// (ADR-0020 Decision 1: created once, at the initial token-exchange grant, unconditionally --
/// see `oauth2_op::store::TokenExchangeOpStore::handle_token_exchange`) or `kind = "browser"`
/// (ADR-0021 Follow-up 6/#441 -- the Keycloak RP-leg callback in
/// `lightbridge_authz_rest::relying_party::KeycloakRelyingParty::complete` mints these on a
/// successful browser sign-in).
#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: String,
    pub account_id: String,
    pub project_id: String,
    pub client_id: Option<String>,
    pub kind: String,
    pub expires_at: DateTime<Utc>,
}

/// The narrow slice of a `sessions` row introspection's fail-closed status check needs
/// (`StoreRepo::find_session_status`, ADR-0020 Decision 4 / #437).
#[derive(Debug, Clone, FromRow)]
pub struct SessionStatusRow {
    pub status: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct BrowserSessionContextRow {
    pub account_id: String,
    pub project_id: String,
}
