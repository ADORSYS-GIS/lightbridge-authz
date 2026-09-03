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
    /// The OAuth client this session belongs to -- the `azp` `/admin/sessions` lists.
    ///
    /// Always set for `kind = 'token'` (ADR-0020's original scope), and enforced as such by the
    /// `sessions_kind_client_id_check` DB constraint. For `kind = 'browser'` it is the client
    /// whose `/authorize` request STARTED the login (provenance, not scope -- ADR-0021 Decision
    /// 3's "a browser session is not scoped to any one client" still holds; nothing gates session
    /// reuse or logout on this value). `None` on a browser row minted before
    /// `migrations/20260903000001_sessions_browser_client_id.sql`, which no backfill can recover:
    /// the authorization code that carried the client id is single-use and long consumed.
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
    /// Raw authenticated IdP subject (Keycloak ID-token `sub`, or the token-exchange
    /// `subject_token`'s validated `sub`) -- the real actor, distinct from `account_id`, which
    /// always holds the project's OWNING account (see `revoke_sessions_and_cascade`'s doc
    /// comment, #492, for why this distinction matters). Populated for `kind = "browser"` rows
    /// since `migrations/20260824000003_sessions_add_subject.sql`, and for `kind = "token"` rows
    /// since #492's companion fix to `oauth2_op::store::TokenExchangeOpStore`. `NULL` only for a
    /// session row minted before whichever of those two changes applies to its `kind`.
    pub subject: Option<String>,
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
    /// See [`SessionRow::client_id`]. `Some` for every path that mints a session today -- the
    /// token-exchange and device grants pass the redeeming client, and the browser-SSO callback
    /// passes the client that started the login (`BrowserLoginTarget::client_id`).
    pub client_id: Option<String>,
    pub kind: String,
    pub expires_at: DateTime<Utc>,
    /// Raw authenticated IdP subject -- always `Some` for both the browser-SSO flow
    /// (`KeycloakRelyingParty::complete`'s `PendingFlow::Browser` arm) and the token-exchange /
    /// device-code flows (`TokenExchangeOpStore::handle_token_exchange`/`issue_device_tokens`).
    /// This is the real actor, kept distinct from `account_id` (the project's owning account) so
    /// `revoke_sessions_and_cascade` can target the person who actually holds the session rather
    /// than whoever owns the project it was minted against (#492).
    pub subject: Option<String>,
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
    /// The real authenticated IdP subject this browser session was minted for -- `None` only for
    /// a session row created before `migrations/20260824000003_sessions_add_subject.sql`. Callers
    /// must treat `None` as unusable and fail closed (see `authorize.rs`), never fall back to
    /// `account_id` -- that fallback is exactly the identity-substitution bug this column fixes.
    pub subject: Option<String>,
}

/// The two facts a listed session needs that its own row cannot answer, keyed by session id
/// (`StoreRepo::session_listing_facts`, #649).
///
/// Read in ONE batch query over the ids a page already returned, rather than per row: the page is
/// capped at 100, and an N+1 here would be 100 round trips to render one table.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct SessionFactsRow {
    pub session_id: String,
    /// `accounts.user_id` for the account named by `sessions.subject` -- the PERSON, not the
    /// account (ADR-0026: one identity may own many accounts). `None` when `subject` is `None`, or
    /// when it names no `accounts` row; both are "unknown", and the caller renders its own
    /// sentinel rather than being handed a fabricated one (#647's contract, kept here).
    pub subject_user_id: Option<String>,
    /// Whether this session's refresh chain carries the `offline_access` scope -- the
    /// owner-confirmed definition of an "offline" (CLI/device) session, as opposed to a browser
    /// one. Never `NULL`: a session with no chain at all is `false`.
    pub offline: bool,
}

/// The narrow slice `revokeSession` needs BEFORE it decides whether the caller may act
/// (`StoreRepo::find_session_owner`, #649): who the session belongs to, and whether it is already
/// revoked. Deliberately not the whole [`SessionRow`] -- the ownership decision reads two columns,
/// and a caller who turns out not to own the session must never have had the rest in hand.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct SessionOwnerRow {
    /// See [`SessionRow::subject`]. `None` for a session minted before the subject column existed;
    /// such a row is owned by nobody, so only a `session:revoke` holder can act on it.
    pub subject: Option<String>,
    /// The STORED status (`"active"` / `"revoked"`), not the computed one -- expiry is irrelevant
    /// to whether a revoke is allowed, only to whether it changes anything.
    pub status: String,
}
