//! The per-page enrichment query behind `querySessions` (ADR-0020 Follow-up 4, #649).
//!
//! Two facts a `sessions` row cannot answer about itself, batched over the ids one page already
//! returned:
//!
//! - **`subject_user_id`** — the PERSON behind the session. `sessions.subject` is an account id
//!   (ADR-0006: `accounts.id` holds the JWT `sub` verbatim), and since ADR-0026 one person may own
//!   several accounts, so the account id is not the identity. `accounts.user_id` is, and the
//!   console batch-resolves it into a name/email through `resolveUserProfiles` (#647).
//! - **`offline`** — whether the session's refresh chain carries `offline_access`, the
//!   owner-confirmed discriminator for a CLI/device login (OIDC Core §11: access that outlives the
//!   end-user's browser session) versus a browser one.
//!
//! # Why hand-written SQL (ADR-0038)
//!
//! `Session` IS a cratestack model and its rows are read through the generated client — that is
//! deliberate, and it is what makes the own-scope policy unbypassable (see the `@@allow("read")`
//! clause in `authz.cstack`). These two fields are not on that model and cannot be: `accounts` is
//! reachable only through an ownership-scoped `@@allow`, and `exchange_refresh_tokens` is one of
//! this repo's documented ADR-0038 exceptions, absent from the schema entirely because it stores
//! token hashes. So the split is: **cratestack decides which rows the caller may see; this query
//! only annotates ids that decision has already released.** It applies no ownership filter, and it
//! must not be called with ids that did not come out of a policy-scoped read.
//!
//! Lives beside `session_revocation.rs` rather than in `repo.rs` for the same reason that file
//! does: `repo.rs` sits on its committed LoC-gate baseline and may be touched but not grown.

use lightbridge_authz_core::error::Result;
use tracing::instrument;

use crate::db::StoreRepo;
use crate::entities::session_row::SessionFactsRow;

/// The scope token that marks a refresh chain as offline (OIDC Core §11). Matched as a whole
/// space-delimited word, never as a substring — a client that asks for a hypothetical
/// `offline_access_readonly` scope must not be reported as offline.
const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

impl StoreRepo {
    /// `subject_user_id` + `offline` for each of `session_ids`, in one query.
    ///
    /// Ids with no `sessions` row are simply absent from the result (they cannot occur when the
    /// caller passes ids from a page it just read, but the query does not pretend otherwise).
    /// `offline` is `EXISTS`-derived, so it is `false` — never null — for a session with no chain.
    ///
    /// The `EXISTS` rides `idx_exchange_refresh_tokens_session_id` (from
    /// `migrations/20260823000002_sessions.sql`); the scope test inside it runs over the handful of
    /// rotations belonging to one session, and `EXISTS` stops at the first match.
    #[instrument(skip(self, session_ids), fields(count = session_ids.len()))]
    pub async fn session_listing_facts(
        &self,
        session_ids: &[String],
    ) -> Result<Vec<SessionFactsRow>> {
        if session_ids.is_empty() {
            return Ok(Vec::new());
        }
        // The scope column is a space-delimited list, so both the haystack and the needle are
        // padded with spaces before the `LIKE` — `'% offline_access %'` against `' openid
        // offline_access '` matches the whole word and nothing longer. `position()` would read
        // more cheaply but would match a substring; correctness first on an authorization-adjacent
        // signal.
        let needle = format!("% {OFFLINE_ACCESS_SCOPE} %");
        let rows = sqlx::query_as::<_, SessionFactsRow>(
            r#"
            SELECT
                s.id       AS session_id,
                a.user_id  AS subject_user_id,
                EXISTS (
                    SELECT 1
                    FROM exchange_refresh_tokens ert
                    WHERE ert.session_id = s.id
                      AND ert.scope IS NOT NULL
                      AND ' ' || ert.scope || ' ' LIKE $2
                )          AS offline
            FROM sessions s
            LEFT JOIN accounts a ON a.id = s.subject
            WHERE s.id = ANY($1)
            "#,
        )
        .bind(session_ids)
        .bind(&needle)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}
