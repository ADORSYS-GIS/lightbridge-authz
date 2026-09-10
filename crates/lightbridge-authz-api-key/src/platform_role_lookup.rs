//! Person-lookup helpers for the platform-role surface (ADR-0033): the account → person hop the
//! mint path and `getMyAccess` both need, the person → accounts fan-out revocation needs, and the
//! email → person resolver behind `lightbridge-authz rbac grant --user <email>`.
//!
//! Separate from `platform_roles.rs` (the grant table's own reads and writes) to keep both files
//! inside the repository's 200-LoC ceiling; that module's doc comment carries the ADR-0038
//! justification for the whole surface.

use lightbridge_authz_core::error::Result;
use tracing::instrument;

use crate::db::StoreRepo;
use crate::entities::platform_role_grant_row::UserEmailMatchRow;

impl StoreRepo {
    /// Whether `users` holds this id. Used ahead of a grant insert so an unknown person is a clean
    /// `404`, not an opaque foreign-key `23503` surfaced as a 500.
    #[instrument(skip(self))]
    pub async fn user_exists(&self, user_id: &str) -> Result<bool> {
        let found: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(self.pool())
            .await?;
        Ok(found.is_some())
    }

    /// The person (`users.id`) behind an account id.
    ///
    /// `Ok(None)` means there is no `accounts` row for that id at all — which happens in exactly
    /// one live situation, the ADR-0025 Stage-2..5 bootstrap window: a brand-new subject whose
    /// only pending operation is `createAccount`. Callers must decide what that means for them
    /// rather than being handed a fabricated id; the claim mapper treats it as "no grants" (a
    /// person with no account cannot have been granted anything) and `getMyAccess` falls back to
    /// the subject itself, which is what `users.id` will become the moment the account is created
    /// (the `accounts_set_user` trigger provisions `users.id = accounts.id`).
    ///
    /// This is deliberately NOT `user_id == account_id`, even though the two are byte-identical
    /// for every grandfathered account: ADR-0026 lets one person own several accounts, and a
    /// platform role follows the human across all of them.
    #[instrument(skip(self))]
    pub async fn resolve_user_id_for_account(&self, account_id: &str) -> Result<Option<String>> {
        let user_id: Option<String> =
            sqlx::query_scalar("SELECT user_id FROM accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(self.pool())
                .await?;
        Ok(user_id)
    }

    /// Every account this person owns, oldest first.
    ///
    /// Backs `revokePlatformRole`'s session fan-out: `sessions.subject` carries the ACTING account
    /// id (#492), and one person may be acting in any of the accounts they own (ADR-0026), so
    /// revoking "this person's sessions" means revoking each account's. Served by
    /// `idx_accounts_user_id_created_at`.
    #[instrument(skip(self))]
    pub async fn account_ids_for_user(&self, user_id: &str) -> Result<Vec<String>> {
        let ids = sqlx::query_scalar::<_, String>(
            r#"
            SELECT id FROM accounts WHERE user_id = $1 ORDER BY created_at, id
            "#,
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await?;
        Ok(ids)
    }

    /// Every person whose federated identity carries `email`, case-insensitively.
    ///
    /// Returns ALL matches, deliberately — the whole point is that the CLI can REFUSE an ambiguous
    /// `--user <email>` instead of guessing. Two different people can genuinely share an email
    /// string here: `federated_identities` is unique on `(issuer, subject)`, not on `email`, so
    /// the same address logged in through two realms is two rows, two accounts and (unless they
    /// were explicitly linked) two `users` rows. Picking one would silently grant admin to the
    /// wrong human.
    ///
    /// Ordered by `user_id` so an ambiguity error lists the candidates identically on every run.
    /// The hop is `federated_identities.account_id -> accounts.user_id`, the same derived path
    /// `resolve_user_profiles` documents — `federated_identities` has carried no `user_id` column
    /// since `20260825000002`.
    #[instrument(skip(self))]
    pub async fn find_users_by_email(&self, email: &str) -> Result<Vec<UserEmailMatchRow>> {
        let rows = sqlx::query_as::<_, UserEmailMatchRow>(
            r#"
            SELECT DISTINCT a.user_id AS user_id, fi.email AS email
            FROM federated_identities fi
            JOIN accounts a ON a.id = fi.account_id
            WHERE fi.email IS NOT NULL AND lower(fi.email) = lower($1)
            ORDER BY user_id
            "#,
        )
        .bind(email.trim())
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}
