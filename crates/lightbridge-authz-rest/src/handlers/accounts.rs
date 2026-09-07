//! Account write operations on [`AuthzStoreImpl`] — `createAccount`, `updateAccountDefaultQuota`,
//! `updateAccountName` — and, since #697, the starting grant that `createAccount` books.
//!
//! A child module of [`super`] rather than a separate type, so these keep reaching
//! `AuthzStoreImpl`'s private fields directly. Split out because `handlers/mod.rs` is at its
//! grandfathered LoC ceiling (`.github/loc-baseline.json`) and the starting grant had to go
//! somewhere it could be documented properly.

use chrono::Utc;
use lightbridge_authz_core::{
    Account, AccountId, CreateAccount,
    error::{Error, Result},
};

use super::AuthzStoreImpl;

impl AuthzStoreImpl {
    /// Create the caller's account. Backs the `createAccount` procedure. Since ADR-0006 the account
    /// id **is** the caller's JWT subject — one account per person — so no id is generated and none
    /// may be supplied: the generic `model.Account.create` verb stays denied precisely because a
    /// caller-chosen id would let one subject create an account keyed to another. Calling this twice
    /// for the same subject is a `Conflict`, not a second account.
    ///
    /// `input.default_quota` is validated against the operator-configured quota-tier catalogue
    /// (#177) before any DB write, same pattern and error shape as `create_api_key`'s
    /// `billing_plan` check (`super`): `None` always passes, and an empty/absent catalogue accepts
    /// any value (see `QuotaTiers::is_allowed`).
    ///
    /// #697: the account is funded before this returns. See [`Self::book_starting_grant`].
    pub async fn create_account(&self, subject: &str, input: CreateAccount) -> Result<Account> {
        if !self.quota_tiers.is_allowed(input.default_quota.as_deref()) {
            let tier = input.default_quota.as_deref().unwrap_or_default();
            return Err(Error::BadRequest(format!(
                "unknown defaultQuota '{tier}': must be one of the configured tiers [{}]",
                self.quota_tiers.tier_ids().join(", ")
            )));
        }
        let input = CreateAccount {
            name: Self::normalize_account_name(input.name.as_deref()).map(str::to_owned),
            ..input
        };
        let account = self
            .repo
            .create_account(&AccountId::assert_already_resolved(subject), input)
            .await?;
        tracing::info!(
            operation = "create_account",
            subject = %subject,
            account_id = %account.id,
            "account created"
        );
        self.book_starting_grant(&account.id).await;
        Ok(account)
    }

    /// Books the new account's starting grant (#697) — one `automatic` grant for the current
    /// period, worth what the account's effective reset schedule would reset it to, idempotent on
    /// `budget-start-<period>-<account_id>`. Without it a brand-new account reads
    /// `remaining = 0` at the enforcing gateway and gets `402` until the next weekly reset.
    ///
    /// **A failure here is logged, not propagated, and that is deliberate.** The `accounts` row is
    /// already committed by the time this runs (the tenancy crate owns that transaction and does
    /// not depend on the budget crate — see `lightbridge_authz_budget::starting_grant`), and since
    /// ADR-0026 a retried `createAccount` for the same identity mints a SECOND account rather than
    /// re-running the first. Failing the procedure would therefore turn one unfunded account into
    /// two. The backstops are the idempotency key (a later `budget grant --idempotency-key
    /// budget-start-…` repairs it exactly once), the account's own reset schedule, and this
    /// `error!` line, which is what a runbook alerts on.
    async fn book_starting_grant(&self, account_id: &str) {
        if let Err(err) = self.starting_grant.book(account_id, Utc::now()).await {
            tracing::error!(
                operation = "create_account",
                account_id = %account_id,
                error = %err,
                "the new account's starting grant could not be booked -- it will read \
                 remaining = 0 at the gateway until a reset schedule or an operator funds it \
                 (idempotency key: budget-start-<period>-<account id>)"
            );
        }
    }

    /// Updates `Account.defaultQuota` post-creation. Backs `updateAccountDefaultQuota` (#379,
    /// completing #177/#375): `Account.defaultQuota` is now `@readonly` on the generic
    /// `model.Account.update` verb (which has no hook for a runtime-configured catalogue check),
    /// so this procedure is the only write path left. Same catalogue check, same pattern/error
    /// shape, as `create_account`'s `default_quota` check above -- see that method's doc comment
    /// for the full contract (`None` always passes, an empty/absent catalogue accepts any value).
    pub async fn update_account_default_quota(
        &self,
        subject: &str,
        account_id: &str,
        default_quota: Option<&str>,
    ) -> Result<Account> {
        if !self.quota_tiers.is_allowed(default_quota) {
            return Err(Error::BadRequest(format!(
                "unknown defaultQuota '{}': must be one of the configured tiers [{}]",
                default_quota.unwrap_or_default(),
                self.quota_tiers.tier_ids().join(", ")
            )));
        }
        let account = self
            .repo
            .update_account_default_quota(
                &AccountId::assert_already_resolved(subject),
                account_id,
                default_quota,
            )
            .await?;
        tracing::info!(
            operation = "update_account_default_quota",
            subject = %subject,
            account_id = %account.id,
            "account defaultQuota updated"
        );
        Ok(account)
    }

    /// Collapses a blank or whitespace-only account name to "no name". `NULL` is the single
    /// representation of unnamed everywhere below this point -- in the DTO, in the column, and in
    /// what a console reads back -- so an empty string must never survive as a *set* name; if it
    /// did, a console could no longer distinguish "named" from "not named yet" and could not
    /// offer a name-me affordance. Trimming is normalisation, not validation: a name is free text
    /// with no catalogue behind it, so surrounding whitespace is silently dropped rather than
    /// rejected, and anything non-blank is stored verbatim. The DB
    /// `CHECK (name IS NULL OR btrim(name) <> '')`
    /// (`migrations/20260829000001_accounts_add_name.sql`) is the backstop that keeps this true
    /// for any future write path, not the primary enforcement.
    fn normalize_account_name(name: Option<&str>) -> Option<&str> {
        name.map(str::trim).filter(|trimmed| !trimmed.is_empty())
    }

    /// Sets `Account.name` post-creation. Backs `updateAccountName` -- the sole write path for that
    /// field: it is `@readonly` in the schema and `model.Account.update` was removed outright by
    /// #398, so there is no generic verb it could ride. Shaped like
    /// `update_account_default_quota` above, minus the catalogue check: a name is free text with
    /// nothing to validate it against. `None` (and, via [`Self::normalize_account_name`], a blank
    /// string) clears it back to unnamed; this always writes, it is not a PATCH.
    ///
    /// The name itself is deliberately NOT logged. It is user-supplied free text on a tenant row,
    /// and the account id already identifies the row for any audit purpose.
    pub async fn update_account_name(
        &self,
        subject: &str,
        account_id: &str,
        name: Option<&str>,
    ) -> Result<Account> {
        let account = self
            .repo
            .update_account_name(
                &AccountId::assert_already_resolved(subject),
                account_id,
                Self::normalize_account_name(name),
            )
            .await?;
        tracing::info!(
            operation = "update_account_name",
            subject = %subject,
            account_id = %account.id,
            cleared = account.name.is_none(),
            "account name updated"
        );
        Ok(account)
    }
}
