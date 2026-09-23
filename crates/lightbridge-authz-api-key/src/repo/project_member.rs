//! **Legitimately exceeds the 200-LoC gate**: this file is one domain slice of the verbatim
//! `repo.rs` -> `repo/` split (#521), with its load-bearing comments restored move-intact
//! under the #760 review. Deeper burn-down is tracked separately, not silently re-factored
//! here (see `docs/code-size-baseline.md`'s rule for honestly-oversized modules).
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{Project, ProjectMember};
use tracing::instrument;

use crate::entities::project_member_row::ProjectMemberRow;
use crate::repo::StoreRepo;

impl StoreRepo {
    const VALID_PROJECT_ROLES: [&'static str; 2] = ["lead", "member"];

    fn validate_project_role(role: &str) -> Result<()> {
        if Self::VALID_PROJECT_ROLES.contains(&role) {
            Ok(())
        } else {
            Err(Error::BadRequest(format!(
                "invalid project role '{role}', must be one of {:?}",
                Self::VALID_PROJECT_ROLES
            )))
        }
    }

    /// `subject`'s `role` on `project_id`'s roster, or `None` if they hold no `project_members` row
    /// there at all. Replaces the removed `member_role` (account-scoped); note this does NOT check
    /// the project's account owner -- callers that need to treat the owner as implicitly authorized
    /// (every lead-gated procedure does) go through `authorize_project_lead` instead, which layers
    /// that check on top of this one.
    ///
    /// `pub`: also read by `authz-opa`'s introspection handler (`OpaRepoTrait::project_member_role`)
    /// to resolve the `role` claim for a native RFC 8693 exchange session at introspection time,
    /// the human/OIDC-plane mirror of `project_member_quota_tier` below (ADR-0017's same
    /// reasoning applies here).
    #[instrument(skip(self, account_id))]
    pub async fn project_member_role(
        &self,
        project_id: &str,
        account_id: &AccountId,
    ) -> Result<Option<String>> {
        let role: Option<String> = sqlx::query_scalar(
            r#"SELECT role FROM project_members WHERE project_id = $1 AND account_id = $2"#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        Ok(role)
    }

    /// Resolves the acting account's per-member `quota_tier` on `project_id` (ADR-0017), the
    /// human/OIDC-plane mirror of the API-key plane's `owner_quota_tier`
    /// (`api_key_validation` view, `migrations/20260731000001_api_keys_owner_account.sql`).
    /// Deliberately keyed on `account_id` (the acting person), not the project's owning account --
    /// same reasoning as that view's `pm.account_id = k.owner_account_id` join: a lead acting on a
    /// project someone else owns is governed by their OWN roster row, not the owner's.
    ///
    /// `Ok(None)` covers two states the caller must NOT distinguish, matching the view's own
    /// documented NULL semantics verbatim: no `project_members` row at all (the common case for a
    /// project's owning account, which normally holds none), or a row whose `quota_tier` column is
    /// NULL. Both mean "no per-member ceiling, the caller is bounded by the pooled
    /// `projects.project_quota` alone" -- a resolved, legitimate answer, not a failure.
    ///
    /// `Err` means the lookup itself could not be completed (e.g. the database is unreachable) --
    /// distinct in kind from `Ok(None)`, and callers MUST NOT collapse the two: a database outage
    /// must never be represented on the wire the same way as "no per-member ceiling", or an
    /// availability failure becomes a quota bypass. See `TokenExchangeOpStore::resolve_quota_tier`
    /// for how the token-exchange/refresh call sites act on that distinction (refuse the mint
    /// rather than omit the claim).
    #[instrument(skip(self, account_id))]
    pub async fn project_member_quota_tier(
        &self,
        project_id: &str,
        account_id: &AccountId,
    ) -> Result<Option<String>> {
        let quota_tier: Option<Option<String>> = sqlx::query_scalar(
            r#"SELECT quota_tier FROM project_members WHERE project_id = $1 AND account_id = $2"#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        Ok(quota_tier.flatten())
    }

    /// Adds `target_account_id` to `project_id`'s roster with `role` (defaults to `"member"` when
    /// `None`, matching the schema's `AddProjectMemberInput.role` doc). Lead-gated via
    /// `authorize_project_lead`. Idempotent like the deleted `add_account_member`: re-adding an
    /// existing member is a no-op that leaves their current role untouched -- use
    /// `set_project_member_role` to change it.
    #[instrument(skip(self))]
    pub async fn add_project_member(
        &self,
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
        role: Option<&str>,
    ) -> Result<Project> {
        let role = role.unwrap_or("member");
        Self::validate_project_role(role)?;
        self.authorize_project_lead(project_id, account_id).await?;

        // ADR-0026 D5: the roster names an ACCOUNT ("a project member IS an account",
        // 20260727000001), and the `Project`/`ApiKey` membership policies compare that account
        // against `auth().id` -- which is only ever a person's HOME account. Once one person can
        // own several accounts, adding a NON-home account to a roster is a silent dead end: the
        // row exists, the member is listed, and they never gain access, because they will never
        // act as that account. Refuse it at the point of insert instead of shipping a roster entry
        // that cannot work.
        //
        // A home account is one that owns itself (`id = user_id`) -- see the LOAD-BEARING
        // INVARIANT block on `Account.userId` in authz.cstack. Checked against `accounts` rather
        // than `federated_identities` deliberately: equivalent under that invariant, and it keeps
        // the credential-bearing table out of an ordinary CRUD path.
        //
        // `BadRequest`, not `NotFound`: the lead is already authorized on this project (the check
        // above passed), so there is no existence to leak here -- and a silent no-op would be the
        // worst outcome of the three.
        let target_is_home_account: Option<(bool,)> =
            sqlx::query_as("SELECT (user_id = id) FROM accounts WHERE id = $1")
                .bind(target_account_id)
                .fetch_optional(self.pool())
                .await?;
        match target_is_home_account {
            Some((true,)) => {}
            Some((false,)) => {
                return Err(Error::BadRequest(
                    "target account is a secondary account and cannot hold project membership; \
                     use the owner's primary account"
                        .to_string(),
                ));
            }
            None => return Err(Error::NotFound),
        }

        sqlx::query(
            r#"
            INSERT INTO project_members (project_id, account_id, role)
            VALUES ($1, $2, $3)
            ON CONFLICT (project_id, account_id) DO NOTHING
            "#,
        )
        .bind(project_id)
        .bind(target_account_id)
        .bind(role)
        .execute(self.pool())
        .await?;

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }

    /// Lists `project_id`'s roster. Backs `listProjectRoster`, the roster's only read path.
    ///
    /// Authorization is deliberately WIDER than the four mutations above: any member of the
    /// project may read it, plus the owning account. Leads are not privileged here -- knowing who
    /// you are working alongside is not a management capability, and gating it on `lead` would
    /// leave plain members unable to see the roster they are on. A caller with no standing at all
    /// gets `NotFound`, matching `authorize_project_lead`'s no-existence-leak contract rather than
    /// distinguishing "no such project" from "not yours".
    ///
    /// `id` is synthesised from the composite primary key. The real `project_members` table is
    /// keyed `(project_id, account_id)` and has no `id` column -- the schema's `ProjectMember.id`
    /// exists only because cratestack requires exactly one scalar `@id` -- so this is the one
    /// place that has to invent it, and it must stay stable for a given row because clients use
    /// it as a list key.
    #[instrument(skip(self))]
    pub async fn list_project_roster(
        &self,
        account_id: &AccountId,
        project_id: &str,
    ) -> Result<Vec<ProjectMember>> {
        let project_account_id: Option<String> =
            sqlx::query_scalar(r#"SELECT account_id FROM projects WHERE id = $1"#)
                .bind(project_id)
                .fetch_optional(self.pool())
                .await?;
        let Some(project_account_id) = project_account_id else {
            return Err(Error::NotFound);
        };
        if project_account_id != account_id.as_str()
            && self
                .project_member_role(project_id, account_id)
                .await?
                .is_none()
        {
            return Err(Error::NotFound);
        }

        let rows = sqlx::query_as::<_, ProjectMemberRow>(
            r#"
            SELECT project_id, account_id, role, quota_tier, created_at
            FROM project_members
            WHERE project_id = $1
            ORDER BY created_at ASC, account_id ASC
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool())
        .await?;

        Ok(rows.into_iter().map(ProjectMember::from).collect())
    }

    /// Removes `target_account_id` from `project_id`'s roster. Lead-gated via
    /// `authorize_project_lead`. Removing a non-member is a no-op (matches the deleted
    /// `remove_account_member`'s behavior for the analogous case). Unlike that method, there is no
    /// last-member/last-owner lockout to enforce: the project's account owner is always a standing
    /// alternate authority over the roster (see `authorize_project_lead`), so a project can never be
    /// left ownerless the way an account with zero memberships could before ADR-0006.
    #[instrument(skip(self))]
    pub async fn remove_project_member(
        &self,
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
    ) -> Result<Project> {
        self.authorize_project_lead(project_id, account_id).await?;

        sqlx::query(r#"DELETE FROM project_members WHERE project_id = $1 AND account_id = $2"#)
            .bind(project_id)
            .bind(target_account_id)
            .execute(self.pool())
            .await?;

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }

    /// Changes `target_account_id`'s role on `project_id`'s roster. Lead-gated via
    /// `authorize_project_lead`. `target_account_id` must already be on the roster (`NotFound`
    /// otherwise, distinct from `remove_project_member`'s no-op-on-non-member, since setting a role
    /// for a nonexistent membership row is meaningless rather than idempotent) -- mirrors the
    /// deleted `set_account_member_role`'s contract exactly, minus its last-owner demotion guard
    /// (no such invariant exists here, see `remove_project_member`).
    #[instrument(skip(self))]
    pub async fn set_project_member_role(
        &self,
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
        role: &str,
    ) -> Result<Project> {
        Self::validate_project_role(role)?;
        self.authorize_project_lead(project_id, account_id).await?;

        let result = sqlx::query(
            r#"UPDATE project_members SET role = $1 WHERE project_id = $2 AND account_id = $3"#,
        )
        .bind(role)
        .bind(project_id)
        .bind(target_account_id)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }

    /// Changes `target_account_id`'s per-member quota tier on `project_id`. Lead-gated via
    /// `authorize_project_lead`; `target_account_id` must already be on the roster (`NotFound`
    /// otherwise, same reasoning as `set_project_member_role`). The tier value itself is NOT
    /// validated against the operator-configured quota-tier catalogue here -- same as
    /// `Project.billing_plan`/`billingPlan`, that catalogue check happens where the request is
    /// first accepted, not in the repository, so an empty/absent catalogue transparently accepts
    /// any value with no special casing needed at this layer. As of #177 that check is real, not
    /// aspirational: `AuthzStoreImpl::set_project_member_quota_tier` (the procedure/handler layer
    /// that holds the loaded `Config`) calls `QuotaTiers::is_allowed` before ever reaching this
    /// method -- see that call site for the enforcement itself and
    /// `crates/lightbridge-authz-rest/tests/quota_tier_it_tests.rs` for live-DB coverage.
    #[instrument(skip(self))]
    pub async fn set_project_member_quota_tier(
        &self,
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
        quota_tier: Option<&str>,
    ) -> Result<Project> {
        self.authorize_project_lead(project_id, account_id).await?;

        let result = sqlx::query(
            r#"UPDATE project_members SET quota_tier = $1 WHERE project_id = $2 AND account_id = $3"#,
        )
        .bind(quota_tier)
        .bind(project_id)
        .bind(target_account_id)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }
}
