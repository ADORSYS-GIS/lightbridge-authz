use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{Project, ResolvedContext, ResourceStatus};
use tracing::instrument;

use crate::repo::StoreRepo;

impl StoreRepo {
    /// Resolves the `{account_id, project_id}` context for an (already-translated, ADR-0025) acting
    /// account id + project on behalf of the `lightbridge-keycloak-spi` token-exchange adapter.
    /// Authorized when `account_id` is the project's account owner OR holds ANY `project_members`
    /// row on it (not lead-gated -- this is a read, same visibility boundary as `Project`'s
    /// `@@allow("read", ...)`). Deliberately a single query with one `NotFound` branch: "unknown
    /// project" and "known project the caller can't see" must resolve identically so this endpoint
    /// never leaks project existence to a non-member -- do not split these cases.
    pub async fn resolve_context(
        &self,
        account_id: &AccountId,
        project_id: &str,
    ) -> Result<ResolvedContext> {
        let row: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT projects.account_id, projects.id AS project_id
            FROM projects
            WHERE projects.id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let (account_id, project_id) = row.ok_or(Error::NotFound)?;
        Ok(ResolvedContext {
            account_id,
            project_id,
        })
    }

    #[instrument(skip(self, account_id))]
    pub async fn authorize_usage_scope(
        &self,
        account_id: &AccountId,
        scope: &str,
        scope_id: &str,
    ) -> Result<()> {
        match scope {
            "account" => {
                let row: Option<(String,)> = sqlx::query_as(
                    r#"
                    SELECT owned.id
                    FROM accounts owned
                    WHERE owned.id = $1
                      AND owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                    "#,
                )
                .bind(scope_id)
                .bind(account_id.as_str())
                .fetch_optional(self.pool())
                .await?;
                row.ok_or(Error::NotFound)?;
                Ok(())
            }
            "project" => {
                let row: Option<(String,)> = sqlx::query_as(
                    r#"
                    SELECT projects.id
                    FROM projects
                    WHERE projects.id = $1
                      AND (
                        projects.account_id IN (
                          SELECT owned.id FROM accounts owned
                          WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                        )
                        OR EXISTS (
                          SELECT 1 FROM project_members pm
                          WHERE pm.project_id = projects.id AND pm.account_id = $2
                        )
                      )
                    "#,
                )
                .bind(scope_id)
                .bind(account_id.as_str())
                .fetch_optional(self.pool())
                .await?;
                row.ok_or(Error::NotFound)?;
                Ok(())
            }
            _ => Err(Error::NotFound),
        }
    }

    /// Enforces the Active-status gate `resolve_context` itself deliberately does not apply (that
    /// function only checks ownership/membership). Single source of truth for every grant/session
    /// path that must refuse a suspended account or an inactive project rather than silently
    /// admitting it: browser SSO (`KeycloakRelyingParty::complete`/`resolve_authorized_context`),
    /// the device-code grant (`issue_device_tokens`), the refresh grant (`handle_refresh_token`),
    /// and the RFC 8693 token-exchange grant (`handle_token_exchange`) all route through this (or
    /// through [`Self::resolve_active_context`] below, which also resolves the context). Returns
    /// the fetched [`Project`] because two of those four callers (`issue_device_tokens`,
    /// `handle_refresh_token`) need `allowed_models`/`model_policy` off the SAME row right after
    /// this check and would otherwise pay for a second, redundant query to get it.
    ///
    /// Fail-closed, unconditionally: a lookup ERROR refuses (`Error::Server`), never falls through
    /// to permit. An inactive project or a suspended account refuses (`Error::Forbidden`). This is
    /// the exact asymmetry that let `handle_token_exchange` silently admit a suspended account
    /// through the RFC 8693 grant while `issue_device_tokens`/`handle_refresh_token` already
    /// refused it -- callers translate the `Result` into their own OAuth error shape (some grants
    /// use a specific `access_denied`, the refresh grant deliberately uses a uniform
    /// `invalid_grant` for both "inactive" and "not authorized" so as not to reveal which applied),
    /// but the underlying check must never drift between them again.
    pub async fn require_active_project_and_account(
        &self,
        project_id: &str,
        account_id: &str,
    ) -> Result<Project> {
        let project = match self.get_project_by_id(project_id).await {
            Ok(Some(project)) if project.status == ResourceStatus::Active => project,
            Ok(_) => return Err(Error::Forbidden("project is not active".to_string())),
            Err(_) => return Err(Error::Server("project lookup failed".to_string())),
        };
        match self.get_account_by_id(account_id).await {
            Ok(Some(account)) if account.status == ResourceStatus::Active => {}
            Ok(_) => return Err(Error::Forbidden("account is suspended".to_string())),
            Err(_) => return Err(Error::Server("account lookup failed".to_string())),
        }
        Ok(project)
    }

    /// `resolve_context` followed immediately by [`Self::require_active_project_and_account`], for
    /// the callers (browser SSO's session creation and cross-project re-resolution) that only need
    /// the resolved ids, not the fetched `Project` value itself.
    pub async fn resolve_active_context(
        &self,
        account_id: &AccountId,
        project_id: &str,
    ) -> Result<ResolvedContext> {
        let context = self.resolve_context(account_id, project_id).await?;
        self.require_active_project_and_account(&context.project_id, &context.account_id)
            .await?;
        Ok(context)
    }
}
