use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{Project, ResolvedContext, ResourceStatus};
use tracing::instrument;

use crate::repo::StoreRepo;

impl StoreRepo {
    #[instrument(skip(self, account_id))]
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
