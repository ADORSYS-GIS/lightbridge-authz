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
