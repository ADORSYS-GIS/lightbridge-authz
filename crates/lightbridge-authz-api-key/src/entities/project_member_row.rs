use chrono::{DateTime, Utc};
use lightbridge_authz_core::ProjectMember;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// A `project_members` row (ADR-0006, `migrations/20260727000001_create_project_members.sql`).
///
/// Note the absent `id`: the real table is keyed `PRIMARY KEY (project_id, account_id)` and has no
/// `id` column. The schema's `ProjectMember.id` is synthetic, present only because cratestack
/// requires exactly one scalar `@id` per model, so nothing here can select one.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProjectMemberRow {
    pub project_id: String,
    pub account_id: String,
    pub role: String,
    pub quota_tier: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<ProjectMemberRow> for ProjectMember {
    fn from(row: ProjectMemberRow) -> Self {
        Self {
            project_id: row.project_id,
            account_id: row.account_id,
            role: row.role,
            quota_tier: row.quota_tier,
            created_at: row.created_at,
        }
    }
}
