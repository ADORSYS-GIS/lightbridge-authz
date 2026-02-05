use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;
use utoipa::ToSchema;

const ACTIVE: &str = "active";
const REVOKED: &str = "revoked";

fn default_limits() -> Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Account {
    pub id: String,
    pub billing_identity: String,
    #[serde(default)]
    pub owners_admins: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateAccount {
    pub billing_identity: String,
    #[serde(default)]
    pub owners_admins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateAccount {
    pub billing_identity: Option<String>,
    pub owners_admins: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Project {
    pub id: String,
    pub account_id: String,
    pub name: String,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default = "default_limits")]
    #[schema(value_type = Object)]
    pub default_limits: Value,
    pub billing_plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateProject {
    pub name: String,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default = "default_limits")]
    #[schema(value_type = Object)]
    pub default_limits: Value,
    pub billing_plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub allowed_models: Option<Vec<String>>,
    #[schema(value_type = Object)]
    pub default_limits: Option<Value>,
    pub billing_plan: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyStatus {
    #[default]
    Active,
    Revoked,
}

impl Display for ApiKeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match self {
            ApiKeyStatus::Active => ACTIVE,
            ApiKeyStatus::Revoked => REVOKED,
        };
        write!(f, "{}", r)
    }
}

impl From<String> for ApiKeyStatus {
    fn from(s: String) -> Self {
        match s.as_str() {
            REVOKED => ApiKeyStatus::Revoked,
            _ => ApiKeyStatus::Active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKey {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub key_prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: ApiKeyStatus,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateApiKey {
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateApiKey {
    pub name: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RotateApiKey {
    pub name: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub grace_period_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeySecret {
    pub api_key: ApiKey,
    pub secret: String,
}
