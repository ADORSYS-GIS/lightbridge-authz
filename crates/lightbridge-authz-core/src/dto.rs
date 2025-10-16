use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Display;

const ACTIVE: &str = "active";
const REVOKED: &str = "REVOKED";

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApiKeyStatus {
    Active,
    #[default]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKey {
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub acl: Option<Acl>, // Add ACL to CreateApiKey
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchApiKey {
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: Option<ApiKeyStatus>,
    pub acl: Option<Acl>, // Add ACL to PatchApiKey
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: ApiKeyStatus,
    pub acl: Acl,
}

/// Defines the Access Control List (ACL) for an API Key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Acl {
    /// A list of models that the API Key is allowed to access.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// A map of model names to their respective token limits.
    #[serde(default)]
    pub tokens_per_model: HashMap<String, u64>,
    /// The rate-limiting configuration for the API Key.
    #[serde(default)]
    pub rate_limit: RateLimit,
}

/// Configures rate-limiting for an API Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// The number of allowed requests per window.
    pub requests: u32,
    /// The time window in seconds.
    pub window_seconds: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            requests: 1000,       // Default to 1000 requests
            window_seconds: 3600, // Default to 1 hour
        }
    }
}
