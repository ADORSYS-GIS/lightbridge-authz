use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ExchangeRefreshTokenRow {
    pub id: String,
    pub subject: String,
    pub account_id: String,
    pub project_id: String,
    pub token_hash: String,
    pub scope: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewExchangeRefreshToken {
    pub id: String,
    pub subject: String,
    pub account_id: String,
    pub project_id: String,
    pub token_hash: String,
    pub scope: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
