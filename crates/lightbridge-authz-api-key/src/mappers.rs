use std::collections::HashMap;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::api_key::{Acl, ApiKey, ApiKeyStatus, RateLimit};

use crate::entities::{AclModelRow, AclRow, ApiKeyRow, NewAclModelRow, NewAclRow};

pub fn api_key_status_to_str(status: &ApiKeyStatus) -> &'static str {
    match status {
        ApiKeyStatus::Active => "active",
        ApiKeyStatus::Revoked => "revoked",
    }
}

pub fn api_key_status_from_str(s: &str) -> ApiKeyStatus {
    match s {
        "revoked" => ApiKeyStatus::Revoked,
        _ => ApiKeyStatus::Active,
    }
}

pub fn to_api_key(api_key: &ApiKeyRow, acl: &AclRow, models: &[AclModelRow]) -> ApiKey {
    let acl_dto = rows_to_acl(acl, models);
    ApiKey {
        id: api_key.id.clone(),
        key_hash: api_key.key_hash.clone(),
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
        metadata: api_key.metadata.clone(),
        status: api_key_status_from_str(&api_key.status),
        acl: acl_dto,
    }
}

pub fn rows_to_acl(acl: &AclRow, models: &[AclModelRow]) -> Acl {
    let mut allowed_models = Vec::with_capacity(models.len());
    let mut tokens_per_model: HashMap<String, u64> = HashMap::with_capacity(models.len());
    for m in models {
        allowed_models.push(m.model_name.clone());
        tokens_per_model.insert(m.model_name.clone(), m.token_limit as u64);
    }
    Acl {
        allowed_models,
        tokens_per_model,
        rate_limit: RateLimit {
            requests: acl.rate_limit_requests as u32,
            window_seconds: acl.rate_limit_window as u32,
        },
    }
}

pub fn acl_to_rows(
    acl: &Acl,
    acl_id: &str,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> (NewAclRow, Vec<NewAclModelRow>) {
    let new_acl = NewAclRow {
        id: acl_id.to_string(),
        rate_limit_requests: acl.rate_limit.requests as i32,
        rate_limit_window: acl.rate_limit.window_seconds as i32,
        created_at,
        updated_at,
    };

    let models = if acl.allowed_models.is_empty() && acl.tokens_per_model.is_empty() {
        Vec::new()
    } else {
        let mut out = Vec::new();
        let model_names: Vec<String> = if !acl.allowed_models.is_empty() {
            acl.allowed_models.clone()
        } else {
            acl.tokens_per_model.keys().cloned().collect()
        };
        for name in model_names {
            let limit = acl.tokens_per_model.get(&name).copied().unwrap_or(0);
            out.push(NewAclModelRow {
                acl_id: acl_id.to_string(),
                model_name: name,
                token_limit: limit as i64,
            });
        }
        out
    };

    (new_acl, models)
}
