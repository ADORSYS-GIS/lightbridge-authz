use std::collections::HashMap;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::api_key::{Acl, ApiKey, RateLimit};

use crate::entities::{
    acl_model_row::AclModelRow, acl_row::AclRow, api_key_row::ApiKeyRow,
    new_acl_model_row::NewAclModelRow, new_acl_row::NewAclRow,
};

pub async fn to_api_key(api_key: &ApiKeyRow, acl: &AclRow, models: &[AclModelRow]) -> ApiKey {
    let acl_dto = rows_to_acl(acl, models).await;
    ApiKey {
        id: api_key.id.clone(),
        user_id: api_key.user_id.clone(),
        key_hash: api_key.key_hash.clone(),
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
        metadata: None,
        status: Default::default(),
        acl: acl_dto,
    }
}

#[allow(unused_variables)]
pub async fn rows_to_acl(acl: &AclRow, models: &[AclModelRow]) -> Acl {
    let mut allowed_models = Vec::with_capacity(models.len());
    let mut tokens_per_model: HashMap<String, u64> = HashMap::with_capacity(models.len());
    for m in models {
        allowed_models.push(m.name.clone());
        tokens_per_model.insert(m.name.clone(), m.model.parse().unwrap_or(10_000));
    }
    Acl {
        allowed_models,
        tokens_per_model,
        rate_limit: RateLimit {
            requests: 0,       // Placeholder, as these fields are removed from AclRow
            window_seconds: 0, // Placeholder
        },
    }
}

#[allow(unused_variables)]
pub fn acl_to_rows(
    acl: &Acl,
    acl_id: &str,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> (NewAclRow, Vec<NewAclModelRow>) {
    let new_acl = NewAclRow {
        id: acl_id.to_string(),
        api_key_id: "".to_string(),
        permission: "".to_string(),
    }; // Placeholder, adjust as needed

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
            let limit = acl.tokens_per_model.get(&name).copied().unwrap_or(10_000);
            out.push(NewAclModelRow {
                id: "".to_string(), // Placeholder, adjust as needed
                name,
                model: limit.to_string(),
            });
        }
        out
    };

    (new_acl, models)
}
