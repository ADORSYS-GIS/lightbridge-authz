use lightbridge_authz_core::api_key::RateLimit;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum AclRule {
    Model(AclRuleTokenModel),
    TokenLimit(AclRuleTokenModel, AclRuleTokenLimit),
    RateLimit(AclRuleRequests, AclRuleWindowSeconds),
}

#[derive(Debug, Clone)]
pub struct AclRuleTokenModel(pub String);

#[derive(Debug, Clone)]
pub struct AclRuleTokenLimit(pub u64);

#[derive(Debug, Clone)]
pub struct AclRuleRequests(pub u32);

#[derive(Debug, Clone)]
pub struct AclRuleWindowSeconds(pub u32);

impl From<String> for AclRule {
    fn from(value: String) -> Self {
        let model = AclRuleTokenModel(value);
        AclRule::Model(model)
    }
}

impl From<(String, u64)> for AclRule {
    fn from(value: (String, u64)) -> Self {
        let model = AclRuleTokenModel(value.0);
        let limit = AclRuleTokenLimit(value.1);
        AclRule::TokenLimit(model, limit)
    }
}

impl From<(u32, u32)> for AclRule {
    fn from(value: (u32, u32)) -> Self {
        let requests = AclRuleRequests(value.0);
        let window_seconds = AclRuleWindowSeconds(value.1);
        AclRule::RateLimit(requests, window_seconds)
    }
}

impl From<RateLimit> for AclRule {
    fn from(value: RateLimit) -> Self {
        AclRule::from((value.requests, value.window_seconds))
    }
}

impl Display for AclRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            AclRule::Model(AclRuleTokenModel(model)) => format!("model::{}", model),
            AclRule::TokenLimit(AclRuleTokenModel(model), AclRuleTokenLimit(limit)) => {
                format!("token::{}::{}", model, limit)
            }
            AclRule::RateLimit(AclRuleRequests(requests), AclRuleWindowSeconds(window_seconds)) => {
                format!("rate::{}::{}", requests, window_seconds)
            }
        };
        write!(f, "{}", str)
    }
}
