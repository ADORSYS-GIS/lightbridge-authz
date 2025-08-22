//! Server module for the gRPC external authorization service.
use std::sync::Arc;

use chrono::Utc;
use lightbridge_authz_api_key::db::ApiKeyRepo;
use lightbridge_authz_core::api_key::ApiKeyStatus;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error as CoreError;

use lightbridge_authz_proto::envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse,
};
use lightbridge_authz_proto::envoy_types::ext_authz::v3::{
    CheckResponseExt, OkHttpResponseBuilder,
};

use crate::types::{
    AclRule, AclRuleRequests, AclRuleTokenLimit, AclRuleTokenModel, AclRuleWindowSeconds,
};
use tonic::{Request, Response, Status};
use tracing::debug;

/// AuthorizationServer handles Envoy external authorization requests.
#[derive(Debug, Clone)]
pub struct AuthServer {
    pool: Arc<DbPool>,
}

impl AuthServer {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }

    async fn resolve_acls(&self, token: &str) -> Result<Vec<AclRule>, CoreError> {
        let repo = ApiKeyRepo;
        // Find the ApiKey by its token (key_hash) first
        let maybe = repo.find_by_token(&self.pool, token).await?;
        let api_key = maybe.ok_or(CoreError::NotFound)?;

        // Check expiration
        if let Some(expires_at) = api_key.expires_at {
            if expires_at < Utc::now() {
                return Err(CoreError::NotFound);
            }
        }

        // Build ACL list based on key's ACL and status
        match api_key.status {
            ApiKeyStatus::Active => {
                let mut acls = Vec::new();
                for model in api_key.acl.allowed_models {
                    acls.push(AclRule::from(model));
                }
                for tpm in api_key.acl.tokens_per_model {
                    acls.push(AclRule::from(tpm));
                }
                acls.push(AclRule::from(api_key.acl.rate_limit));
                Ok(acls)
            }
            ApiKeyStatus::Revoked => Err(CoreError::NotFound),
        }
    }
}

#[tonic::async_trait]
impl Authorization for AuthServer {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let req = request.into_inner();
        let mut api_key: Option<String> = None;

        if let Some(http) = req
            .attributes
            .and_then(|attrs| attrs.request)
            .and_then(|req_ctx| req_ctx.http)
        {
            if !http.headers.is_empty() {
                if let Some(auth) = http.headers.get("authorization") {
                    let a = auth.as_str();
                    if let Some(stripped) = a
                        .strip_prefix("Bearer ")
                        .or_else(|| a.strip_prefix("bearer "))
                    {
                        if !stripped.is_empty() {
                            api_key = Some(stripped.to_string());
                        }
                    }
                }

                if api_key.is_none() {
                    if let Some(val) = http
                        .headers
                        .get("x-api-key")
                        .or_else(|| http.headers.get("x-api_key"))
                        .or_else(|| http.headers.get("x-api-token"))
                        .or_else(|| http.headers.get("x-api_token"))
                    {
                        if !val.is_empty() {
                            api_key = Some(val.clone());
                        }
                    }
                }
            } else if let Some(header_map) = http.header_map {
                for hv in header_map.headers {
                    let key = hv.key.to_ascii_lowercase();
                    let val = String::from_utf8(hv.raw_value).unwrap_or_default();
                    if key == "authorization" {
                        if let Some(stripped) = val
                            .strip_prefix("Bearer ")
                            .or_else(|| val.strip_prefix("bearer "))
                        {
                            if !stripped.is_empty() {
                                api_key = Some(stripped.to_string());
                                break;
                            }
                        }
                    } else if (key == "x-api-key"
                        || key == "x-api_key"
                        || key == "x-api-token"
                        || key == "x-api_token")
                        && !val.is_empty()
                    {
                        api_key = Some(val);
                        break;
                    }
                }
            }
        }

        if let Some(key) = api_key {
            return match self.resolve_acls(&key).await {
                Ok(acls) => {
                    let mut builder = OkHttpResponseBuilder::default();

                    for acl in acls {
                        debug!(acl = acl.to_string(), "found single acl");
                        match acl {
                            AclRule::Model(AclRuleTokenModel(model)) => {
                                builder.add_header(
                                    format!("x-custom-lightbridge-authz-model-{model}"),
                                    "access",
                                    None,
                                    true,
                                );
                            }
                            AclRule::TokenLimit(
                                AclRuleTokenModel(model),
                                AclRuleTokenLimit(limit),
                            ) => {
                                builder.add_header(
                                    format!("x-custom-lightbridge-authz-model-{model}-limit"),
                                    format!("{}", limit),
                                    None,
                                    true,
                                );
                            }
                            AclRule::RateLimit(
                                AclRuleRequests(requests),
                                AclRuleWindowSeconds(window_seconds),
                            ) => {
                                builder.add_header(
                                    "x-custom-lightbridge-authz-requests".to_string(),
                                    requests.to_string(),
                                    None,
                                    true,
                                );
                                builder.add_header(
                                    "x-custom-lightbridge-authz-window-seconds".to_string(),
                                    window_seconds.to_string(),
                                    None,
                                    true,
                                );
                            }
                        }
                    }

                    let response = CheckResponse::default()
                        .set_status(Status::ok("welcome bro"))
                        .set_http_response(builder)
                        .to_owned();

                    Ok(Response::new(response))
                }
                Err(_) => {
                    let response =
                        CheckResponse::with_status(Status::permission_denied("Invalid API key"));

                    Ok(Response::new(response))
                }
            };
        }

        let response = CheckResponse::default()
            .set_status(Status::permission_denied("API key missing"))
            .to_owned();
        Ok(Response::new(response))
    }
}
