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

use tonic::{Request, Response, Status};
use tracing::info;

/// AuthorizationServer handles Envoy external authorization requests.
#[derive(Debug, Clone)]
pub struct AuthServer {
    pool: Arc<DbPool>,
}

impl AuthServer {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }

    async fn resolve_acls(&self, key_id: &str) -> Result<Vec<String>, CoreError> {
        let repo = ApiKeyRepo;
        let maybe = repo.get_by_id(&self.pool, key_id).await?;
        let api_key = maybe.ok_or(CoreError::NotFound)?;

        if let Some(expires_at) = api_key.expires_at {
            if expires_at < Utc::now() {
                return Err(CoreError::NotFound);
            }
        }

        match api_key.status {
            ApiKeyStatus::Active => {
                let mut acls = Vec::new();
                for model in api_key.acl.allowed_models {
                    acls.push(format!("model:{}", model));
                }
                for (model, limit) in api_key.acl.tokens_per_model {
                    acls.push(format!("token_limit:{}:{}", model, limit));
                }
                acls.push(format!(
                    "rate_limit:{}/{}",
                    api_key.acl.rate_limit.requests, api_key.acl.rate_limit.window_seconds
                ));
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

        if let Some(attrs) = req.attributes {
            if let Some(req_ctx) = attrs.request {
                if let Some(http) = req_ctx.http {
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
            }
        }

        if let Some(key) = api_key {
            info!(api_key = key.as_str(), "extracted api key");
            return match self.resolve_acls(&key).await {
                Ok(acls) => {
                    let mut builder = OkHttpResponseBuilder::default();

                    for acl in acls {
                        builder.add_response_header(
                            "x-custom-lightbridge-authz-acl",
                            acl,
                            None,
                            false,
                        );
                    }

                    let response = CheckResponse::default()
                        .set_status(Status::ok("welcome bro"))
                        .set_http_response(builder)
                        .to_owned();

                    Ok(Response::new(response))
                }
                Err(_) => {
                    let response = CheckResponse::default()
                        .set_status(Status::permission_denied("Invalid API key"))
                        .to_owned();

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
