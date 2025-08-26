//! Server module for the gRPC external authorization service.
use std::sync::Arc;

use chrono::Utc;
use lightbridge_authz_api_key::db::ApiKeyRepo;
use lightbridge_authz_core::api_key::ApiKeyStatus;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::{Error as CoreError, Result};

use lightbridge_authz_proto::envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse,
};
use lightbridge_authz_proto::envoy_types::ext_authz::v3::{
    CheckResponseExt, OkHttpResponseBuilder,
};

use lightbridge_authz_core::ApiKey;
use lightbridge_authz_proto::envoy_types::pb::google::protobuf::{Struct, Value}; // Import Struct and Value from envoy_types
use serde_json::json;
use tonic::{Request, Response, Status};

/// AuthorizationServer handles Envoy external authorization requests.
#[derive(Debug, Clone)]
pub struct AuthServer {
    repo: Arc<ApiKeyRepo>,
}

impl AuthServer {
    pub fn new(pool: Arc<DbPool>) -> Self {
        let repo = ApiKeyRepo::new(pool);
        Self {
            repo: Arc::new(repo),
        }
    }

    async fn resolve_api_key(&self, token: &str) -> Result<ApiKey> {
        // Find the ApiKey by its token (key_hash) first
        let maybe = self.repo.find_api_key_for_authz(token).await?;
        let api_key = maybe.ok_or(CoreError::NotFound)?;

        // Check expiration
        if let Some(expires_at) = api_key.expires_at
            && expires_at < Utc::now()
        {
            return Err(CoreError::NotFound);
        }

        if let ApiKeyStatus::Revoked = api_key.status {
            return Err(CoreError::NotFound);
        }

        Ok(api_key)
    }

    #[inline]
    fn map_bearer(option: Option<&String>) -> Option<String> {
        match option {
            Some(a) => a
                .strip_prefix("Bearer ")
                .or_else(|| a.strip_prefix("bearer "))
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned()),
            None => None,
        }
    }

    #[inline]
    fn get_api_key(req: CheckRequest) -> Option<String> {
        if let Some(http) = req
            .attributes
            .and_then(|attrs| attrs.request)
            .and_then(|req_ctx| req_ctx.http)
        {
            if !http.headers.is_empty() {
                if let Some(clean_bearer) = Self::map_bearer(http.headers.get("authorization")) {
                    return Some(clean_bearer);
                }

                if let Some(val) = http
                    .headers
                    .get("x-api-key")
                    .or_else(|| http.headers.get("x-api_key"))
                    .or_else(|| http.headers.get("x-api-token"))
                    .or_else(|| http.headers.get("x-api_token"))
                    .filter(|s| !s.is_empty())
                {
                    return Some(val.clone());
                }
            } else if let Some(header_map) = http.header_map {
                for hv in header_map.headers {
                    let key = hv.key.to_ascii_lowercase();
                    let val = String::from_utf8(hv.raw_value).unwrap_or_default();
                    if key == "authorization" {
                        if let Some(stripped) = val
                            .strip_prefix("Bearer ")
                            .or_else(|| val.strip_prefix("bearer "))
                            .filter(|a| !a.is_empty())
                        {
                            return Some(stripped.to_string());
                        }
                    } else if (key == "x-api-key"
                        || key == "x-api_key"
                        || key == "x-api-token"
                        || key == "x-api_token")
                        && !val.is_empty()
                    {
                        return Some(val);
                    }
                }
            }
        }

        None
    }

    /// Convert an ApiKey to a dynamic metadata Struct.
    /// This function is the core logic for building dynamic metadata and is unit-testable.
    pub fn api_key_to_dynamic_metadata(api_key: ApiKey) -> Result<Struct> {
        let metadata = json!({
            "user_id": api_key.user_id,
            "api_key_id": api_key.id,
            "api_key_name": api_key.id, // Use api_key.id as name for now
            "permissions": api_key.acl,
        });

        let metadata_struct = Struct {
            fields: match Self::json_value_to_prost_value(metadata).kind {
                Some(lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind::StructValue(s)) => s.fields,
                _ => {
                    return Err(CoreError::Server(
                        "Failed to convert metadata to Struct".to_string(),
                    ))
                }
            },
        };

        Ok(metadata_struct)
    }

    pub async fn build_dynamic_metadata(&self, token: &str) -> Result<Struct> {
        let api_key = self.resolve_api_key(token).await?;
        Self::api_key_to_dynamic_metadata(api_key)
    }

    pub fn json_value_to_prost_value(json_val: serde_json::Value) -> Value {
        use lightbridge_authz_proto::envoy_types::pb::google::protobuf::value::Kind;
        match json_val {
            serde_json::Value::Null => Value {
                kind: Some(Kind::NullValue(0)),
            },
            serde_json::Value::Bool(b) => Value {
                kind: Some(Kind::BoolValue(b)),
            },
            serde_json::Value::Number(n) => Value {
                kind: Some(Kind::NumberValue(n.as_f64().unwrap_or_default())),
            },
            serde_json::Value::String(s) => Value {
                kind: Some(Kind::StringValue(s)),
            },
            serde_json::Value::Array(arr) => Value {
                kind: Some(Kind::ListValue(
                    lightbridge_authz_proto::envoy_types::pb::google::protobuf::ListValue {
                        values: arr
                            .into_iter()
                            .map(Self::json_value_to_prost_value)
                            .collect(),
                    },
                )),
            },
            serde_json::Value::Object(obj) => Value {
                kind: Some(Kind::StructValue(Struct {
                    fields: obj
                        .into_iter()
                        .map(|(k, v)| (k, Self::json_value_to_prost_value(v)))
                        .collect(),
                })),
            },
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
        let api_key: Option<String> = Self::get_api_key(req);

        match api_key {
            Some(key) => {
                let api_key_obj = match self.resolve_api_key(&key).await {
                    Ok(k) => k,
                    Err(_) => {
                        let response = CheckResponse::with_status(Status::permission_denied(
                            "Invalid API key",
                        ));

                        return Ok(Response::new(response));
                    }
                };
                let dyn_meta = match self.build_dynamic_metadata(&key).await {
                    Ok(d) => d,
                    Err(_) => {
                        let response =
                            CheckResponse::with_status(Status::permission_denied("Wrong API key"));

                        return Ok(Response::new(response));
                    }
                };

                let mut builder = OkHttpResponseBuilder::default();
                builder.add_header(
                    "x-custom-lightbridge-authz-user-id",
                    api_key_obj.user_id,
                    None,
                    false,
                );

                let response = CheckResponse::default()
                    .set_status(Status::ok("welcome bro"))
                    .set_http_response(builder)
                    .set_dynamic_metadata(Some(dyn_meta))
                    .to_owned();

                Ok(Response::new(response))
            }
            None => {
                let response = CheckResponse::default()
                    .set_status(Status::permission_denied("API key missing"))
                    .to_owned();
                Ok(Response::new(response))
            }
        }
    }
}
