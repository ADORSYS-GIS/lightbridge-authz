//! Server module for the gRPC external authorization service.
use std::sync::Arc;

use chrono::Utc;
use lightbridge_authz_api_key::db::{ApiKeyRepo, ApiKeyRepository};
use lightbridge_authz_core::api_key::ApiKeyStatus;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::db::DbPoolTrait;
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

/// Trait for AuthorizationServer functionality
#[async_trait]
pub trait AuthServerTrait: Send + Sync {
    /// Convert an ApiKey to a dynamic metadata Struct
    fn api_key_to_dynamic_metadata(&self, api_key: ApiKey) -> Result<Struct>;

    /// Build dynamic metadata from a token
    async fn build_dynamic_metadata(&self, token: &str) -> Result<Struct>;

    /// Resolve an API key from a token
    async fn resolve_api_key(&self, token: &str) -> Result<ApiKey>;

    /// Convert a JSON value to a protobuf Value
    fn json_value_to_prost_value(&self, json_val: serde_json::Value) -> Value;

    /// Convert a JSON map to a protobuf Struct
    fn json_map_to_prost_struct(
        &self,
        json_map: serde_json::Map<String, serde_json::Value>,
    ) -> Struct;
}

/// AuthorizationServer handles Envoy external authorization requests.
#[derive(Clone)]
pub struct AuthServer {
    repo: Arc<dyn ApiKeyRepository>,
}

impl AuthServer {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        let repo = ApiKeyRepo::new(pool);
        Self {
            repo: Arc::new(repo),
        }
    }

    #[inline]
    fn extract_api_key_from_header(key: &str, value: &str) -> Option<String> {
        match key.to_ascii_lowercase().as_str() {
            "authorization" => value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned()),
            "x-api-key" | "x-api_key" | "x-api-token" | "x-api_token" => value.to_owned().into(),
            _ => None,
        }
    }

    #[inline]
    fn get_api_key(req: CheckRequest) -> Option<String> {
        if let Some(http) = req
            .attributes
            .and_then(|attrs| attrs.request)
            .and_then(|req_ctx| req_ctx.http)
        {
            // Try to extract from the simpler http.headers map first
            if !http.headers.is_empty() {
                if let Some(auth_value) = http.headers.get("authorization")
                    && let Some(api_key) =
                        Self::extract_api_key_from_header("authorization", auth_value)
                {
                    return Some(api_key);
                }

                for key_name in ["x-api-key", "x-api_key", "x-api-token", "x-api_token"].iter() {
                    if let Some(value) = http.headers.get(*key_name)
                        && let Some(api_key) = Self::extract_api_key_from_header(key_name, value)
                    {
                        return Some(api_key);
                    }
                }
            }
            // Fallback to http.header_map if http.headers is empty or doesn't contain the key
            else if let Some(header_map) = http.header_map {
                for hv in header_map.headers {
                    let key = hv.key.to_ascii_lowercase();
                    let val = match String::from_utf8(hv.raw_value) {
                        Ok(s) => s,
                        Err(_) => return None, // Treat non-UTF8 header values as if no key was found
                    };
                    if let Some(api_key) = Self::extract_api_key_from_header(&key, &val) {
                        return Some(api_key);
                    }
                }
            }
        }

        None
    }
}

#[async_trait]
impl AuthServerTrait for AuthServer {
    fn api_key_to_dynamic_metadata(&self, api_key: ApiKey) -> Result<Struct> {
        // This function is the core logic for building dynamic metadata and is unit-testable.
        let mut metadata_map = serde_json::Map::new();
        metadata_map.insert("user_id".to_string(), json!(api_key.user_id));
        metadata_map.insert("api_key_id".to_string(), json!(api_key.id));
        metadata_map.insert("api_key_name".to_string(), json!(api_key.id)); // Using api_key.id as name for now
        metadata_map.insert(
            "allowed_models".to_string(),
            json!(api_key.acl.allowed_models),
        );
        metadata_map.insert(
            "tokens_per_model".to_string(),
            json!(api_key.acl.tokens_per_model),
        );
        metadata_map.insert(
            "rate_limit_requests".to_string(),
            json!(api_key.acl.rate_limit.requests),
        );
        metadata_map.insert(
            "rate_limit_window_seconds".to_string(),
            json!(api_key.acl.rate_limit.window_seconds),
        );

        // Merge custom metadata if present
        if let Some(custom_metadata_map) = api_key
            .metadata
            .and_then(|custom_metadata| custom_metadata.as_object().map(|m| m.to_owned()))
        {
            for (key, value) in custom_metadata_map {
                metadata_map.insert(key.clone(), value.clone());
            }
        }

        let metadata_struct = self.json_map_to_prost_struct(metadata_map);

        Ok(metadata_struct)
    }

    async fn build_dynamic_metadata(&self, token: &str) -> Result<Struct> {
        let api_key = self.resolve_api_key(token).await?;
        self.api_key_to_dynamic_metadata(api_key)
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

    fn json_value_to_prost_value(&self, json_val: serde_json::Value) -> Value {
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
                            .map(|v| self.json_value_to_prost_value(v))
                            .collect(),
                    },
                )),
            },
            serde_json::Value::Object(obj) => Value {
                kind: Some(Kind::StructValue(Struct {
                    fields: obj
                        .into_iter()
                        .map(|(k, v)| (k, self.json_value_to_prost_value(v)))
                        .collect(),
                })),
            },
        }
    }

    fn json_map_to_prost_struct(
        &self,
        json_map: serde_json::Map<String, serde_json::Value>,
    ) -> Struct {
        Struct {
            fields: json_map
                .into_iter()
                .map(|(k, v)| (k, self.json_value_to_prost_value(v)))
                .collect(),
        }
    }
}

#[async_trait]
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
