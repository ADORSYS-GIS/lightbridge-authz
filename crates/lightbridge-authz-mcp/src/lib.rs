use std::{collections::HashMap, sync::Arc};

use axum::{
    Json as AxumJson, Router,
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, Config, CreateAccount, CreateApiKey, CreateProject,
    DefaultLimits, Error, Project, Result, RotateApiKey, UpdateAccount, UpdateApiKey,
    UpdateProject,
    config::{ApiServer, BasicAuth, Oauth2},
    db::{DbPoolTrait, is_database_ready},
    server::serve_tls,
};
use lightbridge_authz_rest::{
    OpaRepoTrait, OpaState,
    handlers::{AuthzStoreImpl, opa::validate_api_key_context},
    middleware::bearer_auth,
    models::authorino::AuthorinoMetadata,
};
use reqwest::Client;
use rmcp::{
    ErrorData, Json, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::{
        StreamableHttpServerConfig,
        streamable_http_server::{
            session::local::LocalSessionManager, tower::StreamableHttpService,
        },
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct EndpointResponse {
    result: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Oauth2ResolvedEndpoints {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: String,
    jwks_uri: String,
}

#[derive(Clone)]
struct OauthProxyState {
    client: Client,
    endpoints: Option<Oauth2ResolvedEndpoints>,
    fallback_registration_endpoint: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct DefaultLimitsInput {
    #[serde(default)]
    pub requests_per_second: Option<i32>,
    #[serde(default)]
    pub requests_per_day: Option<i32>,
    #[serde(default)]
    pub concurrent_requests: Option<i32>,
}

impl From<DefaultLimitsInput> for DefaultLimits {
    fn from(value: DefaultLimitsInput) -> Self {
        Self {
            requests_per_second: value.requests_per_second,
            requests_per_day: value.requests_per_day,
            concurrent_requests: value.concurrent_requests,
        }
    }
}

#[derive(Clone)]
pub struct LightbridgeMcpHandler {
    tool_router: ToolRouter<Self>,
    store: Arc<dyn AuthzStore>,
    opa_state: Arc<OpaState>,
}

impl std::fmt::Debug for LightbridgeMcpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightbridgeMcpHandler")
            .field("tools", &self.tool_router.list_all().len())
            .finish()
    }
}

impl LightbridgeMcpHandler {
    pub fn new(
        store: Arc<dyn AuthzStore>,
        opa_repo: Arc<dyn OpaRepoTrait>,
        basic_auth: BasicAuth,
    ) -> Self {
        let opa_state = Arc::new(OpaState {
            repo: opa_repo,
            basic_auth,
        });

        Self {
            tool_router: Self::tool_router(),
            store,
            opa_state,
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LightbridgeMcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "MCP interface for Lightbridge Authz API and OPA validation endpoints",
        )
    }
}

fn parse_optional_datetime(
    value: Option<String>,
    field_name: &str,
) -> std::result::Result<Option<DateTime<Utc>>, ErrorData> {
    value
        .map(|raw| {
            DateTime::parse_from_rfc3339(&raw)
                .map(|parsed| parsed.with_timezone(&Utc))
                .map_err(|_| {
                    ErrorData::invalid_params(
                        format!("invalid RFC3339 datetime for `{field_name}`"),
                        None,
                    )
                })
        })
        .transpose()
}

fn to_tool_error(error: Error) -> ErrorData {
    match error {
        Error::NotFound => ErrorData::resource_not_found("not found", None),
        Error::Conflict(msg) => ErrorData::invalid_params(msg, None),
        other => ErrorData::internal_error(other.to_string(), None),
    }
}

fn to_json_value<T: Serialize>(value: T) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
    serde_json::to_value(value)
        .map(|result| Json(EndpointResponse { result }))
        .map_err(|error| {
            ErrorData::internal_error(format!("failed to serialize response: {error}"), None)
        })
}

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 100;

fn default_list_limit() -> u32 {
    DEFAULT_LIST_LIMIT
}

fn normalize_list_pagination(offset: u32, limit: u32) -> (u32, u32) {
    (offset, limit.clamp(1, MAX_LIST_LIMIT))
}

fn subject_from_request_context(
    context: &RequestContext<RoleServer>,
) -> std::result::Result<String, ErrorData> {
    let parts = context
        .extensions
        .get::<axum::http::request::Parts>()
        .ok_or_else(|| ErrorData::internal_error("missing HTTP request context", None))?;

    let token_info = parts
        .extensions
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorData::internal_error("missing bearer token context", None))?;

    Ok(token_info.sub.clone())
}

fn issuer_from_jwks_url(jwks_url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(jwks_url).ok()?;
    let host = parsed.host_str()?;
    let path = parsed.path();
    let realm_path = path.strip_suffix("/protocol/openid-connect/certs")?;
    let mut issuer = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        issuer.push(':');
        issuer.push_str(&port.to_string());
    }
    issuer.push_str(realm_path);
    Some(issuer)
}

fn join_issuer_path(issuer: &str, path: &str) -> String {
    format!(
        "{}/{}",
        issuer.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn resolve_oauth2_endpoints(oauth2: &Oauth2) -> Option<Oauth2ResolvedEndpoints> {
    let issuer = oauth2
        .issuer_url
        .clone()
        .or_else(|| issuer_from_jwks_url(&oauth2.jwks_url))?;

    let authorization_endpoint = oauth2
        .authorization_endpoint
        .clone()
        .unwrap_or_else(|| join_issuer_path(&issuer, "protocol/openid-connect/auth"));
    let token_endpoint = oauth2
        .token_endpoint
        .clone()
        .unwrap_or_else(|| join_issuer_path(&issuer, "protocol/openid-connect/token"));
    let registration_endpoint = oauth2
        .registration_endpoint
        .clone()
        .unwrap_or_else(|| join_issuer_path(&issuer, "clients-registrations/openid-connect"));

    Some(Oauth2ResolvedEndpoints {
        issuer,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        jwks_uri: oauth2.jwks_url.clone(),
    })
}

fn oauth_metadata_response(
    endpoints: &Oauth2ResolvedEndpoints,
    registration_endpoint: &str,
) -> Value {
    json!({
        "issuer": endpoints.issuer,
        "authorization_endpoint": endpoints.authorization_endpoint,
        "token_endpoint": endpoints.token_endpoint,
        "jwks_uri": endpoints.jwks_uri,
        "registration_endpoint": registration_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    })
}

fn request_origin(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())?;
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("https");
    Some(format!("{proto}://{}", host.trim()))
}

fn registration_endpoint_for_request(headers: &HeaderMap, fallback: &str) -> String {
    request_origin(headers)
        .map(|origin| format!("{}/oauth/register", origin.trim_end_matches('/')))
        .unwrap_or_else(|| fallback.to_string())
}

fn fallback_registration_endpoint(api: &ApiServer) -> String {
    format!("https://{}:{}/oauth/register", api.address, api.port)
}

async fn oauth_authorization_server_metadata_handler(
    state: Arc<OauthProxyState>,
    headers: HeaderMap,
) -> Response {
    let Some(endpoints) = state.endpoints.as_ref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(json!({
                "error": "server_error",
                "error_description": "OAuth2 issuer URL could not be derived from configuration"
            })),
        )
            .into_response();
    };

    let registration_endpoint =
        registration_endpoint_for_request(&headers, &state.fallback_registration_endpoint);
    let metadata = oauth_metadata_response(endpoints, &registration_endpoint);
    (StatusCode::OK, AxumJson(metadata)).into_response()
}

async fn openid_configuration_handler(state: Arc<OauthProxyState>, headers: HeaderMap) -> Response {
    oauth_authorization_server_metadata_handler(state, headers).await
}

async fn oauth_register_handler(
    state: Arc<OauthProxyState>,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<Value>,
) -> Response {
    let Some(endpoints) = state.endpoints.as_ref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(json!({
                "error": "server_error",
                "error_description": "OAuth2 registration endpoint could not be derived from configuration"
            })),
        )
            .into_response();
    };

    let mut request = state
        .client
        .post(&endpoints.registration_endpoint)
        .json(&payload);
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(header::AUTHORIZATION, auth);
    }

    let upstream = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                AxumJson(json!({
                    "error": "bad_gateway",
                    "error_description": format!("failed to reach upstream registration endpoint: {error}")
                })),
            )
                .into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    let body = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                AxumJson(json!({
                    "error": "bad_gateway",
                    "error_description": format!("failed to read upstream registration response: {error}")
                })),
            )
                .into_response();
        }
    };

    let mut response = Response::new(Body::from(body.to_vec()));
    *response.status_mut() = status;
    if let Some(content_type) = content_type {
        if let Ok(header_value) = HeaderValue::from_str(&content_type) {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, header_value);
        }
    }
    response
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateAccountParams {
    billing_identity: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListAccountsParams {
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_list_limit")]
    limit: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AccountByIdParams {
    account_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateAccountParams {
    account_id: String,
    #[serde(default)]
    billing_identity: Option<String>,
    #[serde(default)]
    owners_admins: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateProjectParams {
    account_id: String,
    name: String,
    #[serde(default)]
    allowed_models: Option<Vec<String>>,
    #[serde(default)]
    default_limits: Option<DefaultLimitsInput>,
    billing_plan: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListProjectsParams {
    account_id: String,
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_list_limit")]
    limit: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ProjectByIdParams {
    project_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateProjectParams {
    project_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    allowed_models: Option<Option<Vec<String>>>,
    #[serde(default)]
    default_limits: Option<DefaultLimitsInput>,
    #[serde(default)]
    billing_plan: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateApiKeyParams {
    project_id: String,
    name: String,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListApiKeysParams {
    project_id: String,
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_list_limit")]
    limit: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ApiKeyByIdParams {
    key_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateApiKeyParams {
    key_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RotateApiKeyParams {
    key_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    grace_period_seconds: Option<i64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ValidateApiKeyParams {
    api_key: String,
    #[serde(default)]
    ip: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ValidateAuthorinoApiKeyParams {
    api_key: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    metadata: HashMap<String, Value>,
}

#[tool_router(router = tool_router)]
impl LightbridgeMcpHandler {
    #[tool(
        name = "create-account",
        description = "Create an account (maps to POST /api/v1/accounts)"
    )]
    async fn create_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateAccountParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let account = self
            .store
            .create_account(
                &subject,
                CreateAccount {
                    billing_identity: params.billing_identity,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "list-accounts",
        description = "List accounts (maps to GET /api/v1/accounts)"
    )]
    async fn list_accounts_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListAccountsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let accounts: Vec<Account> = self
            .store
            .list_accounts(&subject, offset, limit)
            .await
            .map_err(to_tool_error)?;

        to_json_value(accounts)
    }

    #[tool(
        name = "get-account",
        description = "Get an account (maps to GET /api/v1/accounts/{account_id})"
    )]
    async fn get_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let account = self
            .store
            .get_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "update-account",
        description = "Update an account (maps to PATCH /api/v1/accounts/{account_id})"
    )]
    async fn update_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateAccountParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let account = self
            .store
            .update_account(
                &subject,
                &params.account_id,
                UpdateAccount {
                    billing_identity: params.billing_identity,
                    owners_admins: params.owners_admins,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "delete-account",
        description = "Delete an account (maps to DELETE /api/v1/accounts/{account_id})"
    )]
    async fn delete_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        self.store
            .delete_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(json!({ "deleted": true }))
    }

    #[tool(
        name = "create-project",
        description = "Create a project (maps to POST /api/v1/accounts/{account_id}/projects)"
    )]
    async fn create_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateProjectParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let project = self
            .store
            .create_project(
                &subject,
                &params.account_id,
                CreateProject {
                    name: params.name,
                    allowed_models: params.allowed_models,
                    default_limits: params.default_limits.map(Into::into),
                    billing_plan: params.billing_plan,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "list-projects",
        description = "List projects (maps to GET /api/v1/accounts/{account_id}/projects)"
    )]
    async fn list_projects_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListProjectsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let projects: Vec<Project> = self
            .store
            .list_projects(&subject, &params.account_id, offset, limit)
            .await
            .map_err(to_tool_error)?;

        to_json_value(projects)
    }

    #[tool(
        name = "get-project",
        description = "Get a project (maps to GET /api/v1/projects/{project_id})"
    )]
    async fn get_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let project = self
            .store
            .get_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "update-project",
        description = "Update a project (maps to PATCH /api/v1/projects/{project_id})"
    )]
    async fn update_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateProjectParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let project = self
            .store
            .update_project(
                &subject,
                &params.project_id,
                UpdateProject {
                    name: params.name,
                    allowed_models: params.allowed_models,
                    default_limits: params.default_limits.map(Into::into),
                    billing_plan: params.billing_plan,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "delete-project",
        description = "Delete a project (maps to DELETE /api/v1/projects/{project_id})"
    )]
    async fn delete_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        self.store
            .delete_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(json!({ "deleted": true }))
    }

    #[tool(
        name = "create-api-key",
        description = "Create an API key (maps to POST /api/v1/projects/{project_id}/api-keys)"
    )]
    async fn create_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let expires_at = parse_optional_datetime(params.expires_at, "expires_at")?;

        let api_key_secret: ApiKeySecret = self
            .store
            .create_api_key(
                &subject,
                &params.project_id,
                CreateApiKey {
                    name: params.name,
                    expires_at,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_key_secret)
    }

    #[tool(
        name = "list-api-keys",
        description = "List API keys (maps to GET /api/v1/projects/{project_id}/api-keys)"
    )]
    async fn list_api_keys_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListApiKeysParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let api_keys: Vec<ApiKey> = self
            .store
            .list_api_keys(&subject, &params.project_id, offset, limit)
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_keys)
    }

    #[tool(
        name = "get-api-key",
        description = "Get an API key (maps to GET /api/v1/api-keys/{key_id})"
    )]
    async fn get_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let api_key = self
            .store
            .get_api_key(&subject, &params.key_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "update-api-key",
        description = "Update an API key (maps to PATCH /api/v1/api-keys/{key_id})"
    )]
    async fn update_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let expires_at = parse_optional_datetime(params.expires_at, "expires_at")?;

        let api_key = self
            .store
            .update_api_key(
                &subject,
                &params.key_id,
                UpdateApiKey {
                    name: params.name,
                    expires_at,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "delete-api-key",
        description = "Delete an API key (maps to DELETE /api/v1/api-keys/{key_id})"
    )]
    async fn delete_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        self.store
            .delete_api_key(&subject, &params.key_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(json!({ "deleted": true }))
    }

    #[tool(
        name = "revoke-api-key",
        description = "Revoke an API key (maps to POST /api/v1/api-keys/{key_id}/revoke)"
    )]
    async fn revoke_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let api_key = self
            .store
            .revoke_api_key(&subject, &params.key_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "rotate-api-key",
        description = "Rotate an API key (maps to POST /api/v1/api-keys/{key_id}/rotate)"
    )]
    async fn rotate_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<RotateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context)?;
        let expires_at = parse_optional_datetime(params.expires_at, "expires_at")?;

        let api_key_secret = self
            .store
            .rotate_api_key(
                &subject,
                &params.key_id,
                RotateApiKey {
                    name: params.name,
                    expires_at,
                    grace_period_seconds: params.grace_period_seconds,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_key_secret)
    }

    #[tool(
        name = "validate-api-key",
        description = "Validate API key context (maps to POST /v1/opa/validate)"
    )]
    async fn validate_api_key_tool(
        &self,
        Parameters(params): Parameters<ValidateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let validated = validate_api_key_context(&self.opa_state, &params.api_key, params.ip)
            .await
            .map_err(to_tool_error)?;

        let Some(validated) = validated else {
            return Err(ErrorData::invalid_params(
                "unauthorized",
                Some(json!({ "http_status": 401 })),
            ));
        };

        to_json_value(json!({
            "api_key": validated.api_key,
            "project": validated.project,
            "account": validated.account
        }))
    }

    #[tool(
        name = "validate-authorino-api-key",
        description = "Validate API key + metadata enrichment (maps to POST /v1/authorino/validate)"
    )]
    async fn validate_authorino_api_key(
        &self,
        Parameters(params): Parameters<ValidateAuthorinoApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let validated = validate_api_key_context(&self.opa_state, &params.api_key, params.ip)
            .await
            .map_err(to_tool_error)?;

        let Some(validated) = validated else {
            return Err(ErrorData::invalid_params(
                "unauthorized",
                Some(json!({ "http_status": 401 })),
            ));
        };

        let dynamic_metadata = AuthorinoMetadata {
            account_id: validated.account.id.clone(),
            project_id: validated.project.id.clone(),
            api_key_id: validated.api_key.id.clone(),
            api_key_status: validated.api_key.status.to_string(),
            extra: params.metadata,
        };

        to_json_value(json!({
            "api_key": validated.api_key,
            "project": validated.project,
            "account": validated.account,
            "dynamic_metadata": dynamic_metadata
        }))
    }
}

pub async fn start_mcp_server(
    api: &ApiServer,
    oauth2: &Oauth2,
    basic_auth: &BasicAuth,
    pool: Arc<dyn DbPoolTrait>,
) -> Result<()> {
    let readiness_pool = pool.clone();
    let store: Arc<dyn AuthzStore> = Arc::new(AuthzStoreImpl::with_pool(pool.clone()));
    let opa_repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let bearer_service: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));
    let app_state = Arc::new(lightbridge_authz_api::AppState {
        store: store.clone(),
        bearer: bearer_service,
    });

    let handler = LightbridgeMcpHandler::new(store, opa_repo, basic_auth.clone());
    let oauth_proxy_state = Arc::new(OauthProxyState {
        client: Client::new(),
        endpoints: resolve_oauth2_endpoints(oauth2),
        fallback_registration_endpoint: fallback_registration_endpoint(api),
    });

    let mcp_service: StreamableHttpService<LightbridgeMcpHandler, LocalSessionManager> =
        StreamableHttpService::new(
            {
                let handler = handler.clone();
                move || Ok(handler.clone())
            },
            Default::default(),
            StreamableHttpServerConfig::default(),
        );

    let metadata_state = oauth_proxy_state.clone();
    let openid_state = oauth_proxy_state.clone();
    let register_state = oauth_proxy_state.clone();
    let public =
        Router::new()
            .route("/", get(root_handler))
            .route("/health", get(health_handler))
            .route("/health/startup", get(startup_handler))
            .route(
                "/.well-known/oauth-authorization-server",
                get(move |headers: HeaderMap| {
                    let metadata_state = metadata_state.clone();
                    async move {
                        oauth_authorization_server_metadata_handler(metadata_state, headers).await
                    }
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                get(move |headers: HeaderMap| {
                    let openid_state = openid_state.clone();
                    async move { openid_configuration_handler(openid_state, headers).await }
                }),
            )
            .route(
                "/oauth/register",
                post(move |headers: HeaderMap, body: AxumJson<Value>| {
                    let register_state = register_state.clone();
                    async move { oauth_register_handler(register_state, headers, body).await }
                }),
            )
            .route(
                "/health/ready",
                get(move || {
                    let readiness_pool = readiness_pool.clone();
                    async move { readiness_handler(readiness_pool).await }
                }),
            );

    let protected = Router::new()
        .nest_service("/mcp", mcp_service)
        .with_state(app_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            bearer_auth,
        ));

    let app = public.merge(protected);

    serve_tls("MCP", &api.address, api.port, &api.tls, app).await
}

pub async fn start_mcp_server_from_config(config: &Config) -> Result<()> {
    let pool: Arc<dyn DbPoolTrait> =
        Arc::new(lightbridge_authz_core::db::DbPool::new(&config.database).await?);
    start_mcp_server(
        &config.server.api,
        &config.oauth2,
        &config.server.opa.basic_auth,
        pool,
    )
    .await
}

async fn root_handler() -> (StatusCode, AxumJson<RootResponse>) {
    (
        StatusCode::OK,
        AxumJson(RootResponse {
            status: "ok".to_string(),
            message: "Welcome to Lightbridge Authz MCP API".to_string(),
        }),
    )
}

async fn health_handler() -> StatusCode {
    StatusCode::OK
}

async fn startup_handler() -> StatusCode {
    StatusCode::OK
}

async fn readiness_handler(pool: Arc<dyn DbPoolTrait>) -> StatusCode {
    if is_database_ready(pool.as_ref()).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use chrono::Utc;
    use lightbridge_authz_core::{ApiKeyStatus, async_trait};
    use sqlx::postgres::PgPoolOptions;

    #[derive(Debug)]
    struct MockStore;

    #[async_trait]
    impl AuthzStore for MockStore {
        async fn create_account(
            &self,
            _subject: &str,
            _input: CreateAccount,
        ) -> std::result::Result<Account, Error> {
            Err(Error::NotFound)
        }

        async fn list_accounts(
            &self,
            _subject: &str,
            _offset: u32,
            _limit: u32,
        ) -> std::result::Result<Vec<Account>, Error> {
            Err(Error::NotFound)
        }

        async fn get_account(
            &self,
            _subject: &str,
            _account_id: &str,
        ) -> std::result::Result<Account, Error> {
            Err(Error::NotFound)
        }

        async fn update_account(
            &self,
            _subject: &str,
            _account_id: &str,
            _input: UpdateAccount,
        ) -> std::result::Result<Account, Error> {
            Err(Error::NotFound)
        }

        async fn delete_account(
            &self,
            _subject: &str,
            _account_id: &str,
        ) -> std::result::Result<(), Error> {
            Err(Error::NotFound)
        }

        async fn create_project(
            &self,
            _subject: &str,
            _account_id: &str,
            _input: CreateProject,
        ) -> std::result::Result<Project, Error> {
            Err(Error::NotFound)
        }

        async fn list_projects(
            &self,
            _subject: &str,
            _account_id: &str,
            _offset: u32,
            _limit: u32,
        ) -> std::result::Result<Vec<Project>, Error> {
            Err(Error::NotFound)
        }

        async fn get_project(
            &self,
            _subject: &str,
            _project_id: &str,
        ) -> std::result::Result<Project, Error> {
            Err(Error::NotFound)
        }

        async fn update_project(
            &self,
            _subject: &str,
            _project_id: &str,
            _input: UpdateProject,
        ) -> std::result::Result<Project, Error> {
            Err(Error::NotFound)
        }

        async fn delete_project(
            &self,
            _subject: &str,
            _project_id: &str,
        ) -> std::result::Result<(), Error> {
            Err(Error::NotFound)
        }

        async fn create_api_key(
            &self,
            _subject: &str,
            _project_id: &str,
            _input: CreateApiKey,
        ) -> std::result::Result<ApiKeySecret, Error> {
            Err(Error::NotFound)
        }

        async fn list_api_keys(
            &self,
            _subject: &str,
            _project_id: &str,
            _offset: u32,
            _limit: u32,
        ) -> std::result::Result<Vec<ApiKey>, Error> {
            Err(Error::NotFound)
        }

        async fn get_api_key(
            &self,
            _subject: &str,
            _key_id: &str,
        ) -> std::result::Result<ApiKey, Error> {
            Err(Error::NotFound)
        }

        async fn update_api_key(
            &self,
            _subject: &str,
            _key_id: &str,
            _input: UpdateApiKey,
        ) -> std::result::Result<ApiKey, Error> {
            Err(Error::NotFound)
        }

        async fn delete_api_key(
            &self,
            _subject: &str,
            _key_id: &str,
        ) -> std::result::Result<(), Error> {
            Err(Error::NotFound)
        }

        async fn revoke_api_key(
            &self,
            _subject: &str,
            _key_id: &str,
        ) -> std::result::Result<ApiKey, Error> {
            Err(Error::NotFound)
        }

        async fn rotate_api_key(
            &self,
            _subject: &str,
            _key_id: &str,
            _input: RotateApiKey,
        ) -> std::result::Result<ApiKeySecret, Error> {
            Err(Error::NotFound)
        }
    }

    #[derive(Debug)]
    struct MockOpaRepo {
        api_key: ApiKey,
        project: Project,
        account: Account,
    }

    #[async_trait]
    impl OpaRepoTrait for MockOpaRepo {
        async fn find_api_key_by_hash(&self, _key_hash: &str) -> Result<Option<ApiKey>> {
            Ok(Some(self.api_key.clone()))
        }

        async fn record_api_key_usage(&self, _key_id: &str, _ip: Option<String>) -> Result<ApiKey> {
            Ok(self.api_key.clone())
        }

        async fn get_project(&self, _subject: &str, project_id: &str) -> Result<Option<Project>> {
            if project_id == self.project.id {
                return Ok(Some(self.project.clone()));
            }
            Ok(None)
        }

        async fn get_account(&self, _subject: &str, account_id: &str) -> Result<Option<Account>> {
            if account_id == self.account.id {
                return Ok(Some(self.account.clone()));
            }
            Ok(None)
        }

        async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>> {
            if project_id == self.project.id {
                return Ok(Some(self.project.clone()));
            }
            Ok(None)
        }

        async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>> {
            if account_id == self.account.id {
                return Ok(Some(self.account.clone()));
            }
            Ok(None)
        }
    }

    fn sample_repo() -> Arc<dyn OpaRepoTrait> {
        Arc::new(MockOpaRepo {
            api_key: ApiKey {
                id: "key_1".to_string(),
                project_id: "proj_1".to_string(),
                name: "k1".to_string(),
                key_prefix: "prefix".to_string(),
                key_hash: "hash".to_string(),
                created_at: Utc::now(),
                expires_at: None,
                status: ApiKeyStatus::Active,
                last_used_at: None,
                last_ip: None,
                revoked_at: None,
            },
            project: Project {
                id: "proj_1".to_string(),
                account_id: "acct_1".to_string(),
                name: "project".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "free".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            account: Account {
                id: "acct_1".to_string(),
                billing_identity: "bill_1".to_string(),
                owners_admins: vec!["owner".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        })
    }

    fn basic_auth() -> BasicAuth {
        BasicAuth {
            username: "u".to_string(),
            password: "p".to_string(),
        }
    }

    fn sample_oauth2() -> Oauth2 {
        Oauth2 {
            jwks_url: "http://keycloak:9100/realms/dev/protocol/openid-connect/certs".to_string(),
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
        }
    }

    #[test]
    fn resolve_oauth2_endpoints_from_keycloak_jwks_url() {
        let endpoints = resolve_oauth2_endpoints(&sample_oauth2())
            .expect("keycloak jwks url should resolve default oauth2 endpoints");

        assert_eq!(endpoints.issuer, "http://keycloak:9100/realms/dev");
        assert_eq!(
            endpoints.authorization_endpoint,
            "http://keycloak:9100/realms/dev/protocol/openid-connect/auth"
        );
        assert_eq!(
            endpoints.token_endpoint,
            "http://keycloak:9100/realms/dev/protocol/openid-connect/token"
        );
        assert_eq!(
            endpoints.registration_endpoint,
            "http://keycloak:9100/realms/dev/clients-registrations/openid-connect"
        );
        assert_eq!(
            endpoints.jwks_uri,
            "http://keycloak:9100/realms/dev/protocol/openid-connect/certs"
        );
    }

    #[test]
    fn oauth_metadata_uses_public_registration_endpoint() {
        let endpoints = resolve_oauth2_endpoints(&sample_oauth2())
            .expect("keycloak jwks url should resolve default oauth2 endpoints");
        let metadata =
            oauth_metadata_response(&endpoints, "https://authz.example.com/oauth/register");

        assert_eq!(metadata["issuer"], "http://keycloak:9100/realms/dev");
        assert_eq!(
            metadata["registration_endpoint"],
            "https://authz.example.com/oauth/register"
        );
        assert_eq!(
            metadata["jwks_uri"],
            "http://keycloak:9100/realms/dev/protocol/openid-connect/certs"
        );
    }

    #[test]
    fn registration_endpoint_prefers_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("mcp.example.com"),
        );

        let registration =
            registration_endpoint_for_request(&headers, "https://127.0.0.1:13000/oauth/register");

        assert_eq!(registration, "https://mcp.example.com/oauth/register");
    }

    #[tokio::test]
    async fn metadata_handler_returns_oauth_document() {
        let state = Arc::new(OauthProxyState {
            client: Client::new(),
            endpoints: resolve_oauth2_endpoints(&sample_oauth2()),
            fallback_registration_endpoint: "https://127.0.0.1:13000/oauth/register".to_string(),
        });
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("mcp.example.com"),
        );

        let response = oauth_authorization_server_metadata_handler(state, headers).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("metadata response body should be readable");
        let metadata: Value =
            serde_json::from_slice(&body).expect("metadata response should be valid json");

        assert_eq!(
            metadata["registration_endpoint"],
            "https://mcp.example.com/oauth/register"
        );
        assert_eq!(metadata["issuer"], "http://keycloak:9100/realms/dev");
    }

    #[tokio::test]
    async fn registration_handler_returns_500_when_oauth_endpoints_not_resolved() {
        let state = Arc::new(OauthProxyState {
            client: Client::new(),
            endpoints: None,
            fallback_registration_endpoint: "https://127.0.0.1:13000/oauth/register".to_string(),
        });

        let response =
            oauth_register_handler(state, HeaderMap::new(), AxumJson(json!({"name": "demo"})))
                .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn router_lists_all_lightbridge_endpoint_tools() {
        let handler = LightbridgeMcpHandler::new(Arc::new(MockStore), sample_repo(), basic_auth());

        let mut tool_names = handler
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        tool_names.sort();

        let mut expected = vec![
            "create-account",
            "create-api-key",
            "create-project",
            "delete-account",
            "delete-api-key",
            "delete-project",
            "get-account",
            "get-api-key",
            "get-project",
            "list-accounts",
            "list-api-keys",
            "list-projects",
            "revoke-api-key",
            "rotate-api-key",
            "update-account",
            "update-api-key",
            "update-project",
            "validate-authorino-api-key",
            "validate-api-key",
        ];
        expected.sort();

        assert_eq!(tool_names, expected);
    }

    #[test]
    fn create_account_tool_schema_uses_jwt_subject_not_input_subject() {
        let handler = LightbridgeMcpHandler::new(Arc::new(MockStore), sample_repo(), basic_auth());
        let create_account = handler
            .tool_router
            .list_all()
            .into_iter()
            .find(|tool| tool.name == "create-account")
            .expect("create-account tool should exist");

        let properties = create_account
            .input_schema
            .get("properties")
            .and_then(|value| value.as_object())
            .expect("input schema should contain object properties");

        assert!(
            !properties.contains_key("subject"),
            "subject should come from JWT token claims, not tool input"
        );
        assert!(
            !properties.contains_key("owners_admins"),
            "owners_admins should not be accepted on account creation"
        );
    }

    #[test]
    fn list_tools_schema_include_pagination_fields() {
        let handler = LightbridgeMcpHandler::new(Arc::new(MockStore), sample_repo(), basic_auth());
        for tool_name in ["list-accounts", "list-projects", "list-api-keys"] {
            let tool = handler
                .tool_router
                .list_all()
                .into_iter()
                .find(|tool| tool.name == tool_name)
                .expect("list tool should exist");
            let properties = tool
                .input_schema
                .get("properties")
                .and_then(|value| value.as_object())
                .expect("input schema should contain object properties");

            assert!(
                properties.contains_key("offset"),
                "offset should be present for {tool_name}"
            );
            assert!(
                properties.contains_key("limit"),
                "limit should be present for {tool_name}"
            );
        }
    }

    #[tokio::test]
    async fn authorino_validation_tool_enriches_dynamic_metadata() {
        let handler = LightbridgeMcpHandler::new(Arc::new(MockStore), sample_repo(), basic_auth());
        let mut metadata = HashMap::new();
        metadata.insert("env".to_string(), json!("dev"));

        let result = handler
            .validate_authorino_api_key(Parameters(ValidateAuthorinoApiKeyParams {
                api_key: "lbk_secret_sample".to_string(),
                ip: Some("127.0.0.1".to_string()),
                metadata,
            }))
            .await
            .expect("validation should succeed");

        let output = result.0.result;

        assert_eq!(output["account"]["id"], "acct_1");
        assert_eq!(output["project"]["id"], "proj_1");
        assert_eq!(output["api_key"]["id"], "key_1");
        assert_eq!(output["dynamic_metadata"]["account_id"], "acct_1");
        assert_eq!(output["dynamic_metadata"]["project_id"], "proj_1");
        assert_eq!(output["dynamic_metadata"]["api_key_id"], "key_1");
        assert_eq!(output["dynamic_metadata"]["api_key_status"], "active");
        assert_eq!(output["dynamic_metadata"]["env"], "dev");
    }

    #[tokio::test]
    async fn health_and_startup_endpoints_report_ok() {
        assert_eq!(health_handler().await, StatusCode::OK);
        assert_eq!(startup_handler().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_unavailable_when_database_is_down() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        let pool: Arc<dyn DbPoolTrait> =
            Arc::new(lightbridge_authz_core::db::DbPool::from_pool(pool));

        assert_eq!(
            readiness_handler(pool).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
