use std::{collections::HashMap, sync::Arc};

use axum::{Json as AxumJson, Router, http::StatusCode, routing::get};
use chrono::{DateTime, Utc};
use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, Config, CreateAccount, CreateApiKey, CreateProject,
    DefaultLimits, Error, Project, Result, RotateApiKey, UpdateAccount, UpdateApiKey,
    UpdateProject,
    config::{ApiServer, BasicAuth, Oauth2},
    db::DbPoolTrait,
    server::serve_tls,
};
use lightbridge_authz_rest::{
    OpaRepoTrait, OpaState,
    handlers::{AuthzStoreImpl, opa::validate_api_key_context},
    middleware::bearer_auth,
    models::authorino::AuthorinoMetadata,
};
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateAccountParams {
    billing_identity: String,
    #[serde(default)]
    owners_admins: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListAccountsParams {}

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
                    owners_admins: params.owners_admins,
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
        let _ = params;
        let subject = subject_from_request_context(&context)?;
        let accounts: Vec<Account> = self
            .store
            .list_accounts(&subject)
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
        let projects: Vec<Project> = self
            .store
            .list_projects(&subject, &params.account_id)
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
        let api_keys: Vec<ApiKey> = self
            .store
            .list_api_keys(&subject, &params.project_id)
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
    let store: Arc<dyn AuthzStore> = Arc::new(AuthzStoreImpl::with_pool(pool.clone()));
    let opa_repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let bearer_service: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));
    let app_state = Arc::new(lightbridge_authz_api::AppState {
        store: store.clone(),
        bearer: bearer_service,
    });

    let handler = LightbridgeMcpHandler::new(store, opa_repo, basic_auth.clone());

    let mcp_service: StreamableHttpService<LightbridgeMcpHandler, LocalSessionManager> =
        StreamableHttpService::new(
            {
                let handler = handler.clone();
                move || Ok(handler.clone())
            },
            Default::default(),
            StreamableHttpServerConfig::default(),
        );

    let public = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler));

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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lightbridge_authz_core::{ApiKeyStatus, async_trait};

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

        async fn list_accounts(&self, _subject: &str) -> std::result::Result<Vec<Account>, Error> {
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
}
