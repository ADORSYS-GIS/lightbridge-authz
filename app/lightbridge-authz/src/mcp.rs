use std::{collections::HashMap, sync::Arc};

use axum::{
    Json as AxumJson, Router,
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use cratestack::{CratestackContext, CratestackError, Value as CratestackValue};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::{
    Config, CreateAccount, CreateApiKey, DefaultLimits, Error, Permission, Result, RotateApiKey,
    config::{ApiKeyExpiry, ApiServer, BasicAuth, Billing, ModelCatalog, Oauth2, QuotaTiers},
    cuid::cuid2,
    db::{DbPoolTrait, is_database_ready},
    server::serve_tls,
};
use lightbridge_authz_rest::{
    OpaRepoTrait, OpaState,
    handlers::{AuthzStoreImpl, opa::validate_api_key_context},
    middleware::bearer_auth,
    models::authorino::AuthorinoMetadata,
    rpc_authorize::RpcScope,
    secret_claim::SecretClaimStore,
};
use reqwest::Client;
use rmcp::{
    ErrorData, Json, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo},
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
    #[schemars(schema_with = "json_value_without_boolean_schema")]
    result: Value,
}

fn json_value_without_boolean_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    // Some MCP clients reject boolean JSON Schema nodes (`true` / `false`), so keep this as an
    // object schema while still allowing any valid JSON value.
    schemars::json_schema!({
        "type": ["object", "array", "string", "number", "boolean", "null"]
    })
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

/// MCP handler.
///
/// CRUD tools (account/project/api-key create/list/get/update/delete) call the generated cratestack
/// client directly — `cratestack_db.bind_context(ctx)` yields context-bound model delegates that
/// enforce the schema's `@@allow` membership policies exactly as the RPC surface does (ADR-0003).
/// Procedure-backed tools (create/rotate/revoke api-key, disable/enable account/project,
/// add/remove member) call the reused `AuthzStoreImpl` — the same hand-written, membership-scoped
/// sqlx the RPC `ProcedureRegistry` in `lightbridge-authz-rest` delegates to (see that crate's
/// `Procedures`). Calling the issuer directly rather than through `Procedures` keeps the richer
/// `rotate-api-key` capability (name / expires_at / grace_period_seconds) that the RPC
/// `rotateApiKey` procedure's `keyId`-only input cannot express. Validation tools stay on the
/// hand-written OPA path (`OpaState`) — outside the cratestack CRUD migration's scope.
#[derive(Clone)]
pub struct LightbridgeMcpHandler {
    tool_router: ToolRouter<Self>,
    cratestack_db: schema::Cratestack,
    issuer: Arc<AuthzStoreImpl>,
    opa_state: Arc<OpaState>,
    billing: Arc<Billing>,
    /// ADR-0025 Stage 2: translates a validated bearer token's `(iss, sub)` into the acting
    /// account id -- see `lightbridge_authz_rest::auth_provider::SubjectResolver`'s own doc
    /// comment for the self-signed-vs-external issuer cases this handles.
    resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver>,
    /// Stashes a freshly minted API key secret so it is handed to the human out of band instead
    /// of returned in a tool result (GHSA-9pc6-965v-2c44).
    ///
    /// `None` when `secret_claim` is unconfigured. That does NOT re-enable returning the secret --
    /// `create-api-key`/`rotate-api-key` REFUSE outright in that state. The alternative, failing at
    /// startup, would take this service down on any deployment that upgrades the image before
    /// provisioning the key, so the refusal was moved from process start to the affected operation.
    /// Every other tool keeps working.
    claim_store: Option<Arc<SecretClaimStore>>,
    /// Origin of the `authz-idp` that redeems claims, from `secret_claim.redeem_base_url`.
    /// Configured, never derived from a request header, which would be attacker-influenced.
    /// `Some` exactly when `claim_store` is.
    redeem_base_url: Option<Arc<String>>,
}

impl std::fmt::Debug for LightbridgeMcpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightbridgeMcpHandler")
            .field("tools", &self.tool_router.list_all().len())
            .finish()
    }
}

impl LightbridgeMcpHandler {
    /// `api_key_audience` (`oauth2.signing.audience`) is threaded onto the `OpaState` this
    /// handler builds purely for construction-site consistency with `authz-opa`'s own
    /// `start_opa_server` -- MCP's own tools only ever call
    /// `handlers::opa::validate_api_key_context` (the API-key hash path), never
    /// `handlers::exchange_token::verify_self_issued_token`, so this value is currently inert
    /// here. Kept correct anyway rather than hardcoding `None`, so a future MCP tool that does
    /// reach the exchange-token path inherits the same `azp` gate by construction instead of
    /// silently getting a `None` that would fail closed on every `azp`-bearing token.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cratestack_db: schema::Cratestack,
        issuer: Arc<AuthzStoreImpl>,
        opa_repo: Arc<dyn OpaRepoTrait>,
        basic_auth: BasicAuth,
        billing: &Billing,
        api_key_audience: Option<String>,
        resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver>,
        federation_issuer: String,
        claim_store: Option<Arc<SecretClaimStore>>,
        redeem_base_url: Option<Arc<String>>,
    ) -> Self {
        let billing = Arc::new(billing.clone());
        let opa_state = Arc::new(OpaState {
            repo: opa_repo,
            basic_auth,
            billing: billing.clone(),
            api_key_audience,
            resolver: resolver.clone(),
            federation_issuer,
        });

        Self {
            tool_router: Self::tool_router(),
            cratestack_db,
            issuer,
            opa_state,
            billing,
            resolver,
            claim_store,
            redeem_base_url,
        }
    }

    /// The tool list advertised to clients: the router's tools, with the `create-api-key`
    /// description annotated with the operator-configured billing plan ids so a caller can see the
    /// valid `billing_plan` values without a round-trip.
    fn advertised_tools(&self) -> Vec<rmcp::model::Tool> {
        let mut tools = self.tool_router.list_all();
        let plan_ids = self.billing.plan_ids();
        if !plan_ids.is_empty() {
            let suffix = format!(" Valid `billing_plan` ids: {}.", plan_ids.join(", "));
            for tool in tools.iter_mut() {
                if tool.name == "create-api-key" {
                    let base = tool.description.take().unwrap_or_default().into_owned();
                    tool.description = Some(format!("{base}{suffix}").into());
                }
            }
        }
        tools
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LightbridgeMcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "MCP interface for Lightbridge Authz API and OPA validation endpoints",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, ErrorData> {
        // `with_all_items` (rmcp 3.0's replacement for a bare struct literal, which no longer
        // compiles now that `ListToolsResult` also carries the SEP-2322/SEP-2549 `result_type` /
        // `ttl_ms` / `cache_scope` fields) fills those in with the same no-op defaults a manual
        // `..Default::default()` would: `result_type: Some(ResultType::COMPLETE)` (this is a
        // complete, non-MRTR result), `ttl_ms: None` / `cache_scope: None` (this handler doesn't
        // model result caching), `meta: None`, `next_cursor: None` (unchanged from before).
        Ok(ListToolsResult::with_all_items(self.advertised_tools()))
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<rmcp::model::CallToolResponse, ErrorData> {
        let tool = request.name.clone();

        let token_info = token_info_from_request_context(&context)?;
        let subject = token_info.sub.clone();
        match required_tool_permission(&tool) {
            Some(required) => token_info.require(required).map_err(to_tool_error)?,
            None => {
                return Err(ErrorData::invalid_request(
                    format!("unknown tool: {tool}"),
                    None,
                ));
            }
        }

        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        // `ToolRouter::call` now returns `CallToolResponse` directly (rmcp 3.0's MRTR support,
        // SEP-2322 — a tool call can also resolve to `InputRequired` or `Task`, not just
        // `Complete`), so no conversion is needed here; only the `is_error` outcome-logging check
        // below has to look inside the `Complete` variant, since `InputRequired`/`Task` aren't a
        // completed result and therefore can't be an error outcome.
        let result = self.tool_router.call(tcc).await;
        let outcome = match &result {
            Ok(rmcp::model::CallToolResponse::Complete(call_result))
                if call_result.is_error.unwrap_or(false) =>
            {
                "error"
            }
            Ok(_) => "ok",
            Err(_) => "error",
        };
        tracing::info!(tool = %tool, subject = %subject, outcome, "mcp tool invoked");
        result
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

/// `create-api-key`'s `expires_at` counterpart to `parse_optional_datetime` above --
/// non-`Option`, since lightbridge-authz#395 made an expiry mandatory on every created key.
fn parse_required_datetime(
    value: String,
    field_name: &str,
) -> std::result::Result<DateTime<Utc>, ErrorData> {
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| {
            ErrorData::invalid_params(format!("invalid RFC3339 datetime for `{field_name}`"), None)
        })
}

fn to_tool_error(error: Error) -> ErrorData {
    match error {
        Error::NotFound => ErrorData::resource_not_found("not found", None),
        Error::Forbidden(msg) => ErrorData::invalid_request(msg, None),
        Error::Conflict(msg) => ErrorData::invalid_params(msg, None),
        Error::BadRequest(msg) => ErrorData::invalid_params(msg, None),
        other => ErrorData::internal_error(other.to_string(), None),
    }
}

/// Map a cratestack `CratestackError` (returned by the generated CRUD client) onto an MCP `ErrorData`,
/// mirroring [`to_tool_error`]'s status mapping for the hand-written `Error`. Internal/database
/// variants collapse to a generic internal error so operator detail never leaks to the client.
fn cratestack_error_to_tool_error(error: CratestackError) -> ErrorData {
    match error {
        CratestackError::NotFound(_) => ErrorData::resource_not_found("not found", None),
        CratestackError::Forbidden(msg) | CratestackError::Unauthorized(msg) => {
            ErrorData::invalid_request(msg, None)
        }
        CratestackError::Conflict(msg)
        | CratestackError::PreconditionFailed(msg)
        | CratestackError::BadRequest(msg)
        | CratestackError::Validation(msg)
        | CratestackError::NotAcceptable(msg)
        | CratestackError::UnsupportedMediaType(msg) => ErrorData::invalid_params(msg, None),
        other => ErrorData::internal_error(other.to_string(), None),
    }
}

/// Build a cratestack [`CratestackContext`] for the authenticated MCP caller by delegating to
/// [`lightbridge_authz_rest::auth_provider::build_context`] — the SAME function
/// `CratestackAuthProvider::authenticate` uses for the RPC surface, not a second, independently
/// maintained copy of "how a context gets its permission fields".
///
/// This is load-bearing, not stylistic (issue #383 follow-up): both MCP and the RPC surface hand
/// their built context to the SAME generated cratestack client, which evaluates the SAME
/// `authz.cstack` `@allow`/`@@allow` clauses regardless of which surface reached it. Before this
/// was unified, MCP's own copy set only `auth().id`, which satisfied the schema's old
/// `@allow(auth() != null)` clauses but silently failed every clause #383 added (`auth().rpcScope`,
/// `auth().perm<Permission>`) — found by CI's `integration-test` (`it-servers`) failing the very
/// first MCP tool call after that PR merged, not by any local test, because nothing exercised this
/// second entry point at all. `RpcScope::Crud` because the MCP surface only ever exposes the CRUD
/// tool set (accounts/projects/api-keys) — confirmed against `app/lightbridge-authz/src/bin/
/// lightbridge-mcp.rs` (a dedicated binary, entirely separate from `authz-budget`'s `command:
/// budget` subcommand on the main `lightbridge-authz` binary) and `compose.yaml`'s `authz-mcp`
/// service (own image/port, no budget-scoped env or command, same `DATABASE_URL` as `authz-api`)
/// — `mcp.rs` has no `RpcScope`/budget-procedure concept anywhere in it.
///
/// See `cratestack_context_from_token_info_matches_the_shared_helper` below for the regression
/// test pinning this delegation — it fails immediately if a future edit reintroduces a
/// hand-rolled, out-of-sync copy here.
async fn cratestack_context_from_token_info(
    info: &TokenInfo,
    resolver: &dyn lightbridge_authz_rest::auth_provider::SubjectResolver,
) -> std::result::Result<CratestackContext, ErrorData> {
    lightbridge_authz_rest::auth_provider::build_context(info, RpcScope::Crud, resolver)
        .await
        .map_err(cratestack_error_to_tool_error)
}

/// A `find_unique` that returned `None` (row absent, or hidden by the membership read policy) is a
/// uniform not-found for the caller, matching the RPC surface's policy-driven behavior.
fn require_found<T>(value: Option<T>) -> std::result::Result<T, ErrorData> {
    value.ok_or_else(|| ErrorData::resource_not_found("not found", None))
}

/// Lower a `serde_json::Value` (the shape MCP tool inputs speak) into cratestack's own `Value`
/// enum, which is what the generated model input structs carry for `Json` columns. Mirrors the
/// identical private helper in `lightbridge-authz-rest` (the two crates use different JSON value
/// types and neither ships a cross-conversion).
fn json_to_cratestack_value(value: Value) -> CratestackValue {
    match value {
        Value::Null => CratestackValue::Null,
        Value::Bool(b) => CratestackValue::Bool(b),
        Value::Number(n) => n
            .as_i64()
            .map(CratestackValue::Int)
            .unwrap_or_else(|| CratestackValue::Float(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => CratestackValue::String(s),
        Value::Array(items) => {
            CratestackValue::List(items.into_iter().map(json_to_cratestack_value).collect())
        }
        Value::Object(map) => CratestackValue::Map(
            map.into_iter()
                .map(|(k, v)| (k, json_to_cratestack_value(v)))
                .collect(),
        ),
    }
}

/// Build a `cratestack::Json<cratestack::Value>` payload from any serde_json value.
fn cratestack_json(value: Value) -> cratestack::Json<CratestackValue> {
    cratestack::Json(json_to_cratestack_value(value))
}

/// Builds the tool result for a created or rotated API key.
///
/// GHSA-9pc6-965v-2c44: this function **cannot** leak the secret, because it is never given one.
/// That is deliberate and is the guarantee -- a runtime assertion that some field is absent can be
/// defeated by a later edit, whereas a builder that has no access to the secret cannot emit it no
/// matter what anyone adds to it. Both `create-api-key` and `rotate-api-key` return through here.
fn api_key_claim_response(
    api_key: &lightbridge_authz_core::ApiKey,
    oauth2_url: Option<&str>,
    redeem_base_url: &str,
    claim_token: &str,
    expires_in_seconds: i64,
) -> Value {
    serde_json::json!({
        "api_key": api_key,
        "oauth2_url": oauth2_url,
        "claim_url": format!(
            "{}/api-keys/claim/{}",
            redeem_base_url.trim_end_matches('/'),
            claim_token
        ),
        "expires_in_seconds": expires_in_seconds,
    })
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

/// ADR-0025 Stage 2: resolves the request's bearer token into the acting account id -- never the
/// raw `TokenInfo::sub` directly. Every `AuthzStoreImpl` method this feeds treats its `subject`
/// parameter as already-resolved (see `handlers::AuthzStoreImpl`'s own call sites into
/// `StoreRepo`), so this is the one place on the MCP surface that translation must happen.
async fn subject_from_request_context(
    context: &RequestContext<RoleServer>,
    resolver: &dyn lightbridge_authz_rest::auth_provider::SubjectResolver,
) -> std::result::Result<String, ErrorData> {
    let info = token_info_from_request_context(context)?;
    resolver
        .resolve(&info.iss, &info.sub)
        .await
        .map(String::from)
        .map_err(|_| {
            ErrorData::invalid_request("unable to resolve caller identity".to_string(), None)
        })
}

/// The permission a tool requires, keyed by tool name. Single source of truth for RBAC on the MCP
/// surface; mirrors `required_permission` on the REST server and `docs/rbac.md`. Enforced centrally
/// in `call_tool`, so the tool bodies stay free of authorization code.
fn required_tool_permission(tool: &str) -> Option<Permission> {
    Some(match tool {
        "create-account" => Permission::AccountCreate,
        "list-accounts" | "get-account" => Permission::AccountRead,
        "update-account" => Permission::AccountUpdate,
        "delete-account" => Permission::AccountDelete,
        "disable-account" | "enable-account" => Permission::AccountDisable,
        // Roster management (ADR-0006). The capability moved with the concept: `project:member`,
        // not `account:member`. This is only the coarse gate — the lead check lives in the
        // procedures' hand-written SQL, as cratestack's policy layer cannot express it.
        "list-project-roster"
        | "add-project-member"
        | "remove-project-member"
        | "set-project-member-role"
        | "set-project-member-quota-tier" => Permission::ProjectMember,
        "create-project" => Permission::ProjectCreate,
        "list-projects" | "get-project" => Permission::ProjectRead,
        "update-project"
        | "set-project-quota"
        | "set-project-allowed-models"
        | "set-project-model-policy" => Permission::ProjectUpdate,
        "delete-project" => Permission::ProjectDelete,
        "disable-project" | "enable-project" => Permission::ProjectDisable,
        "set-default-project" => Permission::ProjectUpdate,
        "create-api-key" => Permission::ApiKeyCreate,
        "list-api-keys" | "get-api-key" => Permission::ApiKeyRead,
        "update-api-key" => Permission::ApiKeyUpdate,
        "delete-api-key" => Permission::ApiKeyDelete,
        "revoke-api-key" => Permission::ApiKeyRevoke,
        "rotate-api-key" => Permission::ApiKeyRotate,
        "validate-api-key" | "validate-authorino-api-key" => Permission::ApiKeyValidate,
        _ => return None,
    })
}

fn token_info_from_request_context(
    context: &RequestContext<RoleServer>,
) -> std::result::Result<TokenInfo, ErrorData> {
    let parts = context
        .extensions
        .get::<axum::http::request::Parts>()
        .ok_or_else(|| ErrorData::internal_error("missing HTTP request context", None))?;

    let token_info = parts
        .extensions
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorData::internal_error("missing bearer token context", None))?;

    Ok(token_info.clone())
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
        .or_else(|| oauth2.oauth2_url.clone())
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
    if let Some(content_type) = content_type
        && let Ok(header_value) = HeaderValue::from_str(&content_type)
    {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, header_value);
    }
    response
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateAccountParams {
    /// A governance tier for the account's own default-project usage, validated against the
    /// operator-configured catalogue. Since ADR-0006 `billingIdentity` lives on `Project`, and the
    /// account's id is taken from the caller's JWT subject rather than any input field.
    #[serde(default)]
    default_quota: Option<String>,
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
    /// A tier drawn from the operator-configured catalogue, or omitted/`null` to clear it. Unlike
    /// before #379, this always writes (no PATCH "leave untouched" state) -- `updateAccountDefaultQuota`
    /// is a dedicated single-field procedure, not the generic `model.Account.update` verb, mirroring
    /// `SetProjectMemberQuotaTierParams::quota_tier` below.
    #[serde(default)]
    default_quota: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListProjectRosterParams {
    project_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AddProjectMemberParams {
    project_id: String,
    /// The account being added. Since ADR-0006 an account id *is* the member's JWT subject.
    account_id: String,
    /// "lead" | "member"; defaults to "member" if omitted.
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RemoveProjectMemberParams {
    project_id: String,
    account_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectMemberRoleParams {
    project_id: String,
    account_id: String,
    /// "lead" | "member". Lead-only.
    role: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectMemberQuotaTierParams {
    project_id: String,
    account_id: String,
    /// A tier drawn from the operator-configured catalogue, or omitted to clear the ceiling.
    #[serde(default)]
    quota_tier: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateProjectParams {
    account_id: String,
    name: String,
    #[serde(default)]
    default_limits: Option<DefaultLimitsInput>,
    billing_plan: String,
    /// Who is paying for this project. Moved here from `Account` by ADR-0006 so one account can
    /// bill several projects to different parties; unique across all projects.
    billing_identity: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectQuotaParams {
    project_id: String,
    /// The pooled, tier-catalogue-validated ceiling shared by everyone on the project, drawn from
    /// the operator-configured catalogue, or omitted/`null` to clear it.
    #[serde(default)]
    project_quota: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectAllowedModelsParams {
    project_id: String,
    /// Model ids drawn from the operator-configured catalogue (`list-model-catalog`), or omitted/
    /// `null` for "all models allowed". Rejected (#415, ADR-0018 Decision 5) if any entry is
    /// absent from a non-empty catalogue.
    #[serde(default)]
    allowed_models: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetProjectModelPolicyParams {
    project_id: String,
    /// One of `"allow_all"` (every model, present and future -- the default), `"allowlist"`
    /// (only `allowed_models` entries), or `"deny_all"` (no models). Any other value is refused
    /// (ADR-0018 Decision 5 follow-up). Switching to `"allowlist"` while the project's current
    /// `allowed_models` is empty/absent is refused -- populate it via `set-project-allowed-models`
    /// first. `allowed_models` itself is never touched by this tool; it is preserved across a
    /// policy change in either direction.
    model_policy: String,
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
    default_limits: Option<DefaultLimitsInput>,
    #[serde(default)]
    billing_plan: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateApiKeyParams {
    project_id: String,
    name: String,
    /// Required (RFC3339), lightbridge-authz#395: every api key must carry an expiry, no more
    /// than `api_key_expiry.max_lifetime_days` (default 90) days out. Server-validated
    /// regardless -- see `AuthzStoreImpl::validate_expires_at`.
    expires_at: String,
    billing_plan: String,
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

// No `expires_at` here (lightbridge-authz#395): the generic `model.ApiKey.update` verb this tool
// wraps had its `expiresAt` field removed at the schema level (`@readonly` on `ApiKey.expiresAt`
// in `authz.cstack`) because it was a live, unvalidated bypass -- a caller could set any expiry,
// including explicit `null`, with no cap and no procedure in the path. Changing a key's expiry now
// goes exclusively through `rotate-api-key` (which validates it) or minting a new key via
// `create-api-key`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateApiKeyParams {
    key_id: String,
    #[serde(default)]
    name: Option<String>,
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
        description = "Create an account (RPC procedure.createAccount); seeds the caller as the account's first member"
    )]
    async fn create_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateAccountParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .create_account(
                &subject,
                CreateAccount {
                    default_quota: params.default_quota,
                },
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "list-accounts",
        description = "List accounts (RPC model.Account.list)"
    )]
    async fn list_accounts_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListAccountsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let accounts = bound
            .account()
            .find_many()
            .limit(limit as i64)
            .offset(offset as i64)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(accounts)
    }

    #[tool(
        name = "get-account",
        description = "Get an account (RPC model.Account.get)"
    )]
    async fn get_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let account = bound
            .account()
            .find_unique(params.account_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(require_found(account)?)
    }

    #[tool(
        name = "update-account",
        description = "Update an account's default quota tier (RPC procedure.updateAccountDefaultQuota); tier validated against the configured catalogue"
    )]
    async fn update_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateAccountParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        // Repointed from the generic `model.Account.update` client call (#379): `defaultQuota` is
        // now `@readonly` on that verb's generated input (it has no hook for the runtime-configured
        // quota-tier catalogue check), so this now calls the `updateAccountDefaultQuota` procedure
        // instead, same as the RPC surface -- mirrors how `delete-account` was already repointed
        // from `model.Account.delete` to `deleteAccountPermanently`.
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .update_account_default_quota(
                &subject,
                &params.account_id,
                params.default_quota.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "delete-account",
        description = "Permanently delete an account and cascade-delete its projects/api-keys/memberships (RPC procedure.deleteAccountPermanently); owner-only"
    )]
    async fn delete_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        // Repointed from the generic `model.Account.delete` client call: that op is now denied
        // unconditionally (membership-role gating -- owner-only -- can't be expressed as an
        // `@@allow` policy, see the schema's comment on `Account`), so this now calls the
        // `deleteAccountPermanently` procedure instead, same as the RPC surface.
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .delete_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "disable-account",
        description = "Suspend an account (RPC procedure.disableAccount); every API key beneath it fails validation"
    )]
    async fn disable_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .disable_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "enable-account",
        description = "Reactivate a suspended account (RPC procedure.enableAccount)"
    )]
    async fn enable_account_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AccountByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let account = self
            .issuer
            .enable_account(&subject, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(account)
    }

    #[tool(
        name = "list-project-roster",
        description = "List a project's roster (RPC procedure.listProjectRoster); readable by any member of the project and by the owning account"
    )]
    async fn list_project_roster_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListProjectRosterParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let members = self
            .issuer
            .list_project_roster(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(members)
    }

    #[tool(
        name = "add-project-member",
        description = "Add an account to a project's roster (RPC procedure.addProjectMember); idempotent, lead-only"
    )]
    async fn add_project_member_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<AddProjectMemberParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .add_project_member(
                &subject,
                &params.project_id,
                &params.account_id,
                params.role.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "remove-project-member",
        description = "Remove an account from a project's roster (RPC procedure.removeProjectMember); lead-only"
    )]
    async fn remove_project_member_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<RemoveProjectMemberParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .remove_project_member(&subject, &params.project_id, &params.account_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-member-role",
        description = "Change a roster member's role between lead and member (RPC procedure.setProjectMemberRole); lead-only"
    )]
    async fn set_project_member_role_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectMemberRoleParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_member_role(
                &subject,
                &params.project_id,
                &params.account_id,
                &params.role,
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-member-quota-tier",
        description = "Set a roster member's per-project spending ceiling (RPC procedure.setProjectMemberQuotaTier); lead-only, tier validated against the configured catalogue"
    )]
    async fn set_project_member_quota_tier_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectMemberQuotaTierParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_member_quota_tier(
                &subject,
                &params.project_id,
                &params.account_id,
                params.quota_tier.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-quota",
        description = "Set a project's pooled spending ceiling (RPC procedure.setProjectQuota); owner or any roster member, tier validated against the configured catalogue"
    )]
    async fn set_project_quota_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectQuotaParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_quota(
                &subject,
                &params.project_id,
                params.project_quota.as_deref(),
            )
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-allowed-models",
        description = "Set a project's AI-model allowlist (RPC procedure.setProjectAllowedModels); owner or any roster member, every entry validated against the operator-configured model catalogue (#415, ADR-0018 Decision 5)"
    )]
    async fn set_project_allowed_models_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectAllowedModelsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_allowed_models(&subject, &params.project_id, params.allowed_models)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-project-model-policy",
        description = "Set a project's model access policy to allow_all/allowlist/deny_all (RPC procedure.setProjectModelPolicy); owner or any roster member. Refuses switching to allowlist while allowedModels is empty; never touches allowedModels itself (ADR-0018 Decision 5 follow-up)"
    )]
    async fn set_project_model_policy_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetProjectModelPolicyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_project_model_policy(&subject, &params.project_id, &params.model_policy)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "create-project",
        description = "Create a project (RPC model.Project.create); allowedModels is set afterward via set-project-allowed-models, projectQuota via set-project-quota"
    )]
    async fn create_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateProjectParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let default_limits = params
            .default_limits
            .map(DefaultLimits::from)
            .unwrap_or_default();
        let default_limits_json =
            serde_json::to_value(default_limits).unwrap_or_else(|_| json!({}));
        // `projectQuota`/`allowedModels` are both `@readonly` on this generated input (#379 and
        // #415 respectively -- neither has a hook for a runtime-configured catalogue check on the
        // generic verb) -- a brand-new project always starts with `projectQuota = NULL`/
        // `allowedModels = NULL` (both always valid), settable afterward via the
        // `set-project-quota`/`set-project-allowed-models` tools below.
        let input = schema::inputs::CreateProjectInput {
            id: cuid2(),
            accountId: params.account_id,
            name: params.name,
            defaultLimits: cratestack_json(default_limits_json),
            billingPlan: params.billing_plan,
            billingIdentity: params.billing_identity,
        };
        let project = bound
            .project()
            .create(input)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "list-projects",
        description = "List projects under an account (RPC model.Project.list)"
    )]
    async fn list_projects_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListProjectsParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let projects = bound
            .project()
            .find_many()
            .where_(schema::project::accountId().eq(params.account_id))
            .limit(limit as i64)
            .offset(offset as i64)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(projects)
    }

    #[tool(
        name = "get-project",
        description = "Get a project (RPC model.Project.get)"
    )]
    async fn get_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let project = bound
            .project()
            .find_unique(params.project_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(require_found(project)?)
    }

    #[tool(
        name = "update-project",
        description = "Update a project (RPC model.Project.update); allowedModels is set via set-project-allowed-models, not this tool (#415, ADR-0018 Decision 5)"
    )]
    async fn update_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateProjectParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let mut input = schema::inputs::UpdateProjectInput::default();
        if let Some(name) = params.name {
            input.name = Some(name);
        }
        if let Some(billing_plan) = params.billing_plan {
            input.billingPlan = Some(billing_plan);
        }
        if let Some(default_limits) = params.default_limits {
            let value = serde_json::to_value(DefaultLimits::from(default_limits))
                .unwrap_or_else(|_| json!({}));
            input.defaultLimits = Some(cratestack_json(value));
        }
        let project = bound
            .project()
            .update(params.project_id)
            .set(input)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "delete-project",
        description = "Delete a project (RPC model.Project.delete)"
    )]
    async fn delete_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let project = bound
            .project()
            .delete(params.project_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "disable-project",
        description = "Suspend a project (RPC procedure.disableProject); every API key beneath it fails validation"
    )]
    async fn disable_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .disable_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "enable-project",
        description = "Reactivate a suspended project (RPC procedure.enableProject)"
    )]
    async fn enable_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .enable_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "set-default-project",
        description = "Promote a different project to be its account's default (RPC procedure.setDefaultProject); frees the old default project up for hard deletion"
    )]
    async fn set_default_project_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ProjectByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let project = self
            .issuer
            .set_default_project(&subject, &params.project_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(project)
    }

    #[tool(
        name = "create-api-key",
        description = "Create an API key (RPC procedure.createApiKey; the server generates + hashes the secret, and validates the billing plan and expires_at -- required, RFC3339, at most ~90 days out by default)"
    )]
    async fn create_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let expires_at = parse_required_datetime(params.expires_at, "expires_at")?;

        let api_key_secret = self
            .issuer
            .create_api_key(
                &subject,
                Some(&token_info.access_token),
                &params.project_id,
                CreateApiKey {
                    name: params.name,
                    expires_at: Some(expires_at),
                    billing_plan: params.billing_plan,
                },
            )
            .await
            .map_err(to_tool_error)?;

        // GHSA-9pc6-965v-2c44: an MCP tool result is returned into the calling model's context,
        // so it must never carry the secret. Stash it and hand back a claim only the requesting
        // human, in a browser, can redeem. A failure to stash REFUSES the call -- there is no
        // fallback that returns the secret inline.
        // Fail closed when unconfigured. The secret exists at this point and the key row is
        // written, but there is nowhere safe to put the secret -- and a tool result is not it.
        // Refusing is the only correct answer; returning it would reintroduce the exposure this
        // whole mechanism exists to remove.
        let (Some(claim_store), Some(redeem_base_url)) =
            (self.claim_store.as_ref(), self.redeem_base_url.as_ref())
        else {
            return Err(ErrorData::internal_error(
                "secret_claim is not configured on this deployment, so an API key secret cannot \
                 be delivered safely. An MCP tool result is read by the model, so the secret is \
                 never returned here. Configure secret_claim (encryption_key, redeem_base_url) \
                 and retry."
                    .to_string(),
                None,
            ));
        };
        let claim = claim_store
            .issue(&api_key_secret.secret, &subject)
            .await
            .map_err(to_tool_error)?;
        to_json_value(api_key_claim_response(
            &api_key_secret.api_key,
            api_key_secret.oauth2_url.as_deref(),
            redeem_base_url,
            &claim.token,
            claim.expires_in_seconds,
        ))
    }

    #[tool(
        name = "list-api-keys",
        description = "List API keys under a project (RPC model.ApiKey.list)"
    )]
    async fn list_api_keys_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListApiKeysParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let (offset, limit) = normalize_list_pagination(params.offset, params.limit);
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let api_keys = bound
            .api_key()
            .find_many()
            .where_(schema::api_key::projectId().eq(params.project_id))
            .limit(limit as i64)
            .offset(offset as i64)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(api_keys)
    }

    #[tool(
        name = "get-api-key",
        description = "Get an API key (RPC model.ApiKey.get)"
    )]
    async fn get_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let api_key = bound
            .api_key()
            .find_unique(params.key_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(require_found(api_key)?)
    }

    #[tool(
        name = "update-api-key",
        description = "Update an API key's name (RPC model.ApiKey.update); expires_at can only be changed via rotate-api-key or by creating a new key (lightbridge-authz#395)"
    )]
    async fn update_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let mut input = schema::inputs::UpdateApiKeyInput::default();
        if let Some(name) = params.name {
            input.name = Some(name);
        }
        let api_key = bound
            .api_key()
            .update(params.key_id)
            .set(input)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "delete-api-key",
        description = "Delete (soft-delete) an API key (RPC model.ApiKey.delete)"
    )]
    async fn delete_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let bound = self.cratestack_db.bind_context(
            cratestack_context_from_token_info(&token_info, self.resolver.as_ref()).await?,
        );
        let api_key = bound
            .api_key()
            .delete(params.key_id)
            .run()
            .await
            .map_err(cratestack_error_to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "revoke-api-key",
        description = "Revoke an API key (RPC procedure.revokeApiKey)"
    )]
    async fn revoke_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let api_key = self
            .issuer
            .revoke_api_key(&subject, &params.key_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "rotate-api-key",
        description = "Rotate an API key (RPC procedure.rotateApiKey)"
    )]
    async fn rotate_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<RotateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let expires_at = parse_optional_datetime(params.expires_at, "expires_at")?;

        let api_key_secret = self
            .issuer
            .rotate_api_key(
                &subject,
                Some(&token_info.access_token),
                &params.key_id,
                RotateApiKey {
                    name: params.name,
                    expires_at,
                    grace_period_seconds: params.grace_period_seconds,
                },
            )
            .await
            .map_err(to_tool_error)?;

        // GHSA-9pc6-965v-2c44: an MCP tool result is returned into the calling model's context,
        // so it must never carry the secret. Stash it and hand back a claim only the requesting
        // human, in a browser, can redeem. A failure to stash REFUSES the call -- there is no
        // fallback that returns the secret inline.
        // Fail closed when unconfigured. The secret exists at this point and the key row is
        // written, but there is nowhere safe to put the secret -- and a tool result is not it.
        // Refusing is the only correct answer; returning it would reintroduce the exposure this
        // whole mechanism exists to remove.
        let (Some(claim_store), Some(redeem_base_url)) =
            (self.claim_store.as_ref(), self.redeem_base_url.as_ref())
        else {
            return Err(ErrorData::internal_error(
                "secret_claim is not configured on this deployment, so an API key secret cannot \
                 be delivered safely. An MCP tool result is read by the model, so the secret is \
                 never returned here. Configure secret_claim (encryption_key, redeem_base_url) \
                 and retry."
                    .to_string(),
                None,
            ));
        };
        let claim = claim_store
            .issue(&api_key_secret.secret, &subject)
            .await
            .map_err(to_tool_error)?;
        to_json_value(api_key_claim_response(
            &api_key_secret.api_key,
            api_key_secret.oauth2_url.as_deref(),
            redeem_base_url,
            &claim.token,
            claim.expires_in_seconds,
        ))
    }

    #[tool(
        name = "validate-api-key",
        description = "Validate an API key: hash lookup with status/expiry check, returns account/project context"
    )]
    async fn validate_api_key_tool(
        &self,
        Parameters(params): Parameters<ValidateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        run_validate_api_key(&self.opa_state, params).await
    }

    #[tool(
        name = "validate-authorino-api-key",
        description = "Validate an API key and return account/project context plus dynamic metadata enrichment"
    )]
    async fn validate_authorino_api_key(
        &self,
        Parameters(params): Parameters<ValidateAuthorinoApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        run_validate_authorino(&self.opa_state, params).await
    }
}

/// Core of the `validate-api-key` tool, factored out of the RBAC-gated tool method (which takes
/// no `RequestContext`, so the method itself is already directly callable, but keeping the two
/// validation tools symmetric makes the "unauthorized" branch trivial to exercise in isolation).
async fn run_validate_api_key(
    opa_state: &Arc<OpaState>,
    params: ValidateApiKeyParams,
) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
    let validated = validate_api_key_context(opa_state, &params.api_key, params.ip)
        .await
        .map_err(to_tool_error)?;

    let Some(validated) = validated else {
        return Err(ErrorData::invalid_params(
            "unauthorized",
            Some(json!({ "http_status": 401 })),
        ));
    };

    // `account_id`, not a nested `account` object: introspection stopped fetching the account row
    // in Phase E (ADR-0006) because the `api_key_validation` view already carries the id, so there
    // is no `Account` here to embed and re-adding the query would undo that. Matches
    // `IntrospectResponse.account_id` on the REST surface.
    to_json_value(json!({
        "api_key": validated.api_key,
        "project": validated.project,
        "account_id": validated.account_id
    }))
}

/// Core of the `validate-authorino-api-key` tool (validation + dynamic-metadata enrichment),
/// factored out of the RBAC-gated tool method so it can be exercised directly in tests.
async fn run_validate_authorino(
    opa_state: &Arc<OpaState>,
    params: ValidateAuthorinoApiKeyParams,
) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
    let validated = validate_api_key_context(opa_state, &params.api_key, params.ip)
        .await
        .map_err(to_tool_error)?;

    let Some(validated) = validated else {
        return Err(ErrorData::invalid_params(
            "unauthorized",
            Some(json!({ "http_status": 401 })),
        ));
    };

    let dynamic_metadata = AuthorinoMetadata {
        account_id: validated.account_id.clone(),
        project_id: validated.project.id.clone(),
        api_key_id: validated.api_key.id.clone(),
        api_key_status: validated.api_key.status.to_string(),
        extra: params.metadata,
    };

    to_json_value(json!({
        "api_key": validated.api_key,
        "project": validated.project,
        "account_id": validated.account_id,
        "dynamic_metadata": dynamic_metadata
    }))
}

/// Build the streamable-HTTP transport config for the MCP server.
///
/// Runs statelessly (`legacy_session_mode(false)` + `json_response(true)`) so any replica
/// can serve any request. In legacy session mode the session lives in each pod's in-memory
/// `LocalSessionManager`, so behind a round-robin LB the follow-up POST lands on a
/// different replica and 404s ("Session not found"). This server is a stateless tool
/// proxy — identity comes from the JWT on every request, no server-side session state —
/// so stateless mode is safe and keeps multi-replica HA. `allowed_hosts` (DNS-rebinding
/// protection) is applied on top when configured; unset keeps rmcp's localhost default.
///
/// rmcp 3.0 renamed `stateful_mode`/`with_stateful_mode` to `legacy_session_mode`/
/// `with_legacy_session_mode` (SEP-2567 dropped sessions from the `2026-07-28` protocol
/// version, so what used to be "the stateful/session mode" is now specifically "the legacy,
/// pre-2026-07-28 session mode"); the boolean semantics (`false` = stateless) are unchanged.
fn build_streamable_http_config(allowed_hosts: &Option<Vec<String>>) -> StreamableHttpServerConfig {
    let base_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    match allowed_hosts {
        Some(hosts) if !hosts.is_empty() => base_config.with_allowed_hosts(hosts.clone()),
        _ => base_config,
    }
}

/// Assembles the MCP server router (public probes + OAuth2 discovery/registration proxy, and the
/// bearer-protected `/mcp` streamable-HTTP endpoint). Separated from `start_mcp_server` so the
/// composition can be driven with real HTTP requests (JSON-RPC over `/mcp`) in tests without
/// binding a TLS socket, mirroring `build_api_router`/`build_opa_router` in
/// `lightbridge-authz-rest`.
#[allow(clippy::too_many_arguments)]
fn build_mcp_router(
    api: &ApiServer,
    oauth2: &Oauth2,
    basic_auth: BasicAuth,
    billing: &Billing,
    cratestack_db: schema::Cratestack,
    issuer: Arc<AuthzStoreImpl>,
    opa_repo: Arc<dyn OpaRepoTrait>,
    bearer_service: Arc<dyn BearerTokenServiceTrait>,
    resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver>,
    federation_issuer: String,
    readiness_pool: Arc<dyn DbPoolTrait>,
    claim_store: Option<Arc<SecretClaimStore>>,
    redeem_base_url: Option<Arc<String>>,
) -> Router {
    let app_state = Arc::new(lightbridge_authz_api::AppState {
        bearer: bearer_service,
    });

    let api_key_audience = oauth2
        .signing
        .as_ref()
        .and_then(|signing| signing.audience.clone());
    let handler = LightbridgeMcpHandler::new(
        cratestack_db,
        issuer,
        opa_repo,
        basic_auth,
        billing,
        api_key_audience,
        resolver,
        federation_issuer,
        claim_store,
        redeem_base_url,
    );
    let oauth_proxy_state = Arc::new(OauthProxyState {
        client: Client::new(),
        endpoints: resolve_oauth2_endpoints(oauth2),
        fallback_registration_endpoint: fallback_registration_endpoint(api),
    });

    let http_config = build_streamable_http_config(&api.allowed_hosts);
    let mcp_service: StreamableHttpService<LightbridgeMcpHandler, LocalSessionManager> =
        StreamableHttpService::new(
            // `handler` is not used after this point, so it moves straight into the
            // factory closure; the per-connection clone inside is the one that matters.
            move || Ok(handler.clone()),
            Default::default(),
            http_config,
        );

    let metadata_state = oauth_proxy_state.clone();
    let openid_state = oauth_proxy_state.clone();
    // Last of the three handler states — `oauth_proxy_state` is not used again, so move.
    let register_state = oauth_proxy_state;
    let public =
        Router::new()
            .route("/", get(root_handler))
            .route("/healthz", get(health_handler))
            .route("/healthz/startup", get(startup_handler))
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
                "/healthz/ready",
                get(move || {
                    let readiness_pool = readiness_pool.clone();
                    async move { readiness_handler(readiness_pool).await }
                }),
            );

    let protected = Router::new()
        .nest_service("/mcp", mcp_service)
        .with_state(app_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            // Last use of `app_state`; the `with_state` clone above still needs its own.
            app_state,
            bearer_auth,
        ));

    public.merge(protected)
}

#[expect(
    clippy::too_many_arguments,
    reason = "startup wiring for lightbridge-mcp, mirroring lightbridge-authz-rest's \
              start_api_server/start_budget_server rationale -- each parameter is a distinct, \
              independently-loaded config section"
)]
pub async fn start_mcp_server(
    api: &ApiServer,
    oauth2: &Oauth2,
    basic_auth: &BasicAuth,
    billing: &Billing,
    quota_tiers: &QuotaTiers,
    models: &ModelCatalog,
    api_key_expiry: &ApiKeyExpiry,
    secret_claim: Option<&lightbridge_authz_core::config::SecretClaim>,
    pool: Arc<dyn DbPoolTrait>,
) -> Result<()> {
    billing.validate()?;
    api_key_expiry.validate()?;
    oauth2.rbac.validate()?;
    // ADR-0025 Stage 1: `lightbridge-mcp` is one of the five components mandated to carry
    // `oauth2.federation.issuer` -- see `lightbridge_authz_rest`'s `require_federation` for the
    // identical shape applied to `authz-api`/`authz-idp`/`authz-opa`/`authz-budget`. `mcp.rs`
    // lives in a separate crate from `lightbridge-authz-rest`, so this is its own inline check
    // rather than a shared helper call.
    let federation = oauth2.federation.as_ref().ok_or_else(|| {
        Error::Server(
            "oauth2.federation.issuer is required for lightbridge-mcp (ADR-0025) -- set the \
             oauth2.federation block naming the one issuer this deployment trusts for \
             remote-subject-to-account-id translation"
                .to_string(),
        )
    })?;
    federation.validate()?;
    let readiness_pool = pool.clone();
    if oauth2.is_self_signed() {
        let signing = oauth2.signing.as_ref().ok_or_else(|| {
            Error::Server("oauth2.type is 'self' but oauth2.signing is missing".to_string())
        })?;
        let signing_repo = StoreRepo::new(pool.clone());
        lightbridge_authz_rest::signing::bootstrap_signing_key(&signing_repo, signing).await?;
    }
    // Secret-issuance + membership operations reused by the procedure-backed tools (hand-written
    // sqlx on the core `DbPool`, sqlx 0.9) — the same `AuthzStoreImpl` the RPC procedures delegate
    // to in `lightbridge-authz-rest`.
    let issuer = Arc::new(AuthzStoreImpl::with_pool_and_oauth2(
        pool.clone(),
        oauth2,
        billing,
        quota_tiers,
        models,
        api_key_expiry,
    )?);
    // ADR-0025 Stage 2: `federation` above is already the validated `oauth2.federation` block.
    let resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver> = Arc::new(
        lightbridge_authz_rest::auth_provider::FederatedSubjectResolver::new(
            Arc::new(StoreRepo::new(pool.clone())),
            oauth2.signing.as_ref().map(|s| s.issuer.clone()),
            federation.issuer.clone(),
        ),
    );
    // Validated offline here (base64url, exactly 32 bytes, positive TTL) so a malformed key is a
    // startup failure rather than a first-request failure -- the same posture
    // `KeycloakRelyingParty::new` takes, and for the same reason.
    // Still validated OFFLINE when present (base64url, exactly 32 bytes, positive TTL), so a
    // malformed key is a startup failure -- only an ABSENT block is tolerated, and it degrades to
    // refusing key creation rather than to returning secrets unsafely.
    let claim_store = secret_claim
        .map(|cfg| {
            SecretClaimStore::from_config(Arc::new(StoreRepo::new(pool.clone())), cfg).map(Arc::new)
        })
        .transpose()?;
    let opa_repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let bearer_service: Arc<dyn BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

    // cratestack CRUD client for the model-backed tools. cratestack runs on its own sqlx major
    // (0.8, vs this workspace's 0.9), so it needs a separate pool built with cratestack's sqlx,
    // talking to the same database (the URL comes from `DATABASE_URL`, the same env the schema's
    // `datasource ... env("DATABASE_URL")` reads) — mirroring `start_api_server`.
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        Error::Server(
            "DATABASE_URL must be set for the cratestack CRUD pool (MCP model-backed tools)"
                .to_string(),
        )
    })?;
    let cratestack_pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .connect(&database_url)
        .await
        .map_err(|e| Error::Server(format!("failed to open cratestack Postgres pool: {e}")))?;
    let cratestack_db = schema::Cratestack::builder(cratestack_pool).build();

    let app = build_mcp_router(
        api,
        oauth2,
        basic_auth.clone(),
        billing,
        cratestack_db,
        issuer,
        opa_repo,
        bearer_service,
        resolver,
        federation.issuer.clone(),
        readiness_pool,
        claim_store,
        secret_claim.map(|cfg| Arc::new(cfg.redeem_base_url.clone())),
    );

    let signing_enabled = oauth2.is_self_signed();
    let issuance_enabled = oauth2.is_external();
    tracing::info!(
        server = "lightbridge-mcp",
        address = %api.address,
        port = api.port,
        oauth2_type = ?oauth2.oauth2_type,
        signing_enabled,
        issuance_enabled,
        "starting mcp server"
    );

    serve_tls("MCP", &api.address, api.port, &api.tls, app).await
}

pub async fn start_mcp_server_from_config(config: &Config) -> Result<()> {
    let pool: Arc<dyn DbPoolTrait> =
        Arc::new(lightbridge_authz_core::db::DbPool::new(&config.database).await?);
    // GHSA-9pc6-965v-2c44. Deliberately NOT a startup mandate: an absent block degrades to
    // refusing create-api-key/rotate-api-key, never to returning a secret in a tool result. The
    // startup-mandate version would take this service down on any deployment that ships the image
    // before provisioning the key, which is a worse failure than one tool refusing.
    start_mcp_server(
        &config.server.api,
        &config.oauth2,
        &config.server.opa.basic_auth,
        &config.billing,
        &config.quota_tiers,
        &config.models,
        &config.api_key_expiry,
        config.secret_claim.as_ref(),
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
    use lightbridge_authz_core::{Account, ApiKey, ApiKeyStatus, Project, async_trait};
    use sqlx::postgres::PgPoolOptions;

    /// GHSA-9pc6-965v-2c44 regression. The strong guarantee is structural -- `api_key_claim_response`
    /// takes no secret parameter, so it cannot emit one. This asserts the resulting shape as well,
    /// so a future edit that adds a secret-bearing field is caught rather than merely improbable.
    #[test]
    fn the_api_key_tool_response_carries_a_claim_url_and_no_secret() {
        let api_key = ApiKey {
            id: "key_1".to_string(),
            project_id: "proj_1".to_string(),
            name: "n".to_string(),
            key_prefix: "lbk_abc".to_string(),
            key_hash: "hash-must-not-be-serialized".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            status: ApiKeyStatus::Active,
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
            billing_plan: "free".to_string(),
            updated_at: Utc::now(),
        };
        let value = api_key_claim_response(
            &api_key,
            Some("https://idp.example.test/token"),
            "https://auth.example.test/",
            "claimtoken123",
            300,
        );
        let rendered = serde_json::to_string(&value).expect("serialize");
        assert!(
            !rendered.contains("\"secret\""),
            "the MCP tool result must never carry a secret field: {rendered}"
        );
        assert_eq!(
            value["claim_url"],
            serde_json::json!("https://auth.example.test/api-keys/claim/claimtoken123"),
            "a trailing slash on redeem_base_url must not produce a doubled separator"
        );
        assert_eq!(value["expires_in_seconds"], serde_json::json!(300));
        assert!(
            !rendered.contains("hash-must-not-be-serialized"),
            "ApiKey::key_hash is #[serde(skip_serializing)] and must stay that way: {rendered}"
        );
    }

    /// GHSA-9pc6-965v-2c44 softening contract: the service must come up with `secret_claim`
    /// absent, with every tool still advertised. The refusal happens at `create-api-key`, not at
    /// process start -- see that tool's early return. Booting is what makes this safe to deploy
    /// ahead of provisioning the key.
    #[tokio::test]
    async fn the_handler_builds_and_advertises_every_tool_without_a_claim_store() {
        let with_claims = LightbridgeMcpHandler::new(
            lazy_cratestack_db(),
            lazy_issuer(),
            sample_repo(),
            basic_auth(),
            &sample_billing(),
            None,
            test_resolver(),
            "https://keycloak.example.test/realms/dev".to_string(),
            test_claim_store(),
            test_redeem_base_url(),
        );
        let without_claims = LightbridgeMcpHandler::new(
            lazy_cratestack_db(),
            lazy_issuer(),
            sample_repo(),
            basic_auth(),
            &sample_billing(),
            None,
            test_resolver(),
            "https://keycloak.example.test/realms/dev".to_string(),
            None,
            None,
        );
        assert_eq!(
            without_claims.advertised_tools().len(),
            with_claims.advertised_tools().len(),
            "an unconfigured secret_claim must not remove tools -- it must refuse the two that \
             hand over a secret, at call time"
        );
        assert!(
            without_claims
                .advertised_tools()
                .iter()
                .any(|t| t.name == "create-api-key"),
            "create-api-key stays advertised; it refuses when called"
        );
    }

    #[test]
    fn streamable_http_config_is_stateless_for_multi_replica() {
        let cfg = build_streamable_http_config(&Some(vec!["mcp.example.com".to_string()]));
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("legacy_session_mode: false"),
            "MCP transport must run stateless so any replica can serve any request \
             (legacy-session-mode sessions live per-pod and 404 behind a round-robin LB): {dbg}"
        );
        assert!(
            dbg.contains("json_response: true"),
            "stateless request/response calls should return application/json: {dbg}"
        );
        assert!(
            dbg.contains("mcp.example.com"),
            "configured allowed_hosts must be wired into the transport: {dbg}"
        );

        let cfg_default = build_streamable_http_config(&None);
        assert!(
            format!("{cfg_default:?}").contains("legacy_session_mode: false"),
            "stateless mode must hold even when allowed_hosts is unset"
        );
    }

    #[derive(Debug)]
    struct MockOpaRepo {
        api_key: ApiKey,
        project: Project,
        account: Account,
    }

    #[async_trait]
    impl OpaRepoTrait for MockOpaRepo {
        async fn record_api_key_usage(&self, _key_id: &str, _ip: Option<String>) -> Result<ApiKey> {
            Ok(self.api_key.clone())
        }

        async fn find_api_key_validation_by_hash(
            &self,
            _key_hash: &str,
        ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>> {
            Ok(Some(lightbridge_authz_core::ApiKeyValidation {
                api_key_id: self.api_key.id.clone(),
                key_hash: self.api_key.key_hash.clone(),
                project_id: self.project.id.clone(),
                account_id: self.account.id.clone(),
                // Owner-owned key: the project's owning account holds no `project_members` row, so
                // role/tier are legitimately absent and no per-member ceiling applies.
                owner_account_id: self.account.id.clone(),
                owner_role: None,
                owner_quota_tier: None,
                api_key_status: self.api_key.status.to_string(),
                project_status: self.project.status.to_string(),
                account_status: self.account.status.to_string(),
                expires_at: self.api_key.expires_at,
                effective_status: "active".to_string(),
            }))
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

        async fn resolve_context(
            &self,
            _subject: &str,
            _project_id: &str,
        ) -> Result<lightbridge_authz_core::ResolvedContext> {
            Err(lightbridge_authz_core::error::Error::NotFound)
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

        async fn project_member_quota_tier(
            &self,
            _project_id: &str,
            _subject: &str,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        async fn project_member_role(
            &self,
            _project_id: &str,
            _subject: &str,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        async fn list_verification_jwks(&self) -> Result<Vec<serde_json::Value>> {
            Ok(Vec::new())
        }

        async fn find_session_status(
            &self,
            _session_id: &str,
        ) -> Result<Option<lightbridge_authz_rest::SessionStatusRow>> {
            Ok(None)
        }
    }

    fn fixture_api_key() -> ApiKey {
        ApiKey {
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
            billing_plan: "free".to_string(),
            updated_at: Utc::now(),
        }
    }

    fn fixture_project() -> Project {
        Project {
            id: "proj_1".to_string(),
            account_id: "acct_1".to_string(),
            name: "project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "bill_1".to_string(),
            project_quota: None,
            status: lightbridge_authz_core::ResourceStatus::Active,
            is_default: false,
            model_policy: lightbridge_authz_core::ModelPolicy::AllowAll,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn fixture_account() -> Account {
        Account {
            id: "acct_1".to_string(),
            default_quota: None,
            status: lightbridge_authz_core::ResourceStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn sample_repo() -> Arc<dyn OpaRepoTrait> {
        Arc::new(MockOpaRepo {
            api_key: fixture_api_key(),
            project: fixture_project(),
            account: fixture_account(),
        })
    }

    #[derive(Debug)]
    struct NotFoundOpaRepo;

    #[async_trait]
    impl OpaRepoTrait for NotFoundOpaRepo {
        async fn record_api_key_usage(&self, _key_id: &str, _ip: Option<String>) -> Result<ApiKey> {
            Err(Error::NotFound)
        }

        async fn find_api_key_validation_by_hash(
            &self,
            _key_hash: &str,
        ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>> {
            Ok(None)
        }

        async fn get_project(&self, _subject: &str, _project_id: &str) -> Result<Option<Project>> {
            Ok(None)
        }

        async fn get_account(&self, _subject: &str, _account_id: &str) -> Result<Option<Account>> {
            Ok(None)
        }

        async fn resolve_context(
            &self,
            _subject: &str,
            _project_id: &str,
        ) -> Result<lightbridge_authz_core::ResolvedContext> {
            Err(Error::NotFound)
        }

        async fn get_project_by_id(&self, _project_id: &str) -> Result<Option<Project>> {
            Ok(None)
        }

        async fn get_account_by_id(&self, _account_id: &str) -> Result<Option<Account>> {
            Ok(None)
        }

        async fn project_member_quota_tier(
            &self,
            _project_id: &str,
            _subject: &str,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        async fn project_member_role(
            &self,
            _project_id: &str,
            _subject: &str,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        async fn list_verification_jwks(&self) -> Result<Vec<serde_json::Value>> {
            Ok(Vec::new())
        }

        async fn find_session_status(
            &self,
            _session_id: &str,
        ) -> Result<Option<lightbridge_authz_rest::SessionStatusRow>> {
            Ok(None)
        }
    }

    struct MockBearer {
        token_info: TokenInfo,
    }

    #[async_trait]
    impl BearerTokenServiceTrait for MockBearer {
        async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
            Ok(self.token_info.clone())
        }
    }

    fn token_info_with_permissions(
        permissions: lightbridge_authz_core::authz::PermissionSet,
    ) -> TokenInfo {
        TokenInfo {
            active: true,
            sub: "mcp-tester".to_string(),
            iss: "https://keycloak.example.test/realms/dev".to_string(),
            exp: 0,
            aud: vec![],
            roles: vec![],
            permissions,
            caller_kind: None,
            access_token: "test-access-token".to_string(),
        }
    }

    fn full_access_token_info() -> TokenInfo {
        token_info_with_permissions(Permission::ALL.into_iter().collect())
    }

    /// Issue #383 follow-up regression: MCP's `cratestack_context_from_token_info` must build the
    /// context by delegating to the SAME `lightbridge_authz_rest::auth_provider::build_context`
    /// the RPC surface uses (`RpcScope::Crud` — MCP only ever exposes the CRUD tool set, see that
    /// function's own doc comment for what was confirmed and where). This is the test that fails
    /// immediately if a future edit reintroduces a hand-rolled, independently-drifting copy here
    /// instead of updating (or continuing to call) the shared helper — exactly the failure mode
    /// that shipped once already: MCP's pre-fix copy set only `auth().id`, satisfied the schema's
    /// OLD `@allow(auth() != null)` clauses, and silently failed every #383-added
    /// `auth().rpcScope`/`auth().perm<Permission>` clause with no local test catching it (found by
    /// CI's `integration-test` failing the first live MCP tool call instead).
    ///
    /// Covers both a full-access and a zero-permission token so the comparison can't pass merely
    /// because both sides happen to agree on an all-`true` or all-`false` context.
    #[tokio::test]
    async fn cratestack_context_from_token_info_matches_the_shared_helper() {
        for info in [
            full_access_token_info(),
            token_info_with_permissions(lightbridge_authz_core::authz::PermissionSet::new()),
        ] {
            let mcp_ctx = cratestack_context_from_token_info(&info, test_resolver().as_ref())
                .await
                .expect("the trust-everything test resolver never refuses");
            let shared_ctx = lightbridge_authz_rest::auth_provider::build_context(
                &info,
                RpcScope::Crud,
                test_resolver().as_ref(),
            )
            .await
            .expect("the trust-everything test resolver never refuses");
            assert_eq!(
                mcp_ctx, shared_ctx,
                "MCP's context-builder has drifted from the shared helper for subject {:?} — it \
                 must delegate to lightbridge_authz_rest::auth_provider::build_context, not \
                 maintain its own copy of the permission-field population logic",
                info.sub,
            );
        }
    }

    /// Companion to the delegation test above: independently pins down the actual field SHAPE a
    /// real `authz.cstack` `@allow`/`@@allow` clause reads — `auth().rpcScope == "crud"` and
    /// `auth().perm<Permission>` reflecting the caller's real, computed grant — so a change that
    /// broke both `build_context` AND this MCP delegation identically (which the equality test
    /// above alone would not catch) still fails here.
    #[tokio::test]
    async fn cratestack_context_from_token_info_carries_the_real_permission_set_and_crud_scope() {
        let viewer_perms: lightbridge_authz_core::authz::PermissionSet =
            [lightbridge_authz_core::authz::Permission::AccountRead]
                .into_iter()
                .collect();
        let ctx = cratestack_context_from_token_info(
            &token_info_with_permissions(viewer_perms),
            test_resolver().as_ref(),
        )
        .await
        .expect("the trust-everything test resolver never refuses");

        assert_eq!(
            ctx.auth_field("rpcScope"),
            Some(&cratestack::Value::String("crud".to_owned())),
            "MCP must scope its context to RpcScope::Crud (it never dispatches budget:* op-ids)"
        );
        assert_eq!(
            ctx.auth_field("permAccountRead"),
            Some(&cratestack::Value::Bool(true)),
            "a permission the caller actually holds must read back true"
        );
        assert_eq!(
            ctx.auth_field("permAccountCreate"),
            Some(&cratestack::Value::Bool(false)),
            "a permission the caller does NOT hold must read back false, never absent (absent \
             would make the schema's auth().permAccountCreate == true comparison fail closed for \
             the wrong reason — this pins it explicitly false instead)"
        );
    }

    /// A trust-everything [`lightbridge_authz_rest::auth_provider::SubjectResolver`] test double:
    /// resolves any `(iss, sub)` to `AccountId::assert_already_resolved(sub)` unconditionally, never
    /// touching a database. Correct for every test in this module that is not itself about
    /// resolver behavior -- those get their own dedicated fixtures instead.
    struct TrustEverythingResolver;

    #[lightbridge_authz_core::async_trait]
    impl lightbridge_authz_rest::auth_provider::SubjectResolver for TrustEverythingResolver {
        async fn resolve(
            &self,
            _iss: &str,
            sub: &str,
        ) -> lightbridge_authz_core::error::Result<lightbridge_authz_core::identity::AccountId>
        {
            Ok(lightbridge_authz_core::identity::AccountId::assert_already_resolved(sub))
        }
    }

    fn test_resolver() -> Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver> {
        Arc::new(TrustEverythingResolver)
    }

    /// A resolver double that ALWAYS refuses (`Error::Forbidden`) -- used to prove Finding 1's fix
    /// (lightbridge-authz#PR review, ADR-0025 Stage 2): `create-api-key`/`rotate-api-key` must route
    /// the acting subject through `subject_from_request_context` (and therefore through this
    /// resolver) exactly like their 17 siblings, rather than reading `TokenInfo::sub` directly and
    /// only failing later at the database. With the resolver wired in, a refusal here must surface
    /// as `subject_from_request_context`'s own "unable to resolve caller identity" error -- if a
    /// tool body instead uses `TokenInfo::sub` raw, this resolver is never called at all, and the
    /// call proceeds straight to `AuthzStoreImpl` over the tests' deliberately-unreachable lazy
    /// pool, producing a different (database) error instead.
    struct RefusingResolver;

    #[lightbridge_authz_core::async_trait]
    impl lightbridge_authz_rest::auth_provider::SubjectResolver for RefusingResolver {
        async fn resolve(
            &self,
            _iss: &str,
            _sub: &str,
        ) -> lightbridge_authz_core::error::Result<lightbridge_authz_core::identity::AccountId>
        {
            Err(lightbridge_authz_core::error::Error::Forbidden(
                "test: refusing resolution".to_string(),
            ))
        }
    }

    fn lazy_pool() -> Arc<dyn DbPoolTrait> {
        let pool = PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        Arc::new(lightbridge_authz_core::db::DbPool::from_pool(pool))
    }

    /// Claim store for handler-shape tests. The pool is lazy, so nothing dials a database unless a
    /// test actually issues a claim.
    fn test_claim_store() -> Option<Arc<SecretClaimStore>> {
        Some(Arc::new(SecretClaimStore::new(
            Arc::new(lightbridge_authz_api_key::repo::StoreRepo::new(lazy_pool())),
            [7u8; 32],
            300,
        )))
    }

    fn test_redeem_base_url() -> Option<Arc<String>> {
        Some(Arc::new("https://auth.example.test".to_string()))
    }

    /// The generated cratestack CRUD client over a lazily-connected pool pointed at an unreachable
    /// address. Constructing it never connects; the first actual query a CRUD tool issues fails
    /// fast with a connection error. That is exactly what these tests want: the generated client is
    /// a concrete type over a real sqlx pool (there is no trait seam to mock, unlike the deleted
    /// `AuthzStore`), so instead of a fixture double we assert each CRUD tool is wired to the client
    /// and maps the resulting error to a JSON-RPC error rather than panicking. DB-backed happy-path
    /// coverage for the CRUD surface lives in the RPC integration tests, not here.
    fn lazy_cratestack_db() -> schema::Cratestack {
        let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy cratestack pool should be constructible");
        schema::Cratestack::builder(pool).build()
    }

    /// The reused issuer (procedure-backed tools) over the same unreachable lazy core pool, with the
    /// sample billing catalogue so `create-api-key`'s pre-DB billing-plan check passes and the call
    /// then reaches (and fails at) the dead pool.
    fn lazy_issuer() -> Arc<AuthzStoreImpl> {
        Arc::new(AuthzStoreImpl::with_pool(lazy_pool()).with_billing(sample_billing()))
    }

    /// Build a handler over the lazy (unreachable) cratestack client + issuer. Sufficient for the
    /// non-DB tests (tool listing, schema shape, billing advertisement, permission mapping) and for
    /// the dead-pool dispatch/error-mapping test; DB-touching tool bodies error at first query.
    fn lazy_handler() -> LightbridgeMcpHandler {
        LightbridgeMcpHandler::new(
            lazy_cratestack_db(),
            lazy_issuer(),
            sample_repo(),
            basic_auth(),
            &sample_billing(),
            None,
            test_resolver(),
            "https://keycloak.example.test/realms/dev".to_string(),
            test_claim_store(),
            test_redeem_base_url(),
        )
    }

    fn test_api_server() -> ApiServer {
        ApiServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: lightbridge_authz_core::config::Tls {
                cert_path: "unused".to_string(),
                key_path: "unused".to_string(),
                client_ca_bundle_path: None,
            },
            allowed_hosts: None,
            rpc_base_path: None,
        }
    }

    fn test_router(opa_repo: Arc<dyn OpaRepoTrait>, token_info: TokenInfo) -> Router {
        test_router_with_resolver(opa_repo, token_info, test_resolver())
    }

    fn test_router_with_resolver(
        opa_repo: Arc<dyn OpaRepoTrait>,
        token_info: TokenInfo,
        resolver: Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver>,
    ) -> Router {
        build_mcp_router(
            &test_api_server(),
            &sample_oauth2(),
            basic_auth(),
            &sample_billing(),
            lazy_cratestack_db(),
            lazy_issuer(),
            opa_repo,
            Arc::new(MockBearer { token_info }),
            resolver,
            "https://keycloak.example.test/realms/dev".to_string(),
            lazy_pool(),
            test_claim_store(),
            test_redeem_base_url(),
        )
    }

    fn tool_call_request(
        tool: &str,
        arguments: Value,
        token: Option<&str>,
    ) -> axum::http::Request<Body> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments
            }
        });
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn call_tool(
        router: Router,
        tool: &str,
        arguments: Value,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        use tower::ServiceExt;

        let response = router
            .oneshot(tool_call_request(tool, arguments, token))
            .await
            .expect("router should respond");
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body readable");
        let payload = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, payload)
    }

    /// One representative `arguments` payload per registered tool, driven through the real MCP
    /// router by `every_tool_dispatches_and_maps_backend_errors_through_the_real_mcp_router`.
    fn crud_and_validation_tool_cases() -> Vec<(&'static str, Value)> {
        vec![
            ("create-account", json!({ "default_quota": "small" })),
            ("list-accounts", json!({})),
            ("get-account", json!({ "account_id": "acct_1" })),
            (
                "update-account",
                json!({ "account_id": "acct_1", "default_quota": "medium" }),
            ),
            ("disable-account", json!({ "account_id": "acct_1" })),
            ("enable-account", json!({ "account_id": "acct_1" })),
            ("list-project-roster", json!({ "project_id": "proj_1" })),
            (
                "add-project-member",
                json!({ "project_id": "proj_1", "account_id": "new-member" }),
            ),
            (
                "remove-project-member",
                json!({ "project_id": "proj_1", "account_id": "old-member" }),
            ),
            (
                "set-project-member-role",
                json!({ "project_id": "proj_1", "account_id": "acct_2", "role": "lead" }),
            ),
            (
                "set-project-member-quota-tier",
                json!({ "project_id": "proj_1", "account_id": "acct_2", "quota_tier": "small" }),
            ),
            (
                "create-project",
                json!({ "account_id": "acct_1", "name": "proj", "billing_plan": "free", "billing_identity": "acme" }),
            ),
            (
                "set-project-quota",
                json!({ "project_id": "proj_1", "project_quota": "small" }),
            ),
            (
                "set-project-allowed-models",
                json!({ "project_id": "proj_1", "allowed_models": ["gpt-4.1-mini"] }),
            ),
            (
                "set-project-model-policy",
                json!({ "project_id": "proj_1", "model_policy": "deny_all" }),
            ),
            ("list-projects", json!({ "account_id": "acct_1" })),
            ("get-project", json!({ "project_id": "proj_1" })),
            (
                "update-project",
                json!({ "project_id": "proj_1", "name": "proj2" }),
            ),
            ("disable-project", json!({ "project_id": "proj_1" })),
            ("enable-project", json!({ "project_id": "proj_1" })),
            ("set-default-project", json!({ "project_id": "proj_1" })),
            (
                "create-api-key",
                json!({ "project_id": "proj_1", "name": "key", "expires_at": near_future_expiry(), "billing_plan": "free" }),
            ),
            ("list-api-keys", json!({ "project_id": "proj_1" })),
            ("get-api-key", json!({ "key_id": "key_1" })),
            // No `expires_at` here (lightbridge-authz#395): `UpdateApiKeyParams` no longer
            // carries the field at all, so this exercises the tool's real, current shape.
            (
                "update-api-key",
                json!({ "key_id": "key_1", "name": "key2" }),
            ),
            ("revoke-api-key", json!({ "key_id": "key_1" })),
            (
                "rotate-api-key",
                json!({ "key_id": "key_1", "grace_period_seconds": 60 }),
            ),
            ("delete-api-key", json!({ "key_id": "key_1" })),
            ("delete-project", json!({ "project_id": "proj_1" })),
            ("delete-account", json!({ "account_id": "acct_1" })),
            (
                "validate-api-key",
                json!({ "api_key": "lbk_secret_sample" }),
            ),
            (
                "validate-authorino-api-key",
                json!({ "api_key": "lbk_secret_sample", "metadata": { "env": "test" } }),
            ),
        ]
    }

    fn basic_auth() -> BasicAuth {
        BasicAuth {
            username: "u".to_string(),
            password: "p".to_string(),
        }
    }

    /// A `create-api-key`/`rotate-api-key` test payload's `expires_at`: comfortably inside the
    /// default 90-day `ApiKeyExpiry` ceiling (lightbridge-authz#395) and always in the future,
    /// unlike a hardcoded calendar date which would eventually violate one rule or the other as
    /// time passes.
    fn near_future_expiry() -> String {
        (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339()
    }

    fn sample_billing() -> Billing {
        use lightbridge_authz_core::config::BillingPlan;
        Billing {
            plans: vec![
                BillingPlan {
                    id: "free".to_string(),
                    name: "Free".to_string(),
                    limits: None,
                },
                BillingPlan {
                    id: "pro".to_string(),
                    name: "Pro".to_string(),
                    limits: None,
                },
            ],
        }
    }

    fn sample_oauth2() -> Oauth2 {
        Oauth2 {
            oauth2_type: lightbridge_authz_core::config::Oauth2Type::External,
            jwks_url: "http://keycloak:9100/realms/dev/protocol/openid-connect/certs".to_string(),
            oauth2_url: None,
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            issuance: None,
            audience: None,
            signing: None,
            token_exchange: None,
            relying_party: None,
            rbac: Default::default(),
            clients: Vec::new(),
            federation: Some(lightbridge_authz_core::config::Federation {
                issuer: "https://keycloak.example.test/realms/dev".to_string(),
                discovery_url: None,
            }),
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

    // `#[tokio::test]` (not `#[test]`): `lazy_handler()` builds the cratestack CRUD client over a
    // `connect_lazy` sqlx pool, whose background pool-maintenance task needs a Tokio runtime to
    // spawn onto. A plain sync `#[test]` has none and panics ("this functionality requires a Tokio
    // context") the moment the pool is constructed, even though the assertions below never touch the
    // DB. Running on a Tokio worker gives the pool its runtime; the test body stays synchronous.
    #[tokio::test]
    async fn router_lists_all_lightbridge_endpoint_tools() {
        let handler = lazy_handler();

        let mut tool_names = handler
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        tool_names.sort();

        let mut expected = vec![
            "add-project-member",
            "create-account",
            "create-api-key",
            "create-project",
            "delete-account",
            "delete-api-key",
            "delete-project",
            "disable-account",
            "disable-project",
            "enable-account",
            "enable-project",
            "get-account",
            "get-api-key",
            "get-project",
            "list-accounts",
            "list-api-keys",
            "list-project-roster",
            "list-projects",
            "remove-project-member",
            "revoke-api-key",
            "rotate-api-key",
            "set-default-project",
            "set-project-allowed-models",
            "set-project-member-quota-tier",
            "set-project-member-role",
            "set-project-model-policy",
            "set-project-quota",
            "update-account",
            "update-api-key",
            "update-project",
            "validate-authorino-api-key",
            "validate-api-key",
        ];
        expected.sort();

        assert_eq!(tool_names, expected);
    }

    #[tokio::test]
    async fn create_api_key_tool_advertises_configured_billing_plans() {
        let handler = lazy_handler();

        let tools = handler.advertised_tools();
        let create = tools
            .iter()
            .find(|tool| tool.name == "create-api-key")
            .expect("create-api-key tool should be advertised");
        let description = create.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("Valid `billing_plan` ids: free, pro."),
            "create-api-key description should list the configured plan ids, got: {description}"
        );

        let other = tools
            .iter()
            .find(|tool| tool.name == "get-api-key")
            .expect("get-api-key tool should be advertised");
        assert!(
            !other
                .description
                .as_deref()
                .unwrap_or_default()
                .contains("billing_plan"),
            "only create-api-key should carry the billing-plan annotation"
        );
    }

    #[tokio::test]
    async fn advertised_tools_unchanged_when_no_billing_plans_configured() {
        let handler = LightbridgeMcpHandler::new(
            lazy_cratestack_db(),
            lazy_issuer(),
            sample_repo(),
            basic_auth(),
            &Billing::default(),
            None,
            test_resolver(),
            "https://keycloak.example.test/realms/dev".to_string(),
            test_claim_store(),
            test_redeem_base_url(),
        );
        let tools = handler.advertised_tools();
        let create = tools
            .iter()
            .find(|tool| tool.name == "create-api-key")
            .expect("create-api-key tool should be advertised");
        assert!(
            !create
                .description
                .as_deref()
                .unwrap_or_default()
                .contains("Valid `billing_plan` ids"),
            "no annotation should be added when the catalogue is empty"
        );
    }

    #[test]
    fn roster_tools_are_gated_by_project_member_permission() {
        for tool in [
            "list-project-roster",
            "add-project-member",
            "remove-project-member",
            "set-project-member-role",
            "set-project-member-quota-tier",
        ] {
            assert_eq!(
                required_tool_permission(tool),
                Some(Permission::ProjectMember),
                "tool `{tool}` should require project:member"
            );
        }
    }

    /// ADR-0006 removed account-level membership and the default-*account* feature. Their tool
    /// names must not linger as mapped permissions, or a stale client would fail open into
    /// `call_tool` rather than being rejected by the fail-closed default.
    #[test]
    fn removed_account_member_tools_are_unmapped() {
        for tool in [
            "add-account-member",
            "remove-account-member",
            "set-account-member-role",
            "set-default-account",
        ] {
            assert_eq!(
                required_tool_permission(tool),
                None,
                "removed tool `{tool}` must be unmapped (fail closed)"
            );
        }
    }

    #[tokio::test]
    async fn every_registered_tool_has_a_permission_mapping() {
        let handler = lazy_handler();
        for tool in handler.tool_router.list_all() {
            assert!(
                required_tool_permission(&tool.name).is_some(),
                "tool `{}` is registered but has no permission mapping (would fail closed in call_tool)",
                tool.name
            );
        }
    }

    #[tokio::test]
    async fn create_account_tool_schema_uses_jwt_subject_not_input_subject() {
        let handler = lazy_handler();
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
        assert!(
            !properties.contains_key("id"),
            "the account id is the caller's JWT subject (ADR-0006); accepting it as input would be \
             an impersonation primitive"
        );
        assert!(
            !properties.contains_key("billing_identity"),
            "billing_identity moved to Project (ADR-0006) and must not linger on account creation"
        );
    }

    #[tokio::test]
    async fn list_tools_schema_include_pagination_fields() {
        let handler = lazy_handler();
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
    async fn tool_output_schema_avoids_boolean_schema_for_result_property() {
        let handler = lazy_handler();
        let create_account = handler
            .tool_router
            .list_all()
            .into_iter()
            .find(|tool| tool.name == "create-account")
            .expect("create-account tool should exist");

        let output_schema = create_account
            .output_schema
            .as_ref()
            .expect("output schema should be present");
        let result_schema = output_schema
            .get("properties")
            .and_then(|value| value.as_object())
            .and_then(|properties| properties.get("result"))
            .expect("output schema should contain a result property");

        assert!(
            result_schema.is_object(),
            "result schema should be a JSON object, not a boolean schema"
        );
        assert_eq!(
            result_schema,
            &json!({
                "type": ["object", "array", "string", "number", "boolean", "null"]
            })
        );
    }

    #[tokio::test]
    async fn authorino_validation_tool_enriches_dynamic_metadata() {
        let handler = lazy_handler();
        let mut metadata = HashMap::new();
        metadata.insert("env".to_string(), json!("dev"));

        let result = run_validate_authorino(
            &handler.opa_state,
            ValidateAuthorinoApiKeyParams {
                api_key: "lbk_secret_sample".to_string(),
                ip: Some("127.0.0.1".to_string()),
                metadata,
            },
        )
        .await
        .expect("validation should succeed");

        let output = result.0.result;

        // `account_id`, not a nested `account` object: Phase E (ADR-0006) dropped the redundant
        // account fetch from introspection, so `ValidatedApiKeyContext` carries only the id.
        assert_eq!(output["account_id"], "acct_1");
        assert_eq!(output["project"]["id"], "proj_1");
        assert_eq!(output["api_key"]["id"], "key_1");
        assert_eq!(output["dynamic_metadata"]["account_id"], "acct_1");
        assert_eq!(output["dynamic_metadata"]["project_id"], "proj_1");
        assert_eq!(output["dynamic_metadata"]["api_key_id"], "key_1");
        assert_eq!(output["dynamic_metadata"]["api_key_status"], "active");
        assert_eq!(output["dynamic_metadata"]["env"], "dev");
    }

    #[tokio::test]
    async fn run_validate_api_key_returns_unauthorized_when_key_not_found() {
        let opa_state = Arc::new(OpaState {
            repo: Arc::new(NotFoundOpaRepo),
            basic_auth: basic_auth(),
            billing: Arc::new(sample_billing()),
            api_key_audience: None,
            resolver: test_resolver(),
            federation_issuer: "https://keycloak.example.test/realms/dev".to_string(),
        });

        let result = run_validate_api_key(
            &opa_state,
            ValidateApiKeyParams {
                api_key: "lbk_unknown".to_string(),
                ip: None,
            },
        )
        .await;

        match result {
            Err(error) => assert_eq!(error.message, "unauthorized"),
            Ok(_) => panic!("validation should fail when the key hash is not found"),
        }
    }

    #[tokio::test]
    async fn run_validate_authorino_returns_unauthorized_when_key_not_found() {
        let opa_state = Arc::new(OpaState {
            repo: Arc::new(NotFoundOpaRepo),
            basic_auth: basic_auth(),
            billing: Arc::new(sample_billing()),
            api_key_audience: None,
            resolver: test_resolver(),
            federation_issuer: "https://keycloak.example.test/realms/dev".to_string(),
        });

        let result = run_validate_authorino(
            &opa_state,
            ValidateAuthorinoApiKeyParams {
                api_key: "lbk_unknown".to_string(),
                ip: None,
                metadata: HashMap::new(),
            },
        )
        .await;

        match result {
            Err(error) => assert_eq!(error.message, "unauthorized"),
            Ok(_) => panic!("validation should fail when the key hash is not found"),
        }
    }

    #[tokio::test]
    async fn health_and_startup_endpoints_report_ok() {
        assert_eq!(health_handler().await, StatusCode::OK);
        assert_eq!(startup_handler().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_unavailable_when_database_is_down() {
        assert_eq!(
            readiness_handler(lazy_pool()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Drive every tool through the real MCP router (JSON-RPC over `/mcp`) with a permission-holding
    /// caller. The CRUD tools run against the generated cratestack client and the procedure-backed
    /// tools against the issuer, both over an unreachable lazy pool — so each must dispatch,
    /// serialize its input, reach the DB, and map the resulting connection error onto a JSON-RPC
    /// error rather than panicking (there is no trait seam to substitute a fixture store for; see
    /// `lazy_cratestack_db`). The validate-* tools instead consult `opa_state` (a real mock repo)
    /// and therefore succeed, proving the validation path is unaffected by the CRUD migration.
    #[tokio::test]
    async fn every_tool_dispatches_and_maps_backend_errors_through_the_real_mcp_router() {
        for (tool, arguments) in crud_and_validation_tool_cases() {
            let router = test_router(sample_repo(), full_access_token_info());
            let (status, payload) = call_tool(router, tool, arguments, Some("good")).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "tool `{tool}` should return HTTP 200: {payload}"
            );
            if tool.starts_with("validate-") {
                assert!(
                    payload.get("error").is_none(),
                    "validation tool `{tool}` (mock OPA repo) should succeed: {payload}"
                );
            } else {
                assert!(
                    payload.get("error").is_some(),
                    "tool `{tool}` should map the unreachable-DB error to a JSON-RPC error: {payload}"
                );
            }
        }
    }

    #[tokio::test]
    async fn create_api_key_tool_rejects_an_invalid_expires_at() {
        let router = test_router(sample_repo(), full_access_token_info());
        let (status, payload) = call_tool(
            router,
            "create-api-key",
            json!({ "project_id": "proj_1", "name": "key", "expires_at": "not-a-date", "billing_plan": "free" }),
            Some("good"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            payload.get("error").is_some(),
            "an invalid RFC3339 expires_at should be rejected: {payload}"
        );
    }

    /// Finding 1 (ADR-0025 Stage 2 gap): `create-api-key` must resolve the acting subject via
    /// `subject_from_request_context` (the same seam its 17 siblings use), not
    /// `TokenInfo::sub` directly -- otherwise a federated identity whose `account_id != sub` would
    /// mint a key owned by the wrong account. Proven here by wiring a resolver that always refuses:
    /// the fixed tool body must fail with `subject_from_request_context`'s own error BEFORE ever
    /// reaching `AuthzStoreImpl` (over this test's deliberately-unreachable lazy pool). Prove-fail:
    /// reverting `create_api_key_tool` to read `&token_info.sub` directly makes this resolver
    /// unreachable, so the call instead fails later with a database error and this assertion reds.
    #[tokio::test]
    async fn create_api_key_tool_routes_the_acting_subject_through_the_resolver_seam() {
        let router = test_router_with_resolver(
            sample_repo(),
            full_access_token_info(),
            Arc::new(RefusingResolver),
        );
        let (status, payload) = call_tool(
            router,
            "create-api-key",
            json!({ "project_id": "proj_1", "name": "key", "expires_at": near_future_expiry(), "billing_plan": "free" }),
            Some("good"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let message = payload["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("unable to resolve caller identity"),
            "create-api-key must route the acting subject through subject_from_request_context \
             (ADR-0025 Stage 2), not TokenInfo::sub directly -- a resolver refusal must surface as \
             this specific error, not a dead-pool database error from AuthzStoreImpl: {payload}"
        );
    }

    /// Same proof as `create_api_key_tool_routes_the_acting_subject_through_the_resolver_seam`,
    /// for `rotate-api-key` (Finding 1's other affected tool).
    #[tokio::test]
    async fn rotate_api_key_tool_routes_the_acting_subject_through_the_resolver_seam() {
        let router = test_router_with_resolver(
            sample_repo(),
            full_access_token_info(),
            Arc::new(RefusingResolver),
        );
        let (status, payload) = call_tool(
            router,
            "rotate-api-key",
            json!({ "key_id": "key_1", "grace_period_seconds": 60 }),
            Some("good"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let message = payload["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("unable to resolve caller identity"),
            "rotate-api-key must route the acting subject through subject_from_request_context \
             (ADR-0025 Stage 2), not TokenInfo::sub directly -- a resolver refusal must surface as \
             this specific error, not a dead-pool database error from AuthzStoreImpl: {payload}"
        );
    }

    #[tokio::test]
    async fn call_tool_rejects_a_caller_missing_the_required_permission() {
        let router = test_router(
            sample_repo(),
            token_info_with_permissions(lightbridge_authz_core::authz::PermissionSet::new()),
        );
        let (status, payload) = call_tool(
            router,
            "create-account",
            json!({ "billing_identity": "acme" }),
            Some("good"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            payload.get("error").is_some(),
            "missing permission should produce a JSON-RPC error: {payload}"
        );
    }

    #[tokio::test]
    async fn call_tool_rejects_an_unknown_tool_name() {
        let router = test_router(sample_repo(), full_access_token_info());
        let (status, payload) = call_tool(router, "not-a-real-tool", json!({}), Some("good")).await;

        assert_eq!(status, StatusCode::OK);
        let error = payload
            .get("error")
            .expect("an unknown tool name should produce a JSON-RPC error");
        assert!(
            error["message"]
                .as_str()
                .unwrap_or_default()
                .contains("unknown tool"),
            "unexpected error message: {error}"
        );
    }

    #[tokio::test]
    async fn call_tool_reports_missing_bearer_token_context_when_bearer_auth_is_bypassed() {
        let handler = lazy_handler();
        let http_config = build_streamable_http_config(&None);
        let mcp_service: StreamableHttpService<LightbridgeMcpHandler, LocalSessionManager> =
            StreamableHttpService::new(
                {
                    let handler = handler.clone();
                    move || Ok(handler.clone())
                },
                Default::default(),
                http_config,
            );
        let router = Router::new().nest_service("/mcp", mcp_service);

        let (status, payload) = call_tool(router, "list-accounts", json!({}), None).await;

        assert_eq!(status, StatusCode::OK);
        let error = payload
            .get("error")
            .expect("a request without bearer_auth-injected TokenInfo should error");
        assert!(
            error["message"]
                .as_str()
                .unwrap_or_default()
                .contains("missing bearer token context"),
            "unexpected error message: {error}"
        );
    }
}
