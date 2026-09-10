// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests` (clippy.toml) does
// not reach their free helper functions. Unwrapping in a test is a deliberate assertion that the
// setup held; the workspace gate stays `deny` for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database end-to-end coverage for the procedure-backed MCP tools (lightbridge-authz#645),
//! gated behind `it-tests` and run against real Postgres (`just it-tests` brings it up).
//!
//! `mcp_parity_tests.rs` proves the *tables* agree. This file proves the *pipe* works, over the
//! real `/mcp` JSON-RPC transport: bearer middleware -> `call_tool`'s permission gate ->
//! `procedure_context` (which picks the op-id's own `RpcScope`) -> the generated
//! `invoke_with_db`'s `@allow` evaluation -> the `ProcedureRegistry` method's own SQL -> the
//! `{"result": ...}` structured envelope.
//!
//! Two of the three cases are budget-scoped on purpose. The per-tool `RpcScope` switch is the
//! genuinely new mechanism here: every budget procedure's `@allow` clause demands
//! `auth().rpcScope == "budget"`, which no MCP context ever carried before this change, so a tool
//! that got `Crud` would fail policy at dispatch with a `Forbidden` that no unit test could see.
#![cfg(feature = "it-tests")]

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::authz::{Permission, PermissionSet};
use lightbridge_authz_core::config::{
    ApiServer, BasicAuth, Billing, Oauth2, Oauth2Type, Tls, UsageServiceClient,
};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_rest::auth_provider::SubjectResolver;
use lightbridge_authz_rest::budget_services::build_budget_services;
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::{OpaRepoTrait, Procedures};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use lightbridge_authz::mcp::{SERVICE_MCP, build_mcp_router};

const TEST_POOL_MAX_CONNECTIONS: u32 = 2;
const TEST_ISSUER: &str = "https://keycloak.example.test/realms/dev";

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for it-tests (just it-tests)")
}

/// Bearer double: every token validates to the same `TokenInfo`, so a test picks the caller's
/// permission set by construction rather than by minting a real JWT.
struct MapBearer(TokenInfo);

#[lightbridge_authz_core::async_trait]
impl BearerTokenServiceTrait for MapBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        Ok(self.0.clone())
    }
}

/// Resolver double: the `sub` IS the acting account id, which is what
/// `FederatedSubjectResolver`'s self-signed-issuer branch concludes for every token this
/// deployment mints itself. Avoids seeding a `federated_identities` row purely to exercise a
/// translation this file is not testing.
struct SubjectIsAccount;

#[lightbridge_authz_core::async_trait]
impl SubjectResolver for SubjectIsAccount {
    async fn resolve(
        &self,
        _iss: &str,
        sub: &str,
    ) -> Result<AccountId, lightbridge_authz_core::Error> {
        // `assert_already_resolved` is exactly the promise this double makes: under
        // `oauth2.type: self` (this deployment's own tokens) `sub` IS the resolved account id, and
        // `FederatedSubjectResolver` returns it with no database call for that case.
        Ok(AccountId::assert_already_resolved(sub.to_owned()))
    }
}

fn token_info(subject: &str, permissions: PermissionSet) -> TokenInfo {
    TokenInfo {
        active: true,
        sub: subject.to_string(),
        iss: TEST_ISSUER.to_string(),
        exp: 0,
        aud: vec![],
        roles: vec![],
        permissions,
        caller_kind: None,
        access_token: "it-access-token".to_string(),
    }
}

fn oauth2() -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
        jwks_url: "https://keycloak.example.test/realms/dev/protocol/openid-connect/certs"
            .to_string(),
        jwks_ca_bundle_path: None,
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
            issuer: TEST_ISSUER.to_string(),
            discovery_url: None,
        }),
    }
}

fn api_server() -> ApiServer {
    ApiServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: Tls {
            cert_path: "unused".to_string(),
            key_path: "unused".to_string(),
            client_ca_bundle_path: None,
        },
        allowed_hosts: None,
        rpc_base_path: None,
    }
}

/// The real MCP router, wired to the live database exactly as `start_mcp_server` wires it --
/// including the SAME `build_budget_services` graph, so a budget tool reaches the same
/// `BudgetRepo` the `authz-budget` listener would.
async fn setup(info: TokenInfo) -> Router {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(
        PgPoolOptions::new()
            .max_connections(TEST_POOL_MAX_CONNECTIONS)
            .connect(&database_url())
            .await
            .expect("connect core pool"),
    ));
    let cratestack_pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .max_connections(TEST_POOL_MAX_CONNECTIONS)
        .connect(&database_url())
        .await
        .expect("connect cratestack pool");
    let cratestack_db = lightbridge_authz_api::schema::Cratestack::builder(cratestack_pool).build();

    let billing = Billing { plans: vec![] };
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()).with_billing(billing.clone()));
    let no_usage_service: Option<UsageServiceClient> = None;
    let budget = build_budget_services(core.clone(), &no_usage_service)
        .await
        .expect("budget services should load the seeded active policy revision");
    let procedures = Arc::new(Procedures::new(
        SERVICE_MCP,
        issuer.clone(),
        budget.policy_store,
        budget.refill_service,
        budget.review_service,
        budget.budget_repo,
        budget.reset_scheduler,
        Arc::new(lightbridge_authz_core::platform_role::known_platform_roles(
            &Default::default(),
        )),
    ));
    let opa_repo: Arc<dyn OpaRepoTrait> =
        Arc::new(lightbridge_authz_api_key::repo::StoreRepo::new(core));

    build_mcp_router(
        &api_server(),
        &oauth2(),
        BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
        &billing,
        cratestack_db,
        issuer,
        opa_repo,
        Arc::new(MapBearer(info)),
        Arc::new(SubjectIsAccount),
        TEST_ISSUER.to_string(),
        Arc::new(DbPool::from_pool(
            PgPoolOptions::new()
                .max_connections(1)
                .connect(&database_url())
                .await
                .expect("connect readiness pool"),
        )),
        None,
        None,
        procedures,
    )
}

/// Drive one tool call through the real `/mcp` JSON-RPC transport and return the parsed envelope.
async fn call_tool(router: Router, tool: &str, arguments: Value) -> (StatusCode, Value) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": tool, "arguments": arguments }
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, "Bearer it-token")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body readable");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn perms(permissions: &[Permission]) -> PermissionSet {
    permissions.iter().copied().collect()
}

/// A budget-scoped tool, end to end: the gate admits `budget:read-own`, `procedure_context` builds
/// a `rpcScope == "budget"` context, the schema's `@allow` clause passes, and `BudgetRepo`'s real
/// SQL answers. A balance the caller has never been granted is legitimately absent — NULL means
/// unknown, never 0 — so the assertion is on a successful, well-shaped envelope, not on a number.
#[tokio::test]
async fn get_my_budget_balance_tool_runs_end_to_end_at_budget_scope() {
    let router = setup(token_info(
        &format!("mcp-it-{}", lightbridge_authz_core::cuid::cuid2()),
        perms(&[Permission::BudgetReadOwn]),
    ))
    .await;
    let (status, payload) = call_tool(
        router,
        "get-my-budget-balance",
        json!({ "args": { "period": "2026-09" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "payload: {payload}");
    assert!(
        payload.get("error").is_none(),
        "a permitted budget-scoped tool call must not error: {payload}"
    );
    let result = &payload["result"];
    assert!(
        !result["isError"].as_bool().unwrap_or(false),
        "tool reported an error result: {payload}"
    );
    assert!(
        result["structuredContent"]["result"].is_object(),
        "the tool must return the procedure's own Output under `result`: {payload}"
    );
}

/// The same tool, same transport, a caller WITHOUT `budget:read-own`. Proves the shared map is
/// actually enforced on MCP and not merely consulted: this is the assertion that fails if
/// `call_tool`'s gate is ever bypassed for the dynamically registered routes.
#[tokio::test]
async fn get_my_budget_balance_tool_is_refused_without_budget_read_own() {
    let router = setup(token_info(
        "mcp-it-denied",
        perms(&[Permission::AccountRead]),
    ))
    .await;
    let (status, payload) = call_tool(
        router,
        "get-my-budget-balance",
        json!({ "args": { "period": "2026-09" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        payload.get("error").is_some(),
        "a caller lacking budget:read-own must be refused before the tool body runs: {payload}"
    );
}

/// An authenticated-only tool (`AUTHENTICATED_ONLY_OP_IDS`): a caller holding NO permission at all
/// must still reach it, because `getBuildInfo` serves the same values `GET /version` serves
/// unauthenticated. Also pins that the MCP process reports itself as `lightbridge-mcp`, not
/// `authz-api` — `Procedures::new`'s `service` argument is the only thing that can get that right.
#[tokio::test]
async fn get_build_info_tool_is_reachable_with_no_permissions_and_reports_the_mcp_service() {
    let router = setup(token_info("mcp-it-anon", PermissionSet::new())).await;
    let (status, payload) = call_tool(router, "get-build-info", json!({ "args": {} })).await;

    assert_eq!(status, StatusCode::OK, "payload: {payload}");
    assert!(
        payload.get("error").is_none(),
        "an authenticated-only tool must not require a permission: {payload}"
    );
    assert_eq!(
        payload["result"]["structuredContent"]["result"]["service"],
        json!(SERVICE_MCP),
        "getBuildInfo must report the process the caller actually reached: {payload}"
    );
}
