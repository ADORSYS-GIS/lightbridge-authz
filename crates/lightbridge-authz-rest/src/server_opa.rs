use std::sync::Arc;

use axum::Router;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::{
    config::{Billing, Oauth2, OpaServer},
    db::DbPoolTrait,
    error::Result,
    server::serve_tls,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    SERVICE_OPA,
    auth_provider::{FederatedSubjectResolver, SubjectResolver},
    introspect_budget,
    opa_doc::OpaDoc,
    opa_repo::{OpaRepoTrait, OpaState},
    probe_router,
    routers::opa_router,
    server_idp::require_federation,
};

/// Assembles the OPA server router (public probes + Basic-auth introspection/resolve routes).
/// Separated from `start_opa_server` for testability.
pub fn build_opa_router(state: Arc<OpaState>, readiness_pool: Arc<dyn DbPoolTrait>) -> Router {
    let public = probe_router(readiness_pool, SERVICE_OPA)
        .merge(SwaggerUi::new("/v1/opa/docs").url("/v1/opa/openapi.json", OpaDoc::openapi()));

    let protected = opa_router(state.clone()).with_state(state.clone());

    public.merge(protected).with_state(state)
}

pub async fn start_opa_server(
    opa: &OpaServer,
    pool: Arc<dyn DbPoolTrait>,
    billing: &Billing,
    oauth2: &Oauth2,
) -> Result<()> {
    let federation = require_federation(oauth2, "authz-opa")?;
    let readiness_pool = pool.clone();
    // ADR-0025 Stage 2: `federation` above is already `require_federation`'s validated value.
    let resolver: Arc<dyn SubjectResolver> = Arc::new(FederatedSubjectResolver::new(
        Arc::new(StoreRepo::new(pool.clone())),
        oauth2.signing.as_ref().map(|s| s.issuer.clone()),
        federation.issuer.clone(),
    ));
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let api_key_audience = oauth2
        .signing
        .as_ref()
        .and_then(|signing| signing.audience.clone());
    let state = Arc::new(OpaState {
        repo,
        basic_auth: opa.basic_auth.clone(),
        billing: Arc::new(billing.clone()),
        api_key_audience,
        resolver,
        federation_issuer: federation.issuer.clone(),
        budget: introspect_budget::BudgetIntrospection::default(),
    });

    let app = build_opa_router(state, readiness_pool);

    lightbridge_authz_core::log_build_info(SERVICE_OPA);
    tracing::info!(
        server = SERVICE_OPA,
        address = %opa.address,
        port = opa.port,
        "starting opa server"
    );

    serve_tls("OPA", &opa.address, opa.port, &opa.tls, app).await
}
