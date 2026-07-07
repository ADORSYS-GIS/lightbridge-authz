use std::sync::Arc;

use axum::Router;
use axum::routing::post;

use crate::OpaState;
use crate::handlers::authorino::validate_authorino_api_key;
use crate::handlers::idp::resolve_context;
use crate::handlers::opa::validate_api_key;
use crate::middleware::basic_auth;

/// Returns the OPA/Authorino validation router. Every route sits behind Basic auth; the IdP
/// `resolve-context` endpoint lives here because it returns tenant context and must not be publicly
/// reachable.
pub fn opa_router(state: Arc<OpaState>) -> Router<Arc<OpaState>> {
    Router::new()
        .route("/v1/opa/validate", post(validate_api_key))
        .route("/v1/authorino/validate", post(validate_authorino_api_key))
        .route("/idp/v1/resolve-context", post(resolve_context))
        .layer(axum::middleware::from_fn_with_state(state, basic_auth))
}
