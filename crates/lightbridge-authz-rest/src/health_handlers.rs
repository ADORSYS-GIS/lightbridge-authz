//! The probe surface every `start_*_server` in this crate mounts: `/`, `/healthz`, `/startupz`,
//! `/readyz` and `/version`.
//!
//! Split out of `lib.rs` (which sits far over the LoC gate's ceiling and must not grow) — code
//! moved, not rewritten, the same convention `budget_services.rs` already followed out of the same
//! file. Every handler is `pub(crate)` and reached only through the routers in `lib.rs`.

use std::sync::Arc;

use axum::{Json, http::StatusCode};
use lightbridge_authz_core::db::{DbPoolTrait, is_database_ready};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct RootResponse {
    pub(crate) status: String,
    pub(crate) message: String,
}

pub(crate) async fn root_handler() -> (StatusCode, Json<RootResponse>) {
    let response = RootResponse {
        status: "ok".to_string(),
        message: "Welcome to Lightbridge Authz API".to_string(),
    };
    (StatusCode::OK, Json(response))
}

pub(crate) async fn health_handler() -> StatusCode {
    StatusCode::OK
}

pub(crate) async fn startup_handler() -> StatusCode {
    StatusCode::OK
}

/// `GET /version` (#573): the build stamp of the process answering, as JSON.
///
/// Always `200` — there is no failure mode. The stamp is assembled from compile-time constants
/// plus three environment reads; nothing here touches the database, the network, or the caller's
/// identity, which is why it is safe to leave unauthenticated next to `/healthz`.
pub(crate) async fn version_handler(
    service: &'static str,
) -> Json<lightbridge_authz_core::BuildInfo> {
    Json(lightbridge_authz_core::build_info(service))
}

pub(crate) async fn readiness_handler(pool: Arc<dyn DbPoolTrait>) -> StatusCode {
    if is_database_ready(pool.as_ref()).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
