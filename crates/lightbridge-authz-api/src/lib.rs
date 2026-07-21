//! Generated cratestack CRUD surface for `authz-api` (ADR-0003).
//!
//! This crate owns `schema/authz.cstack` and nothing else: `include_server_schema!` expands it into
//! the `cratestack_schema` module — generated model/input structs, the `transport rpc` router
//! (`cratestack_schema::axum::rpc_router`), and the `procedures::ProcedureRegistry` trait. The
//! hand-written CRUD (`AuthzStore` trait, controllers, routers, OpenAPI) that used to live here is
//! deleted; `lightbridge-authz-rest` builds the RPC router and implements the procedures.

use std::fmt;
use std::sync::Arc;

// Emits `pub mod cratestack_schema { ... }` at the crate root. The macro references `::cratestack::*`
// paths, satisfied by the `cratestack` (package `cratestack-pg`) dependency.
cratestack::include_server_schema!("schema/authz.cstack", db = Postgres);

/// Re-export of the generated schema module under a shorter alias, so consumers write
/// `lightbridge_authz_api::schema::{Account, Cratestack, ...}`.
pub use crate::cratestack_schema as schema;

/// Application state still consumed by the rest crate's bearer/RBAC middleware. The former `store`
/// field (an `Arc<dyn AuthzStore>`) is gone — CRUD now runs through the generated cratestack client
/// behind the RPC router's own `AuthProvider`, not this state.
pub struct AppState {
    pub bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("bearer", &"<BearerTokenService>")
            .finish()
    }
}
