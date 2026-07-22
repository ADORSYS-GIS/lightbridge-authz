//! Generated cratestack CRUD surface for `authz-api` (ADR-0003).
//!
//! This crate owns `schema/authz.cstack` and nothing else: `include_server_schema!` expands it into
//! the `cratestack_schema` module — generated model/input structs, the `transport rpc` router
//! (`cratestack_schema::axum::rpc_router`), and the `procedures::ProcedureRegistry` trait. The
//! hand-written CRUD (`AuthzStore` trait, controllers, routers, OpenAPI) that used to live here is
//! deleted; `lightbridge-authz-rest` builds the RPC router and implements the procedures.
//!
//! Crate-wide `#![allow(clippy::ptr_arg)]`: generated code inside `cratestack_schema` takes `&String`
//! in a few places clippy would otherwise flag under `-D warnings`. It's generated, not ours to fix
//! (clippy's own diagnostic points at this exact lint as the culprit), and an outer `#[allow(...)]` on
//! the macro invocation itself doesn't work — clippy reports it as an unused attribute, since
//! `include_server_schema!` expands to multiple items, not one it can attach the attribute to. A
//! crate-level inner attribute is the reliable suppression, and this crate exists solely to host the
//! generated module (see above), so the scope is precise. `cargo clippy --all-targets --all-features
//! -- -D warnings` (what CI's code-checks action runs) hard-fails on this without the allow;
//! `just all-checks`'s `clippy --fix --allow-dirty` masked it by downgrading unfixable
//! macro-generated lints instead of failing, which is how this got past local verification during
//! the migration.
#![allow(clippy::ptr_arg)]

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
