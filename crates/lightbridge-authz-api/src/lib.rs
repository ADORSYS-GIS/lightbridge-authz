//! Shared public API types and traits across HTTP servers.

pub mod controllers;
pub mod db;
pub mod routers;
pub mod store;

use std::fmt;
use std::sync::Arc;

/// Application-wide state shared by REST handlers and middleware.
/// Contains the store implementation and bearer token service.
pub struct AppState {
    pub store: Arc<dyn store::AuthzStore>,
    pub bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("store", &"<AuthzStore>")
            .field("bearer", &"<BearerTokenService>")
            .finish()
    }
}

/// API contracts shared between HTTP layers.
pub mod contract {
    pub use crate::store::AuthzStore;
}
