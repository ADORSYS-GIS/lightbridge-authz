//! Shared public API types and traits across REST and gRPC.

pub mod api_key_crud;
pub mod api_key_handler;
pub mod api_key_reader;
pub mod controllers;
pub mod db;
pub mod routers;

use std::fmt;
use std::sync::Arc;

pub trait APIKeyService:
    api_key_handler::APIKeyHandler + api_key_crud::APIKeyCrud + Send + Sync + 'static
{
}

impl<T> APIKeyService for T where
    T: api_key_handler::APIKeyHandler + api_key_crud::APIKeyCrud + Send + Sync + 'static
{
}

/// Application-wide state shared by REST and middleware.
/// This contains the API key handler implementation and the bearer token service.
/// It is wrapped by an Arc when inserted as router state.
pub struct AppState {
    pub handler: Arc<dyn APIKeyService>,
    pub bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
}

// Implement a lightweight Debug for AppState so it can be used with tracing/instrument
impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("handler", &"<APIKeyService>")
            .field("bearer", &"<BearerTokenService>")
            .finish()
    }
}

/// API contracts shared between REST and gRPC.
pub mod contract {
    pub use crate::api_key_crud::APIKeyCrud;
    pub use crate::api_key_handler::APIKeyHandler;
    pub use crate::api_key_reader::APIKeyReader;
}
