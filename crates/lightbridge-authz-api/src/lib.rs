//! Shared public API types and traits across REST and gRPC.

pub mod controllers;
pub mod handlers;
pub mod routers;

pub trait APIKeyService:
    handlers::APIKeyHandler + handlers::APIKeyCrud + Send + Sync + 'static
{
}

impl<T> APIKeyService for T where
    T: handlers::APIKeyHandler + handlers::APIKeyCrud + Send + Sync + 'static
{
}

/// API contracts shared between REST and gRPC.
pub mod contract {
    pub use crate::handlers::{APIKeyCrud, APIKeyHandler};
}
