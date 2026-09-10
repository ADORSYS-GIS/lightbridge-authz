//! The OpenAPI document for `authz-opa`'s surface, kept out of `lib.rs` (which sits far over the
//! LoC gate's ceiling and must not grow). Code moved, not rewritten.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::introspect::introspect_api_key,
        crate::handlers::idp::resolve_context,
        crate::handlers::idp::authorize_usage_scope
    ),
    components(
        schemas(
            crate::models::IntrospectRequest,
            crate::models::IntrospectResponse,
            lightbridge_authz_core::ApiKey,
            lightbridge_authz_core::Project,
            lightbridge_authz_core::Account,
            lightbridge_authz_core::ResolveContextRequest,
            lightbridge_authz_core::ResolvedContext,
            lightbridge_authz_core::AuthorizeUsageScopeRequest
        )
    ),
    tags(
        (name = "authorino", description = "Authorino integration"),
        (name = "idp", description = "Identity request resolution")
    )
)]
pub(crate) struct OpaDoc;
