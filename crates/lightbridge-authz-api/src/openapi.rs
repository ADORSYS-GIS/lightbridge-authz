use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::controllers::accounts::create_account,
        crate::controllers::accounts::list_accounts,
        crate::controllers::accounts::get_account,
        crate::controllers::accounts::update_account,
        crate::controllers::accounts::delete_account,
        crate::controllers::projects::create_project,
        crate::controllers::projects::list_projects,
        crate::controllers::projects::get_project,
        crate::controllers::projects::update_project,
        crate::controllers::projects::delete_project,
        crate::controllers::api_keys::create_api_key,
        crate::controllers::api_keys::list_api_keys,
        crate::controllers::api_keys::get_api_key,
        crate::controllers::api_keys::update_api_key,
        crate::controllers::api_keys::delete_api_key,
        crate::controllers::api_keys::revoke_api_key,
        crate::controllers::api_keys::rotate_api_key
    ),
    components(
        schemas(
            lightbridge_authz_core::Account,
            lightbridge_authz_core::CreateAccount,
            lightbridge_authz_core::UpdateAccount,
            lightbridge_authz_core::Project,
            lightbridge_authz_core::CreateProject,
            lightbridge_authz_core::UpdateProject,
            lightbridge_authz_core::ApiKey,
            lightbridge_authz_core::ApiKeyStatus,
            lightbridge_authz_core::CreateApiKey,
            lightbridge_authz_core::UpdateApiKey,
            lightbridge_authz_core::RotateApiKey,
            lightbridge_authz_core::ApiKeySecret
        )
    ),
    tags(
        (name = "accounts", description = "Account management"),
        (name = "projects", description = "Project management"),
        (name = "api_keys", description = "API key management")
    ),
    modifiers(&ApiSecurity),
    security(
        ("bearer_auth" = [])
    )
)]
pub struct ApiDoc;

struct ApiSecurity;

impl Modify for ApiSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}
