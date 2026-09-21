//! The API-key lifecycle MCP tools (lightbridge-authz#520): create/revoke/rotate, all routed
//! through `AuthzStoreImpl` (the hand-written, membership-scoped issuer the RPC surface's
//! `Procedures` also delegates to) rather than the generic cratestack CRUD verbs. Split out of
//! `mcp.rs`'s single tool-router impl block to keep that file under the 200-LoC gate
//! (`docs/code-size-baseline.md` split order item 4) -- every tool body below is moved verbatim,
//! no behavior change. See `mcp_tools_accounts.rs`'s module doc for the mechanics.
//!
//! `create-api-key`/`rotate-api-key` share the GHSA-9pc6-965v-2c44 secret-claim dance
//! (`api_key_claim_response`, `parse_optional_datetime`/`parse_required_datetime`), which is why
//! they group with `revoke-api-key` here rather than with the generic-CRUD tools in
//! `mcp_tools_api_keys_crud.rs`. Those three helpers stay `pub(crate)` in `mcp.rs` because
//! `mcp.rs`'s own test module also exercises `api_key_claim_response` directly.
//!
//! `ApiKeyByIdParams` stays in `mcp.rs` (`pub(crate)`) because `get-api-key`/`delete-api-key` in
//! the sibling `mcp_tools_api_keys_crud.rs` use it too.

use lightbridge_authz_core::{CreateApiKey, RotateApiKey};
use rmcp::{
    ErrorData, Json, RoleServer, handler::server::wrapper::Parameters, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::mcp::{
    ApiKeyByIdParams, EndpointResponse, LightbridgeMcpHandler, api_key_claim_response,
    parse_optional_datetime, parse_required_datetime, subject_from_request_context, to_json_value,
    to_tool_error, token_info_from_request_context,
};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateApiKeyParams {
    project_id: String,
    name: String,
    /// Required (RFC3339), lightbridge-authz#395: every api key must carry an expiry, no more
    /// than `api_key_expiry.max_lifetime_days` (default 90) days out. Server-validated
    /// regardless -- see `AuthzStoreImpl::validate_expires_at`.
    expires_at: String,
    billing_plan: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RotateApiKeyParams {
    key_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    grace_period_seconds: Option<i64>,
}

#[tool_router(router = api_keys_lifecycle_tool_router, vis = "pub(crate)")]
impl LightbridgeMcpHandler {
    #[tool(
        name = "create-api-key",
        description = "Create an API key (RPC procedure.createApiKey; the server generates + hashes the secret, and validates the billing plan and expires_at -- required, RFC3339, at most ~90 days out by default)"
    )]
    async fn create_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let expires_at = parse_required_datetime(params.expires_at, "expires_at")?;

        let api_key_secret = self
            .issuer
            .create_api_key(
                &subject,
                Some(&token_info.access_token),
                &params.project_id,
                CreateApiKey {
                    name: params.name,
                    expires_at: Some(expires_at),
                    billing_plan: params.billing_plan,
                },
            )
            .await
            .map_err(to_tool_error)?;

        // GHSA-9pc6-965v-2c44: an MCP tool result is returned into the calling model's context,
        // so it must never carry the secret. Stash it and hand back a claim only the requesting
        // human, in a browser, can redeem. A failure to stash REFUSES the call -- there is no
        // fallback that returns the secret inline.
        // Fail closed when unconfigured. The secret exists at this point and the key row is
        // written, but there is nowhere safe to put the secret -- and a tool result is not it.
        // Refusing is the only correct answer; returning it would reintroduce the exposure this
        // whole mechanism exists to remove.
        let (Some(claim_store), Some(redeem_base_url)) =
            (self.claim_store.as_ref(), self.redeem_base_url.as_ref())
        else {
            return Err(ErrorData::internal_error(
                "secret_claim is not configured on this deployment, so an API key secret cannot \
                 be delivered safely. An MCP tool result is read by the model, so the secret is \
                 never returned here. Configure secret_claim (encryption_key, redeem_base_url) \
                 and retry."
                    .to_string(),
                None,
            ));
        };
        let claim = claim_store
            .issue(&api_key_secret.secret, &subject)
            .await
            .map_err(to_tool_error)?;
        to_json_value(api_key_claim_response(
            &api_key_secret.api_key,
            api_key_secret.oauth2_url.as_deref(),
            redeem_base_url,
            &claim.token,
            claim.expires_in_seconds,
        ))
    }

    #[tool(
        name = "revoke-api-key",
        description = "Revoke an API key (RPC procedure.revokeApiKey)"
    )]
    async fn revoke_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ApiKeyByIdParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let api_key = self
            .issuer
            .revoke_api_key(&subject, &params.key_id)
            .await
            .map_err(to_tool_error)?;

        to_json_value(api_key)
    }

    #[tool(
        name = "rotate-api-key",
        description = "Rotate an API key (RPC procedure.rotateApiKey)"
    )]
    async fn rotate_api_key_tool(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<RotateApiKeyParams>,
    ) -> std::result::Result<Json<EndpointResponse>, ErrorData> {
        let token_info = token_info_from_request_context(&context)?;
        let subject = subject_from_request_context(&context, self.resolver.as_ref()).await?;
        let expires_at = parse_optional_datetime(params.expires_at, "expires_at")?;

        let api_key_secret = self
            .issuer
            .rotate_api_key(
                &subject,
                Some(&token_info.access_token),
                &params.key_id,
                RotateApiKey {
                    name: params.name,
                    expires_at,
                    grace_period_seconds: params.grace_period_seconds,
                },
            )
            .await
            .map_err(to_tool_error)?;

        // GHSA-9pc6-965v-2c44: an MCP tool result is returned into the calling model's context,
        // so it must never carry the secret. Stash it and hand back a claim only the requesting
        // human, in a browser, can redeem. A failure to stash REFUSES the call -- there is no
        // fallback that returns the secret inline.
        // Fail closed when unconfigured. The secret exists at this point and the key row is
        // written, but there is nowhere safe to put the secret -- and a tool result is not it.
        // Refusing is the only correct answer; returning it would reintroduce the exposure this
        // whole mechanism exists to remove.
        let (Some(claim_store), Some(redeem_base_url)) =
            (self.claim_store.as_ref(), self.redeem_base_url.as_ref())
        else {
            return Err(ErrorData::internal_error(
                "secret_claim is not configured on this deployment, so an API key secret cannot \
                 be delivered safely. An MCP tool result is read by the model, so the secret is \
                 never returned here. Configure secret_claim (encryption_key, redeem_base_url) \
                 and retry."
                    .to_string(),
                None,
            ));
        };
        let claim = claim_store
            .issue(&api_key_secret.secret, &subject)
            .await
            .map_err(to_tool_error)?;
        to_json_value(api_key_claim_response(
            &api_key_secret.api_key,
            api_key_secret.oauth2_url.as_deref(),
            redeem_base_url,
            &claim.token,
            claim.expires_in_seconds,
        ))
    }
}
