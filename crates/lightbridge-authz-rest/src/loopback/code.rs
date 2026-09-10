//! Authorization-code issuance for a redirect URI the RFC 8252 §7.3 carve-out admitted.
//!
//! `/authorize` cannot simply hand an admitted loopback request to the vendored
//! `authkestra_op::handlers::handle_authorize`: that function re-validates `req.redirect_uri`
//! with `ClientRegistration::allows_redirect_uri` -- the same plain `==` the carve-out exists to
//! sidestep, and with no knowledge of it. An ephemeral-port URI would pass `/authorize`'s gate and
//! then be refused inside `handle_authorize` with `RedirectUriMismatch`, which `issue_code` maps
//! to a bare 500. No code would ever be issued, so the flow this rule enables would not work.
//! [`issue_loopback_code`] therefore mirrors the mint/store/redirect tail of
//! `authkestra-op-0.7.1/src/handlers/authorize.rs` for that one case, and nothing else.

use authkestra_engine::auth::state::Identity;
use authkestra_op::OpError;
use authkestra_op::client::ClientRegistration;
use authkestra_op::code::AuthorizationCode;
use authkestra_op::config::OpConfig;
use authkestra_op::handlers::{AuthorizeOutcome, AuthorizeRequest};
use authkestra_op::store::OpStore;
use chrono::{Duration, Utc};

use crate::oauth2_op::random_urlsafe;

/// Mints, stores and redirects an authorization code for an admitted loopback redirect URI.
///
/// The caller (`authorize()`) has already run every check `handle_authorize` runs before its own
/// mint step, and each of them at least as strictly: client lookup, the redirect-URI decision
/// (exact match *or* [`is_loopback_redirect`](super::is_loopback_redirect)), `response_type`,
/// grant type, unconditional S256 PKCE, and scope validation -- `scopes_are_allowed` checks the
/// requested scopes against the client's registration *and* the OP's `scopes_supported`, where
/// upstream's `allows_scope` loop checks only the former. So only the mint/store/redirect steps
/// are replicated here. Any failure returns `AuthorizeOutcome::DirectError`, which the caller
/// turns into a refusal; no path here silently succeeds.
///
/// The stored code is bound to the **actual requested** URI, ephemeral port included, never to
/// the registered one. The token endpoint's redemption check (`authorization_code_matches`,
/// `crates/lightbridge-authz-api-key/src/repo.rs`) compares the presented `redirect_uri` to the
/// stored one byte-exactly, so substituting the registration would make redemption fail -- and
/// would also weaken the binding, since every port would then redeem against one stored value.
pub(crate) async fn issue_loopback_code(
    client: &ClientRegistration,
    request: AuthorizeRequest,
    identity: Identity,
    config: &OpConfig,
    op_store: &dyn OpStore,
) -> AuthorizeOutcome {
    // Parse before storing: a code persisted for a URI we cannot build a redirect from would be
    // a live credential with no way to deliver it.
    let Ok(mut location) = reqwest::Url::parse(&request.redirect_uri) else {
        return AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch);
    };
    let code_value = random_urlsafe(32);
    let expires_at = Utc::now() + Duration::seconds(config.authorization_code_ttl_secs);
    let mut auth_code = AuthorizationCode::new(
        code_value.clone(),
        client.client_id.clone(),
        request.redirect_uri.clone(),
        request.scope.clone(),
        identity,
        expires_at,
        false,
    );
    auth_code.code_challenge = request.code_challenge.clone();
    auth_code.code_challenge_method = request.code_challenge_method.clone();
    auth_code.nonce = request.nonce.clone();
    if let Err(error) = op_store.store_code(auth_code).await {
        tracing::error!(?error, client_id = %client.client_id, "failed to store loopback authorization code");
        return AuthorizeOutcome::DirectError(OpError::Storage);
    }
    {
        let mut query = location.query_pairs_mut();
        query.append_pair("code", &code_value);
        if let Some(state) = &request.state {
            query.append_pair("state", state);
        }
    }
    AuthorizeOutcome::Redirect(location.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::fixtures::{
        ephemeral_port_request, identity, op_config, op_store, public_client_with_loopback,
    };
    use authkestra_op::code::AuthorizationCodeStore;
    use authkestra_op::handlers::handle_authorize;

    /// The end-to-end regression: an admitted ephemeral-port URI must actually get a code, and
    /// the code must be bound to that URI so the token endpoint's exact-match redemption works.
    #[tokio::test]
    async fn an_admitted_loopback_uri_gets_a_code_bound_to_the_requested_uri() {
        let client = public_client_with_loopback();
        let store = op_store(client.clone()).await;

        let outcome = issue_loopback_code(
            &client,
            ephemeral_port_request(&client),
            identity(),
            &op_config(),
            &store,
        )
        .await;

        let AuthorizeOutcome::Redirect(location) = outcome else {
            panic!("the carve-out did not issue a code: {outcome:?}");
        };
        let url = reqwest::Url::parse(&location).expect("the redirect must be a valid URL");
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params.get("state").map(String::as_str), Some("xyz"));
        let stored = store
            .consume_code(params.get("code").expect("a code must be issued"))
            .await
            .expect("consuming the code must not error")
            .expect("the issued code must be persisted");
        assert_eq!(stored.redirect_uri, "http://127.0.0.1:54321/callback");
        assert_eq!(stored.code_challenge.as_deref(), Some("s256challenge"));
    }

    /// Proves the premise of this module: the vendored `handle_authorize` refuses the very same
    /// request, so routing it there instead would never issue a code.
    #[tokio::test]
    async fn handle_authorize_refuses_the_same_ephemeral_port_uri() {
        let client = public_client_with_loopback();
        let store = op_store(client.clone()).await;

        let outcome = handle_authorize(
            ephemeral_port_request(&client),
            identity(),
            &op_config(),
            &store,
        )
        .await;

        assert!(
            matches!(
                outcome,
                AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch)
            ),
            "handle_authorize must refuse the ephemeral-port URI; got {outcome:?}"
        );
    }
}
