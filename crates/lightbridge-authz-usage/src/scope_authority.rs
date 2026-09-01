//! Ownership authority for `/usage/v1/usage/query` (#570): does the end user presenting a scope
//! actually own it? This service has no `accounts`/`projects`/`project_members` tables of its
//! own, so ownership is answered by calling `authz-opa`'s Basic-auth-protected
//! `POST /idp/v1/authorize-usage-scope` -- the same real, Postgres-backed predicate
//! `resolve_context` already enforces for the OIDC token-exchange path.
//!
//! ## Fail-closed contract
//!
//! Every way the HTTP call to `authz-opa` can fail is treated as "not authorized", mirroring
//! `lightbridge-authz-budget::spend::UsageServiceSpendReader`'s fail-closed posture for the
//! sibling `/usage/v1/spend/query` call (see that module's doc comment for the full precedent):
//! a transport failure (DNS, connection refused, TLS handshake failure, timeout), a non-`200`/
//! `404` status, or a response that otherwise cannot be trusted all resolve to `Ok(false)`, never
//! `Ok(true)` and never a propagated `Err` that some caller might mishandle into a permissive
//! default. There is no `unwrap_or(true)` anywhere in this module -- an unreachable authority
//! means the request is refused, never admitted.

use lightbridge_authz_core::{AuthorizeUsageScopeRequest, Result, async_trait};

use crate::models::UsageScope;

/// Maps [`UsageScope`] to the wire string `authz-opa`'s `authorize_usage_scope` predicate
/// matches on (`"account"` / `"project"`). `User`/`ApiKey`/`All` have no resolvable ownership
/// predicate at all -- callers must refuse/resolve those scopes before ever reaching this trait
/// (`User` against the caller's own subject, `All` against `Permission::UsageReadAll`, `ApiKey`
/// unconditionally -- see `handlers::query::query_usage`), so this function is never called with
/// them, but it still maps every variant to a value `authz-opa`'s own `_ => Err(Error::NotFound)`
/// arm refuses uniformly, as defense in depth.
fn scope_wire_value(scope: &UsageScope) -> &'static str {
    match scope {
        UsageScope::Account => "account",
        UsageScope::Project => "project",
        UsageScope::User => "user",
        UsageScope::ApiKey => "api_key",
        UsageScope::All => "all",
    }
}

/// Answers "does `subject` (authenticated by `issuer`) own `scope_id` under `scope`?" for the
/// usage query listener's ownership gate. Implementations must preserve the fail-closed contract
/// documented on this module: every failure mode resolves to `Ok(false)`, never `Ok(true)` and
/// never a propagated error a caller might treat as authorization.
#[async_trait]
pub trait ScopeAuthority: Send + Sync {
    async fn authorize(
        &self,
        issuer: &str,
        subject: &str,
        scope: &UsageScope,
        scope_id: &str,
    ) -> Result<bool>;
}

/// Calls `authz-opa`'s `POST /idp/v1/authorize-usage-scope` over HTTPS with a Basic-auth
/// credential, mirroring `UsageServiceSpendReader`'s construction discipline
/// (`crates/lightbridge-authz-budget/src/spend.rs`): CA bundle / mTLS client-identity
/// configuration, hard construction errors on partial config (never a silent "connect without an
/// identity" fallback), and a fail-closed read side (see this module's doc comment).
pub struct RemoteScopeAuthority {
    client: reqwest::Client,
    base_url: String,
    username: String,
    password: String,
}

/// Hand-written, redacting `Debug` impl -- `password` is a credential
/// (`ScopeAuthorityConfig.password`, the same Basic-auth secret that unlocks authz-opa's whole
/// router, not just this route -- see that field's doc comment) and must never be derived
/// verbatim into a log line or panic message (AGENTS.md's "Keep secrets out of logs" rule).
impl std::fmt::Debug for RemoteScopeAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteScopeAuthority")
            .field("base_url", &self.base_url)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl RemoteScopeAuthority {
    /// Builds an authority from a [`ScopeAuthorityConfig`] (`base_url`, e.g.
    /// `https://authz-opa:3001`, no trailing slash required). See
    /// `UsageServiceSpendReader::new`'s doc comment for the identical `insecure_skip_verify`/
    /// `ca_bundle_path`/`client_cert_path`/`client_key_path` semantics -- this constructor applies
    /// the exact same rules, so a misconfigured trust anchor or a half-set client identity is a
    /// hard startup failure here too, never a silent weaker fallback. Takes the whole config
    /// struct (rather than one parameter per field, `UsageServiceSpendReader::new`'s own shape)
    /// because that constructor's 8-argument, 6-`Option`/`bool` positional call site is exactly
    /// the shape `clippy::too_many_arguments` exists to catch, and this crate's own config type
    /// already carries every field this constructor needs.
    pub fn new(config: &crate::config::ScopeAuthorityConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .danger_accept_invalid_certs(config.insecure_skip_verify);

        if let Some(path) = config.ca_bundle_path.as_deref() {
            let pem = std::fs::read(path).map_err(|err| {
                lightbridge_authz_core::Error::Server(format!(
                    "failed to read scope-authority CA bundle at '{path}': {err}"
                ))
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|err| {
                lightbridge_authz_core::Error::Server(format!(
                    "failed to parse scope-authority CA bundle at '{path}' as PEM: {err}"
                ))
            })?;
            if certs.is_empty() {
                return Err(lightbridge_authz_core::Error::Server(format!(
                    "scope-authority CA bundle at '{path}' contains no PEM certificates"
                )));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        if let Some(identity) = load_client_identity(
            config.client_cert_path.as_deref(),
            config.client_key_path.as_deref(),
        )? {
            builder = builder.identity(identity);
        }

        let client = builder.build().map_err(|err| {
            lightbridge_authz_core::Error::Server(format!(
                "failed to build scope-authority HTTP client: {err}"
            ))
        })?;

        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            username: config.username.clone(),
            password: config.password.clone(),
        })
    }
}

/// See `UsageServiceSpendReader`'s identically-named helper -- setting exactly one of
/// `client_cert_path`/`client_key_path` is a hard construction error, never a silent
/// "present no client certificate" fallback.
fn load_client_identity(
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> Result<Option<reqwest::Identity>> {
    let (cert_path, key_path) = match (client_cert_path, client_key_path) {
        (None, None) => return Ok(None),
        (Some(cert_path), Some(key_path)) => (cert_path, key_path),
        (Some(cert_path), None) => {
            return Err(lightbridge_authz_core::Error::Server(format!(
                "scope-authority client_cert_path '{cert_path}' is set but client_key_path is \
                 missing -- both must be set together"
            )));
        }
        (None, Some(key_path)) => {
            return Err(lightbridge_authz_core::Error::Server(format!(
                "scope-authority client_key_path '{key_path}' is set but client_cert_path is \
                 missing -- both must be set together"
            )));
        }
    };

    let mut pem = std::fs::read(cert_path).map_err(|err| {
        lightbridge_authz_core::Error::Server(format!(
            "failed to read scope-authority client cert at '{cert_path}': {err}"
        ))
    })?;
    let key_pem = std::fs::read(key_path).map_err(|err| {
        lightbridge_authz_core::Error::Server(format!(
            "failed to read scope-authority client key at '{key_path}': {err}"
        ))
    })?;
    pem.push(b'\n');
    pem.extend_from_slice(&key_pem);

    let identity = reqwest::Identity::from_pem(&pem).map_err(|err| {
        lightbridge_authz_core::Error::Server(format!(
            "failed to parse scope-authority client identity from cert '{cert_path}' / key \
             '{key_path}': {err}"
        ))
    })?;

    Ok(Some(identity))
}

#[async_trait]
impl ScopeAuthority for RemoteScopeAuthority {
    async fn authorize(
        &self,
        issuer: &str,
        subject: &str,
        scope: &UsageScope,
        scope_id: &str,
    ) -> Result<bool> {
        let url = format!("{}/idp/v1/authorize-usage-scope", self.base_url);
        let body = AuthorizeUsageScopeRequest {
            issuer: Some(issuer.to_string()),
            subject: Some(subject.to_string()),
            scope: Some(scope_wire_value(scope).to_string()),
            scope_id: Some(scope_id.to_string()),
        };

        let response = match self
            .client
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(&body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "scope-authority request failed; refusing the usage query"
                );
                return Ok(false);
            }
        };

        match response.status() {
            reqwest::StatusCode::OK => Ok(true),
            reqwest::StatusCode::NOT_FOUND => {
                // A `404` here is normally authz-opa's `authorize_usage_scope`'s own uniform
                // not-authorized answer (see its doc comment) -- but a `404` is ALSO exactly what
                // an old/mismatched authz-opa build with no `/idp/v1/authorize-usage-scope` route
                // at all would return, i.e. a version-skew scenario during a rollout where the
                // usage service's image ships #570 before authz-opa's does. Both cases correctly
                // fail closed to `Ok(false)` (never a permissive default either way), but they are
                // operationally very different -- "every query is being correctly refused" vs.
                // "authz-opa needs to be rolled out" -- so this is `debug!`, not silent, to give
                // an operator investigating "why is every usage query 403" a way to at least see
                // that the authority route was reached and rule this scenario in or out from logs
                // alone, without needing to also correlate authz-opa's own deploy history.
                tracing::debug!(
                    "scope-authority returned 404; either genuinely not-authorized or the route \
                     doesn't exist yet on this authz-opa build (version skew) -- refusing either way"
                );
                Ok(false)
            }
            status => {
                tracing::warn!(
                    status = %status,
                    "scope-authority returned an unexpected status; refusing the usage query"
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::POST;
    use httpmock::MockServer;

    fn test_config(base_url: String) -> crate::config::ScopeAuthorityConfig {
        crate::config::ScopeAuthorityConfig {
            base_url,
            username: "authorino".to_string(),
            password: "change-me".to_string(),
            insecure_skip_verify: true,
            ca_bundle_path: None,
            client_cert_path: None,
            client_key_path: None,
            timeout_ms: 1_000,
        }
    }

    fn authority(base_url: String) -> RemoteScopeAuthority {
        RemoteScopeAuthority::new(&test_config(base_url)).expect("authority should construct")
    }

    #[test]
    fn scope_wire_value_maps_every_variant() {
        assert_eq!(scope_wire_value(&UsageScope::Account), "account");
        assert_eq!(scope_wire_value(&UsageScope::Project), "project");
        assert_eq!(scope_wire_value(&UsageScope::User), "user");
        assert_eq!(scope_wire_value(&UsageScope::ApiKey), "api_key");
        assert_eq!(scope_wire_value(&UsageScope::All), "all");
    }

    #[tokio::test]
    async fn authorize_returns_true_on_200() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/idp/v1/authorize-usage-scope");
            then.status(200);
        });

        let authority = authority(server.base_url());
        let authorized = authority
            .authorize(
                "https://issuer.test",
                "sub-1",
                &UsageScope::Account,
                "acct_1",
            )
            .await
            .expect("authorize should not error");
        assert!(authorized);
        mock.assert();
    }

    #[tokio::test]
    async fn authorize_returns_false_on_404() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/idp/v1/authorize-usage-scope");
            then.status(404);
        });

        let authority = authority(server.base_url());
        let authorized = authority
            .authorize(
                "https://issuer.test",
                "sub-1",
                &UsageScope::Account,
                "acct_1",
            )
            .await
            .expect("authorize should not error");
        assert!(!authorized);
    }

    /// Fail-closed: a 500 from the authority must never be treated as authorized.
    #[tokio::test]
    async fn authorize_returns_false_on_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/idp/v1/authorize-usage-scope");
            then.status(500);
        });

        let authority = authority(server.base_url());
        let authorized = authority
            .authorize(
                "https://issuer.test",
                "sub-1",
                &UsageScope::Account,
                "acct_1",
            )
            .await
            .expect("authorize should not error");
        assert!(!authorized);
    }

    /// Fail-closed: an unreachable authority must never be treated as authorized.
    #[tokio::test]
    async fn authorize_returns_false_when_unreachable() {
        let authority = authority("https://127.0.0.1:1".to_string());
        let authorized = authority
            .authorize(
                "https://issuer.test",
                "sub-1",
                &UsageScope::Account,
                "acct_1",
            )
            .await
            .expect("authorize should not error even when the transport fails");
        assert!(!authorized);
    }

    #[test]
    fn constructing_with_only_a_client_cert_path_is_a_hard_error() {
        let mut config = test_config("https://authz-opa:3001".to_string());
        config.client_cert_path = Some("/tls/usage.crt".to_string());
        let err = RemoteScopeAuthority::new(&config)
            .expect_err("a half-set client identity must refuse construction");
        assert!(matches!(err, lightbridge_authz_core::Error::Server(_)));
    }
}
