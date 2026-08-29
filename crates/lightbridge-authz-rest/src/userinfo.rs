//! `GET|POST /oauth2/userinfo` -- OIDC Core 1.0 §5.3 UserInfo.
//!
//! Answers "who is the end-user behind this access token", and nothing else. Authorization data
//! is deliberately out of scope: no roles, no permissions, no `budget_tier`/`quota_tier`. Those
//! are decided per-request by the resource server (`authz-api`'s RBAC gate reads them from the
//! token itself, `docs/rbac.md`), and mirroring them here would create a second, cacheable,
//! silently-staler copy of an authorization answer -- the exact drift
//! `docs/governance-model-and-enforcement.md` argues against for `role`/`project_quota`.
//!
//! **Every claim returned is already inside the token the caller presented.** That is the
//! disclosure rule this endpoint is built on: possession of the token already implies possession
//! of these values, so UserInfo reveals nothing a caller could not read by base64-decoding what
//! they sent. It exists for RP libraries that expect the endpoint to be there, not to hand out
//! anything new.
//!
//! Two rejections, kept distinct because they mean different things to a client (RFC 6750 §3.1):
//! a token that does not verify is `401 invalid_token` (re-authenticate); a token that verifies
//! but was minted without `openid` is `403 insufficient_scope` (ask for the right scope). The
//! second is what a data-plane API-key JWT gets -- it is signed by the same key and carries the
//! same `iss`, so it verifies here, and only the scope check separates it from a human-plane
//! token. Collapsing the two into one status would tell an RP to retry a login that is not the
//! problem.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::token_exchange::{TokenExchangeState, verify_own_token};

/// OIDC Core §5.3.1 permits the access token in a form-encoded body on POST as an alternative to
/// the `Authorization` header. Accepted for RP-library compatibility; the header is preferred and
/// wins when both are present.
#[derive(Debug, Default, Deserialize)]
pub struct UserInfoForm {
    access_token: Option<String>,
}

/// Claims copied through verbatim when present, beyond the always-required `sub`.
///
/// `email`/`email_verified` are gated on the `email` scope per OIDC Core §5.4. The tenant pair is
/// not a standard OIDC claim and is not scope-gated: it is this deployment's own identity context,
/// always present on a human-plane token, and the console's reason for calling this endpoint at
/// all. `profile` grants nothing today -- this IdP holds no name, picture, or locale for anyone,
/// so advertising support for claims it would always omit would be a lie in the discovery
/// document.
const EMAIL_SCOPED_CLAIMS: [&str; 2] = ["email", "email_verified"];
const TENANT_CLAIMS: [&str; 2] = ["account_id", "project_id"];

fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| token.trim())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
}

/// RFC 6750 §3: the `WWW-Authenticate` challenge is what tells an RP library whether to refresh
/// and retry. `no-store` mirrors every other token-adjacent response in this service.
fn challenge(status: StatusCode, challenge: &'static str) -> Response {
    (
        status,
        [
            (header::WWW_AUTHENTICATE, challenge),
            (header::CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response()
}

fn scope_grants_openid(claims: &Map<String, Value>) -> bool {
    claims
        .get("scope")
        .and_then(Value::as_str)
        .is_some_and(|scope| scope.split_whitespace().any(|s| s == "openid"))
}

fn scope_grants_email(claims: &Map<String, Value>) -> bool {
    claims
        .get("scope")
        .and_then(Value::as_str)
        .is_some_and(|scope| scope.split_whitespace().any(|s| s == "email"))
}

/// Projects a verified access token's claims onto the UserInfo response.
///
/// `sub` is mandatory (OIDC Core §5.3.2) and its absence is a malformed token, not an empty
/// response -- hence `Option` rather than a default.
///
/// `pub` for `tests/userinfo_tests.rs`: the scope gating is the part worth asserting exhaustively,
/// and it is pure. The route's auth behaviour is covered separately in `idp_server_tests.rs`,
/// where the offline IdP fixture already exists.
pub fn user_info_claims(claims: &Map<String, Value>) -> Option<Map<String, Value>> {
    let sub = claims.get("sub").and_then(Value::as_str)?;
    let mut body = Map::new();
    body.insert("sub".to_string(), Value::String(sub.to_string()));
    if scope_grants_email(claims) {
        for claim in EMAIL_SCOPED_CLAIMS {
            if let Some(value) = claims.get(claim) {
                body.insert(claim.to_string(), value.clone());
            }
        }
    }
    for claim in TENANT_CLAIMS {
        if let Some(value) = claims.get(claim) {
            body.insert(claim.to_string(), value.clone());
        }
    }
    Some(body)
}

async fn user_info(state: TokenExchangeState, headers: HeaderMap, form: UserInfoForm) -> Response {
    let Some(token) = bearer_from_headers(&headers).or(form.access_token) else {
        // No credential at all: the bare challenge, with no `error` code. RFC 6750 §3.1 reserves
        // `invalid_token` for a token that was presented and failed -- emitting it here would tell
        // an RP its token is bad when it never sent one.
        return challenge(StatusCode::UNAUTHORIZED, "Bearer");
    };

    let Some(claims) = verify_own_token(&state, &token, true).await else {
        return challenge(
            StatusCode::UNAUTHORIZED,
            "Bearer error=\"invalid_token\", error_description=\"the access token is expired, \
             malformed, or not signed by this issuer\"",
        );
    };

    if !scope_grants_openid(&claims) {
        return challenge(
            StatusCode::FORBIDDEN,
            "Bearer error=\"insufficient_scope\", scope=\"openid\", error_description=\"this \
             token was not issued through an OpenID Connect flow\"",
        );
    }

    let Some(body) = user_info_claims(&claims) else {
        tracing::error!("a token verified against our own JWKS carried no `sub` claim");
        return challenge(
            StatusCode::UNAUTHORIZED,
            "Bearer error=\"invalid_token\", error_description=\"the access token carries no \
             subject\"",
        );
    };

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(Value::Object(body)),
    )
        .into_response()
}

async fn user_info_get(State(state): State<TokenExchangeState>, headers: HeaderMap) -> Response {
    user_info(state, headers, UserInfoForm::default()).await
}

/// A body is optional on POST (the token may be in the header), so a missing or non-form body
/// degrades to "no form token" rather than a 415 -- the header path must keep working either way.
async fn user_info_post(
    State(state): State<TokenExchangeState>,
    headers: HeaderMap,
    form: Result<Form<UserInfoForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let form = form.map_or_else(|_| UserInfoForm::default(), |Form(form)| form);
    user_info(state, headers, form).await
}

/// The `/oauth2/userinfo` routes, advertised by `signing::discovery_document` as
/// `userinfo_endpoint`. OIDC Core §5.3.1 requires GET and POST both.
pub fn router<S>(state: TokenExchangeState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/oauth2/userinfo", get(user_info_get))
        .route("/oauth2/userinfo", post(user_info_post))
        .with_state(state)
}
