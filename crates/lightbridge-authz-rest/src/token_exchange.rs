use std::sync::Arc;

use axum::{
    Form, Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_api_key::entities::exchange_refresh_token_row::{
    ExchangeRefreshTokenRow, NewExchangeRefreshToken,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::config::Oauth2TokenExchange;
use lightbridge_authz_core::crypto::hash_api_key;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::Error;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::signing::{ApiKeyJwtSigner, KeyOwner};

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const REFRESH_TOKEN_GRANT: &str = "refresh_token";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const OFFLINE_ACCESS_SCOPE: &str = "offline_access";
const REFRESH_TOKEN_PREFIX: &str = "lgbr_rt_";
const REFRESH_TOKEN_BYTES: usize = 32;

/// Everything the native token-exchange endpoint needs: the DB repo (context resolution + refresh
/// token storage), the self-signed-JWT signer (the exchanged access token), the upstream bearer
/// validator (the presented `subject_token`), and the exchange policy (TTLs + allowed scopes).
#[derive(Clone)]
pub struct TokenExchangeState {
    pub repo: Arc<StoreRepo>,
    pub signer: ApiKeyJwtSigner,
    pub bearer: Arc<dyn BearerTokenServiceTrait>,
    pub cfg: Oauth2TokenExchange,
}

/// Public `/oauth2/token` route. Public because the presented `subject_token` (or `refresh_token`)
/// is itself the credential — no bearer middleware. Provides its own state so it merges into any
/// parent router.
pub fn token_exchange_router<S>(state: TokenExchangeState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/oauth2/token", post(token_endpoint))
        .with_state(state)
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    project_id: Option<String>,
    scope: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_token_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// RFC 6749 §5.2 error body.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

fn is_blank(value: &Option<String>) -> bool {
    value.as_deref().map(str::trim).unwrap_or("").is_empty()
}

async fn token_endpoint(
    State(state): State<TokenExchangeState>,
    Form(request): Form<TokenRequest>,
) -> Response {
    match request.grant_type.as_str() {
        TOKEN_EXCHANGE_GRANT => handle_exchange(&state, request).await,
        REFRESH_TOKEN_GRANT => handle_refresh(&state, request).await,
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("grant_type '{other}' is not supported"),
        ),
    }
}

async fn handle_exchange(state: &TokenExchangeState, request: TokenRequest) -> Response {
    if is_blank(&request.subject_token) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token is required",
        );
    }
    let subject_token = request.subject_token.as_deref().unwrap_or("");
    if let Some(token_type) = request.subject_token_type.as_deref() {
        let token_type = token_type.trim();
        if !token_type.is_empty() && token_type != ACCESS_TOKEN_TYPE {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token",
            );
        }
    }
    if is_blank(&request.project_id) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "project_id is required",
        );
    }
    let project_id = request.project_id.as_deref().unwrap_or("").trim();

    let token_info = match state.bearer.validate_bearer_token(subject_token).await {
        Ok(info) if info.active => info,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "subject_token is not active",
            );
        }
        Err(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "subject_token validation failed",
            );
        }
    };
    let subject = token_info.sub;

    let context = match state.repo.resolve_context(&subject, project_id).await {
        Ok(context) => context,
        Err(Error::NotFound) => {
            return oauth_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "subject is not a member of the requested project",
            );
        }
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "context resolution failed",
            );
        }
    };

    let allowed_models = match state.repo.get_project_by_id(&context.project_id).await {
        Ok(Some(project)) => project.allowed_models,
        _ => None,
    };

    let granted_scopes = grant_scopes(&request.scope, &state.cfg.allowed_scopes);
    let offline = granted_scopes.iter().any(|s| s == OFFLINE_ACCESS_SCOPE);

    let (email, email_verified) = decode_email(subject_token);
    let owner = KeyOwner {
        subject: subject.clone(),
        email,
        email_verified,
    };

    let now = Utc::now();
    let session_id = cuid2();
    let signed = match state
        .signer
        .sign(
            &owner,
            &session_id,
            &context.project_id,
            &context.account_id,
            allowed_models,
            now,
            Some(now + Duration::seconds(state.cfg.access_ttl_seconds)),
        )
        .await
    {
        Ok(signed) => signed,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "access token signing failed",
            );
        }
    };

    let scope_str = scope_to_string(&granted_scopes);
    let refresh_token = if offline {
        let secret = generate_refresh_secret();
        let new = NewExchangeRefreshToken {
            id: cuid2(),
            subject: subject.clone(),
            account_id: context.account_id.clone(),
            project_id: context.project_id.clone(),
            token_hash: hash_api_key(&secret),
            scope: scope_str.clone(),
            created_at: now,
            expires_at: now + Duration::seconds(state.cfg.refresh_ttl_seconds),
        };
        match state.repo.create_exchange_refresh_token(new).await {
            Ok(_) => Some(secret),
            Err(_) => {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "refresh token persistence failed",
                );
            }
        }
    } else {
        None
    };

    tracing::info!(
        subject = %subject,
        account_id = %context.account_id,
        project_id = %context.project_id,
        offline,
        "token-exchange issued access token"
    );

    token_response(
        &signed.expires_at,
        now,
        Some(ACCESS_TOKEN_TYPE),
        refresh_token,
        scope_str,
        signed.token,
    )
}

async fn handle_refresh(state: &TokenExchangeState, request: TokenRequest) -> Response {
    if is_blank(&request.refresh_token) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    }
    let presented = request.refresh_token.as_deref().unwrap_or("").trim();
    let presented_hash = hash_api_key(presented);
    let now = Utc::now();

    let new_secret = generate_refresh_secret();
    let new_hash = hash_api_key(&new_secret);
    let new_expires_at = now + Duration::seconds(state.cfg.refresh_ttl_seconds);

    let rotated = match state
        .repo
        .rotate_exchange_refresh_token(&presented_hash, &cuid2(), &new_hash, new_expires_at, now)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token is invalid, expired, or already used",
            );
        }
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "refresh token rotation failed",
            );
        }
    };

    mint_from_refresh(state, &rotated, new_secret, now).await
}

async fn mint_from_refresh(
    state: &TokenExchangeState,
    session: &ExchangeRefreshTokenRow,
    new_secret: String,
    now: DateTime<Utc>,
) -> Response {
    let allowed_models = match state.repo.get_project_by_id(&session.project_id).await {
        Ok(Some(project)) => project.allowed_models,
        _ => None,
    };
    let owner = KeyOwner {
        subject: session.subject.clone(),
        email: None,
        email_verified: None,
    };
    let session_id = cuid2();
    let signed = match state
        .signer
        .sign(
            &owner,
            &session_id,
            &session.project_id,
            &session.account_id,
            allowed_models,
            now,
            Some(now + Duration::seconds(state.cfg.access_ttl_seconds)),
        )
        .await
    {
        Ok(signed) => signed,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "access token signing failed",
            );
        }
    };

    tracing::info!(
        subject = %session.subject,
        account_id = %session.account_id,
        project_id = %session.project_id,
        "token-exchange refreshed access token"
    );

    token_response(
        &signed.expires_at,
        now,
        None,
        Some(new_secret),
        session.scope.clone(),
        signed.token,
    )
}

fn token_response(
    expires_at: &DateTime<Utc>,
    now: DateTime<Utc>,
    issued_token_type: Option<&'static str>,
    refresh_token: Option<String>,
    scope: Option<String>,
    access_token: String,
) -> Response {
    let expires_in = (*expires_at - now).num_seconds().max(0);
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            issued_token_type,
            refresh_token,
            scope,
        }),
    )
        .into_response()
}

/// Intersects the client's requested scopes with the configured allow-list. An empty/absent
/// request grants the full allow-list (standard OAuth2 "default scope" behaviour).
fn grant_scopes(requested: &Option<String>, allowed: &[String]) -> Vec<String> {
    let requested: Vec<String> = requested
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if requested.is_empty() {
        return allowed.to_vec();
    }
    requested
        .into_iter()
        .filter(|scope| allowed.iter().any(|a| a == scope))
        .collect()
}

fn scope_to_string(scopes: &[String]) -> Option<String> {
    if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    }
}

fn generate_refresh_secret() -> String {
    let mut buf = [0u8; REFRESH_TOKEN_BYTES];
    OsRng.fill_bytes(&mut buf);
    format!(
        "{REFRESH_TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    )
}

/// Snapshots `email`/`email_verified` from the presented upstream token so the exchanged JWT
/// mirrors a Keycloak access token. Best-effort: a token without these claims yields `None`.
fn decode_email(bearer_token: &str) -> (Option<String>, Option<bool>) {
    let Some(payload) = bearer_token.split('.').nth(1) else {
        return (None, None);
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (None, None);
    };
    let email = value
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let email_verified = value
        .get("email_verified")
        .and_then(serde_json::Value::as_bool);
    (email, email_verified)
}
