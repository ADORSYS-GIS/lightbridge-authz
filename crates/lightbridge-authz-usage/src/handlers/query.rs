use crate::UsageState;
use crate::models::{UsageErrorResponse, UsageQueryRequest, UsageQueryResponse, UsageScope};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use lightbridge_authz_core::{Error, Permission, Result};
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Extracts a bearer token from `Authorization: Bearer <token>` (case-insensitive on `Bearer`,
/// mirroring `lightbridge_authz_rest::middleware::bearer_auth`'s own extraction so the two
/// services parse the same header shape identically). `None` for a missing header, an empty
/// value, or a value that is not a `Bearer` credential.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?
        .trim();
    if value.is_empty() {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if !lower.starts_with("bearer ") {
        return None;
    }
    let token = value[7..].trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// `401` with a `WWW-Authenticate: Bearer` challenge, exactly as `bearer_auth` middleware on the
/// authz-api side responds. Deliberately opaque -- no distinction between "missing header" and
/// "token failed validation" is surfaced.
fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// `403` with a deliberately opaque body (#570's acceptance criteria) -- unlike
/// `handlers::idp::authorize_usage_scope`'s uniform-`404` convention on the authz-opa side (which
/// exists to avoid leaking whether a `scope_id` exists at all), this endpoint's caller already
/// knows exactly which scope/scope_id they asked for, so there is no oracle to protect; `403` is
/// the correct, standard "authenticated but not authorized" status here, not a borrowed 404.
fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

#[utoipa::path(
    post,
    path = "/usage/v1/usage/query",
    request_body = UsageQueryRequest,
    responses(
        (status = 200, body = UsageQueryResponse),
        (status = 400, body = UsageErrorResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Authenticated but not authorized for the requested scope")
    ),
    tag = "usage"
)]
// `input` is deliberately skipped too (not just `state`/`headers`): `#[instrument]` records every
// non-skipped parameter into the span at function ENTRY, before any code in this body runs -- so
// leaving `input` unskipped would still have put `scope_id` into the trace span for an
// unauthenticated caller no matter where the `info!` call below moved to. The `info!` line after
// the bearer check is what actually logs the request's shape now, and only once the caller is
// authenticated.
#[instrument(skip(state, headers, input))]
pub async fn query_usage(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    Json(input): Json<UsageQueryRequest>,
) -> Result<Response> {
    // #570: authentication runs BEFORE body validation, deliberately -- an unauthenticated caller
    // must never be able to distinguish a well-formed from a malformed request (a differentiated
    // 400 is itself a signal), and `input.scope_id` must never reach this span (or any other log
    // line) before the caller presenting it has been authenticated. This is the query listener's
    // own authentication boundary, layered on top of the mTLS the listener already requires at
    // the TLS level. A missing/invalid token is "unknown", which per AGENTS.md's fail-closed rule
    // routes to the strictest branch: refuse, never proceed, and never validate the body first.
    let Some(token) = extract_bearer_token(&headers) else {
        warn!("query_usage: no bearer token presented");
        return Ok(unauthorized());
    };

    let token_info = match state.bearer.validate_bearer_token(&token).await {
        Ok(info) if info.active => info,
        Ok(_) => {
            warn!("query_usage: bearer token validated but not active");
            return Ok(unauthorized());
        }
        Err(err) => {
            warn!(error = %err, "query_usage: bearer token validation failed");
            return Ok(unauthorized());
        }
    };

    info!(
        "querying usage with scope={:?}, scope_id={}, bucket={}, limit={}",
        input.scope, input.scope_id, input.bucket, input.limit
    );
    if input.start_time >= input.end_time {
        warn!(
            "invalid time range: start_time={} end_time={}",
            input.start_time, input.end_time
        );
        return Err(Error::BadRequest(
            "start_time must be before end_time".to_string(),
        ));
    }

    // `scope_id` stays a required wire field (`UsageQueryRequest::scope_id` is not `Option`) for
    // every scope, but `UsageScope::All` has no `scope_id` to validate -- there is no single ID an
    // estate-wide query is "about" -- so an empty value is the documented, expected shape for that
    // one scope and must not be rejected here.
    if !matches!(input.scope, UsageScope::All) && input.scope_id.trim().is_empty() {
        warn!("missing scope_id for usage query");
        return Err(Error::BadRequest(
            "scope_id is required for usage queries".to_string(),
        ));
    }

    if input.limit == 0 {
        warn!("invalid limit for usage query: limit=0");
        return Err(Error::BadRequest(
            "limit must be greater than zero".to_string(),
        ));
    }

    // #648: `filters.operation_in` is a CLOSED vocabulary, so an unknown entry is a 400 here and
    // not an empty result set from the repo -- a caller who typed `chat` instead of
    // `chat_completions` deserves to be told, not handed a blank chart that looks like "no usage".
    input.filters.validate()?;

    // #648: the admin bypass. A caller holding `usage:read-all` -- the same coarse RBAC permission
    // that already unlocks the estate-wide `scope=all` -- may read ANY `scope_id` under
    // `user`/`project`/`account`. Without it those three scopes are strictly WIDER than `all` is
    // narrow: `scope=all` already returns every row in the estate to this exact permission
    // holder, so refusing them the same data sliced by one account is not a security boundary, it
    // is a missing feature (it is why `/admin/usage`'s per-actor pages cannot be built today).
    //
    // What this does NOT do, deliberately: it does not touch `scope=api_key` (still refused for
    // everyone -- there is no ownership authority for a raw `api_key_id` and an admin bypass would
    // not create one), and it does not weaken anything for a caller WITHOUT the permission --
    // `scope=user` stays self-only and `scope=account`/`project` still go through
    // `scope_authority`, unchanged.
    let is_usage_admin = token_info.has_permission(Permission::UsageReadAll);

    match &input.scope {
        // Self-ownership (or `usage:read-all`, #648): the caller reading their OWN usage.
        // `user_id` is never a row any `accounts`/`projects` table is keyed by, so there is no
        // `scope_authority` predicate to call for it (unlike account/project) -- but "is this token's own subject" needs no
        // remote call at all, it is answered entirely from the already-JWKS-validated
        // `token_info.sub`. Any `scope_id` other than the caller's own subject is refused --
        // there is still no ownership predicate that would let a caller read someone ELSE's
        // per-user usage -- unless they hold `usage:read-all`, which already entitles them to
        // every one of those rows through `scope=all` anyway.
        UsageScope::User => {
            if !is_usage_admin && input.scope_id != token_info.sub {
                warn!(
                    scope = ?input.scope,
                    "query_usage: scope=user requested for a subject other than the caller's own; refusing"
                );
                return Ok(forbidden());
            }
        }
        // `api_key` has no resolvable ownership authority at all (no `accounts`/`projects` row is
        // ever keyed by a raw `api_key_id`) and no caller-subject shortcut either (an API key's
        // bearer token, if one even existed here, is not "the API key itself") -- refused
        // unconditionally, matching the console's own guard, and never reaching `scope_authority`.
        // #648's admin bypass deliberately stops short of this arm: `usage:read-all` grants a
        // caller data they are already entitled to under `scope=all`, and no amount of permission
        // conjures the ownership authority this scope has never had.
        UsageScope::ApiKey => {
            warn!(
                scope = ?input.scope,
                "query_usage: scope has no resolvable ownership authority; refusing"
            );
            return Ok(forbidden());
        }
        // Estate-wide: no per-row ownership predicate exists for "everything", by definition, so
        // this is gated on a coarse RBAC permission instead -- the SAME `Permission::UsageReadAll`
        // check regardless of what (if anything) `scope_id` was set to (already validated above to
        // be the "ignored" empty-or-anything shape `UsageScope::All` documents).
        UsageScope::All => {
            if !is_usage_admin {
                warn!(
                    scope = ?input.scope,
                    "query_usage: scope=all requires usage:read-all; refusing"
                );
                return Ok(forbidden());
            }
        }
        UsageScope::Account | UsageScope::Project => {
            if is_usage_admin {
                info!(
                    scope = ?input.scope,
                    "query_usage: usage:read-all holder; skipping the ownership round trip"
                );
            } else {
                let authorized = state
                    .scope_authority
                    .authorize(
                        &token_info.iss,
                        &token_info.sub,
                        &input.scope,
                        &input.scope_id,
                    )
                    .await?;
                if !authorized {
                    warn!(
                        scope = ?input.scope,
                        scope_id = %input.scope_id,
                        "query_usage: scope authority refused the requested scope"
                    );
                    return Ok(forbidden());
                }
            }
        }
    }

    // Captured BEFORE the query so the echo describes what was ASKED for, not what came back --
    // a response with zero points still has to say whether percentiles were computed.
    let metrics = input.effective_metrics();
    let (points, truncated) = state.repo.query_usage(&input).await?;

    // P1-5: `/usage/v1/usage/query` reads raw `usage_events` only (the rollup does not carry
    // latency percentiles), so a request whose range extends before the raw retention window has
    // silently no data there. `truncated` is the published field whose job (#578) is to say "we
    // dropped data", so OR in a range-truncation flag rather than report `truncated: false` for a
    // range the API cannot answer.
    let range_truncated = input.start_time < Utc::now() - chrono::Duration::days(state.raw_days);
    let truncated = truncated || range_truncated;

    Ok((
        StatusCode::OK,
        Json(UsageQueryResponse {
            points,
            truncated,
            metrics,
        }),
    )
        .into_response())
}
