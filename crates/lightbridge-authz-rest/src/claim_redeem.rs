//! `GET /api-keys/claim/{token}` -- the human-facing half of secret-claim delivery
//! (GHSA-9pc6-965v-2c44, #538).
//!
//! `lightbridge-mcp` hands the claim token back through a tool result, which means the token
//! reaches the calling model. That is expected and safe **only because this route requires more
//! than the token**: the caller must also present a live `__Host-authz_session` browser session
//! whose subject matches the one that created the key. A model has no such cookie and cannot
//! obtain one, so a token in its context is inert.
//!
//! Every refusal answers the same way and never says why. Distinguishing "no such claim" from
//! "not yours" from "already redeemed" would turn this route into an oracle for which tokens
//! exist; the redeemer learns only that they get nothing.
//!
//! Session lookup binds on `sessions.subject`, never `sessions.account_id`. `account_id` holds
//! the PROJECT's owning account and is identical across every session minted against that project
//! regardless of which real person is acting (`StoreRepo::revoke_sessions_for_subject`'s comment
//! records the incident that taught this). Binding a credential handover to it would let any
//! member of a project collect another member's key.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chrono::Utc;
use lightbridge_authz_api_key::repo::StoreRepo;

use crate::secret_claim::SecretClaimStore;
use crate::session_cookie::read_session_cookie;

#[derive(Clone)]
pub struct ClaimRedeemState {
    pub claims: Arc<SecretClaimStore>,
    pub repo: Arc<StoreRepo>,
}

/// Minimal escaping for the one untrusted-ish value this page interpolates. The secret is
/// server-generated, but it is rendered inside an element, so it is escaped rather than trusted
/// on the strength of where it came from.
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Headers applied to every response from this route. `no-store` keeps the secret out of the
/// browser's disk cache and out of intermediary caches; `no-referrer` stops the claim token
/// leaking through a `Referer` header if the page ever links out; the CSP forbids any script or
/// external fetch, so nothing on the page can exfiltrate what it displays.
fn secure_headers() -> [(header::HeaderName, &'static str); 4] {
    [
        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    ]
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"robots\" content=\"noindex,nofollow\"><title>{title}</title>\
         <style>body{{font:16px system-ui,sans-serif;margin:3rem auto;max-width:34rem;padding:0 1rem}}\
         code{{display:block;padding:.75rem;background:#f4f4f5;border-radius:6px;word-break:break-all}}\
         p{{color:#3f3f46}}</style></head><body>{body}</body></html>"
    )
}

/// Deliberately identical for every failure: unknown token, expired, already redeemed, or owned by
/// someone else. See the module comment on why this is not a usability regression.
fn unavailable() -> Response {
    (
        StatusCode::NOT_FOUND,
        secure_headers(),
        page(
            "Nothing to collect",
            "<h1>Nothing to collect</h1><p>This link is not valid. A key secret can be collected \
             once, by the person who created it, within a few minutes of creation. If that window \
             has passed, rotate the key to get a new one.</p>",
        ),
    )
        .into_response()
}

async fn redeem(
    State(state): State<ClaimRedeemState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(session_id) = read_session_cookie(&headers) else {
        // No session at all. This is the case a model holding the token lands in, and the only
        // one worth distinguishing -- telling a real human to sign in is useful, and it reveals
        // nothing about whether the claim exists.
        return (
            StatusCode::UNAUTHORIZED,
            secure_headers(),
            page(
                "Sign in required",
                "<h1>Sign in required</h1><p>Collecting a key secret requires being signed in as \
                 the person who created it. Sign in, then open this link again.</p>",
            ),
        )
            .into_response();
    };

    let session = match state
        .repo
        .find_active_browser_session(&session_id, Utc::now())
        .await
    {
        Ok(Some(session)) => session,
        // An expired or revoked session is not an error, and is not a claim miss either.
        Ok(None) => return unavailable(),
        Err(error) => {
            tracing::error!(?error, "secret claim redemption failed: session lookup");
            return store_unavailable();
        }
    };

    // `subject` is `None` only for a session row predating
    // `migrations/20260824000003_sessions_add_subject.sql`. Fail closed, exactly as `authorize.rs`
    // does: falling back to `account_id` would be the identity-substitution bug that column was
    // added to fix, and here it would hand one project member another member's key.
    let Some(subject) = session.subject else {
        return unavailable();
    };

    match state.claims.redeem(&token, &subject).await {
        Ok(Some(secret)) => (
            StatusCode::OK,
            secure_headers(),
            page(
                "Your API key secret",
                &format!(
                    "<h1>Your API key secret</h1><p>Copy it now. It is shown once and cannot be \
                     retrieved again.</p><code>{}</code>",
                    escape(&secret)
                ),
            ),
        )
            .into_response(),
        Ok(None) => unavailable(),
        Err(error) => {
            tracing::error!(?error, "secret claim redemption failed: claim store");
            store_unavailable()
        }
    }
}

/// The store being unreachable is the one case that must NOT read as "no such claim": the claim
/// may well still be there, and telling the user it is gone would send them to rotate a key they
/// could still have collected.
fn store_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        secure_headers(),
        page(
            "Temporarily unavailable",
            "<h1>Temporarily unavailable</h1><p>Your secret could not be retrieved right now. \
             This link has not been used up — try again shortly.</p>",
        ),
    )
        .into_response()
}

pub fn router(state: ClaimRedeemState) -> Router {
    Router::new()
        .route("/api-keys/claim/{token}", get(redeem))
        .with_state(state)
}
