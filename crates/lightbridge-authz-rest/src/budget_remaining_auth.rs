//! The credential in front of `GET /budget/v1/remaining` — ADR-0034's 2026-09-03 amendment.
//!
//! ## Why this exists at all, and why it is not mTLS
//!
//! ADR-0034 specified an **mTLS-only** listener, copying `lightbridge-authz-usage`'s query
//! listener (#347), where a verified client certificate is the whole access control and it is
//! enforced at the TLS handshake before any code here runs. That works there because the caller
//! is one of our own Rust services.
//!
//! It does not work here, and the reason is checkable rather than arguable. The only caller is
//! Authorino, as an AuthConfig `metadata` step, and the **deployed** CRD (Authorino v0.24.0,
//! `quay.io/kuadrant/authorino:v0.24.0`) offers no way to attach a client key/certificate to that
//! call:
//!
//! ```console
//! $ kubectl explain authconfigs.spec.metadata.http --api-version=authorino.kuadrant.io/v1beta3
//! FIELDS:
//!   body, bodyParameters, contentType, credentials, headers, method, oauth2,
//!   sharedSecretRef, url, urlExpression
//! ```
//!
//! No `tls`, no `clientCert`. The deployed pod mounts exactly one file — `ca.crt`, at
//! `/etc/pki/tls/certs/lightbridge-ca.crt` — which lets it *verify* our server certificate and
//! nothing more. An mTLS-only listener here would be unreachable by the one client it exists for:
//! every metadata fetch would fail the handshake, Authorino would leave the value absent, and the
//! gateway would read that as `budget_unavailable` on every single request.
//!
//! So the endpoint takes the credential Authorino **can** send: a `sharedSecretRef` value, placed
//! in a custom header by `credentials.customHeader`. Three properties make that an honest
//! substitute rather than a downgrade dressed up as one:
//!
//! 1. **The channel is still TLS**, verified against the internal CA, so the secret is not on the
//!    wire in clear and the caller still authenticates *us*.
//! 2. **The secret lives in the same Kubernetes Secret both ends read** — this listener through
//!    the config's `${VAR}` interpolation, Authorino through `sharedSecretRef` — so they cannot
//!    drift into a state where one side thinks it is authenticated and the other does not.
//! 3. **It is defence in depth, not the only layer**: a NetworkPolicy restricts port 3007 to the
//!    gateway namespace, so a leaked secret alone does not reach the listener from an arbitrary
//!    pod.
//!
//! What it gives up against mTLS is real and worth naming: a bearer secret is replayable by
//! anything that can read it, where a private key is not, and rotation is a two-sided values
//! change rather than a certificate renewal. That is the price of Authorino v0.24.0 not having
//! the field. The day it does, this module is deleted and `tls.client_ca_bundle_path` comes back.
//!
//! ## The two refusals
//!
//! | Condition | Status | `error` |
//! |---|---|---|
//! | An `Authorization` header is present | `403` | `forbidden` |
//! | The shared-secret header is missing or wrong | `401` | `unauthorized` |
//!
//! The `Authorization` check runs **first** and is not a credential check: this route has no
//! business ever receiving a user's bearer token, and a proxy misconfigured to forward one must
//! fail loudly instead of quietly answering a cross-account question. Answering `401` there would
//! invite a retry with a *different* token; `403` says the header itself is the problem.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};

use crate::budget_remaining::BudgetInternalState;
use crate::budget_remaining_wire::error_response;

/// Stable `error` token for a missing or wrong shared secret.
pub const ERROR_UNAUTHORIZED: &str = "unauthorized";

/// Compares two secrets without leaking, through timing, how far a wrong guess got.
///
/// Both sides are hashed first, so the comparison is over two fixed 32-byte digests and the loop
/// count cannot leak the secret's length either. `black_box` keeps the accumulator opaque to the
/// optimiser, which is otherwise free to turn the fold into an early return.
fn secrets_match(presented: &[u8], expected: &[u8]) -> bool {
    let presented = Sha256::digest(presented);
    let expected = Sha256::digest(expected);
    let mut diff = 0u8;
    for (a, b) in presented.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    std::hint::black_box(diff) == 0
}

/// Layered over [`crate::budget_remaining::budget_remaining_router`]. See the module doc comment.
pub async fn require_shared_secret(
    State(state): State<Arc<BudgetInternalState>>,
    req: Request,
    next: Next,
) -> Response {
    if req.headers().contains_key(header::AUTHORIZATION) {
        tracing::warn!(
            "budget_remaining: refusing a request carrying an Authorization header -- this is a \
             service-to-service route with no per-caller ownership check"
        );
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this endpoint does not accept an Authorization header".to_string(),
        );
    }

    let presented = req
        .headers()
        .get(&state.shared_secret_header)
        .map(axum::http::HeaderValue::as_bytes);

    // A missing header and a wrong value are the same answer on purpose: distinguishing them tells
    // a prober whether it guessed the header NAME right, which is free information about the
    // deployment it should not get.
    let authorized =
        presented.is_some_and(|value| secrets_match(value, state.shared_secret.as_bytes()));
    if !authorized {
        tracing::warn!(
            header = %state.shared_secret_header,
            presented = presented.is_some(),
            "budget_remaining: refusing a request without the configured shared secret"
        );
        return error_response(
            StatusCode::UNAUTHORIZED,
            ERROR_UNAUTHORIZED,
            "a valid shared secret is required".to_string(),
        );
    }

    next.run(req).await
}

/// Validates `server.budget_internal` at startup and returns the header name the middleware will
/// read, or the reason the listener must not bind.
///
/// Lives here rather than inline in `start_budget_server` for the same reason
/// [`require_shared_secret`] does: the two are one policy — *what makes a caller legitimate on
/// this listener* — and `lib.rs` sits on its LoC-gate baseline. Code moved, not rewritten.
///
/// Two refusals, both fail-closed and both loud:
///
/// - an **empty** `shared_secret`, because it is the only access control in front of a
///   cross-account balance read and serving the port without it is the silent degrade this
///   codebase's rule forbids; and
/// - a **present** `tls.client_ca_bundle_path`, which is not a stricter configuration here but a
///   broken one — see the module doc comment. Discovering that in production, as a 100 %
///   `budget_unavailable` rate, is exactly what this check exists to prevent.
pub fn validate_budget_internal(
    internal: &lightbridge_authz_core::config::BudgetInternalServer,
    route: &str,
) -> Result<axum::http::HeaderName, String> {
    if internal.shared_secret.trim().is_empty() {
        return Err(format!(
            "server.budget_internal.shared_secret is required: {route} is a cross-account service \
             read gated ONLY by that secret"
        ));
    }
    if internal.tls.client_ca_bundle_path.is_some() {
        return Err(format!(
            "server.budget_internal.tls.client_ca_bundle_path must be unset: Authorino cannot \
             present a client certificate, so requiring one makes {route} unreachable by its only \
             caller"
        ));
    }
    axum::http::HeaderName::try_from(internal.shared_secret_header.to_ascii_lowercase()).map_err(
        |e| format!("server.budget_internal.shared_secret_header is not a valid header name: {e}"),
    )
}

#[cfg(test)]
mod tests {
    use super::secrets_match;

    #[test]
    fn an_identical_secret_matches() {
        assert!(secrets_match(b"s3cr3t", b"s3cr3t"));
    }

    #[test]
    fn a_different_secret_does_not_match() {
        assert!(!secrets_match(b"s3cr3t", b"s3cr3u"));
    }

    /// The hash-then-compare shape must not accidentally make a prefix look equal.
    #[test]
    fn a_prefix_of_the_secret_does_not_match() {
        assert!(!secrets_match(b"s3cr", b"s3cr3t"));
    }

    #[test]
    fn an_empty_presented_secret_does_not_match_a_real_one() {
        assert!(!secrets_match(b"", b"s3cr3t"));
    }
}
