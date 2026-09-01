//! The one minimal HTML shell every browser-facing `authz-idp` page renders into.
//!
//! Extracted from `claim_redeem` when `end_session` needed the same thing. Shared rather than
//! copied specifically because of [`secure_headers`]: it is a security posture, not styling, and
//! two divergent copies of a CSP is how one page quietly loses its `frame-ancestors` and becomes
//! clickjackable while the other stays fine.
//!
//! Deliberately no templating engine, no external assets, and no script. These pages are reached
//! mid-flow by a browser that may be carrying a live session cookie; the CSP below forbids script
//! and every network origin, so nothing rendered here can read or exfiltrate anything.

use axum::http::header;

/// Escapes a value interpolated into element content. Every current caller passes a
/// server-generated string, so this is defence in depth rather than the primary control -- but the
/// primary control is "we happen to trust the source", which is exactly the property that stops
/// holding the day someone adds a caller.
pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Response headers for every page built by [`page`].
///
/// `no-store` keeps page content out of the browser's disk cache and out of intermediaries;
/// `no-referrer` stops a path segment (a claim token, a `state`) leaking through `Referer` if the
/// page ever links out; the CSP forbids script and every external origin, so nothing on the page
/// can exfiltrate what it displays, and `frame-ancestors 'none'` keeps it out of an attacker's
/// iframe.
pub fn secure_headers() -> [(header::HeaderName, &'static str); 4] {
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

/// Wraps `body` in the shared document shell. `title` and `body` are interpolated as-is -- callers
/// pass literals, and anything derived from a request must go through [`escape`] first.
pub fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"robots\" content=\"noindex,nofollow\"><title>{title}</title>\
         <style>body{{font:16px system-ui,sans-serif;margin:3rem auto;max-width:34rem;padding:0 1rem}}\
         code{{display:block;padding:.75rem;background:#f4f4f5;border-radius:6px;word-break:break-all}}\
         p{{color:#3f3f46}}</style></head><body>{body}</body></html>"
    )
}
