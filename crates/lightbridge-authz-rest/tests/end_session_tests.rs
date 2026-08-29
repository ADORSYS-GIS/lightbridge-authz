// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! The open-redirect boundary of `/oauth2/end_session` (OIDC RP-Initiated Logout 1.0).
//!
//! `resolve_post_logout_redirect` decides, on its own, whether an attacker-supplied URL becomes a
//! `Location` header served to a user who has just authenticated. Everything else about logout is
//! recoverable; this is not. So the hostile shapes are asserted one by one rather than left to a
//! single happy-path test:
//!
//! - a scheme swap on a registered host,
//! - a host that merely *contains* or *extends* a registered one,
//! - a path or query appended to a registered URL,
//! - a URL registered to a DIFFERENT client,
//! - a request naming no client at all.
//!
//! Each of these passes under some plausible-but-wrong relaxation of the check (`starts_with`,
//! origin comparison, "search every client's list"), and each is a real reported OAuth
//! redirect-validation bug class. An exact-match implementation refuses all of them; a test per
//! shape is what stops a future "let's be lenient about trailing slashes" from reopening one.
//!
//! Mutation-checked: replacing the `iter().any(|uri| uri == requested)` predicate with
//! `iter().any(|uri| requested.starts_with(uri))` turns `a_path_appended_to_a_registered_uri_is_
//! refused` and `a_query_appended_to_a_registered_uri_is_refused` red, and dropping the
//! `registry.get(client_id?)` scoping turns `a_uri_registered_to_another_client_is_refused` red.

use std::collections::HashMap;

use lightbridge_authz_rest::post_logout::resolve_post_logout_redirect;

const CONSOLE: &str = "lightbridge-console";
const REGISTERED: &str = "https://console.ai.camer.digital/signed-out";

fn registry() -> HashMap<String, Vec<String>> {
    HashMap::from([
        (CONSOLE.to_string(), vec![REGISTERED.to_string()]),
        (
            "other-client".to_string(),
            vec!["https://elsewhere.example.test/bye".to_string()],
        ),
        ("no-logout-client".to_string(), Vec::new()),
    ])
}

fn resolve(client_id: Option<&str>, requested: Option<&str>) -> Option<String> {
    resolve_post_logout_redirect(&registry(), client_id, requested, None)
}

#[test]
fn an_exactly_registered_uri_is_honoured() {
    assert_eq!(
        resolve(Some(CONSOLE), Some(REGISTERED)).as_deref(),
        Some(REGISTERED),
        "the whole point of registering a logout URI is that it is then usable"
    );
}

/// OIDC RP-Initiated Logout 1.0 §2: `state` is round-tripped to the RP so it can correlate the
/// logout it started. Appended as a query parameter rather than string-concatenated, so a
/// registered URI that already carries a query still produces one valid URL.
#[test]
fn state_is_appended_as_a_query_parameter() {
    let with_state =
        resolve_post_logout_redirect(&registry(), Some(CONSOLE), Some(REGISTERED), Some("xyz789"))
            .expect("a registered uri with state still resolves");
    assert_eq!(with_state, format!("{REGISTERED}?state=xyz789"));
}

#[test]
fn state_is_appended_to_a_registered_uri_that_already_has_a_query() {
    let registered = "https://console.ai.camer.digital/signed-out?from=console";
    let registry = HashMap::from([(CONSOLE.to_string(), vec![registered.to_string()])]);
    let resolved =
        resolve_post_logout_redirect(&registry, Some(CONSOLE), Some(registered), Some("xyz789"))
            .expect("a registered uri with an existing query still resolves");
    assert_eq!(
        resolved, "https://console.ai.camer.digital/signed-out?from=console&state=xyz789",
        "state must be appended to the existing query, never replace it"
    );
}

#[test]
fn an_unregistered_uri_is_refused() {
    assert_eq!(
        resolve(Some(CONSOLE), Some("https://attacker.example/steal")),
        None
    );
}

/// `https` -> `http` on an otherwise-registered URL. Refused by exact match; honoured by any
/// check that compares only host and path.
#[test]
fn a_scheme_downgrade_on_a_registered_uri_is_refused() {
    assert_eq!(
        resolve(
            Some(CONSOLE),
            Some("http://console.ai.camer.digital/signed-out")
        ),
        None
    );
}

/// The classic suffix attack: `console.ai.camer.digital.attacker.example` contains the registered
/// host as a prefix, and `evil-console.ai.camer.digital` contains it as a suffix.
#[test]
fn a_lookalike_host_is_refused() {
    for hostile in [
        "https://console.ai.camer.digital.attacker.example/signed-out",
        "https://evil-console.ai.camer.digital/signed-out",
    ] {
        assert_eq!(
            resolve(Some(CONSOLE), Some(hostile)),
            None,
            "{hostile} must not be treated as the registered host"
        );
    }
}

#[test]
fn a_path_appended_to_a_registered_uri_is_refused() {
    assert_eq!(
        resolve(
            Some(CONSOLE),
            Some(&format!("{REGISTERED}/../../elsewhere"))
        ),
        None
    );
}

#[test]
fn a_query_appended_to_a_registered_uri_is_refused() {
    assert_eq!(
        resolve(
            Some(CONSOLE),
            Some(&format!("{REGISTERED}?next=//attacker"))
        ),
        None,
        "a registered URI is registered exactly; a caller-supplied query is not part of it"
    );
}

/// Registration is per-client. A URI registered by `other-client` must not become reachable just
/// because the request names `lightbridge-console`.
#[test]
fn a_uri_registered_to_another_client_is_refused() {
    assert_eq!(
        resolve(Some(CONSOLE), Some("https://elsewhere.example.test/bye")),
        None
    );
}

#[test]
fn an_unknown_client_is_refused() {
    assert_eq!(resolve(Some("never-registered"), Some(REGISTERED)), None);
}

/// A client that registered no logout URIs cannot redirect anywhere -- the empty list is a real
/// answer ("this client does not do redirects"), not a wildcard.
#[test]
fn a_client_with_no_registered_logout_uris_is_refused() {
    assert_eq!(resolve(Some("no-logout-client"), Some(REGISTERED)), None);
}

/// Without a `client_id` (and without a verifiable `id_token_hint` to supply one) there is no
/// registration list to check against, so there is nothing that could make a redirect safe.
#[test]
fn a_request_naming_no_client_is_refused() {
    assert_eq!(resolve(None, Some(REGISTERED)), None);
}

/// Not an error: RP-Initiated Logout makes `post_logout_redirect_uri` optional, and its absence
/// simply means the OP renders its own confirmation page.
#[test]
fn no_requested_uri_resolves_to_no_redirect() {
    assert_eq!(resolve(Some(CONSOLE), None), None);
}
