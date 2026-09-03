//! RFC 8252 §7.3 loopback redirect-URI support for public native-app clients.
//!
//! Native apps that receive the OAuth redirect on a loopback listener cannot bind a fixed port:
//! the port is whatever the operating system hands out at login time. RFC 8252 §7.3 therefore
//! requires an authorization server to "allow any port to be specified at the time of the request
//! for loopback IP redirect URIs". The registry this service validates against
//! (`ClientRegistration::allows_redirect_uri`, a plain `==`) cannot express that, so the rule is
//! implemented here as a *narrow* second chance that runs only after the exact match has failed.
//!
//! Two halves, in two files so each stays inside the 200-LoC house rule (plus a third holding
//! the fixtures both test modules share):
//! - [`redirect`] — the rule itself: which requested URIs the carve-out admits.
//! - [`code`] — code issuance for an admitted URI, which the vendored `handle_authorize` would
//!   otherwise refuse with its own exact-match re-check.
//!
//! `docs/rfc-8252-loopback-redirects.md` is the prose source of truth, diagrams included.

pub mod code;
#[cfg(test)]
pub(crate) mod fixtures;
pub mod redirect;

pub(crate) use code::issue_loopback_code;
pub(crate) use redirect::is_loopback_redirect;
