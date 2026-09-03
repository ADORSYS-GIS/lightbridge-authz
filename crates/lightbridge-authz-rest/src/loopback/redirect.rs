//! The RFC 8252 §7.3 rule: which loopback redirect URIs `/authorize` admits.
//!
//! **The rule, stated once, normatively** — a requested `redirect_uri` that failed the registry's
//! exact match is admitted if and only if all of the following hold:
//!
//! 1. The client is **public** (`token_endpoint_auth_method == NoAuth`). A native app ships to
//!    laptops and holds no secret; a confidential client has no reason to redirect to loopback.
//! 2. The requested URI uses the **`http` scheme** and its host is a **loopback IP literal** --
//!    `127.0.0.1` or `[::1]`, and nothing else. `http://localhost:…` is **rejected**: RFC 8252
//!    §8.3 says its use is NOT RECOMMENDED, because `localhost` goes through name resolution and
//!    can be pointed off-host, which is exactly the property the IP literal removes. This is the
//!    RFC-strict reading; it is a deliberate policy choice, not an oversight (see the PR body).
//! 3. It carries **no fragment** (RFC 6749 §3.1.2 forbids one on a redirection endpoint).
//! 4. It matches one of the client's **registered** loopback URIs on scheme, host, path and
//!    query **exactly** -- the **port is the only component allowed to differ**. §7.3's carve-out
//!    is "any port", not "any path": without the path check, one registered loopback entry would
//!    admit every path on every loopback port, so a local process that wins the port race would
//!    only need the `client_id`, not the registered path, to receive `code` + `state`.
//!
//! Everything else is unchanged: an exact registry match is still tried first and still wins, so
//! existing clients (including the five fixed `127.0.0.1:174xx/callback` ports
//! `governance-auth-cli` pins today) behave exactly as before.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use authkestra_op::client::{ClientRegistration, TokenEndpointAuthMethod};

/// Whether the RFC 8252 §7.3 carve-out admits `redirect_uri` for `client`. See the module docs
/// for the rule; this function is the only place it is decided.
pub(crate) fn is_loopback_redirect(client: &ClientRegistration, redirect_uri: &str) -> bool {
    // Fail closed on anything that is not explicitly `NoAuth`. `None` (a registration predating
    // the field) is documented upstream as behaving like a public client when it also has no
    // `client_secret_hash`, so it is *arguably* eligible -- but `to_registration`
    // (`oauth2_op/client_store.rs`) is the only production constructor and always sets `Some(..)`,
    // so widening the gate on that reasoning would buy nothing and cost the fail-closed default.
    if client.token_endpoint_auth_method != Some(TokenEndpointAuthMethod::NoAuth) {
        return false;
    }
    let Some(requested) = LoopbackRedirect::parse(redirect_uri) else {
        return false;
    };
    client
        .redirect_uris
        .iter()
        .filter_map(|registered| LoopbackRedirect::parse(registered))
        .any(|registered| registered.matches_ignoring_port(&requested))
}

/// A parsed loopback redirect URI, reduced to the components the rule compares. The port is
/// deliberately absent: it is the one component §7.3 lets float.
#[derive(Debug, PartialEq, Eq)]
struct LoopbackRedirect {
    host: IpAddr,
    path: String,
    query: Option<String>,
}

impl LoopbackRedirect {
    /// Parses `uri` if -- and only if -- it is a loopback redirect URI in the RFC-strict sense
    /// (rule points 2 and 3 above). Returns `None` for every other input, including `localhost`,
    /// a non-`http` scheme, a non-loopback IP, a hostname that merely *contains* a loopback
    /// literal (`127.0.0.1.evil.example`, which parses as a domain, not an address), and anything
    /// that is not a URL at all.
    fn parse(uri: &str) -> Option<Self> {
        let url = reqwest::Url::parse(uri).ok()?;
        if url.scheme() != "http" || url.fragment().is_some() {
            return None;
        }
        // `host_str()` renders an IPv6 host bracketed (`[::1]`); strip the brackets so both
        // families go through the same `IpAddr` parse. A domain host (`localhost`, or any
        // `127.0.0.1.<something>`) fails that parse and is rejected here.
        let host: IpAddr = url.host_str()?.trim_matches(['[', ']']).parse().ok()?;
        if host != IpAddr::V4(Ipv4Addr::LOCALHOST) && host != IpAddr::V6(Ipv6Addr::LOCALHOST) {
            return None;
        }
        Some(Self {
            host,
            path: url.path().to_owned(),
            query: url.query().map(str::to_owned),
        })
    }

    /// Whether `self` (a registered URI) and `requested` differ in nothing but the port.
    fn matches_ignoring_port(&self, requested: &Self) -> bool {
        self == requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::fixtures::{
        confidential_client_with_loopback, public_client, public_client_with_loopback,
    };

    /// Rule point 4, the reason this PR exists: the registered port is `17452`, the browser comes
    /// back on an ephemeral one, and only the port differs -- so it is admitted.
    #[test]
    fn a_different_port_on_a_registered_loopback_path_is_admitted() {
        let client = public_client_with_loopback();
        assert!(is_loopback_redirect(
            &client,
            "http://127.0.0.1:54321/callback"
        ));
        // No port at all is still "a port that differs".
        assert!(is_loopback_redirect(&client, "http://127.0.0.1/callback"));
        // And the registered URI itself, unchanged.
        assert!(is_loopback_redirect(
            &client,
            "http://127.0.0.1:17452/callback"
        ));
    }

    /// Rule point 4: the port floats, the path does not.
    #[test]
    fn a_path_that_is_not_the_registered_one_is_rejected() {
        let client = public_client_with_loopback();
        assert!(!is_loopback_redirect(
            &client,
            "http://127.0.0.1:54321/totally-different"
        ));
        assert!(!is_loopback_redirect(&client, "http://127.0.0.1:54321/"));
        // A query the registration does not carry is a mismatch too.
        assert!(!is_loopback_redirect(
            &client,
            "http://127.0.0.1:54321/callback?x=1"
        ));
        // A fragment is refused outright (RFC 6749 §3.1.2).
        assert!(!is_loopback_redirect(
            &client,
            "http://127.0.0.1:54321/callback#frag"
        ));
    }

    /// Rule point 2, the RFC-strict half: IPv6 loopback is in, `localhost` is out.
    #[test]
    fn ipv6_loopback_is_admitted_and_localhost_is_rejected() {
        let mut client = public_client_with_loopback();
        client.redirect_uris = vec!["http://[::1]/callback".into()];
        assert!(is_loopback_redirect(&client, "http://[::1]:9000/callback"));
        // The fully expanded IPv6 literal is the same address, and is admitted.
        assert!(is_loopback_redirect(
            &client,
            "http://[0:0:0:0:0:0:0:1]:9000/callback"
        ));
        // `localhost` is NOT RECOMMENDED by RFC 8252 §8.3 and is refused on both sides of the
        // comparison: as the requested URI, and as a registration that could admit one.
        assert!(!is_loopback_redirect(
            &client,
            "http://localhost:9000/callback"
        ));
        let mut localhost_client = public_client_with_loopback();
        localhost_client.redirect_uris = vec!["http://localhost/callback".into()];
        assert!(!is_loopback_redirect(
            &localhost_client,
            "http://localhost:9000/callback"
        ));
    }

    /// Rule point 2: a non-loopback host never reaches the carve-out, however it is dressed up.
    #[test]
    fn a_non_loopback_host_is_rejected() {
        let client = public_client_with_loopback();
        assert!(!is_loopback_redirect(
            &client,
            "https://rp.example.test/callback"
        ));
        // A hostname that merely contains the literal parses as a domain, not an address.
        assert!(!is_loopback_redirect(
            &client,
            "http://127.0.0.1.evil.example:54321/callback"
        ));
        // Another address in 127.0.0.0/8 is not "the loopback IP literal" §7.3 names.
        assert!(!is_loopback_redirect(
            &client,
            "http://127.0.0.2:54321/callback"
        ));
        // Loopback host, but `https` -- §7.3's carve-out is `http`-only.
        assert!(!is_loopback_redirect(
            &client,
            "https://127.0.0.1:54321/callback"
        ));
        assert!(!is_loopback_redirect(&client, "not a url"));
    }

    /// Rule point 1, and the registration opt-in: a confidential client never gets the carve-out,
    /// and a public client that registered no loopback URI does not silently gain one.
    #[test]
    fn only_a_public_client_that_registered_a_loopback_uri_is_eligible() {
        assert!(!is_loopback_redirect(
            &confidential_client_with_loopback(),
            "http://127.0.0.1:54321/callback"
        ));
        assert!(!is_loopback_redirect(
            &public_client(),
            "http://127.0.0.1:54321/callback"
        ));
    }
}
