//! The OIDC Session Management 1.0 §3 `session_state` parameter on `/authorize`'s response
//! redirect.
//!
//! Split out of `authorize.rs` (which is over the 200-LoC house ceiling and grandfathered at its
//! current size, so it may be touched but not grown): these two helpers and their tests are a
//! self-contained concern -- deciding whether a location `handle_authorize` built is a success
//! redirect, and appending `session_state` to it when it is.

/// Appends OIDC Session Management 1.0 §3's `session_state` parameter to the authorization
/// response redirect `handle_authorize` built. Only redirects WITHOUT an `error` query parameter
/// get it appended -- see [`redirect_carries_error`]'s doc comment for why that string check,
/// rather than the `AuthorizeOutcome` variant, is what decides this. A request arriving without
/// an OP browser-state cookie (see `crate::session_management`) also gets no `session_state` at
/// all rather than a value the check-session iframe could never match.
pub(crate) fn append_session_state(location: &str, session_state: &str) -> String {
    match reqwest::Url::parse(location) {
        Ok(mut url) => {
            url.query_pairs_mut()
                .append_pair("session_state", session_state);
            url.into()
        }
        Err(_) => location.to_string(),
    }
}

/// Whether an `AuthorizeOutcome::Redirect` location is an error redirect rather than a successful
/// code issuance. `handle_authorize` (`authkestra_op::handlers`) returns the SAME
/// `AuthorizeOutcome::Redirect(String)` variant for both cases -- e.g. a `store_code` failure
/// redirects with `?error=server_error&...` rather than returning `DirectError` -- so the variant
/// alone cannot distinguish them; only the `error` query parameter on the URL itself can. Used to
/// decide whether [`append_session_state`] should run: `session_state` is an OIDC Session
/// Management 1.0 artifact of a successful authentication response and must not be attached to an
/// error redirect the RP never asked the check-session iframe to track. A URL that fails to parse
/// is treated as NOT carrying an error (matching [`append_session_state`]'s own parse-failure
/// fallback of returning the location unchanged) -- this function only ever gates whether an
/// extra query parameter gets added, never whether the redirect itself happens.
pub(crate) fn redirect_carries_error(location: &str) -> bool {
    reqwest::Url::parse(location)
        .map(|url| url.query_pairs().any(|(key, _)| key == "error"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F5 (adversarial-review finding): `handle_authorize` returns the SAME
    /// `AuthorizeOutcome::Redirect(String)` variant for both a successful code issuance and an
    /// error redirect (e.g. a `store_code` failure), so `session_state` must never be appended
    /// based on the variant alone -- only the presence of an `error` query parameter on the
    /// location itself can distinguish them.
    #[test]
    fn redirect_carries_error_detects_an_error_query_parameter() {
        assert!(redirect_carries_error(
            "https://rp.example.test/callback?error=server_error&error_description=boom"
        ));
        assert!(!redirect_carries_error(
            "https://rp.example.test/callback?code=abc123&state=xyz"
        ));
    }

    /// An unparseable location is treated as NOT carrying an error, matching
    /// `append_session_state`'s own parse-failure fallback of returning the location unchanged --
    /// this function only ever gates an EXTRA query parameter, never whether the redirect itself
    /// happens.
    #[test]
    fn redirect_carries_error_defaults_to_false_for_an_unparseable_location() {
        assert!(!redirect_carries_error("not a url at all"));
    }

    /// Reproduces the pre-fix bug at the decision-logic level and proves the fix changes the
    /// outcome. The pre-fix `issue_code` match arm was
    /// `Some(session_state) => append_session_state(&location, &session_state)` -- no
    /// `redirect_carries_error` check existed at all, so ANY `Some(session_state)` (an OP
    /// browser-state cookie was presented) got attached to ANY `AuthorizeOutcome::Redirect`,
    /// including one carrying `error=...`. This test evaluates the pre-fix condition
    /// (`session_state.is_some()` alone) and the post-fix condition
    /// (`session_state.is_some() && !redirect_carries_error(location)`) against the SAME
    /// error-carrying location and asserts they disagree -- i.e. the `redirect_carries_error`
    /// check is load-bearing, not a no-op, for exactly the case the finding describes.
    #[test]
    fn the_fix_changes_the_outcome_for_an_error_redirect() {
        let error_location =
            "https://rp.example.test/callback?error=server_error&error_description=boom";
        let session_state = Some("deadbeef.salt".to_string());

        let pre_fix_would_append = session_state.is_some();
        assert!(
            pre_fix_would_append,
            "sanity: the pre-fix condition alone says yes for this fixture"
        );

        let post_fix_would_append =
            session_state.is_some() && !redirect_carries_error(error_location);
        assert!(
            !post_fix_would_append,
            "the fix must refuse to append session_state to an error redirect"
        );
    }

    /// Control: the post-fix condition still says yes for a genuine success redirect, so the fix
    /// is not a blanket refusal.
    #[test]
    fn the_fix_still_appends_session_state_to_a_success_redirect() {
        let success_location = "https://rp.example.test/callback?code=abc123&state=xyz";
        let session_state = Some("deadbeef.salt".to_string());

        let post_fix_would_append =
            session_state.is_some() && !redirect_carries_error(success_location);
        assert!(post_fix_would_append);

        let appended = append_session_state(success_location, "deadbeef.salt");
        assert!(appended.contains("session_state=deadbeef.salt"));
    }
}
