#!/usr/bin/env python3
"""End-to-end coverage for `authz-idp` (ADR-0012/0019/0021/0023/0025): discovery, JWKS, the
browser authorization-code flow (PKCE + OIDC Session Management), the RFC 8628 device flow, RFC
8693 token exchange, RFC 7662 introspection, and RFC 7009 revocation.

Mirrors `servers_it.py`'s structure/log style/env-var conventions -- same CBOR RPC helpers (via
`cbor_min`) to provision an account/project through `authz-api`, same `wait_until_ready` shape,
same `[it-idp]` log prefix. What's new here is a hand-rolled cookie jar and a redirect-suppressing
opener: the browser and device flows need to inspect `Set-Cookie`/`Location` at every hop (the RP
state cookie, the browser session cookie, the OP browser-state cookie, the device-confirm cookie)
rather than following redirects blindly the way a real browser would.

Every section below runs unconditionally against whatever `authz-idp` this process is pointed at.
Some sections exercise routes/params that only exist as of the OIDC Session Management +
introspection work (session_state, /oauth2/check_session_iframe, /oauth2/introspect) -- against an
older deployment those sections simply fail loudly, which is the correct behavior for an IT suite:
it should not silently skip coverage.
"""

import base64
import hashlib
import html
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import cbor_min

IDP_URL = os.environ.get("IDP_URL", "https://authz-idp:3004").rstrip("/")
API_URL = os.environ.get("API_URL", "https://authz-api:3000").rstrip("/")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:9100").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "test-client")
USERNAME = os.environ.get("USERNAME", "test@admin")
PASSWORD = os.environ.get("PASSWORD", "test")
MAX_WAIT_SECONDS = int(os.environ.get("MAX_WAIT_SECONDS", "180"))

BROWSER_CLIENT_ID = "it-browser"
BROWSER_REDIRECT_URI = "http://it-client.invalid/callback"
EXCHANGE_CLIENT_ID = "it-exchange"
DEVICE_CLIENT_ID = "opencode-cli"

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

INSECURE_TLS = ssl.create_default_context()
INSECURE_TLS.check_hostname = False
INSECURE_TLS.verify_mode = ssl.CERT_NONE


def log(message: str) -> None:
    print(f"[it-idp] {message}", flush=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Returns the raw 3xx response instead of following it, so callers can inspect
    `Location`/`Set-Cookie` at every hop of the browser and device flows."""

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_NO_REDIRECT_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=INSECURE_TLS), _NoRedirect()
)


class CookieJar:
    """A minimal, single-flow cookie jar keyed by cookie name only (every cookie this suite
    handles is `Path=/` on a single host per flow, so name-only tracking is enough)."""

    def __init__(self):
        self.values = {}

    def update_from(self, headers) -> None:
        for raw in headers.get_all("Set-Cookie") or []:
            attrs = raw.split(";")
            name, _, value = attrs[0].strip().partition("=")
            if not name:
                continue
            if any(attr.strip().lower().startswith("max-age=0") for attr in attrs[1:]):
                self.values.pop(name, None)
            else:
                self.values[name] = value

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.values.items())


def http_raw(method: str, url: str, *, body=None, headers=None, cookies: CookieJar = None):
    """Issues one HTTP request without following redirects. Returns
    (status, response_headers, body_bytes). `response_headers` supports `.get`/`.get_all` exactly
    like `http.client.HTTPMessage` (both success and `HTTPError` responses carry one)."""
    all_headers = dict(headers or {})
    if cookies is not None and cookies.header():
        all_headers["Cookie"] = cookies.header()
    req = urllib.request.Request(url=url, method=method, data=body, headers=all_headers)
    try:
        resp = _NO_REDIRECT_OPENER.open(req, timeout=30)
        status = resp.status
        resp_headers = resp.headers
        payload = resp.read()
    except urllib.error.HTTPError as err:
        status = err.code
        resp_headers = err.headers
        payload = err.read()
    if cookies is not None:
        cookies.update_from(resp_headers)
    return status, resp_headers, payload


def http_form(method: str, url: str, form: dict, *, headers=None, cookies: CookieJar = None):
    body = urllib.parse.urlencode(form).encode("utf-8")
    all_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    all_headers.update(headers or {})
    return http_raw(method, url, body=body, headers=all_headers, cookies=cookies)


def http_json(method: str, url: str, *, body=None, headers=None, cookies: CookieJar = None):
    encoded = None
    all_headers = dict(headers or {})
    if body is not None:
        encoded = json.dumps(body).encode("utf-8")
        all_headers["Content-Type"] = "application/json"
    all_headers.setdefault("Accept", "application/json")
    status, resp_headers, payload = http_raw(
        method, url, body=encoded, headers=all_headers, cookies=cookies
    )
    parsed = json.loads(payload) if payload else {}
    return status, parsed, resp_headers


def request_rpc(method: str, url: str, body: dict, headers: dict):
    """CBOR RPC helper for `authz-api`'s `/rpc/*` surface (ADR-0013) -- same shape as
    `servers_it.py`'s own `request_rpc`, trimmed to what this suite needs."""
    encoded = cbor_min.encode(body)
    req_headers = {"Accept": "application/cbor", "Content-Type": "application/cbor"}
    req_headers.update(headers)
    status, resp_headers, payload = http_raw(
        method, url, body=encoded, headers=req_headers
    )
    if status >= 400:
        raise urllib.error.HTTPError(url, status, "rpc error", resp_headers, None)
    return status, (cbor_min.decode(payload) if payload else {})


def decode_jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))


def wait_until_ready() -> None:
    probe_urls = [
        f"{IDP_URL}/healthz",
        f"{IDP_URL}/healthz/startup",
        f"{IDP_URL}/healthz/ready",
        f"{API_URL}/healthz",
    ]
    start = time.time()
    last_error = "readiness checks have not run yet"
    while True:
        try:
            for probe_url in probe_urls:
                status, _, _ = http_raw("GET", probe_url)
                assert status == 200, f"probe failed {probe_url}: status={status}"
            status, _, _ = http_raw(
                "GET", f"{KEYCLOAK_URL}/realms/dev/.well-known/openid-configuration"
            )
            assert status == 200, "keycloak discovery not ready"
            log("all probes and keycloak discovery endpoint are ready")
            return
        except Exception as err:
            last_error = str(err) or err.__class__.__name__
            if time.time() - start > MAX_WAIT_SECONDS:
                raise TimeoutError(
                    f"services not ready after {MAX_WAIT_SECONDS}s: {last_error}"
                ) from None
            time.sleep(2)


def fetch_keycloak_token(client_id: str = CLIENT_ID) -> str:
    status, _, payload = http_form(
        "POST",
        f"{KEYCLOAK_URL}/realms/dev/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "client_id": client_id,
            "username": USERNAME,
            "password": PASSWORD,
        },
    )
    body = json.loads(payload)
    assert status == 200 and "access_token" in body, f"keycloak token fetch failed: {body}"
    return body["access_token"]


def account_id_from_token(token: str) -> str:
    return decode_jwt_claims(token)["sub"]


def ensure_account_and_project(token: str) -> tuple[str, str]:
    """Provisions the account + a project for the human subject driving every flow below.

    The IdP refuses login for a subject with no `accounts` row (ADR-0024) and 502s the browser
    callback when the account has no default project -- so this must run before any browser or
    device approval below. `createAccount` is once-per-subject (409 on replay, tolerated exactly
    like `servers_it.py`'s `ensure_account`); the project this mints becomes that account's
    default project (server-computed `is_default`, AGENTS.md) since accounts provisioned this way
    start with none.
    """
    authz_headers = {"Authorization": f"Bearer {token}"}
    try:
        _, account = request_rpc(
            "POST", f"{API_URL}/rpc/procedure.createAccount", {"args": {}}, authz_headers
        )
        account_id = account["id"]
    except urllib.error.HTTPError as err:
        if err.code != 409:
            raise
        account_id = account_id_from_token(token)
        log(f"account already exists for this subject; reusing {account_id}")

    billing_identity = f"it-idp-{uuid_hex()}"
    project_id = "c" + uuid_hex()
    _, project = request_rpc(
        "POST",
        f"{API_URL}/rpc/model.Project.create",
        {
            "id": project_id,
            "accountId": account_id,
            "name": "it-idp-project",
            "allowedModels": {"List": [{"String": "gpt-4.1-mini"}]},
            "defaultLimits": {"Map": {}},
            "billingPlan": "free",
            "billingIdentity": billing_identity,
            "status": "active",
        },
        authz_headers,
    )
    return account_id, project["id"]


def uuid_hex() -> str:
    return uuid.uuid4().hex[:24]


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def origin_of(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def query_params(url: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}


def parse_login_form_action(html_body: str) -> str:
    match = re.search(r'<form[^>]+id="kc-form-login"[^>]*action="([^"]+)"', html_body)
    assert match is not None, "keycloak login form action not found"
    return html.unescape(match.group(1))


def drive_keycloak_login(authorize_location: str, cookies: CookieJar) -> str:
    """Follows a redirect to Keycloak's authorization endpoint through the password login form,
    returning the `Location` of the resulting redirect back to `authz-idp` (either `/idp/callback`
    directly, for a fresh Keycloak session, or an intermediate consent/step page -- this deployment
    has none configured, so it is always the callback)."""
    status, headers, body = http_raw("GET", authorize_location, cookies=cookies)
    assert status == 200, f"keycloak login page failed: status={status}"
    action = parse_login_form_action(body.decode("utf-8"))
    status, headers, _ = http_form(
        "POST",
        action,
        {"username": USERNAME, "password": PASSWORD, "credentialId": ""},
        cookies=cookies,
    )
    assert status == 302, f"keycloak login submit failed: status={status}"
    location = headers.get("Location")
    assert location and "/idp/callback" in location, f"unexpected keycloak login redirect: {location}"
    return to_in_network(location)


def to_in_network(url: str) -> str:
    """Rewrites a browser-facing `https://localhost:13004/...` callback URL -- the RP's configured
    `callback_url` that Keycloak echoes back -- to the in-network `authz-idp` address this container
    can actually reach. A real browser on the host resolves `localhost:13004` to `authz-idp` via the
    published port; inside the compose network this container's own `localhost:13004` has nothing
    listening (ECONNREFUSED), and the RP state cookie is bound to the `authz-idp` origin the initial
    `/authorize` was served from -- so both reachability and cookie continuity require this swap.
    Path and query (`code`/`state`) are preserved untouched."""
    parts = urllib.parse.urlsplit(url)
    if parts.hostname == "localhost" and parts.port == 13004:
        idp = urllib.parse.urlsplit(IDP_URL)
        return urllib.parse.urlunsplit(
            (idp.scheme, idp.netloc, parts.path, parts.query, parts.fragment)
        )
    return url


def session_state(client_id: str, origin: str, op_browser_state: str, salt: str) -> str:
    digest = hashlib.sha256(f"{client_id} {origin} {op_browser_state} {salt}".encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode() + "." + salt


# --- 1. Probes ---------------------------------------------------------------------------------


def section_probes() -> None:
    for path in ("/healthz", "/healthz/startup", "/healthz/ready"):
        status, _, _ = http_raw("GET", f"{IDP_URL}{path}")
        assert status == 200, f"probe {path} failed: status={status}"
    log("probes passed")


# --- 2. Root + SPA -------------------------------------------------------------------------------


def section_root_and_spa() -> None:
    status, body, headers = http_json("GET", f"{IDP_URL}/")
    assert status == 200, f"root failed: status={status}"
    assert body.get("status") == "ok", f"root is not the JSON welcome body: {body}"
    content_type = headers.get("Content-Type", "")
    assert "html" not in content_type.lower(), f"root served HTML, not JSON: {content_type}"

    for path in ("/ui/", "/ui/login"):
        status, headers, body = http_raw("GET", f"{IDP_URL}{path}")
        assert status == 200, f"{path} failed: status={status}"
        content_type = headers.get("Content-Type", "")
        assert "html" in content_type.lower(), f"{path} did not serve the SPA index: {content_type}"

    status, _, _ = http_raw("GET", f"{IDP_URL}/does-not-exist")
    assert status == 404, f"unknown non-/ui path did not 404: status={status}"
    log("root + spa passed")


# --- 3. Discovery --------------------------------------------------------------------------------


def section_discovery() -> None:
    status, doc, _ = http_json("GET", f"{IDP_URL}/.well-known/openid-configuration")
    assert status == 200, f"discovery failed: status={status}"
    assert doc["issuer"], "discovery missing issuer"
    assert doc["jwks_uri"], "discovery missing jwks_uri"
    assert doc["token_endpoint"], "discovery missing token_endpoint"
    assert doc["revocation_endpoint"], "discovery missing revocation_endpoint"
    assert doc["device_authorization_endpoint"], "discovery missing device_authorization_endpoint"
    assert doc["authorization_endpoint"], "discovery missing authorization_endpoint"
    assert "openid" in doc["scopes_supported"], "discovery scopes_supported missing openid"
    assert doc["scopes_supported"] == [
        "openid",
        "profile",
        "email",
        "offline_access",
    ], f"unexpected scopes_supported: {doc['scopes_supported']}"
    for grant in (
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
        TOKEN_EXCHANGE_GRANT,
        "refresh_token",
    ):
        assert grant in doc["grant_types_supported"], f"discovery missing grant type {grant}"
    assert doc["code_challenge_methods_supported"] == ["S256"], "discovery code_challenge mismatch"
    assert doc["introspection_endpoint"], "discovery missing introspection_endpoint"
    assert doc["check_session_iframe"], "discovery missing check_session_iframe"
    assert doc["claims_parameter_supported"] is False, "claims_parameter_supported must be false"

    status, alt_doc, _ = http_json("GET", f"{IDP_URL}/.well-known/oauth-authorization-server")
    assert status == 200, f"oauth-authorization-server discovery failed: status={status}"
    assert alt_doc == doc, "oauth-authorization-server document differs from openid-configuration"
    log("discovery passed")


# --- 4. JWKS ---------------------------------------------------------------------------------------


def section_jwks() -> None:
    status, body, _ = http_json("GET", f"{IDP_URL}/.well-known/jwks.json")
    assert status == 200, f"jwks failed: status={status}"
    keys = body.get("keys", [])
    assert keys, "jwks has no keys"
    for key in keys:
        assert key.get("kid"), f"jwk missing kid: {key}"
        assert key.get("kty") == "RSA", f"jwk is not RSA: {key}"
    log("jwks passed")


# --- 5. /authorize negatives -----------------------------------------------------------------------


def section_authorize_negatives() -> None:
    _, challenge = pkce_pair()

    status, _, body = http_raw(
        "GET",
        f"{IDP_URL}/authorize?"
        + urllib.parse.urlencode(
            {
                "client_id": "no-such-client",
                "redirect_uri": BROWSER_REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        ),
    )
    assert status == 400, f"unknown client_id did not 400: status={status}"
    assert "unknown client" in body.decode("utf-8"), f"unexpected body: {body!r}"
    log("authorize rejects an unknown client_id with 400")

    status, _, body = http_raw(
        "GET",
        f"{IDP_URL}/authorize?"
        + urllib.parse.urlencode(
            {
                "client_id": BROWSER_CLIENT_ID,
                "redirect_uri": "http://not-registered.invalid/callback",
                "response_type": "code",
                "scope": "openid",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        ),
    )
    assert status == 400, f"unregistered redirect_uri did not 400: status={status}"
    assert "invalid redirect_uri" in body.decode("utf-8"), f"unexpected body: {body!r}"
    log("authorize rejects an unregistered redirect_uri with 400")

    status, headers, _ = http_raw(
        "GET",
        f"{IDP_URL}/authorize?"
        + urllib.parse.urlencode(
            {
                "client_id": BROWSER_CLIENT_ID,
                "redirect_uri": BROWSER_REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "state": "missing-pkce",
            }
        ),
    )
    assert status == 307, f"missing code_challenge did not redirect: status={status}"
    location = query_params(headers.get("Location", ""))
    assert location.get("error") == "invalid_request", f"unexpected error: {location}"
    log("authorize redirects invalid_request when code_challenge is missing")

    _, challenge = pkce_pair()
    status, headers, _ = http_raw(
        "GET",
        f"{IDP_URL}/authorize?"
        + urllib.parse.urlencode(
            {
                "client_id": BROWSER_CLIENT_ID,
                "redirect_uri": BROWSER_REDIRECT_URI,
                "response_type": "code",
                "scope": "openid not-a-real-scope",
                "state": "bad-scope",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        ),
    )
    assert status == 307, f"disallowed scope did not redirect: status={status}"
    location = query_params(headers.get("Location", ""))
    assert location.get("error") == "invalid_scope", f"unexpected error: {location}"
    log("authorize redirects invalid_scope for a disallowed scope")


# --- 6. Full browser flow -----------------------------------------------------------------------


def section_browser_flow() -> None:
    """Self-contained: drives the full browser authorization-code flow end to end and asserts
    along the way. Nothing it mints is reused by a later section."""
    cookies = CookieJar()
    verifier, challenge = pkce_pair()
    state = "it-idp-" + uuid_hex()
    authorize_url = f"{IDP_URL}/authorize?" + urllib.parse.urlencode(
        {
            "client_id": BROWSER_CLIENT_ID,
            "redirect_uri": BROWSER_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile email offline_access",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    status, headers, _ = http_raw("GET", authorize_url, cookies=cookies)
    assert status == 307, f"initial /authorize did not redirect to keycloak: status={status}"
    keycloak_location = headers.get("Location")
    assert keycloak_location, "missing keycloak redirect location"

    callback_location = drive_keycloak_login(keycloak_location, cookies)

    status, headers, _ = http_raw("GET", callback_location, cookies=cookies)
    assert status == 303, f"/idp/callback did not redirect back to /authorize: status={status}"
    resume_location = headers.get("Location")
    assert resume_location and "/authorize" in resume_location, (
        f"unexpected callback resume location: {resume_location}"
    )
    assert cookies.get("__Host-authz_session"), "callback did not set the browser session cookie"
    assert cookies.get("__Host-authz_op_state"), "callback did not set the OP browser-state cookie"

    if not resume_location.startswith("http"):
        resume_location = f"{IDP_URL}{resume_location}"
    status, headers, _ = http_raw("GET", resume_location, cookies=cookies)
    assert status == 307, f"resumed /authorize did not redirect to redirect_uri: status={status}"
    final_location = headers.get("Location")
    assert final_location and final_location.startswith(BROWSER_REDIRECT_URI), (
        f"unexpected final redirect: {final_location}"
    )
    final_params = query_params(final_location)
    code = final_params.get("code")
    assert code, f"no authorization code in final redirect: {final_params}"
    assert final_params.get("state") == state, "state mismatch on final redirect"
    actual_session_state = final_params.get("session_state")
    assert actual_session_state, "session_state missing from the final redirect"

    salt = actual_session_state.rsplit(".", 1)[-1]
    expected_session_state = session_state(
        BROWSER_CLIENT_ID,
        origin_of(BROWSER_REDIRECT_URI),
        cookies.get("__Host-authz_op_state"),
        salt,
    )
    assert actual_session_state == expected_session_state, (
        f"session_state hash mismatch: got {actual_session_state}, expected {expected_session_state}"
    )
    log("session_state matches the OIDC Session Management 1.0 hash contract")

    status, _, body_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": BROWSER_REDIRECT_URI,
                "client_id": BROWSER_CLIENT_ID,
                "code_verifier": verifier,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token_body = json.loads(body_bytes)
    assert status == 200, f"authorization_code redemption failed: status={status}, body={token_body}"
    access_token = token_body["access_token"]
    claims = decode_jwt_claims(access_token)
    assert claims.get("sub"), f"access token missing sub: {claims}"
    identity_attrs = claims.get("identity", {}).get("attributes", {})
    assert identity_attrs.get("account_id"), f"access token missing identity.attributes.account_id: {claims}"
    assert identity_attrs.get("project_id"), f"access token missing identity.attributes.project_id: {claims}"
    log("authorization_code redemption passed with the expected claim shape")

    status, _, replay_body = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": BROWSER_REDIRECT_URI,
                "client_id": BROWSER_CLIENT_ID,
                "code_verifier": verifier,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    replay_body = json.loads(replay_body)
    assert status == 400 and replay_body.get("error") == "invalid_grant", (
        f"replayed authorization code was not rejected: status={status}, body={replay_body}"
    )
    log("replayed authorization code is rejected with invalid_grant")

    second_verifier, second_challenge = pkce_pair()
    second_state = "it-idp-" + uuid_hex()
    second_authorize_url = f"{IDP_URL}/authorize?" + urllib.parse.urlencode(
        {
            "client_id": BROWSER_CLIENT_ID,
            "redirect_uri": BROWSER_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile email offline_access",
            "state": second_state,
            "code_challenge": second_challenge,
            "code_challenge_method": "S256",
        }
    )
    status, headers, _ = http_raw("GET", second_authorize_url, cookies=cookies)
    assert status == 307, f"second /authorize with a live session did not skip keycloak: status={status}"
    second_location = headers.get("Location")
    second_params = query_params(second_location or "")
    second_code = second_params.get("code")
    assert second_code and second_code != code, "second /authorize did not mint a fresh code"
    log("a second /authorize with the session cookie skips Keycloak entirely")


# --- 7. check_session_iframe -----------------------------------------------------------------------


def section_check_session_iframe() -> None:
    status, headers, body = http_raw("GET", f"{IDP_URL}/oauth2/check_session_iframe")
    assert status == 200, f"check_session_iframe failed: status={status}"
    content_type = headers.get("Content-Type", "")
    assert "text/html" in content_type, f"unexpected content type: {content_type}"
    assert headers.get("Cache-Control") == "no-store", f"unexpected cache-control: {headers.get('Cache-Control')}"
    text = body.decode("utf-8")
    assert "__Host-authz_op_state" in text, "iframe body missing the OP browser-state cookie name"
    assert "postMessage" in text, "iframe body missing postMessage"
    log("check_session_iframe passed")


# --- 8. Device flow ------------------------------------------------------------------------------


def section_device_flow() -> tuple[str, str]:
    status, _, body_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/device_authorization",
        body=urllib.parse.urlencode(
            {"client_id": DEVICE_CLIENT_ID, "scope": "openid offline_access"}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    auth_body = json.loads(body_bytes)
    assert status == 200, f"device_authorization failed: status={status}, body={auth_body}"
    device_code = auth_body["device_code"]
    user_code = auth_body["user_code"]

    status, _, pending_body = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": DEVICE_CODE_GRANT,
                "device_code": device_code,
                "client_id": DEVICE_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    pending_body = json.loads(pending_body)
    assert status == 400 and pending_body.get("error") == "authorization_pending", (
        f"unapproved device poll should be authorization_pending: status={status}, body={pending_body}"
    )
    log("device poll reports authorization_pending before approval")

    cookies = CookieJar()
    status, _, _ = http_raw("GET", f"{IDP_URL}/device/verify?user_code={user_code}", cookies=cookies)
    assert status == 200, f"device verify page failed: status={status}"

    status, headers, _ = http_form(
        "POST", f"{IDP_URL}/device/verify", {"user_code": user_code}, cookies=cookies
    )
    assert status == 200, f"device verify submit failed: status={status}"
    assert cookies.get("__Host-authz_device_confirm"), "device confirm cookie was not set"

    status, headers, _ = http_form(
        "POST", f"{IDP_URL}/device/verify/continue", {"user_code": user_code}, cookies=cookies
    )
    assert status == 303, f"device verify continue did not redirect: status={status}"
    keycloak_location = headers.get("Location")
    assert keycloak_location, "device verify continue missing keycloak redirect"

    callback_location = drive_keycloak_login(keycloak_location, cookies)
    status, _, _ = http_raw("GET", callback_location, cookies=cookies)
    assert status == 200, f"device callback did not complete pairing: status={status}"
    log("device pairing approved through the browser")

    status, _, token_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": DEVICE_CODE_GRANT,
                "device_code": device_code,
                "client_id": DEVICE_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token_body = json.loads(token_bytes)
    assert status == 200, f"device poll after approval failed: status={status}, body={token_body}"
    access_token = token_body["access_token"]
    refresh_token = token_body["refresh_token"]
    claims = decode_jwt_claims(access_token)
    assert claims.get("budget_tier"), f"device access token missing budget_tier: {claims}"
    log("device grant issued an access token carrying budget_tier")

    status, _, refreshed_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": DEVICE_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    refreshed_body = json.loads(refreshed_bytes)
    assert status == 200, f"device refresh rotation failed: status={status}, body={refreshed_body}"
    new_refresh_token = refreshed_body["refresh_token"]
    assert new_refresh_token != refresh_token, "refresh rotation did not mint a new refresh_token"

    status, _, reuse_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": DEVICE_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    reuse_body = json.loads(reuse_bytes)
    assert status == 400 and reuse_body.get("error") == "invalid_grant", (
        f"reused refresh_token was not rejected: status={status}, body={reuse_body}"
    )
    log("device refresh_token rotates, and the superseded token is invalid on reuse")
    return refreshed_body["access_token"], new_refresh_token


# --- 9. Token exchange ---------------------------------------------------------------------------


def section_token_exchange(project_id: str) -> tuple[str, str]:
    subject_token = fetch_keycloak_token()
    status, _, body_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": TOKEN_EXCHANGE_GRANT,
                "client_id": EXCHANGE_CLIENT_ID,
                "subject_token": subject_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "scope": "openid offline_access",
                "project_id": project_id,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    body = json.loads(body_bytes)
    assert status == 200, f"token exchange failed: status={status}, body={body}"
    access_token = body["access_token"]
    refresh_token = body.get("refresh_token")
    assert refresh_token, "token exchange with offline_access did not return a refresh_token"
    claims = decode_jwt_claims(access_token)
    assert claims.get("sub"), f"exchanged access token missing sub: {claims}"
    assert claims.get("account_id"), f"exchanged access token missing account_id: {claims}"
    assert claims.get("project_id") == project_id, f"exchanged access token project_id mismatch: {claims}"
    assert claims.get("budget_tier"), f"exchanged access token missing budget_tier: {claims}"
    log("token exchange minted an access token with the expected claims")

    status, _, rotated_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": EXCHANGE_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    rotated_body = json.loads(rotated_bytes)
    assert status == 200, f"token exchange refresh rotation failed: status={status}, body={rotated_body}"
    assert rotated_body["refresh_token"] != refresh_token, "token exchange refresh did not rotate"
    log("token exchange refresh_token rotates")
    return rotated_body["access_token"], rotated_body["refresh_token"]


# --- 10. Introspection ---------------------------------------------------------------------------


def section_introspection(
    exchange_access_token: str,
    exchange_refresh_token: str,
    device_access_token: str,
) -> None:
    status, _, body_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/introspect",
        body=urllib.parse.urlencode(
            {"token": exchange_refresh_token, "client_id": EXCHANGE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    body = json.loads(body_bytes)
    assert status == 200 and body.get("active") is True, (
        f"live refresh token did not introspect active: status={status}, body={body}"
    )
    assert body.get("client_id") == EXCHANGE_CLIENT_ID, f"unexpected client_id: {body}"
    log("introspection reports active:true for its own live refresh token")

    status, _, cross_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/introspect",
        body=urllib.parse.urlencode(
            {"token": exchange_refresh_token, "client_id": DEVICE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    cross_body = json.loads(cross_bytes)
    assert status == 200 and cross_body.get("active") is False, (
        f"cross-client introspection should be inactive: status={status}, body={cross_body}"
    )
    log("introspection reports active:false when checked by a different client")

    status, _, garbage_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/introspect",
        body=urllib.parse.urlencode(
            {"token": "not-a-real-token", "client_id": EXCHANGE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    garbage_body = json.loads(garbage_bytes)
    assert status == 200 and garbage_body.get("active") is False, (
        f"garbage token should be inactive: status={status}, body={garbage_body}"
    )
    log("introspection reports active:false for a garbage token")

    status, _, _ = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/introspect",
        body=urllib.parse.urlencode({"token": exchange_refresh_token}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 401, f"introspection with no client should 401: status={status}"
    log("introspection requires client authentication")

    status, _, _ = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/revoke",
        body=urllib.parse.urlencode(
            {"token": exchange_refresh_token, "client_id": EXCHANGE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200, "revoking the exchange refresh token failed"

    status, _, revoked_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/introspect",
        body=urllib.parse.urlencode(
            {"token": exchange_refresh_token, "client_id": EXCHANGE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    revoked_body = json.loads(revoked_bytes)
    assert status == 200 and revoked_body.get("active") is False, (
        f"revoked token should introspect inactive: status={status}, body={revoked_body}"
    )
    log("introspection reports active:false after revocation")

    status, _, access_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/introspect",
        body=urllib.parse.urlencode(
            {"token": device_access_token, "client_id": DEVICE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    access_body = json.loads(access_bytes)
    assert status == 200 and access_body.get("active") is True, (
        f"live access token did not introspect active: status={status}, body={access_body}"
    )
    log("introspection reports active:true for a live access token checked by its issuing client")


# --- 11. Revocation ------------------------------------------------------------------------------


def section_revocation(device_refresh_token: str) -> None:
    status, _, _ = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/revoke",
        body=urllib.parse.urlencode({"client_id": DEVICE_CLIENT_ID}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 400, f"revoke with no token should 400: status={status}"
    log("revoke rejects a missing token")

    status, _, _ = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/revoke",
        body=urllib.parse.urlencode(
            {"token": "irrelevant", "client_id": "no-such-client"}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 401, f"revoke with an unknown client should 401: status={status}"
    log("revoke rejects an unknown client")

    status, _, _ = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/revoke",
        body=urllib.parse.urlencode(
            {"token": device_refresh_token, "client_id": DEVICE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200, f"valid revoke failed: status={status}"
    log("revoke accepts a valid token")

    status, _, _ = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/revoke",
        body=urllib.parse.urlencode(
            {"token": device_refresh_token, "client_id": DEVICE_CLIENT_ID}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200, f"idempotent revoke failed: status={status}"
    log("revoke is idempotent on a second call")


def main() -> int:
    try:
        wait_until_ready()

        token = fetch_keycloak_token()
        account_id, project_id = ensure_account_and_project(token)
        log(f"provisioned account {account_id} / project {project_id}")

        section_probes()
        section_root_and_spa()
        section_discovery()
        section_jwks()
        section_authorize_negatives()
        section_browser_flow()
        section_check_session_iframe()
        device_access_token, device_refresh_token = section_device_flow()
        exchange_access_token, exchange_refresh_token = section_token_exchange(project_id)
        section_introspection(exchange_access_token, exchange_refresh_token, device_access_token)
        section_revocation(device_refresh_token)

        return 0
    except Exception as err:
        log(f"FAILED: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
