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
import jwt_min

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
# #534/ADR-0030: the live client_credentials (M2M) IT client -- see
# `generate_it_machine_fixtures.py`'s own doc comment for the full picture. Its `it-machine`
# registration exists ONLY in the generated `container.it.yaml` (`compose.it.yaml` mounts that,
# not the checked-in `container.yaml`, as `authz-idp`'s config for this run), and its private key
# is generated fresh at every IT-stack-up, never checked into the repo (PR #604) -- `it-idp`
# reads it from wherever `IT_MACHINE_KEY_PATH` points, defaulting to the path
# `generate_it_machine_fixtures.py` itself writes to when run directly (outside compose) for local
# debugging.
MACHINE_CLIENT_ID = "it-machine"
MACHINE_CLIENT_AUDIENCE = "lightbridge-api-key"
MACHINE_PRIVATE_KEY_PATH = os.environ.get(
    "IT_MACHINE_KEY_PATH",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "generated", "it-machine-key.pem"
    ),
)
MACHINE_KID = "it-machine-2026-08"

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
CLIENT_CREDENTIALS_GRANT = "client_credentials"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

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
    device approval below. Account provisioning is keyed on the ANCHOR account (`id = subject`,
    ADR-0026 D3) rather than on `createAccount` returning 409 -- since ADR-0026 a replay returns
    200 and a NEW account, so the old 409 signal would never fire and every re-run would mint a
    stray one; see `servers_it.py`'s `ensure_account` for the full reasoning. The project this
    mints becomes that account's
    default project (server-computed `is_default`, AGENTS.md) since accounts provisioned this way
    start with none.
    """
    authz_headers = {"Authorization": f"Bearer {token}"}
    account_id = account_id_from_token(token)
    provisioned = False
    # A read policy FILTERS rather than rejects, so an absent account is a 404, which `urlopen`
    # raises. Absent is the expected first-run case, not an error.
    try:
        status, existing = request_rpc(
            "POST", f"{API_URL}/rpc/model.Account.get", {"id": account_id}, authz_headers
        )
        provisioned = (
            status == 200 and isinstance(existing, dict) and existing.get("id") == account_id
        )
    except urllib.error.HTTPError as err:
        if err.code != 404:
            raise
    if provisioned:
        log(f"anchor account already provisioned; reusing {account_id}")
    else:
        _, account = request_rpc(
            "POST", f"{API_URL}/rpc/procedure.createAccount", {"args": {}}, authz_headers
        )
        assert account["id"] == account_id, (
            "the first account for a subject must be the anchor, keyed by the subject itself "
            f"(ADR-0026 D3): got {account['id']}, expected {account_id}"
        )

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
    status, headers, body = http_raw(
        "GET", to_in_network(authorize_location), cookies=cookies
    )
    assert status == 200, f"keycloak login page failed: status={status}"
    action = parse_login_form_action(body.decode("utf-8"))
    status, headers, _ = http_form(
        "POST",
        to_in_network(action),
        {"username": USERNAME, "password": PASSWORD, "credentialId": ""},
        cookies=cookies,
    )
    assert status == 302, f"keycloak login submit failed: status={status}"
    location = headers.get("Location")
    assert location and "/idp/callback" in location, f"unexpected keycloak login redirect: {location}"
    return to_in_network(location)


def to_in_network(url: str) -> str:
    """Rewrites a browser-facing URL to the in-network address this container can actually reach.

    Two hosts need this, both for the same reason -- a frontchannel URL is built for a browser on
    the HOST, and this runner is a container:

    - `https://localhost:13004/idp/callback` -- the RP's configured `callback_url`, echoed back by
      Keycloak -> `authz-idp:3004`.
    - `http://localhost:9100/...` -- Keycloak's own frontchannel endpoints. Compose sets
      `KC_HOSTNAME=http://localhost:9100` (+ `KC_HOSTNAME_BACKCHANNEL_DYNAMIC`) so Keycloak stamps
      ONE stable external issuer while still handing in-network callers container-reachable
      backchannel URLs; that makes `authorization_endpoint` and every login-form action point at
      `localhost:9100`, which inside this container is the container itself -> `keycloak:9100`.

    A real browser on the host resolves both via the published ports; A real browser on the host resolves `localhost:13004` to `authz-idp` via the
    published port; inside the compose network they are
    ECONNREFUSED, and the RP state cookie is additionally bound to the `authz-idp` origin the
    initial `/authorize` was served from -- so both reachability and cookie continuity require these
    swaps. Path and query (`code`/`state`) are preserved untouched."""
    parts = urllib.parse.urlsplit(url)
    if parts.hostname == "localhost" and parts.port == 13004:
        idp = urllib.parse.urlsplit(IDP_URL)
        return urllib.parse.urlunsplit(
            (idp.scheme, idp.netloc, parts.path, parts.query, parts.fragment)
        )
    if parts.hostname == "localhost" and parts.port == 9100:
        kc = urllib.parse.urlsplit(KEYCLOAK_URL)
        return urllib.parse.urlunsplit(
            (kc.scheme, kc.netloc, parts.path, parts.query, parts.fragment)
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

    # #598: /ui is a route ALLOWLIST now, not a catch-all. `/ui/login` used to pass here
    # VACUOUSLY -- no such route has ever existed; the old SPA fallback answered 200 for any
    # path at all. Now it must 404, and that assertion is what proves the allowlist is real.
    #
    # Consolidated review (R4): this loop is the ONLY place that checks the REAL, pinned artifact's
    # actual route set over real HTTP -- `idp_server_tests.rs`'s equivalent assertions all run
    # against hand-built fixtures, not the shipped bundle. All six of `dist/routes.json`'s routes
    # go through here, not just a subset, so a route the artifact forgot to list is caught here
    # even if every Rust-side fixture still agrees with itself.
    for path in (
        "/ui/",
        "/ui/device",
        "/ui/device/invalid",
        "/ui/device/confirm",
        "/ui/device/success",
        "/ui/error",
    ):
        status, headers, body = http_raw("GET", f"{IDP_URL}{path}")
        assert status == 200, f"{path} failed: status={status}"
        content_type = headers.get("Content-Type", "")
        assert "html" in content_type.lower(), f"{path} did not serve the SPA index: {content_type}"

    for path in ("/ui/login", "/ui/does-not-exist", "/ui/device/nope"):
        status, _, _ = http_raw("GET", f"{IDP_URL}{path}")
        assert status == 404, f"unallowlisted {path} did not 404: status={status}"

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
        CLIENT_CREDENTIALS_GRANT,
    ):
        assert grant in doc["grant_types_supported"], f"discovery missing grant type {grant}"
    assert doc["code_challenge_methods_supported"] == ["S256"], "discovery code_challenge mismatch"
    assert doc["introspection_endpoint"], "discovery missing introspection_endpoint"
    assert doc["check_session_iframe"], "discovery missing check_session_iframe"
    assert doc["end_session_endpoint"], "discovery missing end_session_endpoint"
    assert doc["userinfo_endpoint"], "discovery missing userinfo_endpoint"
    # Neither logout channel is implemented, so neither may be advertised. ADR-0023's rule: a
    # capability in this document is a promise that a handler exists.
    for unimplemented in ("frontchannel_logout_supported", "backchannel_logout_supported"):
        assert unimplemented not in doc, f"discovery advertises unimplemented {unimplemented}"
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


def section_browser_flow() -> tuple["CookieJar", str, str, str]:
    """Drives the full browser authorization-code flow end to end and asserts along the way.

    Returns the live browser session it established -- cookie jar, access token, id_token and a
    current refresh token -- because `section_end_session` needs a REAL session to end. Asserting
    that logout works requires something to log out of; minting a second one would test a
    different session than the one the rest of this section proved out."""
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
                "scope": "openid offline_access",
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token_body = json.loads(body_bytes)
    assert status == 200, f"authorization_code redemption failed: status={status}, body={token_body}"
    access_token = token_body["access_token"]
    claims = decode_jwt_claims(access_token)
    assert claims.get("sub"), f"access token missing sub: {claims}"

    # lightbridge-authz#524: the browser grant mints through the same path as the device and
    # exchange grants, so tenant context is a TOP-LEVEL claim. It used to arrive nested under
    # `identity.attributes` purely because authkestra's default handler passed the authorization
    # code's stored identity through verbatim -- a shape nothing downstream actually read.
    assert claims.get("account_id"), f"access token missing account_id: {claims}"
    assert claims.get("project_id"), f"access token missing project_id: {claims}"

    # The whole point of #524: a browser login must carry the SAME enforcement claims a device
    # login does. Without these the console is authenticated but unauthorized -- refused by every
    # RBAC-gated procedure, with nothing in the token explaining why.
    assert claims.get("budget_tier"), f"browser token missing budget_tier (ADR-0014): {claims}"
    assert claims.get("sid"), f"browser login did not persist a revocable session: {claims}"
    assert claims.get("model_policy"), f"browser token missing model_policy: {claims}"
    # RFC 8693 §2.2.1 requires `issued_token_type` on a token-exchange response and ONLY there.
    assert "issued_token_type" not in token_body, (
        f"issued_token_type belongs to the token-exchange response only: {token_body}"
    )
    log("browser access token carries budget_tier, tenant context and a session id")

    # lightbridge-authz#525: offline_access on the browser grant yields a ROTATING refresh token,
    # and the superseded one must be refused -- the same single-use CAS the device grant gets.
    browser_refresh = token_body.get("refresh_token")
    assert browser_refresh, f"offline_access must yield a refresh token: {token_body}"
    status, _, rotated_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": browser_refresh,
                "client_id": BROWSER_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    rotated = json.loads(rotated_bytes)
    assert status == 200, f"browser refresh failed: status={status}, body={rotated}"
    assert rotated.get("refresh_token") and rotated["refresh_token"] != browser_refresh, (
        f"the browser refresh token must ROTATE, not be reissued: {rotated}"
    )
    status, _, replayed_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": browser_refresh,
                "client_id": BROWSER_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    # #569 changed this contract deliberately, after the 2026-08-30 console-401s incident: a
    # rotated token replayed within `refresh_reuse_grace_seconds` (deployed default 30) is a benign
    # race, not theft, so it mints a SECOND independent successor instead of cascading. This replay
    # is immediate, so it is always inside the window.
    #
    # Asserting only `status == 200` would be a hollow test -- a server that simply replayed the
    # first rotation's cached response would pass it. The two assertions that carry weight are that
    # the graced replay mints a genuinely NEW token, and that the first successor is still alive
    # afterwards: "a racing client no longer kills its own chain" is the entire point of #569, and
    # a cascade would have killed it. The cascade OUTSIDE the window is not re-proven here (it
    # would cost a 30s sleep) -- `refresh_reuse_outside_grace_window_still_cascades` and
    # `refresh_reuse_grace_disabled_cascades_on_immediate_replay` in
    # `crates/lightbridge-authz-rest/tests/token_exchange_tests.rs` own that, against a
    # configurable clock. What this suite adds is that the DEPLOYED config behaves this way.
    replayed = json.loads(replayed_bytes)
    assert status == 200, (
        "a replay inside the reuse-grace window must be graced, not cascaded: "
        f"status={status}, body={replayed}"
    )
    graced_refresh = replayed.get("refresh_token")
    assert graced_refresh and graced_refresh not in (browser_refresh, rotated["refresh_token"]), (
        "a graced replay must mint a second INDEPENDENT successor, not reissue the replayed token "
        f"nor echo the first rotation's: {replayed}"
    )
    status, _, survivor_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": rotated["refresh_token"],
                "client_id": BROWSER_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    survivor = json.loads(survivor_bytes)
    assert status == 200 and survivor.get("refresh_token"), (
        "the graced replay must NOT have cascaded the chain -- the first successor has to still "
        f"renew afterwards: status={status}, body={survivor}"
    )
    log("browser refresh rotates; a replay inside the grace window is graced without cascading")

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

    # `survivor`, not `rotated`: the assertion above consumed `rotated` to prove the chain outlived
    # the graced replay, so it is itself rotated now. `section_end_session` needs a LIVE token to
    # prove logout cascades, and a token that was already spent would pass that test for the wrong
    # reason.
    return cookies, token_body["access_token"], token_body["id_token"], survivor["refresh_token"]


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
    status, headers, _ = http_raw(
        "GET", f"{IDP_URL}/device/verify?user_code={user_code}", cookies=cookies
    )
    # #598: RFC 8628 `verification_uri_complete` still lands on a live URL; it hands off to the
    # SPA now rather than rendering. The prefill survives the hop.
    assert status == 303, f"device verify page did not hand off to the SPA: status={status}"
    assert headers.get("Location", "").startswith("/ui/device"), headers.get("Location")
    assert user_code in headers.get("Location", ""), "user_code prefill was dropped in the handoff"

    status, headers, _ = http_form(
        "POST", f"{IDP_URL}/device/verify", {"user_code": user_code}, cookies=cookies
    )
    assert status == 303, f"device verify submit did not redirect: status={status}"
    assert headers.get("Location") == "/ui/device/confirm", headers.get("Location")
    assert cookies.get("__Host-authz_device_confirm"), "device confirm cookie was not set"

    # The confirmation page's data, cookie-bound. Same cookie the CSRF check requires.
    status, _, ctx_bytes = http_raw(
        "GET", f"{IDP_URL}/device/verify/context", cookies=cookies
    )
    assert status == 200, f"device verify context failed: status={status}"
    ctx = json.loads(ctx_bytes)
    assert ctx["user_code"] == user_code, ctx
    assert ctx["client_id"] == DEVICE_CLIENT_ID, ctx
    assert "device_code" not in ctx_bytes.decode("utf-8"), "context leaked the device_code"

    # No cookie -> uniform 404, never an enumeration oracle.
    status, _, _ = http_raw("GET", f"{IDP_URL}/device/verify/context")
    assert status == 404, f"context without the confirm cookie did not 404: status={status}"

    status, headers, _ = http_form(
        "POST", f"{IDP_URL}/device/verify/continue", {"user_code": user_code}, cookies=cookies
    )
    assert status == 303, f"device verify continue did not redirect: status={status}"
    keycloak_location = headers.get("Location")
    assert keycloak_location, "device verify continue missing keycloak redirect"

    callback_location = drive_keycloak_login(keycloak_location, cookies)
    status, headers, _ = http_raw("GET", callback_location, cookies=cookies)
    assert status == 303, f"device callback did not complete pairing: status={status}"
    assert headers.get("Location") == "/ui/device/success", headers.get("Location")
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
    # Same #569 grace window as the browser leg above -- reuse classification is shared
    # (`TokenExchangeOpStore::classify_replayed_refresh_token`), so the device grant inherits it.
    # Kept lighter than the browser assertions on purpose: the browser leg is the one the
    # 2026-08-30 incident actually happened on, so it carries the full no-cascade proof, and
    # duplicating that here would only re-test shared code through a second door.
    reuse_body = json.loads(reuse_bytes)
    assert status == 200, (
        "a replay inside the reuse-grace window must be graced, not cascaded: "
        f"status={status}, body={reuse_body}"
    )
    assert reuse_body.get("refresh_token") not in (None, refresh_token, new_refresh_token), (
        f"a graced replay must mint a second independent successor: {reuse_body}"
    )
    log("device refresh_token rotates; a replay inside the grace window is graced")
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


# --- 9b. client_credentials (M2M, #534/ADR-0030) --------------------------------------------------


def section_client_credentials() -> None:
    """Live end-to-end coverage of the `client_credentials` grant: `it-machine` signs a real
    `private_key_jwt` assertion (`jwt_min.py`, against the keypair
    `generate_it_machine_fixtures.py` generates fresh at IT-stack-up time -- never checked into
    the repo, see that script's own doc comment), mints via `POST /oauth2/token`, the resulting
    access token verifies against the exact JWKS `/.well-known/jwks.json` serves, and
    `POST /oauth2/introspect` reports it `active: true`.

    Deliberately does NOT attempt a live call against `authz-api`'s RPC surface with this token --
    but ONLY because of a LOCAL-COMPOSE-SPECIFIC drift, not a platform limitation: in production
    (`ai-helm-values`), `authz-api`/`authz-budget` validate against `authz-idp`'s own JWKS (the
    platform rule -- every authz resource server validates against `authz-idp`, which alone brokers
    the Keycloak login leg), so a self-signed `client_credentials` token DOES pass signature
    validation there and IS refused by the empty permission set instead, exactly as designed. THIS
    local stack's `.docker/authz/container.yaml` still points `oauth2.jwks_url` directly at
    Keycloak -- never migrated when ADR-0023 made `authz-idp` the full IdP (tracked separately, see
    `docs/local-testing.md`) -- so here, and only here, the token is rejected at signature
    validation before any permission is ever checked, making a live RPC call pointless to attempt
    in this suite. The zero-permissions property itself (no roles claim -> zero `Permission`s ->
    every `@allow` denies) is instead proven directly against the real
    `BearerTokenService::validate_bearer_token` code path in
    `crates/lightbridge-authz-bearer/tests/token_validation_tests.rs`'s
    `client_credentials_style_token_has_no_roles_and_zero_permissions_for_every_permission`.
    """
    status, discovery, _ = http_json("GET", f"{IDP_URL}/.well-known/openid-configuration")
    assert status == 200, f"discovery failed: status={status}"
    issuer = discovery["issuer"]

    with open(MACHINE_PRIVATE_KEY_PATH, encoding="utf-8") as key_file:
        private_key_pem = key_file.read()

    def sign_assertion() -> str:
        return jwt_min.sign_private_key_jwt(
            private_key_pem,
            MACHINE_KID,
            MACHINE_CLIENT_ID,
            issuer,
            str(uuid.uuid4()),
            300,
            int(time.time()),
        )

    status, _, body_bytes = http_form(
        "POST",
        f"{IDP_URL}/oauth2/token",
        {
            "grant_type": CLIENT_CREDENTIALS_GRANT,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": sign_assertion(),
            "scope": "read:usage",
        },
    )
    body = json.loads(body_bytes)
    assert status == 200, f"client_credentials mint failed: status={status}, body={body}"
    assert "refresh_token" not in body or body["refresh_token"] is None, (
        f"RFC 6749 Sec4.4.3 MUST NOT: client_credentials must never return a refresh_token: {body}"
    )
    assert "id_token" not in body or body["id_token"] is None, (
        f"client_credentials must never return an id_token: {body}"
    )
    access_token = body["access_token"]

    header, claims = jwt_min.decode_header_and_claims(access_token)
    assert claims.get("sub") == f"svc:{MACHINE_CLIENT_ID}", f"unexpected sub: {claims}"
    assert claims.get("azp") == MACHINE_CLIENT_ID, f"unexpected azp: {claims}"
    assert claims.get("typ") == "Bearer", f"unexpected typ: {claims}"
    assert claims.get("lightbridge_caller_kind") == "service", f"unexpected claims: {claims}"
    assert str(claims.get("jti", "")).startswith("lgbr:"), f"jti must be this repo's own CUID2 convention, not a bare UUIDv4: {claims}"
    for absent in ("account_id", "project_id", "api_key_id", "sid", "budget_tier", "quota_tier"):
        assert absent not in claims, f"{absent} must be absent from a client_credentials token: {claims}"
    log("client_credentials access token carries the expected service-token claim shape")

    status, jwks_body, _ = http_json("GET", f"{IDP_URL}/.well-known/jwks.json")
    assert status == 200, f"jwks failed: status={status}"
    matching_jwk = next(
        (k for k in jwks_body.get("keys", []) if k.get("kid") == header.get("kid")), None
    )
    assert matching_jwk, f"no jwks key matches the access token's kid {header.get('kid')!r}"
    assert jwt_min.verify_rs256(access_token, matching_jwk), (
        "client_credentials access token does not verify against the server's own published JWKS"
    )
    log("client_credentials access token verifies against the same JWKS discovery serves")

    status, _, introspect_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/introspect",
        body=urllib.parse.urlencode(
            {
                "token": access_token,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": sign_assertion(),
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    introspect_body = json.loads(introspect_bytes)
    assert status == 200 and introspect_body.get("active") is True, (
        f"client_credentials access token did not introspect active: status={status}, "
        f"body={introspect_body}"
    )
    assert introspect_body.get("client_id") == MACHINE_CLIENT_ID, (
        f"unexpected introspection client_id: {introspect_body}"
    )
    log("client_credentials access token introspects active:true")


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


# --- 11. UserInfo + RP-Initiated Logout -------------------------------------------------------


def section_userinfo(browser_access_token: str, no_profile_scope_access_token: str) -> None:
    """OIDC Core §5.3. The important assertion is the NEGATIVE one: authorization data must not be
    reachable through this endpoint. `budget_tier`/`quota_tier`/roles all sit one `claims.get`
    away in the same token, so nothing but a deliberate allow-list keeps them out.

    `no_profile_scope_access_token` is `section_token_exchange`'s token, minted with
    `openid offline_access` and neither `email` nor `profile`. It is the scope gate's only real
    end-to-end negative: it DOES carry `email`/`name`/`preferred_username` claims (that grant
    decodes them straight off the presented Keycloak token, unconditionally), so the sole thing
    that can keep them out of the response is `scope_grants_email`/`scope_grants_profile` actually
    running. Answering the second half of the tripwire #565 fired -- "confirm the email scope
    actually gates it"."""
    status, body, _ = http_json(
        "GET",
        f"{IDP_URL}/oauth2/userinfo",
        headers={"Authorization": f"Bearer {browser_access_token}"},
    )
    assert status == 200, f"userinfo rejected a live browser token: status={status}, body={body}"
    assert body.get("sub"), f"userinfo response missing the required sub claim: {body}"
    assert body.get("account_id") and body.get("project_id"), (
        f"userinfo must carry this deployment's tenant context: {body}"
    )
    # This was a TRIPWIRE pinning a known gap -- a browser login used to mint `email: None` at
    # source, so UserInfo could never return one. #565 closed that by persisting the profile-claim
    # snapshot as plaintext columns on `federated_identities` and loading it at mint time, which
    # fired the tripwire exactly as designed. Its instruction was to update the assertion AND
    # re-confirm the scope gating; both happen here (the gate itself is the negative below).
    #
    # Exact-match, not a presence check: a presence check would pass on someone ELSE's email. The
    # realm seeds `USERNAME`'s user with its username as its email and a distinct display name
    # (`.docker/keycloak_config/realm.json`), so these pin the right person's claims specifically.
    assert body.get("email") == USERNAME, (
        f"userinfo must return the email #565 snapshotted at login for {USERNAME}: {body}"
    )
    assert body.get("email_verified") is True, (
        f"userinfo must return email_verified for a realm-verified user: {body}"
    )
    assert body.get("preferred_username") == USERNAME and body.get("name"), (
        f"userinfo must return the profile claims #565 added under the profile scope: {body}"
    )
    for authorization_claim in (
        "budget_tier",
        "quota_tier",
        "model_policy",
        "allowed_models",
        "lightbridge_api_roles",
    ):
        assert authorization_claim not in body, (
            f"userinfo leaked authorization data ({authorization_claim}): {body}"
        )
    log("userinfo returns identity claims and no authorization data")

    status, scopeless_body, _ = http_json(
        "GET",
        f"{IDP_URL}/oauth2/userinfo",
        headers={"Authorization": f"Bearer {no_profile_scope_access_token}"},
    )
    assert status == 200, (
        f"userinfo rejected a live exchange token: status={status}, body={scopeless_body}"
    )
    minted = decode_jwt_claims(no_profile_scope_access_token)
    assert "email" in minted and "name" in minted, (
        "this negative only proves something if the token itself carries the claims being "
        f"withheld -- if the exchange grant stopped minting them, rewrite this: {minted}"
    )
    for gated in ("email", "email_verified", "name", "preferred_username"):
        assert gated not in scopeless_body, (
            f"userinfo returned {gated} for a token minted without the email/profile scope: "
            f"{scopeless_body}"
        )
    log("userinfo withholds email and profile claims from a token minted without those scopes")

    status, headers, _ = http_raw("GET", f"{IDP_URL}/oauth2/userinfo")
    assert status == 401, f"userinfo without a bearer must be 401: status={status}"
    assert headers.get("WWW-Authenticate") == "Bearer", (
        "RFC 6750 §3.1: a missing credential gets the bare challenge, never invalid_token "
        f"-- got {headers.get('WWW-Authenticate')!r}"
    )

    status, headers, _ = http_raw(
        "GET", f"{IDP_URL}/oauth2/userinfo", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert status == 401, f"userinfo with a malformed bearer must be 401: status={status}"
    assert 'error="invalid_token"' in (headers.get("WWW-Authenticate") or ""), (
        f"expected invalid_token challenge, got {headers.get('WWW-Authenticate')!r}"
    )
    log("userinfo distinguishes a missing credential from a bad one")


def section_end_session(cookies: CookieJar, id_token: str, refresh_token: str) -> None:
    """OIDC RP-Initiated Logout 1.0, driven against the live session `section_browser_flow` left
    behind.

    Three properties, in the order they matter:

    1. An UNREGISTERED `post_logout_redirect_uri` never reaches a Location header. This is checked
       FIRST, while the session is still live, because it is the security property -- and because
       running it first also proves the refusal did not depend on the session already being gone.
    2. A registered one is honoured, with `state` round-tripped, and the session cookie is cleared.
    3. The refresh token is DEAD afterwards. Without this the whole endpoint would be theatre: the
       cookie would be gone from the browser while every issued refresh chain kept renewing."""
    hostile = f"{IDP_URL}/oauth2/end_session?" + urllib.parse.urlencode(
        {
            "client_id": BROWSER_CLIENT_ID,
            "post_logout_redirect_uri": "http://attacker.invalid/steal",
        }
    )
    status, headers, _ = http_raw("GET", hostile, cookies=CookieJar())
    assert status == 200, f"an unregistered redirect must render the OP page: status={status}"
    assert not headers.get("Location"), (
        f"an unregistered post_logout_redirect_uri reached a Location header: "
        f"{headers.get('Location')!r}"
    )
    log("end_session refuses an unregistered post_logout_redirect_uri")

    logout_url = f"{IDP_URL}/oauth2/end_session?" + urllib.parse.urlencode(
        {
            "client_id": BROWSER_CLIENT_ID,
            "id_token_hint": id_token,
            "post_logout_redirect_uri": "http://it-client.invalid/signed-out",
            "state": "it-logout-state",
        }
    )
    status, headers, _ = http_raw("GET", logout_url, cookies=cookies)
    assert status == 303, f"logout with a registered redirect must 303: status={status}"
    location = headers.get("Location") or ""
    assert location.startswith("http://it-client.invalid/signed-out"), (
        f"logout redirected somewhere unexpected: {location}"
    )
    assert query_params(location).get("state") == "it-logout-state", (
        f"state must round-trip to the RP: {location}"
    )
    set_cookie = headers.get("Set-Cookie") or ""
    assert "__Host-authz_session=" in set_cookie and "Max-Age=0" in set_cookie, (
        f"logout must clear the session cookie: {set_cookie!r}"
    )
    log("end_session honours a registered redirect, round-trips state and clears the cookie")

    status, _, refused_bytes = http_raw(
        "POST",
        f"{IDP_URL}/oauth2/token",
        body=urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": BROWSER_CLIENT_ID,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    refused = json.loads(refused_bytes)
    assert status == 400 and refused.get("error") == "invalid_grant", (
        "logout must cascade to the refresh chain -- a still-renewable token after logout means "
        f"the session only LOOKS ended: status={status}, body={refused}"
    )
    log("logout cascaded: the browser session's refresh token is refused afterwards")


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
        browser_cookies, browser_access, browser_id_token, browser_refresh = (
            section_browser_flow()
        )
        section_check_session_iframe()
        device_access_token, device_refresh_token = section_device_flow()
        exchange_access_token, exchange_refresh_token = section_token_exchange(project_id)
        # After the exchange, not before: the scope gate's negative needs a token minted WITHOUT
        # the email/profile scopes, and the exchange grant is the only place one exists.
        section_userinfo(browser_access, exchange_access_token)
        section_client_credentials()
        section_introspection(exchange_access_token, exchange_refresh_token, device_access_token)
        section_revocation(device_refresh_token)
        # Last: it ends the browser session every earlier section relied on.
        section_end_session(browser_cookies, browser_id_token, browser_refresh)

        return 0
    except Exception as err:
        log(f"FAILED: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
