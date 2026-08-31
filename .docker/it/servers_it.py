#!/usr/bin/env python3
import base64
import datetime
import json
import os
import ssl
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request

import cbor_min


KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:9100").rstrip("/")
API_URL = os.environ.get("API_URL", "https://authz-api:3000").rstrip("/")
OPA_URL = os.environ.get("OPA_URL", "https://authz-opa:3001").rstrip("/")
USAGE_URL = os.environ.get("USAGE_URL", "https://authz-usage:3002").rstrip("/")
# mTLS-required query listener (#347): /usage/v1/usage/query + /usage/v1/spend/query moved here,
# off the unauthenticated USAGE_URL ingest listener above -- see UsageServerGroup::query's doc
# comment in crates/lightbridge-authz-usage/src/config.rs.
USAGE_QUERY_URL = os.environ.get("USAGE_QUERY_URL", "https://authz-usage:3006").rstrip("/")
USAGE_CLIENT_CERT = os.environ.get("USAGE_CLIENT_CERT")
USAGE_CLIENT_KEY = os.environ.get("USAGE_CLIENT_KEY")
MCP_URL = os.environ.get("MCP_URL", "https://authz-mcp:3000").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "test-client")
USERNAME = os.environ.get("USERNAME", "test@admin")
PASSWORD = os.environ.get("PASSWORD", "test")
AUTHORINO_BASIC = os.environ.get("AUTHORINO_BASIC", "authorino:change-me")
MAX_WAIT_SECONDS = int(os.environ.get("MAX_WAIT_SECONDS", "180"))
EXPECTED_MCP_TOOLS = {
    "create-account",
    "list-accounts",
    "get-account",
    "update-account",
    "update-account-name",
    "delete-account",
    "disable-account",
    "enable-account",
    "list-project-roster",
    "add-project-member",
    "remove-project-member",
    "set-project-member-role",
    "set-project-member-quota-tier",
    "create-project",
    "list-projects",
    "get-project",
    "update-project",
    "delete-project",
    "disable-project",
    "enable-project",
    "set-default-project",
    "set-project-quota",
    "set-project-allowed-models",
    "set-project-model-policy",
    "create-api-key",
    "list-api-keys",
    "get-api-key",
    "update-api-key",
    "delete-api-key",
    "revoke-api-key",
    "rotate-api-key",
    "validate-api-key",
    "validate-authorino-api-key",
}


INSECURE_TLS = ssl.create_default_context()
INSECURE_TLS.check_hostname = False
INSECURE_TLS.verify_mode = ssl.CERT_NONE

# Presents a client certificate for the mTLS-required query listener (#347). Built only when
# USAGE_CLIENT_CERT/USAGE_CLIENT_KEY are set (compose.it.yaml's it-servers service mounts the same
# authz_tls volume authz-api reads its own client identity from -- see that service's environment
# block) so this script still degrades gracefully to "no mTLS test" when run standalone without
# those env vars.
MTLS_CLIENT_TLS = None
if USAGE_CLIENT_CERT and USAGE_CLIENT_KEY:
    MTLS_CLIENT_TLS = ssl.create_default_context()
    MTLS_CLIENT_TLS.check_hostname = False
    MTLS_CLIENT_TLS.verify_mode = ssl.CERT_NONE
    MTLS_CLIENT_TLS.load_cert_chain(certfile=USAGE_CLIENT_CERT, keyfile=USAGE_CLIENT_KEY)



def _it_expires_at() -> str:
    """RFC3339 expiry 30 days out.

    `createApiKey` requires `expiresAt` and rejects anything past the configured
    ceiling (default 90 days) or in the past, so this must be computed at run time
    rather than hardcoded -- a literal date would silently start failing once it
    drifted into the past.
    """
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")

def log(message: str) -> None:
    print(f"[it-servers] {message}", flush=True)


def request_raw(
    method: str,
    url: str,
    body=None,
    headers=None,
    insecure_tls: bool = False,
    ssl_context=None,
):
    encoded = None
    if body is not None:
        encoded = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url=url, method=method, data=encoded)
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)

    if ssl_context is not None:
        context = ssl_context
    else:
        context = INSECURE_TLS if insecure_tls else None
    with urllib.request.urlopen(req, timeout=30, context=context) as response:
        payload = response.read().decode("utf-8")
        return response.status, payload, dict(response.headers.items())


def request_rpc(
    method: str,
    url: str,
    body=None,
    headers=None,
    insecure_tls: bool = False,
    ssl_context=None,
):
    """Like `request_json`, but for `authz-api`'s/`authz-budget`'s `/rpc/*` surfaces, which speak
    CBOR only post-ADR-0013 (see `cbor_min.py`'s module doc). Every other endpoint this script
    calls -- health probes, Keycloak, OPA (JSON and form-encoded), the usage query API, MCP -- is
    untouched by that ADR and stays on `request_json`/`request_raw`.
    """
    encoded = None
    if body is not None:
        encoded = cbor_min.encode(body)

    req = urllib.request.Request(url=url, method=method, data=encoded)
    req.add_header("Accept", "application/cbor")
    if body is not None:
        req.add_header("Content-Type", "application/cbor")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)

    if ssl_context is not None:
        context = ssl_context
    else:
        context = INSECURE_TLS if insecure_tls else None
    with urllib.request.urlopen(req, timeout=30, context=context) as response:
        payload = response.read()
        response_headers = dict(response.headers.items())
        if not payload:
            return response.status, {}, response_headers
        return response.status, cbor_min.decode(payload), response_headers


def request_json(
    method: str,
    url: str,
    body=None,
    headers=None,
    insecure_tls: bool = False,
    ssl_context=None,
):
    status, payload, response_headers = request_raw(
        method=method,
        url=url,
        body=body,
        headers=headers,
        insecure_tls=insecure_tls,
        ssl_context=ssl_context,
    )
    if not payload:
        return status, {}, response_headers
    return status, json.loads(payload), response_headers


def expect_http_error(
    expected_status: int,
    *,
    method: str,
    url: str,
    body=None,
    headers=None,
    insecure_tls: bool = False,
) -> None:
    try:
        request_raw(
            method=method,
            url=url,
            body=body,
            headers=headers,
            insecure_tls=insecure_tls,
        )
    except urllib.error.HTTPError as err:
        if err.code != expected_status:
            raise AssertionError(
                f"expected HTTP {expected_status} from {method} {url}, got {err.code}"
            ) from err
        return
    raise AssertionError(f"expected HTTP {expected_status} from {method} {url}")


def post_form(url: str, form_data: dict, headers=None, insecure_tls: bool = False):
    payload = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(url=url, method="POST", data=payload)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    context = INSECURE_TLS if insecure_tls else None
    with urllib.request.urlopen(req, timeout=30, context=context) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def parse_sse_json_messages(raw: str) -> list[dict]:
    try:
        message = json.loads(raw)
        if isinstance(message, dict):
            return [message]
    except json.JSONDecodeError:
        pass

    messages = []
    for line in raw.splitlines():
        if not line.startswith("data: "):
            continue
        payload = line[6:].strip()
        if not payload or not payload.startswith("{"):
            continue
        messages.append(json.loads(payload))
    return messages


def wait_until_ready() -> None:
    probe_urls = [
        f"{API_URL}/healthz",
        f"{API_URL}/healthz/startup",
        f"{API_URL}/healthz/ready",
        f"{OPA_URL}/healthz",
        f"{OPA_URL}/healthz/startup",
        f"{OPA_URL}/healthz/ready",
        f"{USAGE_URL}/healthz",
        f"{USAGE_URL}/healthz/startup",
        f"{USAGE_URL}/healthz/ready",
        f"{MCP_URL}/healthz",
        f"{MCP_URL}/healthz/startup",
        f"{MCP_URL}/healthz/ready",
    ]
    # The mTLS-required query listener (#347) serves its own probes too, but reaching them needs a
    # client certificate -- see MTLS_CLIENT_TLS above. Only probed when one is configured, so this
    # script degrades gracefully when run standalone.
    mtls_probe_urls = [
        f"{USAGE_QUERY_URL}/healthz",
        f"{USAGE_QUERY_URL}/healthz/startup",
        f"{USAGE_QUERY_URL}/healthz/ready",
    ]

    start = time.time()
    last_error = "readiness checks have not run yet"
    while True:
        try:
            for probe_url in probe_urls:
                status, _, _ = request_raw("GET", probe_url, insecure_tls=True)
                assert status == 200, f"probe failed {probe_url}: status={status}"

            if MTLS_CLIENT_TLS is not None:
                for probe_url in mtls_probe_urls:
                    status, _, _ = request_raw(
                        "GET", probe_url, ssl_context=MTLS_CLIENT_TLS
                    )
                    assert status == 200, f"mtls probe failed {probe_url}: status={status}"

            request_json(
                "GET",
                f"{KEYCLOAK_URL}/realms/dev/.well-known/openid-configuration",
            )
            log("all probes and Keycloak discovery endpoint are ready")
            return
        except Exception as err:
            last_error = str(err) or err.__class__.__name__
            if time.time() - start > MAX_WAIT_SECONDS:
                raise TimeoutError(
                    f"services not ready after {MAX_WAIT_SECONDS}s: {last_error}"
                ) from None
            time.sleep(2)


def fetch_token(username: str = USERNAME, password: str = PASSWORD) -> str:
    token_url = f"{KEYCLOAK_URL}/realms/dev/protocol/openid-connect/token"
    status, payload = post_form(
        token_url,
        {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": username,
            "password": password,
        },
    )
    if status != 200 or "access_token" not in payload:
        raise RuntimeError(f"token fetch failed: status={status}, payload={payload}")
    return payload["access_token"]


def account_id_from_token(token: str) -> str:
    """The caller's account id, read straight off the JWT.

    Since ADR-0006 `accounts.id` IS the authenticated subject, so the id needs no lookup.
    """
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))["sub"]


def ensure_account(authz_headers: dict, token: str) -> str:
    """Provision the caller's ANCHOR account, idempotently.

    ADR-0026 changed the mechanism this used to rely on. `createAccount` was once-per-subject, so
    a replay returned 409 and the 409 itself WAS the "already provisioned" signal. One identity may
    now own several accounts, so a replay returns 200 and a genuinely NEW account -- catching 409
    would never fire again, and every re-run would silently mint another account instead of reusing
    the one it wants. That matters here rather than theoretically: this suite shares a compose stack
    (and therefore a database) with the other IT suites, all authenticate as the same Keycloak user,
    and the CI runner retries a suite up to three times.

    So provisioning is now keyed on the ANCHOR account instead of on an error code. An identity's
    first account keeps `id = subject` (ADR-0026 D3) precisely because it anchors the identity, so
    the subject read off the token IS the id to look for. Read it first; only create when it is
    genuinely absent, and assert the created id matches -- which also keeps this suite exercising
    the anchor path rather than drifting onto the secondary-account one.
    """
    anchor_id = account_id_from_token(token)
    # A read policy FILTERS rather than rejects, so an absent (or unreadable) account is a 404,
    # which `urlopen` raises. Absent is the expected first-run case, not an error.
    try:
        status, existing, _ = request_rpc(
            "POST",
            f"{API_URL}/rpc/model.Account.get",
            {"id": anchor_id},
            headers=authz_headers,
            insecure_tls=True,
        )
        if status == 200 and isinstance(existing, dict) and existing.get("id") == anchor_id:
            log(f"anchor account already provisioned; reusing {anchor_id}")
            return anchor_id
    except urllib.error.HTTPError as err:
        if err.code != 404:
            raise

    status, account, _ = request_rpc(
        "POST",
        f"{API_URL}/rpc/procedure.createAccount",
        {"args": {}},
        headers=authz_headers,
        insecure_tls=True,
    )
    assert status == 200, f"create account failed: status={status}, body={account}"
    assert account["id"] == anchor_id, (
        "the first account for a subject must be the anchor, keyed by the subject itself "
        f"(ADR-0026 D3): got {account['id']}, expected {anchor_id}"
    )
    return anchor_id


def assert_mcp_oauth_metadata() -> None:
    authorization_server_url = f"{MCP_URL}/.well-known/oauth-authorization-server"
    openid_configuration_url = f"{MCP_URL}/.well-known/openid-configuration"
    status, authorization_server, _ = request_json(
        "GET", authorization_server_url, insecure_tls=True
    )
    assert status == 200, f"oauth metadata failed: status={status}, body={authorization_server}"
    status, openid_configuration, _ = request_json(
        "GET", openid_configuration_url, insecure_tls=True
    )
    assert status == 200, f"openid metadata failed: status={status}, body={openid_configuration}"
    assert authorization_server == openid_configuration, "oauth metadata documents differ"

    issuer = f"{KEYCLOAK_URL}/realms/dev"
    expected = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
        "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
        "registration_endpoint": f"{MCP_URL}/oauth/register",
    }
    for field, value in expected.items():
        assert authorization_server.get(field) == value, (
            f"unexpected MCP OAuth metadata {field}: {authorization_server}"
        )
    log("mcp oauth discovery metadata passed")


def mcp_initialize(token: str) -> None:
    status, body, headers = request_raw(
        "POST",
        f"{MCP_URL}/mcp",
        body={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "it-servers", "version": "1.0"},
            },
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        insecure_tls=True,
    )
    assert status == 200, f"mcp initialize failed: status={status}, body={body}"

    assert not any(key.lower() == "mcp-session-id" for key in headers), (
        f"stateless MCP server unexpectedly returned a session header: {headers}"
    )

    messages = parse_sse_json_messages(body)
    init_result = next((msg for msg in messages if msg.get("id") == 1), None)
    assert init_result is not None, f"missing initialize result: body={body}"
    assert init_result.get("result"), f"unexpected initialize payload: {init_result}"

def mcp_post(token: str, payload: dict):
    return request_raw(
        "POST",
        f"{MCP_URL}/mcp",
        body=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        insecure_tls=True,
    )


def main() -> int:
    try:
        wait_until_ready()
        assert_mcp_oauth_metadata()

        token = fetch_token()
        authz_headers = {"Authorization": f"Bearer {token}"}
        billing_identity = f"it-servers-{uuid.uuid4().hex[:12]}"

        # authz-api migrated to cratestack RPC transport (ADR-0003): CRUD dispatches via
        # POST /rpc/{op_id}, CBOR-only since ADR-0013 (see `request_rpc`/`cbor_min.py`). A mapped
        # op with no bearer is rejected by the coarse RBAC gate with 401 (fail-closed) before
        # dispatch -- that gate runs before codec/Content-Type validation, so the plain
        # JSON-encoded probe body below still exercises the right thing.
        expect_http_error(
            401,
            method="POST",
            url=f"{API_URL}/rpc/model.Account.list",
            body={},
            insecure_tls=True,
        )
        log("api rejects missing bearer token")

        account_id = ensure_account(authz_headers, token)
        log(f"api create-account passed ({account_id})")

        project_client_id = "c" + uuid.uuid4().hex[:24]
        status, project, _ = request_rpc(
            "POST",
            f"{API_URL}/rpc/model.Project.create",
            {
                "id": project_client_id,
                "accountId": account_id,
                "name": "it-servers-project",
                "allowedModels": {"List": [{"String": "gpt-4.1-mini"}]},
                "defaultLimits": {"Map": {}},
                "billingPlan": "free",
                "billingIdentity": billing_identity,
                "status": "active",
            },
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create project failed: status={status}, body={project}"
        project_id = project["id"]

        status, key_payload, _ = request_rpc(
            "POST",
            f"{API_URL}/rpc/procedure.createApiKey",
            {"args": {"projectId": project_id, "name": "it-servers-key", "billingPlan": "free", "expiresAt": _it_expires_at()}},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 200, f"create api key failed: status={status}, body={key_payload}"
        secret = key_payload["secret"]

        expect_http_error(
            401,
            method="POST",
            url=f"{OPA_URL}/v1/authorino/validate/introspect",
            body={"token": secret},
            insecure_tls=True,
        )
        log("opa rejects missing basic auth")

        basic = base64.b64encode(AUTHORINO_BASIC.encode("utf-8")).decode("utf-8")
        status, opa_ok = post_form(
            f"{OPA_URL}/v1/authorino/validate/introspect",
            {"token": secret, "token_type_hint": "access_token"},
            headers={"Authorization": f"Basic {basic}"},
            insecure_tls=True,
        )
        assert status == 200, f"opa introspection failed: status={status}, body={opa_ok}"
        assert opa_ok["active"] is True, f"expected active token: {opa_ok}"
        assert opa_ok["account_id"] == account_id, f"unexpected opa account: {opa_ok}"
        assert opa_ok["project_id"] == project_id, f"unexpected opa project: {opa_ok}"
        log("opa introspect endpoint passed")

        if MTLS_CLIENT_TLS is None:
            raise AssertionError(
                "USAGE_CLIENT_CERT/USAGE_CLIENT_KEY must be set to exercise the mTLS-required "
                "query listener (#347) -- compose.it.yaml's it-servers service should always set "
                "these"
            )

        usage_query_body = {
            "scope": "project",
            "scope_id": "proj_invalid",
            "start_time": "2026-03-01T01:00:00Z",
            "end_time": "2026-03-01T00:00:00Z",
            "bucket": "5 minutes",
            "group_by": ["model"],
            "filters": {},
            "limit": 100,
        }

        # #347, acceptance criterion 1: no client certificate -> rejected at the TLS layer, never
        # reaching the router (so never an HTTPError with a JSON body -- a bare connection/TLS
        # failure).
        try:
            request_raw(
                "POST",
                f"{USAGE_QUERY_URL}/usage/v1/usage/query",
                body=usage_query_body,
                insecure_tls=True,
            )
            raise AssertionError(
                "usage query listener accepted a request with no client certificate"
            )
        except urllib.error.HTTPError as err:
            raise AssertionError(
                f"expected a TLS-layer rejection with no client certificate, got an HTTP "
                f"response instead: {err.code}"
            ) from err
        except (ssl.SSLError, urllib.error.URLError, ConnectionError):
            pass
        log("usage query listener rejects a connection with no client certificate")

        # #347, acceptance criterion 2: authz-api's configured client certificate -> reaches the
        # router (TLS-layer mTLS is satisfied). #570 review remediation: authentication now runs
        # BEFORE body validation in the handler (crates/lightbridge-authz-usage/src/handlers/
        # query.rs), specifically so an unauthenticated caller can never distinguish a malformed
        # request from a well-formed one via a differentiated 400 -- this request carries a
        # trusted client certificate but NO Authorization header, so it must be refused with 401,
        # never the invalid-time-window 400 it used to get before that reordering.
        usage_status = None
        usage_error_body = ""
        try:
            request_raw(
                "POST",
                f"{USAGE_QUERY_URL}/usage/v1/usage/query",
                body=usage_query_body,
                ssl_context=MTLS_CLIENT_TLS,
            )
            raise AssertionError("usage query unexpectedly succeeded")
        except urllib.error.HTTPError as err:
            usage_status = err.code
            usage_error_body = err.read().decode("utf-8")

        if usage_status != 401:
            raise AssertionError(
                f"a trusted-mTLS request with no bearer token must be refused with 401 "
                f"(auth runs before body validation), got {usage_status}: {usage_error_body}"
            )
        log(
            "usage query listener accepts a trusted client certificate but refuses a request "
            "with no bearer token (401, auth-before-validation)"
        )

        # Bearer-carrying variant of the same malformed body, so the invalid-time-window
        # validation itself stays covered even though the unauthenticated variant above no longer
        # reaches it: with a valid bearer token, the SAME malformed request must now get the
        # ordinary 400 "start_time must be before end_time" the pre-#570 assertion checked for.
        usage_status = None
        usage_error_body = ""
        try:
            request_raw(
                "POST",
                f"{USAGE_QUERY_URL}/usage/v1/usage/query",
                body=usage_query_body,
                headers={"Authorization": f"Bearer {token}"},
                ssl_context=MTLS_CLIENT_TLS,
            )
            raise AssertionError("usage query unexpectedly succeeded")
        except urllib.error.HTTPError as err:
            usage_status = err.code
            usage_error_body = err.read().decode("utf-8")

        if usage_status not in (400, 500):
            raise AssertionError(
                f"an authenticated usage query should reject an invalid time window, got "
                f"{usage_status}: {usage_error_body}"
            )
        if "start_time must be before end_time" not in usage_error_body:
            raise AssertionError(f"unexpected usage error body: {usage_error_body}")
        log(
            "usage query listener accepts a trusted client certificate and a valid bearer "
            "token, and rejects an invalid request (400)"
        )

        # #347 covers both routes named in its acceptance criteria -- prove /usage/v1/spend/query
        # is reachable with the trusted client certificate too (no client cert -> same TLS-layer
        # rejection mechanism as usage/query above, already proven at the listener level).
        spend_status, spend_body, _ = request_json(
            "POST",
            f"{USAGE_QUERY_URL}/usage/v1/spend/query",
            body={
                "account_id": "acct_it_servers_probe",
                "start": "2026-03-01T00:00:00Z",
                "end": "2026-03-02T00:00:00Z",
            },
            ssl_context=MTLS_CLIENT_TLS,
        )
        assert spend_status == 200, f"spend query failed: status={spend_status}, body={spend_body}"
        assert "total_cost" in spend_body, f"unexpected spend query body: {spend_body}"
        log("spend query listener accepts a trusted client certificate")

        # #570: two-tenant end-to-end proof that `/usage/v1/usage/query` enforces ownership, not
        # just mTLS. `test@admin` (this suite's primary tenant, `token`/`account_id` above) and
        # `test@editor` (a second, distinct Keycloak subject seeded by the same realm import --
        # `.docker/keycloak_config/realm.json` -- and therefore a distinct `accounts.id` anchor
        # per ADR-0006/ADR-0026) each query their OWN account scope (200) and each other's (403).
        other_token = fetch_token(username="test@editor", password="test")
        other_headers = {"Authorization": f"Bearer {other_token}"}
        other_account_id = ensure_account(other_headers, other_token)
        assert other_account_id != account_id, (
            "the second tenant must resolve to a DIFFERENT account than the primary tenant, or "
            "this test proves nothing"
        )

        def usage_query_status(bearer_token: str, scope_id: str) -> tuple:
            body = {
                "scope": "account",
                "scope_id": scope_id,
                "start_time": "2026-03-01T00:00:00Z",
                "end_time": "2026-03-02T00:00:00Z",
                "bucket": "1 day",
                "group_by": [],
                "filters": {},
                "limit": 10,
            }
            try:
                status, payload, _ = request_raw(
                    "POST",
                    f"{USAGE_QUERY_URL}/usage/v1/usage/query",
                    body=body,
                    headers={"Authorization": f"Bearer {bearer_token}"},
                    ssl_context=MTLS_CLIENT_TLS,
                )
                return status, payload
            except urllib.error.HTTPError as err:
                return err.code, err.read().decode("utf-8")

        status, payload = usage_query_status(token, account_id)
        assert status == 200, (
            f"tenant A must be authorized for their own account scope: status={status}, "
            f"body={payload}"
        )
        log("usage query: tenant A authorized for their own account scope")

        status, payload = usage_query_status(other_token, other_account_id)
        assert status == 200, (
            f"tenant B must be authorized for their own account scope: status={status}, "
            f"body={payload}"
        )
        log("usage query: tenant B authorized for their own account scope")

        status, payload = usage_query_status(other_token, account_id)
        assert status == 403, (
            f"tenant B must be refused for tenant A's account scope: status={status}, "
            f"body={payload}"
        )
        assert not payload or "points" not in payload, (
            f"a refused cross-tenant query must never leak tenant A's data: {payload}"
        )
        log("usage query: tenant B refused for tenant A's account scope (#570)")

        status, payload = usage_query_status(token, other_account_id)
        assert status == 403, (
            f"tenant A must be refused for tenant B's account scope: status={status}, "
            f"body={payload}"
        )
        log("usage query: tenant A refused for tenant B's account scope (#570)")

        status, payload = None, None
        try:
            request_raw(
                "POST",
                f"{USAGE_QUERY_URL}/usage/v1/usage/query",
                body={
                    "scope": "account",
                    "scope_id": account_id,
                    "start_time": "2026-03-01T00:00:00Z",
                    "end_time": "2026-03-02T00:00:00Z",
                    "bucket": "1 day",
                    "group_by": [],
                    "filters": {},
                    "limit": 10,
                },
                ssl_context=MTLS_CLIENT_TLS,
            )
            raise AssertionError("usage query succeeded with no bearer token")
        except urllib.error.HTTPError as err:
            assert err.code == 401, f"expected 401 with no bearer token, got {err.code}"
        log("usage query: missing bearer token refused with 401 (#570)")

        expect_http_error(
            401,
            method="POST",
            url=f"{MCP_URL}/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Accept": "application/json, text/event-stream"},
            insecure_tls=True,
        )
        log("mcp rejects missing bearer token")

        mcp_initialize(token)
        log("stateless mcp initialize passed")

        status, _, _ = mcp_post(
            token,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        assert status in (200, 202, 204), f"initialized notify failed: status={status}"

        status, tools_body, _ = mcp_post(
            token,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert status == 200, f"tools/list failed: status={status}, body={tools_body}"
        tools_messages = parse_sse_json_messages(tools_body)
        tools_result = next((msg for msg in tools_messages if msg.get("id") == 2), None)
        assert tools_result is not None, f"missing tools/list result: body={tools_body}"
        tool_names = [tool["name"] for tool in tools_result["result"]["tools"]]
        assert len(tool_names) == len(EXPECTED_MCP_TOOLS), (
            f"unexpected MCP tool count: {tool_names}"
        )
        assert set(tool_names) == EXPECTED_MCP_TOOLS, (
            f"unexpected MCP tools: {tool_names}"
        )

        status, account_body, _ = mcp_post(
            token,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "get-account",
                    "arguments": {"account_id": account_id},
                },
            },
        )
        assert status == 200, f"tools/call failed: status={status}, body={account_body}"
        account_messages = parse_sse_json_messages(account_body)
        account_result = next((msg for msg in account_messages if msg.get("id") == 3), None)
        assert account_result is not None, f"missing get-account result: body={account_body}"

        call_result = account_result.get("result", {})
        assert call_result.get("isError") is False, f"mcp tool returned error: {call_result}"
        structured = call_result.get("structuredContent", {})
        account_data = structured.get("result", {})
        assert (
            account_data.get("id") == account_id
        ), f"unexpected mcp account payload: {account_result}"
        log("mcp jwt-protected flow passed")

        return 0
    except Exception as err:
        log(f"FAILED: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
