#!/usr/bin/env python3
import base64
import json
import os
import ssl
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request


KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:9100").rstrip("/")
API_URL = os.environ.get("API_URL", "https://authz-api:3000").rstrip("/")
OPA_URL = os.environ.get("OPA_URL", "https://authz-opa:3001").rstrip("/")
USAGE_URL = os.environ.get("USAGE_URL", "https://authz-usage:3002").rstrip("/")
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
    "delete-account",
    "disable-account",
    "enable-account",
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


def log(message: str) -> None:
    print(f"[it-servers] {message}", flush=True)


def request_raw(
    method: str,
    url: str,
    body=None,
    headers=None,
    insecure_tls: bool = False,
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

    context = INSECURE_TLS if insecure_tls else None
    with urllib.request.urlopen(req, timeout=30, context=context) as response:
        payload = response.read().decode("utf-8")
        return response.status, payload, dict(response.headers.items())


def request_json(
    method: str,
    url: str,
    body=None,
    headers=None,
    insecure_tls: bool = False,
):
    status, payload, response_headers = request_raw(
        method=method,
        url=url,
        body=body,
        headers=headers,
        insecure_tls=insecure_tls,
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

    start = time.time()
    last_error = "readiness checks have not run yet"
    while True:
        try:
            for probe_url in probe_urls:
                status, _, _ = request_raw("GET", probe_url, insecure_tls=True)
                assert status == 200, f"probe failed {probe_url}: status={status}"

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


def fetch_token() -> str:
    token_url = f"{KEYCLOAK_URL}/realms/dev/protocol/openid-connect/token"
    status, payload = post_form(
        token_url,
        {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": USERNAME,
            "password": PASSWORD,
        },
    )
    if status != 200 or "access_token" not in payload:
        raise RuntimeError(f"token fetch failed: status={status}, payload={payload}")
    return payload["access_token"]


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
        # POST /rpc/{op_id}. A mapped op with no bearer is rejected by the coarse RBAC gate with 401
        # (fail-closed) before dispatch.
        expect_http_error(
            401,
            method="POST",
            url=f"{API_URL}/rpc/model.Account.list",
            body={},
            insecure_tls=True,
        )
        log("api rejects missing bearer token")

        status, account, _ = request_json(
            "POST",
            f"{API_URL}/rpc/procedure.createAccount",
            {"args": {}},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 200, f"create account failed: status={status}, body={account}"
        account_id = account["id"]
        log(f"api create-account passed ({account_id})")

        project_client_id = "c" + uuid.uuid4().hex[:24]
        status, project, _ = request_json(
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
                "isDefault": False,
                "status": "active",
            },
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create project failed: status={status}, body={project}"
        project_id = project["id"]

        status, key_payload, _ = request_json(
            "POST",
            f"{API_URL}/rpc/procedure.createApiKey",
            {"args": {"projectId": project_id, "name": "it-servers-key", "billingPlan": "free"}},
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

        usage_status = None
        usage_error_body = ""
        try:
            request_raw(
                "POST",
                f"{USAGE_URL}/usage/v1/usage/query",
                body={
                    "scope": "project",
                    "scope_id": "proj_invalid",
                    "start_time": "2026-03-01T01:00:00Z",
                    "end_time": "2026-03-01T00:00:00Z",
                    "bucket": "5 minutes",
                    "group_by": ["model"],
                    "filters": {},
                    "limit": 100,
                },
                insecure_tls=True,
            )
            raise AssertionError("usage query unexpectedly succeeded")
        except urllib.error.HTTPError as err:
            usage_status = err.code
            usage_error_body = err.read().decode("utf-8")

        if usage_status not in (400, 500):
            raise AssertionError(
                f"usage query should reject invalid time window, got {usage_status}: {usage_error_body}"
            )
        if "start_time must be before end_time" not in usage_error_body:
            raise AssertionError(f"unexpected usage error body: {usage_error_body}")
        log("usage endpoint responds without auth and rejects invalid request")

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
