#!/usr/bin/env python3
import base64
import json
import os
import ssl
import sys
import time
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


def post_form(url: str, form_data: dict):
    payload = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(url=url, method="POST", data=payload)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def parse_sse_json_messages(raw: str) -> list[dict]:
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
        f"{API_URL}/health",
        f"{API_URL}/health/startup",
        f"{API_URL}/health/ready",
        f"{OPA_URL}/health",
        f"{OPA_URL}/health/startup",
        f"{OPA_URL}/health/ready",
        f"{USAGE_URL}/health",
        f"{USAGE_URL}/health/startup",
        f"{USAGE_URL}/health/ready",
        f"{MCP_URL}/health",
        f"{MCP_URL}/health/startup",
        f"{MCP_URL}/health/ready",
    ]

    start = time.time()
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
        except Exception:
            if time.time() - start > MAX_WAIT_SECONDS:
                raise TimeoutError(
                    f"services not ready after {MAX_WAIT_SECONDS}s"
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


def mcp_initialize(token: str) -> str:
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

    session_id = None
    for key, value in headers.items():
        if key.lower() == "mcp-session-id":
            session_id = value
            break
    assert session_id, f"missing mcp-session-id header: headers={headers}"

    messages = parse_sse_json_messages(body)
    init_result = next((msg for msg in messages if msg.get("id") == 1), None)
    assert init_result is not None, f"missing initialize result: body={body}"
    assert init_result.get("result"), f"unexpected initialize payload: {init_result}"

    return session_id


def mcp_post(token: str, session_id: str, payload: dict):
    return request_raw(
        "POST",
        f"{MCP_URL}/mcp",
        body=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Mcp-Session-Id": session_id,
            "Accept": "application/json, text/event-stream",
        },
        insecure_tls=True,
    )


def main() -> int:
    try:
        wait_until_ready()

        token = fetch_token()
        authz_headers = {"Authorization": f"Bearer {token}"}
        billing_identity = f"it-servers-{int(time.time())}"

        expect_http_error(
            401,
            method="GET",
            url=f"{API_URL}/api/v1/accounts",
            insecure_tls=True,
        )
        log("api rejects missing bearer token")

        status, account, _ = request_json(
            "POST",
            f"{API_URL}/api/v1/accounts",
            {"billing_identity": billing_identity, "owners_admins": [USERNAME]},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create account failed: status={status}, body={account}"
        account_id = account["id"]
        log(f"api create-account passed ({account_id})")

        status, project, _ = request_json(
            "POST",
            f"{API_URL}/api/v1/accounts/{account_id}/projects",
            {
                "name": "it-servers-project",
                "allowed_models": ["gpt-4.1-mini"],
                "default_limits": {},
                "billing_plan": "free",
            },
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create project failed: status={status}, body={project}"
        project_id = project["id"]

        status, key_payload, _ = request_json(
            "POST",
            f"{API_URL}/api/v1/projects/{project_id}/api-keys",
            {"name": "it-servers-key"},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create api key failed: status={status}, body={key_payload}"
        secret = key_payload["secret"]

        expect_http_error(
            401,
            method="POST",
            url=f"{OPA_URL}/v1/opa/validate",
            body={"api_key": secret, "ip": "203.0.113.10"},
            insecure_tls=True,
        )
        log("opa rejects missing basic auth")

        basic = base64.b64encode(AUTHORINO_BASIC.encode("utf-8")).decode("utf-8")
        status, opa_ok, _ = request_json(
            "POST",
            f"{OPA_URL}/v1/opa/validate",
            {"api_key": secret, "ip": "203.0.113.10"},
            headers={"Authorization": f"Basic {basic}"},
            insecure_tls=True,
        )
        assert status == 200, f"opa validation failed: status={status}, body={opa_ok}"
        assert opa_ok["account"]["id"] == account_id, f"unexpected opa account: {opa_ok}"
        assert opa_ok["project"]["id"] == project_id, f"unexpected opa project: {opa_ok}"
        log("opa validate endpoint passed")

        usage_status = None
        usage_error_body = ""
        try:
            request_raw(
                "POST",
                f"{USAGE_URL}/v1/usage/query",
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

        session_id = mcp_initialize(token)
        log(f"mcp initialize passed (session={session_id})")

        status, _, _ = mcp_post(
            token,
            session_id,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        assert status in (200, 202, 204), f"initialized notify failed: status={status}"

        status, tools_body, _ = mcp_post(
            token,
            session_id,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert status == 200, f"tools/list failed: status={status}, body={tools_body}"
        tools_messages = parse_sse_json_messages(tools_body)
        tools_result = next((msg for msg in tools_messages if msg.get("id") == 2), None)
        assert tools_result is not None, f"missing tools/list result: body={tools_body}"
        tool_names = [tool["name"] for tool in tools_result["result"]["tools"]]
        assert "get-account" in tool_names, f"missing get-account tool: {tool_names}"

        status, account_body, _ = mcp_post(
            token,
            session_id,
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
