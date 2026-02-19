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
CLIENT_ID = os.environ.get("CLIENT_ID", "test-client")
USERNAME = os.environ.get("USERNAME", "test@admin")
PASSWORD = os.environ.get("PASSWORD", "test")
AUTHORINO_BASIC = os.environ.get("AUTHORINO_BASIC", "authorino:change-me")
MAX_WAIT_SECONDS = int(os.environ.get("MAX_WAIT_SECONDS", "180"))


INSECURE_TLS = ssl.create_default_context()
INSECURE_TLS.check_hostname = False
INSECURE_TLS.verify_mode = ssl.CERT_NONE


def log(msg: str) -> None:
    print(f"[it-authorino] {msg}", flush=True)


def request_json(
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
        for k, v in headers.items():
            req.add_header(k, v)

    context = INSECURE_TLS if insecure_tls else None
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        payload = resp.read()
        if not payload:
            return resp.status, {}
        return resp.status, json.loads(payload.decode("utf-8"))


def post_form(url: str, form_data: dict):
    payload = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(url=url, method="POST", data=payload)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def wait_until_ready() -> None:
    start = time.time()
    while True:
        try:
            request_json("GET", f"{API_URL}/health", insecure_tls=True)
            request_json("GET", f"{OPA_URL}/health", insecure_tls=True)
            log("API and OPA health endpoints are ready")
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


def main() -> int:
    try:
        wait_until_ready()
        token = fetch_token()
        authz_headers = {"Authorization": f"Bearer {token}"}

        status, account = request_json(
            "POST",
            f"{API_URL}/api/v1/accounts",
            {"billing_identity": "acme-it", "owners_admins": [USERNAME]},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create account failed: status={status}, body={account}"
        account_id = account["id"]
        log(f"created account {account_id}")

        status, project = request_json(
            "POST",
            f"{API_URL}/api/v1/accounts/{account_id}/projects",
            {
                "name": "it-project",
                "allowed_models": ["gpt-4.1-mini"],
                "default_limits": {},
                "billing_plan": "free",
            },
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create project failed: status={status}, body={project}"
        project_id = project["id"]
        log(f"created project {project_id}")

        status, key_payload = request_json(
            "POST",
            f"{API_URL}/api/v1/projects/{project_id}/api-keys",
            {"name": "it-key"},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 201, f"create api key failed: status={status}, body={key_payload}"
        secret = key_payload["secret"]
        api_key_id = key_payload["api_key"]["id"]
        log(f"created api key {api_key_id}")

        basic = base64.b64encode(AUTHORINO_BASIC.encode("utf-8")).decode("utf-8")
        status, authorino_ok = request_json(
            "POST",
            f"{OPA_URL}/v1/authorino/validate",
            {
                "api_key": secret,
                "ip": "203.0.113.10",
                "metadata": {"tenant": "acme", "request_id": "it-001"},
            },
            headers={"Authorization": f"Basic {basic}"},
            insecure_tls=True,
        )
        assert status == 200, (
            "authorino validate should succeed, "
            f"got status={status}, body={authorino_ok}"
        )

        metadata = authorino_ok.get("dynamic_metadata", {})
        assert metadata.get("tenant") == "acme", f"tenant metadata mismatch: {metadata}"
        assert metadata.get("request_id") == "it-001", f"request_id mismatch: {metadata}"
        assert metadata.get("account_id") == account_id, f"account_id mismatch: {metadata}"
        assert metadata.get("project_id") == project_id, f"project_id mismatch: {metadata}"
        assert metadata.get("api_key_id") == api_key_id, f"api_key_id mismatch: {metadata}"
        assert metadata.get("api_key_status") == "active", f"status mismatch: {metadata}"
        log("authorino validate success payload assertions passed")

        try:
            request_json(
                "POST",
                f"{OPA_URL}/v1/authorino/validate",
                {
                    "api_key": "lbk_secret_invalid_key",
                    "ip": "203.0.113.10",
                    "metadata": {"tenant": "acme"},
                },
                headers={"Authorization": f"Basic {basic}"},
                insecure_tls=True,
            )
            raise AssertionError("invalid key should return 401")
        except urllib.error.HTTPError as err:
            if err.code != 401:
                raise AssertionError(f"expected 401 for invalid key, got {err.code}") from err
            log("invalid key returns 401 as expected")

        return 0
    except Exception as err:
        log(f"FAILED: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
