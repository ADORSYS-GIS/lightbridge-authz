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
CLIENT_ID = os.environ.get("CLIENT_ID", "test-client")
USERNAME = os.environ.get("USERNAME", "test@admin")
PASSWORD = os.environ.get("PASSWORD", "test")
AUTHORINO_BASIC = os.environ.get("AUTHORINO_BASIC", "authorino:change-me")
MAX_WAIT_SECONDS = int(os.environ.get("MAX_WAIT_SECONDS", "180"))


INSECURE_TLS = ssl.create_default_context()
INSECURE_TLS.check_hostname = False
INSECURE_TLS.verify_mode = ssl.CERT_NONE



def _it_expires_at() -> str:
    """RFC3339 expiry 30 days out.

    `createApiKey` requires `expiresAt` and rejects anything past the configured
    ceiling (default 90 days) or in the past, so this must be computed at run time
    rather than hardcoded -- a literal date would silently start failing once it
    drifted into the past.
    """
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")

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


def request_rpc(
    method: str,
    url: str,
    body=None,
    headers=None,
    insecure_tls: bool = False,
):
    """Like `request_json`, but for `authz-api`'s `/rpc/*` surface, which speaks CBOR only
    post-ADR-0013 (see `cbor_min.py`'s module doc). Everything else this script calls -- health
    probes, Keycloak, OPA's introspect (form-encoded, unrelated to this codec) -- stays on
    `request_json`/`post_form`.
    """
    encoded = None
    if body is not None:
        encoded = cbor_min.encode(body)
    req = urllib.request.Request(url=url, method=method, data=encoded)
    req.add_header("Accept", "application/cbor")
    if body is not None:
        req.add_header("Content-Type", "application/cbor")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    context = INSECURE_TLS if insecure_tls else None
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        payload = resp.read()
        if not payload:
            return resp.status, {}
        return resp.status, cbor_min.decode(payload)


def post_form(url: str, form_data: dict, headers=None, insecure_tls: bool = False):
    payload = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(url=url, method="POST", data=payload)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    context = INSECURE_TLS if insecure_tls else None
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def wait_until_ready() -> None:
    start = time.time()
    last_error = "readiness checks have not run yet"
    while True:
        try:
            request_json("GET", f"{API_URL}/healthz", insecure_tls=True)
            request_json("GET", f"{OPA_URL}/healthz", insecure_tls=True)
            request_json(
                "GET",
                f"{KEYCLOAK_URL}/realms/dev/.well-known/openid-configuration",
            )
            log("API, OPA, and Keycloak are ready")
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


def account_id_from_token(token: str) -> str:
    """The caller's account id, read straight off the JWT.

    Since ADR-0006 `accounts.id` IS the authenticated subject, so the id needs no lookup.
    """
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))["sub"]


def ensure_account(authz_headers: dict, token: str) -> str:
    """Create the caller's account, tolerating the one that already exists.

    `createAccount` is once-per-subject since ADR-0006 -- a second call is a 409, not a second
    row. This suite hits that routinely rather than exceptionally: it shares a compose stack (and
    therefore a database) with the servers suite, both authenticate as the same Keycloak user, and
    the CI runner retries a suite up to three times. So a 409 here means "already provisioned",
    and the id is the subject.
    """
    try:
        status, account = request_rpc(
            "POST",
            f"{API_URL}/rpc/procedure.createAccount",
            {"args": {}},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 200, f"create account failed: status={status}, body={account}"
        return account["id"]
    except urllib.error.HTTPError as err:
        if err.code != 409:
            raise
        account_id = account_id_from_token(token)
        log(f"account already exists for this subject; reusing {account_id}")
        return account_id


def main() -> int:
    try:
        wait_until_ready()
        token = fetch_token()
        authz_headers = {"Authorization": f"Bearer {token}"}

        # authz-api migrated to cratestack RPC transport (ADR-0003): CRUD is dispatched via
        # POST /rpc/{op_id} with the codec-encoded input as the body. The router serves CBOR only
        # (ADR-0013 -- the JSON secondary codec was removed), so this script talks CBOR via
        # `request_rpc`/`cbor_min.py`. Model verbs use camelCase field names (the generated schema
        # struct fields); the `Json` columns carry cratestack's own externally tagged `Value` enum,
        # so `{}` is `{"Map": {}}` and a string list is `{"List": [...]}`.
        billing_identity = f"acme-it-{uuid.uuid4().hex[:12]}"
        account_id = ensure_account(authz_headers, token)
        log(f"using account {account_id}")

        project_client_id = "c" + uuid.uuid4().hex[:24]
        status, project = request_rpc(
            "POST",
            f"{API_URL}/rpc/model.Project.create",
            {
                "id": project_client_id,
                "accountId": account_id,
                "name": "it-project",
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
        log(f"created project {project_id}")

        status, key_payload = request_rpc(
            "POST",
            f"{API_URL}/rpc/procedure.createApiKey",
            {"args": {"projectId": project_id, "name": "it-key", "billingPlan": "free", "expiresAt": _it_expires_at()}},
            headers=authz_headers,
            insecure_tls=True,
        )
        assert status == 200, f"create api key failed: status={status}, body={key_payload}"
        secret = key_payload["secret"]
        api_key_id = key_payload["apiKey"]["id"]
        log(f"created api key {api_key_id}")

        basic = base64.b64encode(AUTHORINO_BASIC.encode("utf-8")).decode("utf-8")
        status, introspected = post_form(
            f"{OPA_URL}/v1/authorino/validate/introspect",
            {"token": secret, "token_type_hint": "access_token"},
            headers={"Authorization": f"Basic {basic}"},
            insecure_tls=True,
        )
        assert status == 200, (
            "authorino introspection should succeed, "
            f"got status={status}, body={introspected}"
        )

        assert introspected.get("active") is True, f"expected active token: {introspected}"
        assert introspected.get("account_id") == account_id, f"account_id mismatch: {introspected}"
        assert introspected.get("project_id") == project_id, f"project_id mismatch: {introspected}"
        assert introspected.get("api_key_id") == api_key_id, f"api_key_id mismatch: {introspected}"
        assert introspected.get("api_key_status") == "active", f"status mismatch: {introspected}"
        log("authorino introspect success payload assertions passed")

        status, inactive = post_form(
            f"{OPA_URL}/v1/authorino/validate/introspect",
            {"token": "lbk_secret_invalid_key", "token_type_hint": "access_token"},
            headers={"Authorization": f"Basic {basic}"},
            insecure_tls=True,
        )
        assert status == 200, f"introspection of invalid key should be 200: {inactive}"
        assert inactive.get("active") is False, f"invalid key should be inactive: {inactive}"
        log("invalid key returns active=false as expected")

        return 0
    except Exception as err:
        log(f"FAILED: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
