"""Generates the `it-machine` `client_credentials` (M2M, #534/ADR-0030) IT fixture keypair at
IT-stack-up time, and renders the IT-only `authz-idp` config that registers it.

A real RSA private key checked into git -- even test-only material scoped to
`compose.it.yaml`'s `it-idp` runner -- trips secret scanners (Gitleaks, Trivy) exactly the way a
real credential would, and CI treats that failure as real (PR #604). Generating the keypair fresh
at IT-stack-up time and never writing it to the repository closes that for good, following the
same "generate into a shared location at compose-up time, never commit it" shape
`compose.yaml`'s `authz-tls` service already establishes for TLS certificates.

Run by the `it-machine-keygen` one-shot service (`compose.it.yaml`), which mounts this repository's
`.docker` directory read-write so the two files this script produces land in the host working
tree (both `.gitignore`d, see that file):

- `.docker/it/generated/it-machine-key.pem` -- the private key `idp_it.py` signs
  `private_key_jwt` assertions with (`IT_MACHINE_KEY_PATH` env var, defaulting to this path).
- `.docker/authz/container.it.yaml` -- the checked-in `.docker/authz/container.yaml` (read
  unmodified, never edited in place) PLUS an `it-machine` `oauth2.clients` entry carrying the
  matching PUBLIC JWK, spliced in immediately after the pre-existing `it-exchange` client entry.
  `compose.it.yaml` mounts this generated file as `authz-idp`'s `/tmp/config.yaml` INSTEAD OF the
  checked-in `container.yaml`, for the IT run only -- the plain `just up` stack never sees an
  `it-machine` client at all, so its `oauth2.type: self` startup validation
  (`validate_client_credentials_and_service_clients`, #534/ADR-0030) never has anything to check
  it against. This also resolves the earlier review note that the registration was live in the
  ordinary stack, not IT-only.

Splicing text into a copy of `container.yaml` rather than hand-maintaining a second, parallel
config file means there is exactly one source of truth for the base config; this script re-derives
the IT variant from whatever `container.yaml` currently says every time it runs, so the two can
never drift apart the way two independently hand-edited YAML files eventually would.
"""

import os
import subprocess
import sys

import jwt_min

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
_BASE_CONFIG_PATH = os.path.join(_REPO_ROOT, ".docker", "authz", "container.yaml")
_RENDERED_CONFIG_PATH = os.path.join(_REPO_ROOT, ".docker", "authz", "container.it.yaml")
_GENERATED_DIR = os.path.join(_REPO_ROOT, ".docker", "it", "generated")
_PRIVATE_KEY_PATH = os.path.join(_GENERATED_DIR, "it-machine-key.pem")

_KID = "it-machine-2026-08"

# The exact line `container.yaml`'s `it-exchange` client entry ends on -- the splice point. If
# `container.yaml` is ever restructured such that this line no longer exists, this script fails
# loudly (`ValueError`) rather than silently omitting the `it-machine` client from the rendered
# IT config, which would surface as a confusing IT-suite failure far from the actual cause.
_SPLICE_AFTER = '        - refresh_token\n'
_SPLICE_MARKER_CONTEXT = "    - client_id: it-exchange\n"


def _generate_private_key_pem() -> str:
    subprocess.run(
        ["openssl", "genrsa", "-out", _PRIVATE_KEY_PATH, "2048"],
        check=True,
        capture_output=True,
    )
    with open(_PRIVATE_KEY_PATH, encoding="utf-8") as key_file:
        return key_file.read()


def _render_it_machine_client_block(jwk: dict) -> str:
    return (
        "    # #534/ADR-0030: the live client_credentials (M2M) IT client -- generated fresh at\n"
        "    # IT-stack-up time by `.docker/it/generate_it_machine_fixtures.py` (never checked into\n"
        "    # the repo -- a real private key trips secret scanners even as test-only material).\n"
        "    # This client registration exists ONLY in this generated file, never in the checked-in\n"
        "    # `container.yaml` the ordinary `just up` stack mounts -- see that script's own doc\n"
        "    # comment for why. Drives the mint -> JWKS-verify -> introspect flow end to end in\n"
        "    # `idp_it.py` -- NOT an RPC 403, but only because of a LOCAL-COMPOSE-SPECIFIC drift, not\n"
        "    # a platform limitation: THIS local stack's oauth2.jwks_url still points at Keycloak\n"
        "    # directly (never migrated when ADR-0023 made authz-idp the full IdP -- tracked\n"
        "    # separately, see docs/local-testing.md), so a token minted from this client is\n"
        "    # rejected at signature validation here before any permission is ever checked. In\n"
        "    # production (ai-helm-values), authz-api/authz-budget validate against authz-idp's own\n"
        "    # JWKS instead, where a token like this one DOES pass signature validation and is\n"
        "    # refused by its empty permission set -- see `section_client_credentials`'s own\n"
        "    # docstring in idp_it.py and ADR-0030 Decision 6.\n"
        "    - client_id: it-machine\n"
        "      type: service\n"
        "      scopes: [read:usage]\n"
        "      grant_types:\n"
        "        - client_credentials\n"
        "      allowed_audiences: [lightbridge-api-key]\n"
        "      jwks:\n"
        "        keys:\n"
        f"          - kty: {jwk['kty']}\n"
        f"            kid: \"{jwk['kid']}\"\n"
        f"            alg: {jwk['alg']}\n"
        f"            n: \"{jwk['n']}\"\n"
        f"            e: \"{jwk['e']}\"\n"
    )


def _render_it_config(jwk: dict) -> str:
    with open(_BASE_CONFIG_PATH, encoding="utf-8") as base_file:
        base_config = base_file.read()
    marker_index = base_config.find(_SPLICE_MARKER_CONTEXT)
    if marker_index == -1:
        raise ValueError(
            f"could not find the it-exchange client entry in {_BASE_CONFIG_PATH} -- "
            "the splice point this script depends on has moved or been removed"
        )
    splice_index = base_config.find(_SPLICE_AFTER, marker_index)
    if splice_index == -1:
        raise ValueError(
            f"could not find the end of the it-exchange client entry in {_BASE_CONFIG_PATH} -- "
            "the splice point this script depends on has moved or been removed"
        )
    insert_at = splice_index + len(_SPLICE_AFTER)
    return (
        base_config[:insert_at]
        + _render_it_machine_client_block(jwk)
        + base_config[insert_at:]
    )


def main() -> int:
    # Idempotent by design, mirroring `authz-tls`'s own "generate only if not already present"
    # shape (`compose.yaml`'s `authz-tls` service: `if [ ! -f /tls/ca.key ]; then openssl req ...
    # fi`) -- NOT "regenerate unconditionally on every run". This matters for a reason `authz-tls`
    # does not have to worry about: `authz-idp` reads this script's output exactly once, at its own
    # process startup, and never again. `condition: service_completed_successfully` on a one-shot
    # dependency does not guarantee "runs exactly once for the whole compose project lifetime" --
    # a LATER, separate `docker compose run --rm it-idp` (a fresh dependency-graph evaluation) can
    # recreate and rerun this container even while `authz-idp` is already up. If that rerun
    # regenerated a brand-new keypair, `authz-idp` -- already running with the OLD public JWK baked
    # into its in-memory config -- would reject every assertion `idp_it.py` signs with the NEW
    # private key this rerun just wrote, with a confusing `401 invalid_client` that has nothing to
    # do with the assertion actually being wrong. Skipping regeneration when both output files
    # already exist keeps the keypair stable for the life of the generated files on the host
    # filesystem, exactly matching how long `authz-idp` actually keeps trusting it.
    if os.path.exists(_PRIVATE_KEY_PATH) and os.path.exists(_RENDERED_CONFIG_PATH):
        print(
            f"[it-machine-keygen] {_PRIVATE_KEY_PATH} and {_RENDERED_CONFIG_PATH} already exist "
            "-- reusing, not regenerating (delete both to force a fresh keypair)",
            flush=True,
        )
        return 0
    os.makedirs(_GENERATED_DIR, exist_ok=True)
    private_key_pem = _generate_private_key_pem()
    jwk = jwt_min.public_jwk_from_private_pem(private_key_pem, _KID)
    rendered = _render_it_config(jwk)
    with open(_RENDERED_CONFIG_PATH, "w", encoding="utf-8") as rendered_file:
        rendered_file.write(rendered)
    print(f"[it-machine-keygen] wrote {_PRIVATE_KEY_PATH}", flush=True)
    print(f"[it-machine-keygen] wrote {_RENDERED_CONFIG_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
