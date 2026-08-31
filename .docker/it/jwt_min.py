"""Minimal, dependency-free RFC 7523 `private_key_jwt` (RS256) client-assertion signer/verifier,
and RSA-public-JWK deriver, for the IT test runners.

#534/ADR-0030's `client_credentials` (M2M) flow authenticates exclusively via `private_key_jwt`
(ADR-0011 Decision 6 -- no client secrets, ever), so `idp_it.py`'s live coverage of it needs to
sign a real RS256 JWT. Same constraint as `cbor_min.py` right next to this file (see that module's
own doc comment): the IT runners are plain `python:3.12-slim` containers with no package-install
step (`compose.it.yaml`), so this hand-rolls exactly the primitives that need it -- a byte-for-byte
minimal ASN.1 DER walker sufficient to pull `(n, e, d)` out of a PKCS#8-wrapped RSA private key PEM,
RSASSA-PKCS1-v1_5 signing/verification (RFC 8017 §8.2) built on nothing but `hashlib` and Python's
arbitrary-precision `pow(base, exp, mod)` for the modular exponentiation, and deriving the PUBLIC
JWK (`n`/`e` only) from that same private key -- rather than adding a `pip install
cryptography`/`PyJWT` step to a self-hosted CI runner.

The `it-machine` client's keypair is generated fresh at IT-stack-up time by
`generate_it_machine_fixtures.py` (`openssl genrsa`, never checked into the repo -- a private key
committed to git trips secret scanners even as test-only material, see that script's own doc
comment); this module is what turns the generated PEM into both the signing input `idp_it.py`
needs and the public JWK `generate_it_machine_fixtures.py` embeds into the rendered IT-only
`authz-idp` config.

Not a general-purpose JWT/ASN.1 library: only RS256, only the fixed PKCS#8/PKCS#1 RSA private-key
shape `openssl genpkey -algorithm RSA` produces, and only enough JWT construction (header + claims
+ signature, compact serialization) for a `private_key_jwt` assertion. If the generated key were
ever an EC/OKP key, or a differently-wrapped PEM, this would need extending, not silently
misinterpreting it -- `_pem_to_rsa_components` raises loudly (`IndexError`/`AssertionError`) rather
than guessing.
"""

import base64
import hashlib
import json


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """One DER tag-length-value at `offset`. Supports the short and long (multi-byte) length
    forms (DER §8.1.3); this fixture's 2048-bit RSA key exercises both."""
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    value = data[offset : offset + length]
    return tag, value, offset + length


def _parse_der_sequence(data: bytes) -> list[tuple[int, bytes]]:
    """Every top-level TLV inside a DER SEQUENCE's payload, in order."""
    items = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _read_der_tlv(data, offset)
        items.append((tag, value))
    return items


def _pem_to_der(pem_text: str) -> bytes:
    """Strips PEM armor (and any comment lines preceding `-----BEGIN`, like the provenance note
    at the top of `it-machine-key.pem`) down to the raw DER bytes."""
    body_lines = []
    in_body = False
    for line in pem_text.splitlines():
        if line.startswith("-----BEGIN"):
            in_body = True
            continue
        if line.startswith("-----END"):
            break
        if in_body:
            body_lines.append(line.strip())
    return base64.b64decode("".join(body_lines))


def _pem_to_rsa_components(pem_text: str) -> tuple[int, int, int]:
    """Extracts `(modulus, publicExponent, privateExponent)` from a PKCS#8 `PrivateKeyInfo`
    wrapping a PKCS#1 `RSAPrivateKey` (RFC 5958 / RFC 8017 Appendix A.1.2) -- exactly what
    `openssl genpkey -algorithm RSA` writes. `RSAPrivateKey`'s field order is fixed: version(0),
    modulus(1), publicExponent(2), privateExponent(3), ... -- indices below are that order, not a
    guess.
    """
    der = _pem_to_der(pem_text)
    tag, value, _ = _read_der_tlv(der, 0)
    assert tag == 0x30, "expected an outer DER SEQUENCE (PrivateKeyInfo)"
    outer_items = _parse_der_sequence(value)
    octet_tag, octet_value = outer_items[2]
    assert octet_tag == 0x04, "expected PrivateKeyInfo.privateKey as an OCTET STRING"
    inner_tag, inner_value, _ = _read_der_tlv(octet_value, 0)
    assert inner_tag == 0x30, "expected an inner DER SEQUENCE (RSAPrivateKey)"
    inner_items = _parse_der_sequence(inner_value)
    n = int.from_bytes(inner_items[1][1], "big")
    e = int.from_bytes(inner_items[2][1], "big")
    d = int.from_bytes(inner_items[3][1], "big")
    return n, e, d


def _pem_to_rsa_n_d(pem_text: str) -> tuple[int, int]:
    """`(modulus, privateExponent)` only -- what [`sign_private_key_jwt`] actually needs to sign."""
    n, _e, d = _pem_to_rsa_components(pem_text)
    return n, d


def public_jwk_from_private_pem(pem_text: str, kid: str) -> dict:
    """Derives the PUBLIC JWK (`n`/`e` only, never `d`/`p`/`q`/...) that
    `generate_it_machine_fixtures.py` embeds into the rendered IT-only `authz-idp` config, from
    the SAME private key PEM `sign_private_key_jwt` signs assertions with -- so the two are always
    the matching halves of one generated keypair, never independently derived values that could
    drift apart."""
    n, e, _d = _pem_to_rsa_components(pem_text)
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url(n.to_bytes((n.bit_length() + 7) // 8, "big")),
        "e": _b64url(e.to_bytes((e.bit_length() + 7) // 8, "big")),
    }


# RFC 8017 Appendix A.2.4: the DER encoding of `DigestInfo` for SHA-256, prepended to the digest
# before PKCS#1 v1.5 padding -- the fixed "magic prefix" every RS256 signer/verifier agrees on.
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _rsassa_pkcs1_v1_5_sign(message: bytes, n: int, d: int) -> bytes:
    """RFC 8017 §8.2.1 EMSA-PKCS1-v1_5 encode + RSASP1 sign, using SHA-256 as the hash -- the
    "RS256" `alg`. `key_size` is inferred from `n` (this fixture's key is exactly 2048 bits/256
    bytes, but the padding math holds for any RSA modulus size)."""
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    key_size = (n.bit_length() + 7) // 8
    padding_len = key_size - len(t) - 3
    assert padding_len >= 8, "RSA modulus too small for RS256 PKCS#1 v1.5 padding"
    encoded_message = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + t
    signature_int = pow(int.from_bytes(encoded_message, "big"), d, n)
    return signature_int.to_bytes(key_size, "big")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_json(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


def sign_private_key_jwt(
    private_key_pem: str,
    kid: str,
    client_id: str,
    audience: str,
    jti: str,
    exp_seconds_from_now: int,
    now: int,
) -> str:
    """Signs an RFC 7523 §3 `private_key_jwt` client assertion: `iss`/`sub` are both `client_id`
    (RFC 7523 §3, points 1-2), `aud` is the token endpoint or issuer the OP's own
    `verify_client_assertion` accepts (mirrors `token_exchange_tests.rs`'s `sign_client_assertion`
    fixture on the Rust side of this same feature)."""
    n, d = _pem_to_rsa_n_d(private_key_pem)
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": jti,
        "exp": now + exp_seconds_from_now,
    }
    signing_input = f"{_b64url_json(header)}.{_b64url_json(claims)}"
    signature = _rsassa_pkcs1_v1_5_sign(signing_input.encode(), n, d)
    return f"{signing_input}.{_b64url(signature)}"


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_header_and_claims(token: str) -> tuple[dict, dict]:
    header_b64, claims_b64, _ = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    claims = json.loads(_b64url_decode(claims_b64))
    return header, claims


def verify_rs256(token: str, jwk: dict) -> bool:
    """Signature-verifies `token` (compact RS256 JWT) against a single JWK dict (`{"n": ...,
    "e": ..., "kid": ...}`, e.g. one entry of `/.well-known/jwks.json`'s `keys` array) -- the
    RSAVP1 counterpart (RFC 8017 §5.2.2 + §8.2.2 EMSA-PKCS1-v1_5 verify) to
    [`sign_private_key_jwt`]'s RSASP1/EMSA-PKCS1-v1_5-encode. Raises `AssertionError` (not a bare
    `False`) on a `kid` mismatch -- a JWKS lookup miss is a test-setup bug, not a signature failure
    this function should silently paper over as "verification failed."""
    header_b64, claims_b64, signature_b64 = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    assert header.get("alg") == "RS256", f"unexpected alg: {header.get('alg')}"
    assert header.get("kid") == jwk["kid"], (
        f"token kid {header.get('kid')!r} does not match the JWK under test {jwk['kid']!r}"
    )
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    signature = int.from_bytes(_b64url_decode(signature_b64), "big")
    key_size = (n.bit_length() + 7) // 8
    decrypted = pow(signature, e, n).to_bytes(key_size, "big")
    signing_input = f"{header_b64}.{claims_b64}".encode()
    digest = hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (
        key_size - len(_SHA256_DIGEST_INFO_PREFIX) - len(digest) - 3
    ) + b"\x00" + _SHA256_DIGEST_INFO_PREFIX + digest
    return decrypted == expected
