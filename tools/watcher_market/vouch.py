"""Verifies wctl's signed grants (``control/internal/platform/vouch``) outside wctl, with the standard library only.

A grant is a Verifiable Credential under the Data Integrity cryptosuite eddsa-jcs-2022: an Ed25519 signature
(RFC 8032) over sha256(JCS(proof options + @context)) || sha256(JCS(credential without proof)), where JCS is the
JSON Canonicalization Scheme (RFC 8785) restricted, as wctl does, to strings, integers, booleans, null, arrays and
objects. The issuer is a did:key; callers pin it to the ones wctl publishes (``data/wctl-signing.did``: its current
key, plus the keys a ``wctl keys rotate-signing-key`` replaced until ``--finish``), so a grant written into the
database by anyone without wctl's key is refused. Signing is here for tests, fixtures and the marketplace tools
(``watcher.market``) only: nothing outside wctl holds its key.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_PUB_CODEC = b"\xed\x01"  # multicodec prefix of an Ed25519 public key
_TIME = "%Y-%m-%dT%H:%M:%SZ"
_MAX_INT = 1 << 53

# The did:keys a grant may be issued by: one, or several (wctl's published file lists its current key and, after a
# key rotation, the replaced keys it still trusts).
Issuers = str | tuple[str, ...]


# --- base58btc and did:key ----------------------------------------------------------------------------------------
def base58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _ALPHABET[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def unbase58(text: str) -> bytes:
    n = 0
    for char in text:
        index = _ALPHABET.find(char)
        if index < 0:
            raise ValueError("not base58")
        n = n * 58 + index
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def did_key(public: bytes) -> str:
    return "did:key:z" + base58(_PUB_CODEC + public)


def public_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("not a base58btc did:key")
    raw = unbase58(did.removeprefix("did:key:z"))
    if len(raw) != 34 or raw[:2] != _PUB_CODEC:
        raise ValueError("not an Ed25519 did:key")
    return raw[2:]


def verification_method(did: str) -> str:
    return did + "#" + did.removeprefix("did:key:")


# --- RFC 8785 canonical JSON ----------------------------------------------------------------------------------------
def canonical(value: Any) -> bytes:
    return _canonical(value).encode()


def _canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _MAX_INT:
            raise ValueError("integer outside the exactly representable range")
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _canonical(value[k]) for k in keys) + "}"
    raise ValueError(f"canonical JSON here cannot hold {type(value).__name__}")


def hash_data(document: dict[str, Any], proof: dict[str, Any]) -> bytes:
    options = {k: v for k, v in proof.items() if k != "proofValue"}
    if "@context" in document:
        options["@context"] = document["@context"]
    unsecured = {k: v for k, v in document.items() if k != "proof"}
    return hashlib.sha256(canonical(options)).digest() + hashlib.sha256(canonical(unsecured)).digest()


# --- Ed25519 (RFC 8032) -------------------------------------------------------------------------------------------
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_Point = tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def _add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _mul(scalar: int, point: _Point) -> _Point:
    out: _Point = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            out = _add(out, point)
        point = _add(point, point)
        scalar >>= 1
    return out


def _x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _x(_GY, 0) or 0
_G: _Point = (_GX, _GY, 1, _GX * _GY % _P)


def _encode(point: _Point) -> bytes:
    inverse = pow(point[2], _P - 2, _P)
    x, y = point[0] * inverse % _P, point[1] * inverse % _P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _decode(data: bytes) -> _Point | None:
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _h(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    return (int.from_bytes(digest[:32], "little") & ((1 << 254) - 8)) | (1 << 254), digest[32:]


def public_from_seed(seed: bytes) -> bytes:
    return _encode(_mul(_expand(seed)[0], _G))


def sign(seed: bytes, message: bytes) -> bytes:
    secret, prefix = _expand(seed)
    public = _encode(_mul(secret, _G))
    r = _h(prefix, message) % _L
    big_r = _encode(_mul(r, _G))
    return big_r + ((r + _h(big_r, public, message) % _L * secret) % _L).to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decode(public), _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    left, right = _mul(s, _G), _add(r, _mul(_h(signature[:32], public, message) % _L, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (left[1] * right[2] - right[1] * left[2]) % _P == 0


# --- grants ---------------------------------------------------------------------------------------------------------
def grant_signature_problem(grant: Any, issuer: Issuers, now: datetime) -> str | None:
    """Why ``grant`` is not a valid grant by ``issuer`` (one of them, when several) at ``now``, or None.
    ``grant_forged``: not issued by such a key, or changed after signing; ``approval_stale``: outside its validity
    window."""
    if not isinstance(grant, dict) or not isinstance(proof := grant.get("proof"), dict):
        return "grant_forged"
    signer = grant.get("issuer")
    if signer not in ((issuer,) if isinstance(issuer, str) else issuer) or proof.get("type") != "DataIntegrityProof" \
            or proof.get("cryptosuite") != "eddsa-jcs-2022" or proof.get("proofPurpose") != "assertionMethod" \
            or proof.get("verificationMethod") != verification_method(signer):
        return "grant_forged"
    value = proof.get("proofValue")
    try:
        if not isinstance(value, str) or not value.startswith("z"):
            return "grant_forged"
        if not verify(public_key(signer), hash_data(grant, proof), unbase58(value[1:])):
            return "grant_forged"
        start = datetime.strptime(str(grant.get("validFrom")), _TIME).replace(tzinfo=UTC)
        until = datetime.strptime(str(grant.get("validUntil")), _TIME).replace(tzinfo=UTC)
    except ValueError:
        return "grant_forged"
    if now < start - timedelta(minutes=1) or now >= until:
        return "approval_stale"
    return None


def credential_problem(credential: Any, issuer: Issuers, kind: str, now: datetime) -> str | None:
    """Why ``credential`` is not a valid credential of type ``["VerifiableCredential", kind]`` by ``issuer`` at
    ``now`` (wctl's vouch.Signer.IssueCredential, e.g. a bot engine turn's WatcherEngineTurn), or None. The proof
    and validity are checked as for grants (``grant_forged``, ``approval_stale``); another type or no subject is
    ``credential_mismatch``."""
    problem = grant_signature_problem(credential, issuer, now)
    if problem:
        return problem
    if credential.get("type") != ["VerifiableCredential", kind] \
            or not isinstance(credential.get("credentialSubject"), dict):
        return "credential_mismatch"
    return None
