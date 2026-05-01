"""Minimal HMAC-SHA256 JWT.

A tiny, dependency-free implementation of JWS-compact ``HS256`` JWTs. Used
for approval-token signing where a full ``python-jose`` dependency would
be overkill. Production deployments may inject a ``Signer`` from a more
capable library; the public surface of :func:`encode_jwt` / :func:`decode_jwt`
is stable.

Supports a single algorithm (``HS256``); attempting any other ``alg`` raises
:class:`JwtError`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

ALG = "HS256"
TYP = "JWT"


class JwtError(RuntimeError):
    """Raised on encoding / decoding errors (signature, expiry, format)."""


def encode_jwt(
    payload: dict[str, Any],
    *,
    key: bytes,
    expires_in_seconds: int | None = None,
    issued_at: int | None = None,
) -> str:
    """Encode an HS256 JWT.

    Args:
        payload: Claims to embed.
        key: Symmetric HMAC key (non-empty).
        expires_in_seconds: If supplied, sets ``exp`` to ``iat + expires_in_seconds``.
        issued_at: Unix epoch override (default: ``time.time()``).
    """
    if not key:
        raise JwtError("key must be non-empty")
    iat = int(issued_at if issued_at is not None else time.time())
    claims: dict[str, Any] = {"iat": iat, **payload}
    if expires_in_seconds is not None:
        if expires_in_seconds <= 0:
            raise JwtError("expires_in_seconds must be positive")
        claims["exp"] = iat + expires_in_seconds

    header = {"alg": ALG, "typ": TYP}
    h = _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    s = _b64url(sig)
    return f"{h}.{p}.{s}"


def decode_jwt(
    token: str, *, key: bytes, now: int | None = None, leeway_seconds: int = 0
) -> dict[str, Any]:
    """Decode + verify an HS256 JWT. Raises :class:`JwtError` on failure."""
    if not key:
        raise JwtError("key must be non-empty")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("JWT must have three dot-separated parts")
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
        sig = _b64url_decode(s_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise JwtError(f"malformed JWT: {exc}") from exc

    if header.get("alg") != ALG:
        raise JwtError(f"unsupported alg: {header.get('alg')!r}")
    if header.get("typ") not in (None, TYP):
        raise JwtError(f"unexpected typ: {header.get('typ')!r}")

    signing_input = f"{h_b64}.{p_b64}".encode()
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise JwtError("signature mismatch")

    moment = int(now if now is not None else time.time())
    exp = payload.get("exp")
    if isinstance(exp, int) and moment > exp + leeway_seconds:
        raise JwtError("token expired")
    nbf = payload.get("nbf")
    if isinstance(nbf, int) and moment + leeway_seconds < nbf:
        raise JwtError("token not yet valid")

    if not isinstance(payload, dict):
        raise JwtError("payload must be a JSON object")
    return payload


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))
