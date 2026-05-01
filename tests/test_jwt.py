"""Tests for the minimal HS256 JWT helper."""

from __future__ import annotations

import time

import pytest

from threat_emulation.auth.jwt import JwtError, decode_jwt, encode_jwt

KEY = b"a-test-symmetric-key" * 2


def test_jwt_roundtrip() -> None:
    token = encode_jwt({"sub": "alice"}, key=KEY)
    claims = decode_jwt(token, key=KEY)
    assert claims["sub"] == "alice"
    assert "iat" in claims


def test_jwt_includes_iat_and_optional_exp() -> None:
    token = encode_jwt({"sub": "alice"}, key=KEY, expires_in_seconds=60)
    claims = decode_jwt(token, key=KEY)
    assert claims["exp"] - claims["iat"] == 60


def test_jwt_signature_mismatch_rejected() -> None:
    token = encode_jwt({"sub": "alice"}, key=KEY)
    with pytest.raises(JwtError, match="signature mismatch"):
        decode_jwt(token, key=b"different-key" * 4)


def test_jwt_tampered_payload_rejected() -> None:
    token = encode_jwt({"sub": "alice"}, key=KEY)
    h, _, s = token.split(".")
    # Replace payload with a different valid base64url string.
    tampered = f"{h}.eyJzdWIiOiJtYWxsb3J5In0.{s}"
    with pytest.raises(JwtError):
        decode_jwt(tampered, key=KEY)


def test_jwt_expired_token_rejected() -> None:
    token = encode_jwt(
        {"sub": "alice"},
        key=KEY,
        expires_in_seconds=1,
        issued_at=int(time.time()) - 60,
    )
    with pytest.raises(JwtError, match="expired"):
        decode_jwt(token, key=KEY)


def test_jwt_leeway_allows_small_clock_drift() -> None:
    iat = int(time.time()) - 100
    token = encode_jwt({"sub": "alice"}, key=KEY, expires_in_seconds=60, issued_at=iat)
    # Without leeway, expired.
    with pytest.raises(JwtError):
        decode_jwt(token, key=KEY)
    # With leeway, accepted.
    claims = decode_jwt(token, key=KEY, leeway_seconds=120)
    assert claims["sub"] == "alice"


def test_jwt_rejects_malformed() -> None:
    with pytest.raises(JwtError, match="three"):
        decode_jwt("not.a.real.jwt", key=KEY)


def test_jwt_rejects_unsupported_alg() -> None:
    # Build a JWT-shaped string with a different alg.
    import base64
    import json

    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    h = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    p = b64(b"{}")
    token = f"{h}.{p}.AAAA"
    with pytest.raises(JwtError, match="unsupported alg"):
        decode_jwt(token, key=KEY)


def test_jwt_empty_key_rejected() -> None:
    with pytest.raises(JwtError, match="non-empty"):
        encode_jwt({"sub": "x"}, key=b"")
    with pytest.raises(JwtError, match="non-empty"):
        decode_jwt("a.b.c", key=b"")
