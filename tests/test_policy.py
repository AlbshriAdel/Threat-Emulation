"""Tests for the Pydantic guardrail policy DSL."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_emulation.guardrails.policy import (
    ApprovalRequirements,
    EgressPolicy,
    Policy,
    ScopeConstraints,
    TlpRoutingPolicy,
)
from threat_emulation.schemas.enums import (
    TLP,
    DestructivenessTier,
    EmulationBackend,
)


def _policy(**kwargs: object) -> Policy:
    return Policy(
        name="default",
        version=1,
        issued_at=datetime.now(UTC),
        **kwargs,
    )


def test_policy_defaults_are_safe() -> None:
    p = _policy()
    assert p.scope_constraints.max_destructiveness == DestructivenessTier.OBSERVATIONAL
    assert p.scope_constraints.allowed_backends == frozenset({EmulationBackend.ATOMIC_RED_TEAM})
    assert p.scope_constraints.require_test_allowlist is True
    assert p.egress.default_deny is True
    assert p.egress.require_c2_sink is True
    assert p.approvals.observational == 0
    assert p.approvals.intrusive == 1
    assert p.approvals.destructive == 2
    assert TLP.AMBER not in p.tlp.cloud_allowed


def test_policy_rejects_naive_issued_at() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Policy(name="x", version=1, issued_at=datetime(2026, 1, 1))


def test_approval_requirements_must_be_monotonic() -> None:
    with pytest.raises(ValueError, match="monotonic"):
        ApprovalRequirements(observational=2, intrusive=1, destructive=2)


def test_approval_requirements_required_for_each_tier() -> None:
    a = ApprovalRequirements(observational=0, intrusive=1, destructive=3)
    assert a.required_for(DestructivenessTier.OBSERVATIONAL) == 0
    assert a.required_for(DestructivenessTier.INTRUSIVE) == 1
    assert a.required_for(DestructivenessTier.DESTRUCTIVE) == 3


def test_tlp_routing_policy_rejects_amber_in_cloud() -> None:
    with pytest.raises(ValueError, match="AMBER"):
        TlpRoutingPolicy(cloud_allowed=frozenset({TLP.CLEAR, TLP.AMBER}))


def test_policy_content_hash_is_stable_for_identical_inputs() -> None:
    issued = datetime(2026, 5, 1, tzinfo=UTC)
    a = Policy(name="default", version=1, issued_at=issued)
    b = Policy(name="default", version=1, issued_at=issued, id=a.id)
    assert a.content_hash() == b.content_hash()


def test_policy_content_hash_excludes_signature() -> None:
    p = _policy()
    h_unsigned = p.content_hash()
    signed = p.sign(key=b"k" * 32)
    assert signed.signature is not None
    assert signed.content_hash() == h_unsigned


def test_policy_signature_roundtrip() -> None:
    p = _policy()
    key = b"super-secret-key" * 4
    signed = p.sign(key=key)
    assert signed.verify(key=key) is True
    # Different key -> verification fails.
    assert signed.verify(key=b"wrong-key" * 4) is False


def test_policy_unsigned_does_not_verify() -> None:
    assert _policy().verify(key=b"k") is False


def test_policy_sign_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _policy().sign(key=b"")


def test_egress_policy_defaults() -> None:
    e = EgressPolicy()
    assert e.default_deny is True
    assert e.require_c2_sink is True
    assert e.allowed_protocols == frozenset()


def test_scope_constraints_custom_backends() -> None:
    c = ScopeConstraints(
        allowed_backends=frozenset(
            {EmulationBackend.ATOMIC_RED_TEAM, EmulationBackend.STRATUS_RED_TEAM}
        )
    )
    assert EmulationBackend.STRATUS_RED_TEAM in c.allowed_backends
