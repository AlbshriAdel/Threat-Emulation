"""Tests for the 2-person-integrity gate."""

from __future__ import annotations

from threat_emulation.auth.rbac import Principal, Role
from threat_emulation.auth.twopi import (
    ApprovalToken,
    TwoPersonIntegrity,
)
from threat_emulation.guardrails.policy import ApprovalRequirements
from threat_emulation.schemas.enums import DestructivenessTier

KEY = b"twopi-key-for-tests" * 2
CAMPAIGN_HASH = "a" * 64
SCOPE_HASH = "b" * 64


def _approver(name: str, role: Role = Role.APPROVER) -> Principal:
    return Principal(subject=f"oidc|{name}", roles=frozenset({role}))


def _gate(
    *,
    requirements: ApprovalRequirements | None = None,
) -> TwoPersonIntegrity:
    return TwoPersonIntegrity(
        requirements=requirements or ApprovalRequirements(),
        verification_key=KEY,
    )


def _token(
    approver: Principal,
    *,
    tier: DestructivenessTier,
    campaign_hash: str = CAMPAIGN_HASH,
    scope_hash: str = SCOPE_HASH,
) -> ApprovalToken:
    return ApprovalToken.issue(
        approver=approver,
        tier=tier,
        campaign_hash=campaign_hash,
        scope_hash=scope_hash,
        key=KEY,
    )


def test_observational_requires_no_approvals() -> None:
    decision = _gate().evaluate(
        tier=DestructivenessTier.OBSERVATIONAL,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(),
    )
    assert decision.granted is True
    assert decision.distinct_approvers == ()


def test_intrusive_requires_one_distinct_approver() -> None:
    alice = _approver("alice")
    decision = _gate().evaluate(
        tier=DestructivenessTier.INTRUSIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(_token(alice, tier=DestructivenessTier.INTRUSIVE),),
    )
    assert decision.granted is True
    assert decision.distinct_approvers == ("oidc|alice",)


def test_destructive_requires_two_distinct_approvers() -> None:
    alice = _approver("alice")
    bob = _approver("bob")
    gate = _gate()
    one = gate.evaluate(
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(_token(alice, tier=DestructivenessTier.DESTRUCTIVE),),
    )
    assert one.granted is False

    two = gate.evaluate(
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(
            _token(alice, tier=DestructivenessTier.DESTRUCTIVE),
            _token(bob, tier=DestructivenessTier.DESTRUCTIVE),
        ),
    )
    assert two.granted is True
    assert set(two.distinct_approvers) == {"oidc|alice", "oidc|bob"}


def test_two_tokens_same_approver_count_once() -> None:
    alice = _approver("alice")
    decision = _gate().evaluate(
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(
            _token(alice, tier=DestructivenessTier.DESTRUCTIVE),
            _token(alice, tier=DestructivenessTier.DESTRUCTIVE),
        ),
    )
    assert decision.granted is False
    assert decision.distinct_approvers == ("oidc|alice",)


def test_token_for_wrong_campaign_is_ignored() -> None:
    alice = _approver("alice")
    bob = _approver("bob")
    decision = _gate().evaluate(
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(
            _token(alice, tier=DestructivenessTier.DESTRUCTIVE),
            _token(bob, tier=DestructivenessTier.DESTRUCTIVE, campaign_hash="c" * 64),
        ),
    )
    assert decision.granted is False


def test_token_for_wrong_scope_is_ignored() -> None:
    alice = _approver("alice")
    bob = _approver("bob")
    decision = _gate().evaluate(
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(
            _token(alice, tier=DestructivenessTier.DESTRUCTIVE),
            _token(bob, tier=DestructivenessTier.DESTRUCTIVE, scope_hash="d" * 64),
        ),
    )
    assert decision.granted is False


def test_approver_without_role_rejected() -> None:
    plain = _approver("plain", role=Role.OPERATOR)  # operator can't approve
    bob = _approver("bob")
    decision = _gate().evaluate(
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(
            _token(plain, tier=DestructivenessTier.DESTRUCTIVE),
            _token(bob, tier=DestructivenessTier.DESTRUCTIVE),
        ),
    )
    assert decision.granted is False
    assert decision.distinct_approvers == ("oidc|bob",)


def test_token_for_wrong_tier_rejected() -> None:
    alice = _approver("alice")
    decision = _gate().evaluate(
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=CAMPAIGN_HASH,
        scope_hash=SCOPE_HASH,
        approvals=(_token(alice, tier=DestructivenessTier.INTRUSIVE),),
    )
    assert decision.granted is False
