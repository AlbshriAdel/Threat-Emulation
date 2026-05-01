"""Tests for the policy + 2PI preflight pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from uuid import uuid4

from threat_emulation.auth.rbac import Principal, Role
from threat_emulation.auth.twopi import ApprovalToken, TwoPersonIntegrity
from threat_emulation.guardrails.policy import (
    ApprovalRequirements,
    Policy,
    ScopeConstraints,
)
from threat_emulation.guardrails.preflight import (
    PreflightChecker,
    hash_campaign,
    hash_scope,
)
from threat_emulation.schemas import (
    Campaign,
    CampaignStep,
    DestructivenessTier,
    EmulationBackend,
    Scope,
    ScopeOfEngagement,
)

KEY = b"preflight-test-key" * 2


# --------------------------------------------------------------------------- #
# Fixtures-ish helpers
# --------------------------------------------------------------------------- #


def _scope(
    *,
    max_destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL,
    test_allowlist: frozenset[str] | None = None,
    egress_allowed: bool = False,
) -> Scope:
    return Scope(
        targets_cidr=(IPv4Network("10.0.0.0/24"),),
        test_allowlist=test_allowlist
        if test_allowlist is not None
        else frozenset({"atomic-T1059.001"}),
        max_destructiveness=max_destructiveness,
        egress_allowed=egress_allowed,
    )


def _step(
    technique: str,
    *,
    backend: EmulationBackend = EmulationBackend.ATOMIC_RED_TEAM,
    destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL,
) -> CampaignStep:
    return CampaignStep(
        order=0,
        technique_id=technique,
        backend=backend,
        test_id=f"atomic-{technique}",
        destructiveness=destructiveness,
    )


def _campaign(*steps: CampaignStep) -> Campaign:
    return Campaign(name="t", scope_id=uuid4(), steps=steps)


def _soe(scope: Scope) -> ScopeOfEngagement:
    now = datetime.now(UTC)
    return ScopeOfEngagement(
        organization="Acme",
        authorized_by="ciso@acme.example",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1),
        scope=scope,
        signature="deadbeef",
    )


def _policy(
    *,
    max_destructiveness: DestructivenessTier = DestructivenessTier.DESTRUCTIVE,
) -> Policy:
    return Policy(
        name="default",
        version=1,
        issued_at=datetime.now(UTC),
        scope_constraints=ScopeConstraints(max_destructiveness=max_destructiveness),
        approvals=ApprovalRequirements(),
    )


def _checker(*, policy: Policy | None = None) -> PreflightChecker:
    return PreflightChecker(
        policy=policy or _policy(),
        two_person_integrity=TwoPersonIntegrity(
            requirements=(policy or _policy()).approvals,
            verification_key=KEY,
        ),
    )


# --------------------------------------------------------------------------- #
# Hashes
# --------------------------------------------------------------------------- #


def test_hashes_are_deterministic() -> None:
    s = _scope()
    c = _campaign(_step("T1059.001"))
    assert hash_scope(s) == hash_scope(s)
    assert hash_campaign(c) == hash_campaign(c)


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #


def test_preflight_observational_passes_without_approvals() -> None:
    scope = _scope()
    campaign = _campaign(_step("T1059.001"))
    report = _checker().check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=_soe(scope),
        approvals=(),
    )
    assert report.ok is True
    assert report.violations == ()


def test_preflight_blocks_when_soe_window_inactive() -> None:
    scope = _scope()
    campaign = _campaign(_step("T1059.001"))
    expired = datetime.now(UTC) - timedelta(days=10)
    soe = ScopeOfEngagement(
        organization="Acme",
        authorized_by="ciso@acme.example",
        valid_from=expired - timedelta(days=1),
        valid_until=expired,
        scope=scope,
        signature="x",
    )
    report = _checker().check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=soe,
        approvals=(),
    )
    assert report.ok is False
    assert any(v.rule == "soe.window" for v in report.violations)


def test_preflight_blocks_when_scope_exceeds_policy_ceiling() -> None:
    scope = _scope(max_destructiveness=DestructivenessTier.DESTRUCTIVE)
    campaign = _campaign(_step("T1059.001"))
    policy = _policy(max_destructiveness=DestructivenessTier.OBSERVATIONAL)
    report = _checker(policy=policy).check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=_soe(scope),
        approvals=(),
    )
    assert report.ok is False
    assert any(v.rule == "policy.scope.max_destructiveness" for v in report.violations)


def test_preflight_blocks_disallowed_backend() -> None:
    scope = _scope(test_allowlist=frozenset({"stratus-1"}))
    campaign = _campaign(
        _step(
            "T1078",
            backend=EmulationBackend.STRATUS_RED_TEAM,
        )
    )
    # Override step.test_id to "stratus-1" so allowlist isn't the violation.
    step = CampaignStep(
        order=0,
        technique_id="T1078",
        backend=EmulationBackend.STRATUS_RED_TEAM,
        test_id="stratus-1",
    )
    campaign = _campaign(step)
    report = _checker().check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=_soe(scope),
        approvals=(),
    )
    assert report.ok is False
    assert any(v.rule == "policy.scope.allowed_backends" for v in report.violations)


def test_preflight_requires_test_allowlist_when_policy_says_so() -> None:
    scope = _scope(test_allowlist=frozenset())
    campaign = _campaign(_step("T1059.001"))
    report = _checker().check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=_soe(scope),
        approvals=(),
    )
    assert any(v.rule == "policy.scope.require_test_allowlist" for v in report.violations)


def test_preflight_destructive_requires_two_distinct_approvers() -> None:
    scope = _scope(
        max_destructiveness=DestructivenessTier.DESTRUCTIVE,
        test_allowlist=frozenset({"atomic-T1485"}),
    )
    step = CampaignStep(
        order=0,
        technique_id="T1485",
        backend=EmulationBackend.ATOMIC_RED_TEAM,
        test_id="atomic-T1485",
        destructiveness=DestructivenessTier.DESTRUCTIVE,
    )
    campaign = _campaign(step)
    soe = _soe(scope)
    checker = _checker()

    alice = Principal(subject="oidc|alice", roles=frozenset({Role.APPROVER}))
    bob = Principal(subject="oidc|bob", roles=frozenset({Role.APPROVER}))
    c_hash = hash_campaign(campaign)
    s_hash = hash_scope(scope)
    one_token = ApprovalToken.issue(
        approver=alice,
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=c_hash,
        scope_hash=s_hash,
        key=KEY,
    )
    two_token = ApprovalToken.issue(
        approver=bob,
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=c_hash,
        scope_hash=s_hash,
        key=KEY,
    )

    one_only = checker.check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=soe,
        approvals=(one_token,),
    )
    assert one_only.ok is False
    assert any(v.rule == "auth.twopi" for v in one_only.violations)

    both = checker.check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=soe,
        approvals=(one_token, two_token),
    )
    assert both.ok is True
    assert set(both.distinct_approvers) == {"oidc|alice", "oidc|bob"}


def test_preflight_egress_with_default_deny_records_sink_requirement() -> None:
    scope = _scope(egress_allowed=True)
    campaign = _campaign(_step("T1059.001"))
    report = _checker().check(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=_soe(scope),
        approvals=(),
    )
    assert report.ok is False
    assert any(v.rule == "policy.egress.require_c2_sink" for v in report.violations)
