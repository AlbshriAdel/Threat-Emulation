"""Integration tests for the executor with Phase 4 wiring (audit + kill-switch + preflight)."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from threading import Thread
from uuid import uuid4

from threat_emulation.audit import AuditLog
from threat_emulation.auth.rbac import Principal, Role
from threat_emulation.auth.twopi import ApprovalToken, TwoPersonIntegrity
from threat_emulation.emulation import (
    AtomicRedTeamAdapter,
    Executor,
    ExecutorOptions,
)
from threat_emulation.guardrails.killswitch import KillReason, KillSwitch
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
from threat_emulation.lab import InMemoryProvisioner
from threat_emulation.schemas import (
    Campaign,
    CampaignStep,
    DestructivenessTier,
    EmulationBackend,
    Scope,
    ScopeOfEngagement,
)

KEY = b"phase4-key" * 4


def _scope(*, allowlist: frozenset[str], egress: bool = False) -> Scope:
    return Scope(
        targets_cidr=(IPv4Network("10.0.0.0/24"),),
        targets_hostnames=("lab-01",),
        test_allowlist=allowlist,
        egress_allowed=egress,
    )


def _campaign(*technique_ids: str) -> Campaign:
    steps = tuple(
        CampaignStep(
            order=i,
            technique_id=t,
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            test_id=f"atomic-{t}",
        )
        for i, t in enumerate(technique_ids)
    )
    return Campaign(name="phase4-test", scope_id=uuid4(), steps=steps)


def _soe(scope: Scope) -> ScopeOfEngagement:
    now = datetime.now(UTC)
    return ScopeOfEngagement(
        organization="Acme",
        authorized_by="ciso@acme.example",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1),
        scope=scope,
        signature="x",
    )


def _policy() -> Policy:
    return Policy(
        name="default",
        version=1,
        issued_at=datetime.now(UTC),
        scope_constraints=ScopeConstraints(
            max_destructiveness=DestructivenessTier.DESTRUCTIVE,
        ),
        approvals=ApprovalRequirements(),
    )


def _checker(policy: Policy) -> PreflightChecker:
    return PreflightChecker(
        policy=policy,
        two_person_integrity=TwoPersonIntegrity(
            requirements=policy.approvals, verification_key=KEY
        ),
    )


# --------------------------------------------------------------------------- #
# Audit-log wiring
# --------------------------------------------------------------------------- #


def test_executor_emits_audit_events_when_log_wired() -> None:
    scope = _scope(allowlist=frozenset({"atomic-T1059.001"}))
    campaign = _campaign("T1059.001")
    soe = _soe(scope)
    rid = uuid4()
    soe_hash = "f" * 64
    audit_log = AuditLog(run_id=rid, scope_of_engagement_hash=soe_hash)

    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(AtomicRedTeamAdapter(),),
        audit_log=audit_log,
    )
    result = executor.run_campaign(
        campaign=campaign,
        scope=scope,
        run_id=rid,
        scope_of_engagement=soe,
        operator="oidc|alice",
    )

    assert result.successful is True
    event_types = [e.event_type for e in audit_log.events]
    # Expect: run.start, lab.provisioned, step.executed, lab.teardown, run.complete.
    for required in (
        "run.start",
        "lab.provisioned",
        "step.executed",
        "lab.teardown",
        "run.complete",
    ):
        assert required in event_types, f"missing audit event {required!r}"
    assert audit_log.verify().valid is True


# --------------------------------------------------------------------------- #
# Preflight wiring
# --------------------------------------------------------------------------- #


def test_executor_blocks_when_preflight_rejects() -> None:
    # Scope grants destructive, but the policy ceiling is observational;
    # the policy preflight must reject before the lightweight executor preflight.
    scope = _scope(allowlist=frozenset({"atomic-T1059.001"})).model_copy(
        update={"max_destructiveness": DestructivenessTier.DESTRUCTIVE}
    )
    campaign = _campaign("T1059.001")  # observational step keeps lightweight preflight happy
    policy = Policy(
        name="strict",
        version=1,
        issued_at=datetime.now(UTC),
        scope_constraints=ScopeConstraints(max_destructiveness=DestructivenessTier.OBSERVATIONAL),
    )
    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(AtomicRedTeamAdapter(),),
        preflight_checker=_checker(policy),
    )
    soe = _soe(scope)
    result = executor.run_campaign(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=soe,
    )
    assert result.successful is False
    assert result.handle is None
    assert result.preflight is not None
    assert any(v.rule == "policy.scope.max_destructiveness" for v in result.preflight.violations)


def test_executor_with_preflight_requires_soe() -> None:
    scope = _scope(allowlist=frozenset({"atomic-T1059.001"}))
    campaign = _campaign("T1059.001")
    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(AtomicRedTeamAdapter(),),
        preflight_checker=_checker(_policy()),
    )
    result = executor.run_campaign(campaign=campaign, scope=scope)
    assert result.error is not None
    assert "scope_of_engagement" in result.error


def test_executor_destructive_path_requires_two_approvals() -> None:
    scope = _scope(allowlist=frozenset({"atomic-T1485"}))
    scope = scope.model_copy(update={"max_destructiveness": DestructivenessTier.DESTRUCTIVE})
    step = CampaignStep(
        order=0,
        technique_id="T1485",
        backend=EmulationBackend.ATOMIC_RED_TEAM,
        test_id="atomic-T1485",
        destructiveness=DestructivenessTier.DESTRUCTIVE,
    )
    campaign = Campaign(name="destructive", scope_id=uuid4(), steps=(step,))
    soe = _soe(scope)

    alice = Principal(subject="oidc|alice", roles=frozenset({Role.APPROVER}))
    bob = Principal(subject="oidc|bob", roles=frozenset({Role.APPROVER}))
    c_hash = hash_campaign(campaign)
    s_hash = hash_scope(scope)
    a_token = ApprovalToken.issue(
        approver=alice,
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=c_hash,
        scope_hash=s_hash,
        key=KEY,
    )
    b_token = ApprovalToken.issue(
        approver=bob,
        tier=DestructivenessTier.DESTRUCTIVE,
        campaign_hash=c_hash,
        scope_hash=s_hash,
        key=KEY,
    )

    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(AtomicRedTeamAdapter(),),
        preflight_checker=_checker(_policy()),
    )

    # One approval -> rejected.
    one = executor.run_campaign(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=soe,
        approvals=(a_token,),
    )
    assert one.successful is False
    assert one.preflight is not None
    assert any(v.rule == "auth.twopi" for v in one.preflight.violations)

    # Two distinct approvals -> cleared (even though we keep dry_run=True).
    two = executor.run_campaign(
        campaign=campaign,
        scope=scope,
        scope_of_engagement=soe,
        approvals=(a_token, b_token),
        options=ExecutorOptions(dry_run=True),
    )
    assert two.successful is True


# --------------------------------------------------------------------------- #
# Kill-switch wiring
# --------------------------------------------------------------------------- #


def test_executor_aborts_when_kill_switch_tripped_before_provisioning() -> None:
    ks = KillSwitch()
    ks.trip(KillReason.OPERATOR, detail="pre-provision")
    scope = _scope(allowlist=frozenset({"atomic-T1059.001"}))
    campaign = _campaign("T1059.001")
    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(AtomicRedTeamAdapter(),),
        kill_switch=ks,
    )
    result = executor.run_campaign(campaign=campaign, scope=scope)
    assert result.killed is True
    assert result.successful is False
    assert result.handle is None


def test_executor_aborts_mid_campaign_on_kill_switch() -> None:
    ks = KillSwitch()
    scope = _scope(
        allowlist=frozenset({"atomic-T1059.001", "atomic-T1547.001", "atomic-T1071.001"})
    )
    campaign = _campaign("T1059.001", "T1547.001", "T1071.001")

    class _SlowAtomic(AtomicRedTeamAdapter):
        def execute(self, request):  # type: ignore[no-untyped-def]
            time.sleep(0.05)
            return super().execute(request)

    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(_SlowAtomic(),),
        kill_switch=ks,
    )

    def _trip_after_first_step() -> None:
        time.sleep(0.06)
        ks.trip(KillReason.API)

    Thread(target=_trip_after_first_step, daemon=True).start()
    result = executor.run_campaign(
        campaign=campaign, scope=scope, options=ExecutorOptions(dry_run=True)
    )
    # First step should have run; subsequent steps skipped.
    assert result.killed is True
    assert 0 < len(result.results) < 3
    assert result.successful is False
