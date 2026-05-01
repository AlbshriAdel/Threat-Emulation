"""Tests for the campaign Executor (end-to-end dry-run)."""

from __future__ import annotations

from ipaddress import IPv4Network
from uuid import uuid4

import pytest

from threat_emulation.emulation import (
    AtomicRedTeamAdapter,
    CalderaAdapter,
    Executor,
    ExecutorOptions,
    StratusRedTeamAdapter,
)
from threat_emulation.emulation.adapter import ExecutionOutcome
from threat_emulation.emulation.executor import ExecutorError
from threat_emulation.lab import InMemoryProvisioner
from threat_emulation.schemas import (
    Campaign,
    CampaignStep,
    DestructivenessTier,
    EmulationBackend,
    Scope,
)


def _scope(
    *,
    allowlist: frozenset[str] = frozenset(),
    max_destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL,
    egress_allowed: bool = False,
) -> Scope:
    return Scope(
        targets_cidr=(IPv4Network("10.0.0.0/24"),),
        targets_hostnames=("lab-host-01",),
        test_allowlist=allowlist,
        max_destructiveness=max_destructiveness,
        egress_allowed=egress_allowed,
    )


def _step(
    order: int,
    technique: str,
    *,
    backend: EmulationBackend = EmulationBackend.ATOMIC_RED_TEAM,
    test_id: str | None = None,
    destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL,
) -> CampaignStep:
    return CampaignStep(
        order=order,
        technique_id=technique,
        backend=backend,
        test_id=test_id or f"atomic-{technique}",
        destructiveness=destructiveness,
    )


def _five_step_campaign() -> Campaign:
    return Campaign(
        name="apt29-min",
        scope_id=uuid4(),
        steps=(
            _step(0, "T1059.001"),
            _step(1, "T1547.001"),
            _step(2, "T1003.001"),
            _step(3, "T1055"),
            _step(4, "T1071.001"),
        ),
    )


def _executor(*, c2_sink: object | None = None) -> Executor:
    return Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(
            AtomicRedTeamAdapter(),
            StratusRedTeamAdapter(),
            CalderaAdapter(),
        ),
        c2_sink=c2_sink,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #


def test_executor_requires_at_least_one_adapter() -> None:
    with pytest.raises(ExecutorError, match="at least one"):
        Executor(provisioner=InMemoryProvisioner(), adapters=())


def test_executor_rejects_duplicate_adapters() -> None:
    with pytest.raises(ExecutorError, match="Duplicate adapter"):
        Executor(
            provisioner=InMemoryProvisioner(),
            adapters=(AtomicRedTeamAdapter(), AtomicRedTeamAdapter()),
        )


# --------------------------------------------------------------------------- #
# End-to-end dry-run
# --------------------------------------------------------------------------- #


def test_executor_runs_five_step_campaign_dry_run_end_to_end() -> None:
    campaign = _five_step_campaign()
    scope = _scope(
        allowlist=frozenset(s.test_id for s in campaign.steps),
    )
    executor = _executor()

    result = executor.run_campaign(campaign=campaign, scope=scope)

    # Five steps, dispatched to one target each (one_target=True default).
    assert len(result.results) == 5
    for r in result.results:
        assert r.outcome == ExecutionOutcome.SUCCESS
        assert "DRY-RUN" in r.stdout
    assert result.teardown is not None
    assert result.teardown.successful is True
    assert result.teardown.residual_resources == ()
    assert result.successful is True


def test_executor_dispatches_to_every_target_when_one_target_false() -> None:
    campaign = Campaign(
        name="multi-target",
        scope_id=uuid4(),
        steps=(_step(0, "T1059.001"),),
    )
    scope = Scope(
        targets_hostnames=("h1", "h2", "h3"),
        test_allowlist=frozenset({"atomic-T1059.001"}),
    )
    executor = _executor()
    result = executor.run_campaign(
        campaign=campaign,
        scope=scope,
        options=ExecutorOptions(one_target=False),
    )
    assert {r.target for r in result.results} == {"h1", "h2", "h3"}


# --------------------------------------------------------------------------- #
# Pre-flight
# --------------------------------------------------------------------------- #


def test_executor_blocks_step_above_scope_destructiveness_ceiling() -> None:
    campaign = Campaign(
        name="too-hot",
        scope_id=uuid4(),
        steps=(
            _step(
                0,
                "T1485",
                test_id="atomic-T1485",
                destructiveness=DestructivenessTier.DESTRUCTIVE,
            ),
        ),
    )
    scope = _scope(
        allowlist=frozenset({"atomic-T1485"}),
        max_destructiveness=DestructivenessTier.OBSERVATIONAL,
    )
    result = _executor().run_campaign(campaign=campaign, scope=scope)
    assert result.error is not None
    assert "DESTRUCTIVE" in result.error.upper() or "destructive" in result.error
    assert result.handle is None
    assert result.results == ()


def test_executor_blocks_step_outside_scope_allowlist() -> None:
    campaign = Campaign(
        name="not-allowed",
        scope_id=uuid4(),
        steps=(_step(0, "T1059.001", test_id="atomic-T1059.001"),),
    )
    scope = _scope(allowlist=frozenset({"atomic-OTHER"}))
    result = _executor().run_campaign(campaign=campaign, scope=scope)
    assert result.error is not None
    assert "allowlist" in result.error


def test_executor_blocks_when_no_adapter_for_backend() -> None:
    campaign = Campaign(
        name="no-adapter",
        scope_id=uuid4(),
        steps=(
            _step(
                0,
                "T1078",
                backend=EmulationBackend.STRATUS_RED_TEAM,
                test_id="stratus-1",
            ),
        ),
    )
    scope = _scope(allowlist=frozenset({"stratus-1"}))
    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(AtomicRedTeamAdapter(),),  # no Stratus adapter
    )
    result = executor.run_campaign(campaign=campaign, scope=scope)
    assert result.error is not None
    assert "No adapter" in result.error


def test_executor_blocks_egress_when_sink_missing() -> None:
    campaign = _five_step_campaign()
    scope = _scope(
        allowlist=frozenset(s.test_id for s in campaign.steps),
        egress_allowed=True,
    )
    result = _executor().run_campaign(campaign=campaign, scope=scope)
    assert result.error is not None
    assert "egress" in result.error.lower()


# --------------------------------------------------------------------------- #
# Teardown
# --------------------------------------------------------------------------- #


def test_executor_marks_run_failed_when_teardown_leaks() -> None:
    from threat_emulation.lab.provisioner import LabHandle

    class LeakyProvisioner(InMemoryProvisioner):
        def teardown(self, handle: LabHandle) -> None:
            return None

    campaign = _five_step_campaign()
    scope = _scope(allowlist=frozenset(s.test_id for s in campaign.steps))
    executor = Executor(
        provisioner=LeakyProvisioner(),
        adapters=(AtomicRedTeamAdapter(),),
    )
    result = executor.run_campaign(campaign=campaign, scope=scope)
    assert result.teardown is not None
    assert result.teardown.successful is False
    assert result.successful is False
