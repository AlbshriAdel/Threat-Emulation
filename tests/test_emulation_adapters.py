"""Tests for emulation adapters."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from threat_emulation.emulation import (
    AtomicRedTeamAdapter,
    CalderaAdapter,
    StratusRedTeamAdapter,
)
from threat_emulation.emulation.adapter import (
    ExecutionOutcome,
    ExecutionRequest,
    ExecutionResult,
)
from threat_emulation.schemas.enums import (
    DestructivenessTier,
    EmulationBackend,
)


def _request(
    *,
    backend: EmulationBackend = EmulationBackend.ATOMIC_RED_TEAM,
    test_id: str = "atomic-T1059.001",
    dry_run: bool = True,
    destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL,
) -> ExecutionRequest:
    return ExecutionRequest(
        run_id=uuid4(),
        backend=backend,
        test_id=test_id,
        technique_id="T1059.001",
        target="lab-host-01",
        dry_run=dry_run,
        destructiveness=destructiveness,
    )


# --------------------------------------------------------------------------- #
# Atomic Red Team
# --------------------------------------------------------------------------- #


def test_atomic_dry_run_succeeds_without_pwsh() -> None:
    adapter = AtomicRedTeamAdapter()
    result = adapter.execute(_request())
    assert result.outcome == ExecutionOutcome.SUCCESS
    assert "DRY-RUN Atomic Red Team" in result.stdout
    assert "Invoke-AtomicTest T1059.001" in result.stdout
    assert result.exit_code == 0
    assert result.error is None


def test_atomic_dry_run_skips_other_backends() -> None:
    adapter = AtomicRedTeamAdapter()
    result = adapter.execute(_request(backend=EmulationBackend.STRATUS_RED_TEAM))
    assert result.outcome == ExecutionOutcome.SKIPPED
    assert result.error is not None


def test_atomic_live_mode_blocked_when_pwsh_missing() -> None:
    adapter = AtomicRedTeamAdapter(allow_live=True, pwsh_executable="/no/such/pwsh")
    result = adapter.execute(_request(dry_run=False))
    # Either BLOCKED (FileNotFoundError) or FAILED (subprocess returns non-zero)
    # is acceptable; what matters is that it does NOT silently succeed.
    assert result.outcome != ExecutionOutcome.SUCCESS


def test_atomic_supports_method() -> None:
    adapter = AtomicRedTeamAdapter()
    assert adapter.supports(EmulationBackend.ATOMIC_RED_TEAM)
    assert not adapter.supports(EmulationBackend.STRATUS_RED_TEAM)


def test_execution_result_duration_is_non_negative() -> None:
    adapter = AtomicRedTeamAdapter()
    result = adapter.execute(_request())
    assert result.duration_seconds >= 0


def test_execution_result_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ExecutionResult(
            request_id=uuid4(),
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            technique_id="T1059.001",
            target="x",
            started_at=datetime(2026, 1, 1),  # naive
            finished_at=datetime.now(UTC),
            outcome=ExecutionOutcome.SUCCESS,
        )


# --------------------------------------------------------------------------- #
# Stratus
# --------------------------------------------------------------------------- #


def test_stratus_dry_run_succeeds() -> None:
    adapter = StratusRedTeamAdapter()
    result = adapter.execute(
        _request(backend=EmulationBackend.STRATUS_RED_TEAM, test_id="stratus-attack-1")
    )
    assert result.outcome == ExecutionOutcome.SUCCESS
    assert "DRY-RUN Stratus" in result.stdout


def test_stratus_live_is_blocked() -> None:
    adapter = StratusRedTeamAdapter()
    result = adapter.execute(_request(backend=EmulationBackend.STRATUS_RED_TEAM, dry_run=False))
    assert result.outcome == ExecutionOutcome.BLOCKED


# --------------------------------------------------------------------------- #
# CALDERA
# --------------------------------------------------------------------------- #


def test_caldera_dry_run_succeeds() -> None:
    adapter = CalderaAdapter()
    result = adapter.execute(
        _request(backend=EmulationBackend.CALDERA, test_id="caldera-ability-1")
    )
    assert result.outcome == ExecutionOutcome.SUCCESS
    assert "DRY-RUN CALDERA" in result.stdout


def test_caldera_live_is_blocked() -> None:
    adapter = CalderaAdapter()
    result = adapter.execute(_request(backend=EmulationBackend.CALDERA, dry_run=False))
    assert result.outcome == ExecutionOutcome.BLOCKED
