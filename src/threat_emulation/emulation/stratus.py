"""Stratus Red Team adapter (cloud TTPs).

Phase 3 ships this as a *dry-run-only stub*: it validates the request and
returns a synthetic result describing the cloud-native attack technique
that would have been triggered. Live mode (`stratus-red-team detonate`) is
deferred until the lab has a deny-by-default cloud sandbox wired up.
"""

from __future__ import annotations

from datetime import UTC, datetime

from threat_emulation.emulation.adapter import (
    EmulationAdapter,
    ExecutionOutcome,
    ExecutionRequest,
    ExecutionResult,
)
from threat_emulation.schemas.enums import EmulationBackend


class StratusRedTeamAdapter(EmulationAdapter):
    """Stub adapter: dry-run-only emulation of cloud TTPs."""

    @property
    def backend(self) -> EmulationBackend:
        return EmulationBackend.STRATUS_RED_TEAM

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        started = datetime.now(UTC)
        if request.backend != self.backend:
            outcome = ExecutionOutcome.SKIPPED
            stdout = ""
            error: str | None = f"Adapter handles {self.backend.value}, got {request.backend.value}"
        elif not request.dry_run:
            outcome = ExecutionOutcome.BLOCKED
            stdout = ""
            error = "Stratus live execution not enabled in Phase 3"
        else:
            outcome = ExecutionOutcome.SUCCESS
            stdout = (
                f"DRY-RUN Stratus Red Team\n"
                f"  attack_id={request.test_id}\n"
                f"  technique={request.technique_id}\n"
                f"  cloud_target={request.target}\n"
                f"  command (would have run): "
                f"stratus detonate {request.test_id}"
            )
            error = None
        return ExecutionResult(
            request_id=request.id,
            backend=request.backend,
            technique_id=request.technique_id,
            target=request.target,
            started_at=started,
            finished_at=datetime.now(UTC),
            outcome=outcome,
            stdout=stdout,
            error=error,
        )
