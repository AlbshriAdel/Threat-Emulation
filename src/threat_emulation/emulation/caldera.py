"""CALDERA adapter (multi-step adversary operations).

Phase 3 ships this as a dry-run stub. Live mode requires a CALDERA server
URL + API key and is deferred.
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


class CalderaAdapter(EmulationAdapter):
    """Stub adapter: dry-run-only emulation of CALDERA abilities."""

    @property
    def backend(self) -> EmulationBackend:
        return EmulationBackend.CALDERA

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        started = datetime.now(UTC)
        if request.backend != self.backend:
            outcome = ExecutionOutcome.SKIPPED
            stdout = ""
            error: str | None = f"Adapter handles {self.backend.value}, got {request.backend.value}"
        elif not request.dry_run:
            outcome = ExecutionOutcome.BLOCKED
            stdout = ""
            error = "CALDERA live execution not enabled in Phase 3"
        else:
            outcome = ExecutionOutcome.SUCCESS
            stdout = (
                f"DRY-RUN CALDERA\n"
                f"  ability_id={request.test_id}\n"
                f"  technique={request.technique_id}\n"
                f"  target={request.target}"
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
