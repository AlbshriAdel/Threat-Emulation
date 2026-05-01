"""Teardown verifier.

Per CLAUDE.md hard rules: every run must verify lab teardown before being
marked complete. The verifier asks the provisioner to enumerate residual
resources for a torn-down handle; if any remain, the run is marked
:class:`~threat_emulation.schemas.RunPhase.FAILED`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from threat_emulation.lab.provisioner import LabHandle, LabProvisioner


@dataclass(frozen=True)
class TeardownReport:
    """The result of a teardown + verification attempt."""

    handle: LabHandle
    completed_at: datetime
    duration_seconds: float
    successful: bool
    residual_resources: tuple[str, ...] = field(default_factory=tuple)
    error: str | None = None


class TeardownVerifier:
    """Tear a lab down and verify it's gone.

    Args:
        max_duration_seconds: Hard ceiling on the teardown duration. The
            kill-switch contract (CLAUDE.md hard rule 7) requires teardown
            within 5 seconds; production deployments tighten this further.
    """

    def __init__(self, *, max_duration_seconds: float = 5.0) -> None:
        if max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be positive")
        self._budget = max_duration_seconds

    def verify(self, *, provisioner: LabProvisioner, handle: LabHandle) -> TeardownReport:
        started = datetime.now(UTC)
        teardown_error: str | None = None
        try:
            provisioner.teardown(handle)
        except Exception as exc:
            teardown_error = f"teardown raised: {exc!s}"

        completed = datetime.now(UTC)
        duration = (completed - started).total_seconds()
        residual = provisioner.list_resources(handle)

        successful = teardown_error is None and not residual and duration <= self._budget
        error = teardown_error
        if error is None and residual:
            error = (
                f"teardown left {len(residual)} residual resource(s): "
                + ", ".join(residual[:5])
                + ("..." if len(residual) > 5 else "")
            )
        elif error is None and duration > self._budget:
            error = f"teardown exceeded budget ({duration:.2f}s > {self._budget:.2f}s)"

        return TeardownReport(
            handle=handle,
            completed_at=completed,
            duration_seconds=duration,
            successful=successful,
            residual_resources=tuple(residual),
            error=error,
        )
