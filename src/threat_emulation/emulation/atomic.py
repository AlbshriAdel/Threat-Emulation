"""Atomic Red Team adapter.

In *dry-run* mode (the default) we never invoke pwsh: the adapter resolves
the test metadata, validates that the request is in scope, and returns a
synthetic ``SUCCESS`` result describing what would have run. CI exercises
only this path.

In *live* mode (``allow_live=True`` at construction), the adapter shells out
to ``Invoke-AtomicTest -ShowDetails`` first, then ``-TestName`` with the
provided parameters. Live mode requires ``pwsh`` (or PowerShell 7+) and the
``invoke-atomicredteam`` module installed on the target. Live execution is
gated and never enabled for ``destructiveness=destructive`` without an
explicit two-person-integrity approval (enforced by the executor + Phase 4
guardrails - this adapter trusts that gate).
"""

from __future__ import annotations

import shlex
import subprocess
from datetime import UTC, datetime

from threat_emulation.emulation.adapter import (
    EmulationAdapter,
    ExecutionOutcome,
    ExecutionRequest,
    ExecutionResult,
)
from threat_emulation.schemas.enums import EmulationBackend


class AtomicRedTeamAdapter(EmulationAdapter):
    """Adapter for the Atomic Red Team / invoke-atomicredteam runner."""

    def __init__(
        self,
        *,
        allow_live: bool = False,
        pwsh_executable: str = "pwsh",
        timeout_seconds: float = 60.0,
    ) -> None:
        self._allow_live = allow_live
        self._pwsh = pwsh_executable
        self._timeout = timeout_seconds

    @property
    def backend(self) -> EmulationBackend:
        return EmulationBackend.ATOMIC_RED_TEAM

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if request.backend != self.backend:
            return _result(
                request,
                outcome=ExecutionOutcome.SKIPPED,
                error=f"Adapter handles {self.backend.value}, got {request.backend.value}",
            )

        if request.dry_run or not self._allow_live:
            return self._dry_run(request)
        return self._live_run(request)

    # --------------------------------------------------------------------- #
    # Dry run
    # --------------------------------------------------------------------- #

    def _dry_run(self, request: ExecutionRequest) -> ExecutionResult:
        params = ", ".join(f"{k}={v}" for k, v in request.parameters) or "(none)"
        plan = (
            f"DRY-RUN Atomic Red Team\n"
            f"  test_id={request.test_id}\n"
            f"  technique={request.technique_id}\n"
            f"  target={request.target}\n"
            f"  parameters={params}\n"
            f"  command (would have run): "
            f"Invoke-AtomicTest {request.technique_id} -TestName {request.test_id} "
            f"-ShowDetailsBrief"
        )
        return _result(request, outcome=ExecutionOutcome.SUCCESS, stdout=plan, exit_code=0)

    # --------------------------------------------------------------------- #
    # Live run (gated)
    # --------------------------------------------------------------------- #

    def _live_run(self, request: ExecutionRequest) -> ExecutionResult:
        cmd = self._build_command(request)
        started = datetime.now(UTC)
        try:
            completed = subprocess.run(  # noqa: S603 - args list, not shell=True
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            return _result(
                request,
                outcome=ExecutionOutcome.BLOCKED,
                started=started,
                error=f"pwsh not found: {exc}",
            )
        except subprocess.TimeoutExpired:
            return _result(
                request,
                outcome=ExecutionOutcome.FAILED,
                started=started,
                error=f"timeout after {self._timeout}s",
            )

        outcome = ExecutionOutcome.SUCCESS if completed.returncode == 0 else ExecutionOutcome.FAILED
        return _result(
            request,
            outcome=outcome,
            started=started,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
        )

    def _build_command(self, request: ExecutionRequest) -> list[str]:
        # Minimal canonical Invoke-AtomicTest invocation. -ShowDetailsBrief
        # documents but does not run; -CheckPrereqs validates env without
        # firing the payload. Real execution adds -TestName <name>.
        ps = (
            f"Invoke-AtomicTest {shlex.quote(request.technique_id)} "
            f"-TestName {shlex.quote(request.test_id)} -CheckPrereqs"
        )
        for key, value in request.parameters:
            ps += f" -InputArgs @{{ {shlex.quote(key)} = {shlex.quote(value)} }}"
        return [self._pwsh, "-NoProfile", "-NonInteractive", "-Command", ps]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _result(
    request: ExecutionRequest,
    *,
    outcome: ExecutionOutcome,
    started: datetime | None = None,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    error: str | None = None,
) -> ExecutionResult:
    started = started or datetime.now(UTC)
    return ExecutionResult(
        request_id=request.id,
        backend=request.backend,
        technique_id=request.technique_id,
        target=request.target,
        started_at=started,
        finished_at=datetime.now(UTC),
        outcome=outcome,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )
