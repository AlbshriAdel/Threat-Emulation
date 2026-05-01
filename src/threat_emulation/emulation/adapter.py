"""Abstract emulation adapter and request/result schemas.

An :class:`EmulationAdapter` runs one ``test_id`` from one
:class:`~threat_emulation.schemas.EmulationBackend` against one target inside
the lab. It is deliberately small: dispatching across multiple steps,
provisioning, teardown, and audit are the executor's responsibility, not
the adapter's.

All inputs and outputs are typed Pydantic models so they flow into the audit
log unchanged.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threat_emulation.schemas.enums import (
    DestructivenessTier,
    EmulationBackend,
)


class ExecutionOutcome(StrEnum):
    """Terminal status for a single emulation step."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ExecutionRequest(BaseModel):
    """A single emulation request dispatched to an adapter."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    backend: EmulationBackend
    test_id: str = Field(min_length=1, max_length=200)
    technique_id: str = Field(min_length=1, max_length=20)
    target: str = Field(
        min_length=1,
        max_length=253,
        description="Target identifier from the run's scope (hostname, IP, account id).",
    )
    destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL
    dry_run: bool = True
    parameters: tuple[tuple[str, str], ...] = Field(default_factory=tuple)


class ExecutionResult(BaseModel):
    """The result of a single emulation request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: UUID
    backend: EmulationBackend
    technique_id: str
    target: str
    started_at: datetime
    finished_at: datetime
    outcome: ExecutionOutcome
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artefacts: tuple[str, ...] = Field(
        default_factory=tuple,
        description="URIs / paths to artefacts produced by the test (logs, evidence).",
    )
    error: str | None = None

    @field_validator("started_at", "finished_at")
    @classmethod
    def _ensure_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return v

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class EmulationAdapter(ABC):
    """Adapter for a specific emulation backend.

    Implementations declare which :class:`EmulationBackend` they handle and
    expose a single :meth:`execute` method. Adapters MUST honour
    ``request.dry_run``: when true they must not run any payload that
    modifies system state.
    """

    @property
    @abstractmethod
    def backend(self) -> EmulationBackend:
        """The backend this adapter implements."""

    @abstractmethod
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a single request and return a typed result."""

    def supports(self, backend: EmulationBackend) -> bool:
        return backend == self.backend
