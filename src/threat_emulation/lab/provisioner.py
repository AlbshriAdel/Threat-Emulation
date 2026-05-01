"""Abstract lab provisioner."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from uuid import UUID

from threat_emulation.schemas import Scope


class ProvisioningError(RuntimeError):
    """Raised when the lab cannot be provisioned (out-of-scope, infra failure)."""


@dataclass(frozen=True)
class LabHandle:
    """Opaque handle to a provisioned lab.

    The handle is immutable and is the *only* way the executor talks to the
    lab. ``targets`` are the in-lab identifiers (hostnames / container ids /
    cloud account ids) reachable from the executor. ``egress_allowed`` is
    enforced as ``False`` unless the scope explicitly grants egress.
    """

    run_id: UUID
    provisioner: str
    targets: tuple[str, ...]
    egress_allowed: bool = False
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.targets:
            raise ProvisioningError("LabHandle requires at least one target")


class LabProvisioner(ABC):
    """Provision and tear down an ephemeral lab per run."""

    name: str = "abstract"

    @abstractmethod
    def provision(self, *, run_id: UUID, scope: Scope) -> LabHandle:
        """Bring the lab up; return a :class:`LabHandle`.

        Raises :class:`ProvisioningError` if the scope is empty or the
        underlying infra cannot honour the request.
        """

    @abstractmethod
    def teardown(self, handle: LabHandle) -> None:
        """Tear the lab down. Idempotent.

        Implementations must not raise if the lab is already gone; they may
        raise if teardown fails partway, in which case the
        :class:`TeardownVerifier` will catch residual resources.
        """

    @abstractmethod
    def list_resources(self, handle: LabHandle) -> tuple[str, ...]:
        """Return the resource identifiers currently allocated for ``handle``.

        Returning an empty tuple after :meth:`teardown` is the contract that
        :class:`~threat_emulation.lab.TeardownVerifier` checks.
        """
