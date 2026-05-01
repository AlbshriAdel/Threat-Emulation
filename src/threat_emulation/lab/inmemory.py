"""In-memory lab provisioner.

Simulates the full lifecycle (provision -> targets -> teardown -> verified)
without allocating any real infrastructure. Used by tests, the eval harness,
and CI smoke tests. The targets it returns are derived directly from
``Scope`` so the executor can plumb them through to adapters identically to
the real provisioners.
"""

from __future__ import annotations

from uuid import UUID

from threat_emulation.lab.provisioner import (
    LabHandle,
    LabProvisioner,
    ProvisioningError,
)
from threat_emulation.schemas import Scope


class InMemoryProvisioner(LabProvisioner):
    """A no-op provisioner that records lifecycle state in memory."""

    name = "in-memory"

    def __init__(self) -> None:
        self._resources: dict[UUID, set[str]] = {}

    def provision(self, *, run_id: UUID, scope: Scope) -> LabHandle:
        targets = self._targets_from_scope(scope)
        if not targets:
            raise ProvisioningError("Scope must declare at least one target for the in-memory lab")
        # Allocate one synthetic resource id per target.
        self._resources[run_id] = {f"inmemory://{run_id}/{t}" for t in targets}
        return LabHandle(
            run_id=run_id,
            provisioner=self.name,
            targets=targets,
            egress_allowed=scope.egress_allowed,
            metadata=(("simulated", "true"),),
        )

    def teardown(self, handle: LabHandle) -> None:
        # Idempotent: drop the run's resources if present.
        self._resources.pop(handle.run_id, None)

    def list_resources(self, handle: LabHandle) -> tuple[str, ...]:
        return tuple(sorted(self._resources.get(handle.run_id, set())))

    @staticmethod
    def _targets_from_scope(scope: Scope) -> tuple[str, ...]:
        targets: list[str] = []
        for cidr in scope.targets_cidr:
            targets.append(str(cidr))
        targets.extend(scope.targets_hostnames)
        targets.extend(scope.cloud_account_ids)
        return tuple(targets)
