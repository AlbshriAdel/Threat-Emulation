"""Docker / Kata-isolated container provisioner (stub).

Real implementation lands alongside ``infra/docker-compose.lab.yml`` in
Phase 3.5. The stub raises :class:`ProvisioningError` so callers can detect
that the backend is unavailable and fall back to the in-memory provisioner.
"""

from __future__ import annotations

from uuid import UUID

from threat_emulation.lab.provisioner import (
    LabHandle,
    LabProvisioner,
    ProvisioningError,
)
from threat_emulation.schemas import Scope


class DockerProvisioner(LabProvisioner):
    name = "docker-kata"

    def __init__(self, *, available: bool = False) -> None:
        # ``available=False`` keeps this strictly a stub for now; flip to
        # True once the docker-compose lab lands. Tests can construct with
        # available=True to exercise the placeholder happy-path.
        self._available = available

    def provision(self, *, run_id: UUID, scope: Scope) -> LabHandle:
        if not self._available:
            raise ProvisioningError("DockerProvisioner not yet implemented")
        targets = (*scope.targets_hostnames, *(str(c) for c in scope.targets_cidr))
        return LabHandle(
            run_id=run_id,
            provisioner=self.name,
            targets=targets or (f"docker://{run_id}",),
            egress_allowed=scope.egress_allowed,
        )

    def teardown(self, handle: LabHandle) -> None:
        if not self._available:
            return None
        # Real implementation will `docker compose down` for the run.
        return None

    def list_resources(self, handle: LabHandle) -> tuple[str, ...]:
        return ()
