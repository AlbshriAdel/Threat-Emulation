"""Vagrant Windows VM provisioner (stub).

Real implementation provisions a per-run Vagrant VM with EDR / Sysmon /
Wazuh pre-baked. Phase 3 ships this as a stub that surfaces a clear
:class:`ProvisioningError` so callers can fall back to the in-memory
provisioner in CI.
"""

from __future__ import annotations

from uuid import UUID

from threat_emulation.lab.provisioner import (
    LabHandle,
    LabProvisioner,
    ProvisioningError,
)
from threat_emulation.schemas import Scope


class VagrantProvisioner(LabProvisioner):
    name = "vagrant-windows"

    def __init__(self, *, available: bool = False) -> None:
        self._available = available

    def provision(self, *, run_id: UUID, scope: Scope) -> LabHandle:
        if not self._available:
            raise ProvisioningError("VagrantProvisioner not yet implemented")
        return LabHandle(
            run_id=run_id,
            provisioner=self.name,
            targets=scope.targets_hostnames or (f"vagrant://{run_id}/win",),
            egress_allowed=scope.egress_allowed,
        )

    def teardown(self, handle: LabHandle) -> None:
        if not self._available:
            return None
        return None

    def list_resources(self, handle: LabHandle) -> tuple[str, ...]:
        return ()
