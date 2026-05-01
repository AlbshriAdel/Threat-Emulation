"""Ephemeral lab provisioning.

A :class:`LabProvisioner` creates an isolated, deny-by-default-egress lab
per ``run_id`` and tears it down on completion. Three implementations:

* :class:`InMemoryProvisioner` - simulated lab used by tests, the eval
  harness, and CI. No real resources allocated.
* :class:`DockerProvisioner` - Kata-isolated Docker containers (stub in
  Phase 3; real implementation lands in Phase 3.5 alongside the
  docker-compose lab manifest).
* :class:`VagrantProvisioner` - Vagrant Windows VM (stub).

The :class:`TeardownVerifier` checks that no resources from a torn-down lab
remain. Per CLAUDE.md hard rules, an unverified teardown fails the run.
"""

from threat_emulation.lab.docker import DockerProvisioner
from threat_emulation.lab.inmemory import InMemoryProvisioner
from threat_emulation.lab.provisioner import (
    LabHandle,
    LabProvisioner,
    ProvisioningError,
)
from threat_emulation.lab.teardown import TeardownReport, TeardownVerifier
from threat_emulation.lab.vagrant import VagrantProvisioner

__all__ = [
    "DockerProvisioner",
    "InMemoryProvisioner",
    "LabHandle",
    "LabProvisioner",
    "ProvisioningError",
    "TeardownReport",
    "TeardownVerifier",
    "VagrantProvisioner",
]
