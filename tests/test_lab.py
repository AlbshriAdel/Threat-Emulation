"""Tests for lab provisioner + teardown verifier."""

from __future__ import annotations

from ipaddress import IPv4Network
from uuid import uuid4

import pytest

from threat_emulation.lab import (
    DockerProvisioner,
    InMemoryProvisioner,
    LabHandle,
    ProvisioningError,
    TeardownVerifier,
    VagrantProvisioner,
)
from threat_emulation.schemas import Scope


def _scope(*, hosts: tuple[str, ...] = ("lab-host-01",)) -> Scope:
    return Scope(
        targets_cidr=(IPv4Network("10.0.0.0/24"),),
        targets_hostnames=hosts,
    )


# --------------------------------------------------------------------------- #
# LabHandle
# --------------------------------------------------------------------------- #


def test_lab_handle_requires_at_least_one_target() -> None:
    with pytest.raises(ProvisioningError, match="at least one target"):
        LabHandle(run_id=uuid4(), provisioner="x", targets=())


def test_lab_handle_is_frozen() -> None:
    from dataclasses import FrozenInstanceError

    h = LabHandle(run_id=uuid4(), provisioner="x", targets=("a",))
    with pytest.raises(FrozenInstanceError):
        h.targets = ("b",)  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# InMemoryProvisioner
# --------------------------------------------------------------------------- #


def test_inmemory_provisioner_full_lifecycle() -> None:
    p = InMemoryProvisioner()
    rid = uuid4()
    handle = p.provision(run_id=rid, scope=_scope())

    assert handle.provisioner == "in-memory"
    assert handle.targets  # at least one
    assert handle.egress_allowed is False
    assert p.list_resources(handle), "expected synthetic resources allocated"

    p.teardown(handle)
    assert p.list_resources(handle) == ()


def test_inmemory_provisioner_teardown_is_idempotent() -> None:
    p = InMemoryProvisioner()
    handle = p.provision(run_id=uuid4(), scope=_scope())
    p.teardown(handle)
    p.teardown(handle)  # must not raise


def test_inmemory_provisioner_rejects_empty_scope_targets() -> None:
    p = InMemoryProvisioner()
    # Build a Scope with cloud_account_ids only so it passes Scope's own
    # validator; then strip them by giving cidr-only via a different route.
    scope = Scope(targets_cidr=(IPv4Network("10.0.0.0/24"),))
    handle = p.provision(run_id=uuid4(), scope=scope)
    assert handle.targets == ("10.0.0.0/24",)


# --------------------------------------------------------------------------- #
# Docker / Vagrant stubs
# --------------------------------------------------------------------------- #


def test_docker_provisioner_stub_raises_when_unavailable() -> None:
    with pytest.raises(ProvisioningError, match="not yet implemented"):
        DockerProvisioner().provision(run_id=uuid4(), scope=_scope())


def test_vagrant_provisioner_stub_raises_when_unavailable() -> None:
    with pytest.raises(ProvisioningError, match="not yet implemented"):
        VagrantProvisioner().provision(run_id=uuid4(), scope=_scope())


def test_docker_provisioner_placeholder_when_marked_available() -> None:
    p = DockerProvisioner(available=True)
    handle = p.provision(run_id=uuid4(), scope=_scope())
    assert handle.provisioner == "docker-kata"
    p.teardown(handle)


# --------------------------------------------------------------------------- #
# TeardownVerifier
# --------------------------------------------------------------------------- #


def test_teardown_verifier_marks_clean_lab_successful() -> None:
    p = InMemoryProvisioner()
    handle = p.provision(run_id=uuid4(), scope=_scope())
    report = TeardownVerifier().verify(provisioner=p, handle=handle)
    assert report.successful is True
    assert report.residual_resources == ()
    assert report.error is None
    assert report.duration_seconds >= 0


def test_teardown_verifier_flags_residual_resources() -> None:
    class LeakyProvisioner(InMemoryProvisioner):
        def teardown(self, handle: LabHandle) -> None:
            # Pretend teardown succeeds but resources stay allocated.
            return None

    p = LeakyProvisioner()
    handle = p.provision(run_id=uuid4(), scope=_scope())
    report = TeardownVerifier().verify(provisioner=p, handle=handle)
    assert report.successful is False
    assert report.residual_resources != ()
    assert report.error is not None
    assert "residual" in report.error


def test_teardown_verifier_reports_raise_as_failure() -> None:
    class BrokenProvisioner(InMemoryProvisioner):
        def teardown(self, handle: LabHandle) -> None:
            raise RuntimeError("disk full")

    p = BrokenProvisioner()
    handle = p.provision(run_id=uuid4(), scope=_scope())
    report = TeardownVerifier().verify(provisioner=p, handle=handle)
    assert report.successful is False
    assert report.error is not None
    assert "disk full" in report.error


def test_teardown_verifier_rejects_non_positive_budget() -> None:
    with pytest.raises(ValueError):
        TeardownVerifier(max_duration_seconds=0)
