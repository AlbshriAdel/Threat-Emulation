"""Tests for the RBAC primitives."""

from __future__ import annotations

import pytest

from threat_emulation.auth.rbac import (
    DEFAULT_ROLE_PERMISSIONS,
    Permission,
    Principal,
    Role,
)


def _principal(*roles: Role) -> Principal:
    return Principal(subject="oidc|alice", roles=frozenset(roles))


def test_default_matrix_assigns_run_intrusive_to_operator() -> None:
    assert Permission.RUN_INTRUSIVE in DEFAULT_ROLE_PERMISSIONS[Role.OPERATOR]


def test_default_matrix_does_not_grant_destructive_to_operator() -> None:
    assert Permission.RUN_DESTRUCTIVE not in DEFAULT_ROLE_PERMISSIONS[Role.OPERATOR]


def test_admin_carries_all_permissions() -> None:
    admin_perms = DEFAULT_ROLE_PERMISSIONS[Role.ADMIN]
    for perm in Permission:
        assert perm in admin_perms


def test_principal_aggregates_permissions_across_roles() -> None:
    p = _principal(Role.OPERATOR, Role.AUDITOR)
    assert p.has(Permission.RUN_INTRUSIVE)
    assert p.has(Permission.READ_AUDIT)
    assert not p.has(Permission.APPROVE_DESTRUCTIVE)


def test_principal_require_raises_on_missing() -> None:
    p = _principal(Role.OPERATOR)
    p.require(Permission.RUN_INTRUSIVE)
    with pytest.raises(PermissionError, match="lacks permission"):
        p.require(Permission.APPROVE_DESTRUCTIVE)


def test_principal_can_use_custom_matrix() -> None:
    custom = {Role.OPERATOR: frozenset({Permission.RUN_DESTRUCTIVE})}
    p = _principal(Role.OPERATOR)
    assert p.has(Permission.RUN_DESTRUCTIVE, matrix=custom) is True
    # Default matrix doesn't grant destructive to operator.
    assert p.has(Permission.RUN_DESTRUCTIVE) is False


def test_principal_rejects_extra_fields() -> None:
    with pytest.raises(ValueError):
        Principal(subject="x", roles=frozenset(), bogus="y")  # type: ignore[call-arg]
