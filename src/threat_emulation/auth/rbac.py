"""Role / permission matrix and OIDC-bound principals."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    """Roles assignable via OIDC group claims."""

    OPERATOR = "operator"
    APPROVER = "approver"
    AUDITOR = "auditor"
    ADMIN = "admin"


class Permission(StrEnum):
    """Atomic permissions checked at the API boundary."""

    RUN_OBSERVATIONAL = "run.observational"
    RUN_INTRUSIVE = "run.intrusive"
    RUN_DESTRUCTIVE = "run.destructive"
    APPROVE_INTRUSIVE = "approve.intrusive"
    APPROVE_DESTRUCTIVE = "approve.destructive"
    READ_AUDIT = "audit.read"
    KILL_RUN = "kill.run"
    MANAGE_POLICY = "policy.manage"


# Default permission matrix. Production deployments override per-org.
DEFAULT_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OPERATOR: frozenset(
        {
            Permission.RUN_OBSERVATIONAL,
            Permission.RUN_INTRUSIVE,
            Permission.KILL_RUN,
        }
    ),
    Role.APPROVER: frozenset(
        {
            Permission.APPROVE_INTRUSIVE,
            Permission.APPROVE_DESTRUCTIVE,
        }
    ),
    Role.AUDITOR: frozenset({Permission.READ_AUDIT}),
    Role.ADMIN: frozenset(
        {
            Permission.RUN_OBSERVATIONAL,
            Permission.RUN_INTRUSIVE,
            Permission.RUN_DESTRUCTIVE,
            Permission.APPROVE_INTRUSIVE,
            Permission.APPROVE_DESTRUCTIVE,
            Permission.READ_AUDIT,
            Permission.KILL_RUN,
            Permission.MANAGE_POLICY,
        }
    ),
}


class Principal(BaseModel):
    """An authenticated identity bound to an OIDC subject.

    The ``subject`` is the canonical identifier embedded in audit events;
    ``email`` is informational only and must not be used for authorization.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str = Field(min_length=1, max_length=255)
    email: str | None = Field(default=None, max_length=320)
    roles: frozenset[Role] = Field(default_factory=frozenset)

    def permissions(
        self,
        *,
        matrix: dict[Role, frozenset[Permission]] | None = None,
    ) -> frozenset[Permission]:
        m = matrix or DEFAULT_ROLE_PERMISSIONS
        result: set[Permission] = set()
        for role in self.roles:
            result |= m.get(role, frozenset())
        return frozenset(result)

    def has(
        self,
        permission: Permission,
        *,
        matrix: dict[Role, frozenset[Permission]] | None = None,
    ) -> bool:
        return permission in self.permissions(matrix=matrix)

    def require(
        self,
        permission: Permission,
        *,
        matrix: dict[Role, frozenset[Permission]] | None = None,
    ) -> None:
        if not self.has(permission, matrix=matrix):
            raise PermissionError(f"principal {self.subject!r} lacks permission {permission.value}")
