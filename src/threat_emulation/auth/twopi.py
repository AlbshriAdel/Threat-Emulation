"""Two-person-integrity gate.

An :class:`ApprovalToken` is a JWT that binds an approver's OIDC subject to a
specific ``(campaign_hash, scope_hash, tier)`` tuple. The
:class:`TwoPersonIntegrity` gate counts *distinct* valid approvals for a
target tier and refuses to clear when the count is below the policy
threshold.

Per CLAUDE.md hard rule 2: destructive tier requires two distinct approvers
with the ``approve.destructive`` permission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from threat_emulation.auth.jwt import JwtError, decode_jwt, encode_jwt
from threat_emulation.auth.rbac import (
    DEFAULT_ROLE_PERMISSIONS,
    Permission,
    Principal,
    Role,
)
from threat_emulation.guardrails.policy import ApprovalRequirements
from threat_emulation.schemas.enums import DestructivenessTier

_TIER_PERMISSION: dict[DestructivenessTier, Permission] = {
    DestructivenessTier.OBSERVATIONAL: Permission.RUN_OBSERVATIONAL,
    DestructivenessTier.INTRUSIVE: Permission.APPROVE_INTRUSIVE,
    DestructivenessTier.DESTRUCTIVE: Permission.APPROVE_DESTRUCTIVE,
}


@dataclass(frozen=True)
class ApprovalToken:
    """A JWT-encoded approval signed by the approver's OIDC-bound key."""

    jwt: str

    @classmethod
    def issue(
        cls,
        *,
        approver: Principal,
        tier: DestructivenessTier,
        campaign_hash: str,
        scope_hash: str,
        key: bytes,
        expires_in_seconds: int = 3600,
    ) -> ApprovalToken:
        token = encode_jwt(
            {
                "sub": approver.subject,
                "roles": sorted(r.value for r in approver.roles),
                "tier": tier.value,
                "campaign_hash": campaign_hash,
                "scope_hash": scope_hash,
            },
            key=key,
            expires_in_seconds=expires_in_seconds,
        )
        return cls(jwt=token)

    def claims(self, *, key: bytes) -> dict[str, Any]:
        return decode_jwt(self.jwt, key=key)


@dataclass(frozen=True)
class ApprovalDecision:
    """Outcome of the 2PI gate."""

    granted: bool
    tier: DestructivenessTier
    distinct_approvers: tuple[str, ...]
    reason: str = ""

    def __bool__(self) -> bool:
        return self.granted


class TwoPersonIntegrity:
    """Evaluate whether a candidate run has sufficient approvals.

    Args:
        requirements: Per-tier minimum approver counts (from the policy).
        verification_key: Symmetric key used to verify approval JWTs. In
            production this is the OIDC provider's signing key (Ed25519 /
            RS256); the gate is algorithm-agnostic from the caller's POV.
        role_matrix: Permission matrix used to verify each approver carries
            the right ``approve.*`` permission for the tier.
    """

    def __init__(
        self,
        *,
        requirements: ApprovalRequirements,
        verification_key: bytes,
        role_matrix: dict[Role, frozenset[Permission]] | None = None,
    ) -> None:
        if not verification_key:
            raise ValueError("verification_key must be non-empty")
        self._req = requirements
        self._key = verification_key
        self._matrix = role_matrix or DEFAULT_ROLE_PERMISSIONS

    def evaluate(
        self,
        *,
        tier: DestructivenessTier,
        campaign_hash: str,
        scope_hash: str,
        approvals: tuple[ApprovalToken, ...],
    ) -> ApprovalDecision:
        required = self._req.required_for(tier)
        if required == 0:
            return ApprovalDecision(
                granted=True, tier=tier, distinct_approvers=(), reason="no approvals required"
            )

        permission_for_tier = _TIER_PERMISSION[tier]
        seen: set[str] = set()
        for token in approvals:
            try:
                claims = token.claims(key=self._key)
            except JwtError:
                continue
            if claims.get("tier") != tier.value:
                continue
            if claims.get("campaign_hash") != campaign_hash:
                continue
            if claims.get("scope_hash") != scope_hash:
                continue
            subject = claims.get("sub")
            if not isinstance(subject, str):
                continue
            roles_raw = claims.get("roles", [])
            try:
                roles = frozenset(Role(r) for r in roles_raw)
            except ValueError:
                continue
            principal = Principal(subject=subject, roles=roles)
            if not principal.has(permission_for_tier, matrix=self._matrix):
                continue
            seen.add(subject)

        granted = len(seen) >= required
        return ApprovalDecision(
            granted=granted,
            tier=tier,
            distinct_approvers=tuple(sorted(seen)),
            reason=(
                f"{len(seen)} distinct approver(s) with {permission_for_tier.value}; "
                f"required {required}"
            ),
        )
