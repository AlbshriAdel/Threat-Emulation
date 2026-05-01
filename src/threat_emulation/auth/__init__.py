"""OIDC + RBAC + 2-person-integrity layer.

Three pieces:

* :mod:`rbac` - role / permission matrix, :class:`Principal` carrying an
  OIDC subject and assigned roles.
* :mod:`jwt` - minimal HMAC-SHA256 JWT sign/verify (no external dep).
  Production deployments swap in ``python-jose`` or ``authlib``; the
  interface is stable.
* :mod:`twopi` - the 2-person-integrity gate. Approval tokens are JWTs
  binding ``(campaign_hash, scope_hash, tier)`` to an approver.
"""

from threat_emulation.auth.jwt import (
    JwtError,
    decode_jwt,
    encode_jwt,
)
from threat_emulation.auth.rbac import (
    DEFAULT_ROLE_PERMISSIONS,
    Permission,
    Principal,
    Role,
)
from threat_emulation.auth.twopi import (
    ApprovalDecision,
    ApprovalToken,
    TwoPersonIntegrity,
)

__all__ = [
    "DEFAULT_ROLE_PERMISSIONS",
    "ApprovalDecision",
    "ApprovalToken",
    "JwtError",
    "Permission",
    "Principal",
    "Role",
    "TwoPersonIntegrity",
    "decode_jwt",
    "encode_jwt",
]
