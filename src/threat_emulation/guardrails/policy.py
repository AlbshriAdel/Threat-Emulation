"""Pydantic policy DSL.

A :class:`Policy` is the versioned, content-hashed, optionally-signed
declaration of what's allowed in a deployment. Per ADR-0001 D7 we
intentionally avoid OPA/Rego here: a small Pydantic surface keeps policies
greppable, type-checkable, and audit-hashable without a second runtime.

Policies declare four areas:

* :class:`ScopeConstraints` - upper bound on what a run's scope may request.
* :class:`EgressPolicy` - default-deny; per-protocol exceptions allowed only
  via signed policy diffs.
* :class:`ApprovalRequirements` - minimum number of distinct approvers per
  destructiveness tier (the 2-person-integrity baseline).
* :class:`TlpRoutingPolicy` - which TLP levels may use a third-party LLM /
  embedder (CLAUDE.md hard rule 4).

A loaded policy carries a SHA-256 ``content_hash`` (computed over the
canonical JSON sans the ``signature`` field) so audit events can bind to it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from threat_emulation.schemas.enums import (
    TLP,
    DestructivenessTier,
    EmulationBackend,
)


class PolicyViolation(RuntimeError):  # noqa: N818 - canonical name per CLAUDE.md
    """Raised when a runtime decision violates a loaded policy."""


# --------------------------------------------------------------------------- #
# Sub-models
# --------------------------------------------------------------------------- #


class ScopeConstraints(BaseModel):
    """Upper bound the policy places on any run's scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL
    allowed_backends: frozenset[EmulationBackend] = Field(
        default_factory=lambda: frozenset({EmulationBackend.ATOMIC_RED_TEAM})
    )
    require_test_allowlist: bool = True


class EgressPolicy(BaseModel):
    """Egress containment policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    default_deny: bool = True
    allowed_protocols: frozenset[str] = Field(default_factory=frozenset)
    require_c2_sink: bool = True


class ApprovalRequirements(BaseModel):
    """Minimum distinct approvers per destructiveness tier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observational: int = Field(default=0, ge=0, le=10)
    intrusive: int = Field(default=1, ge=0, le=10)
    destructive: int = Field(default=2, ge=0, le=10)

    def required_for(self, tier: DestructivenessTier) -> int:
        return {
            DestructivenessTier.OBSERVATIONAL: self.observational,
            DestructivenessTier.INTRUSIVE: self.intrusive,
            DestructivenessTier.DESTRUCTIVE: self.destructive,
        }[tier]

    @model_validator(mode="after")
    def _monotonic(self) -> ApprovalRequirements:
        if not (self.observational <= self.intrusive <= self.destructive):
            raise ValueError(
                "approval requirements must be monotonic: observational <= intrusive <= destructive"
            )
        return self


class TlpRoutingPolicy(BaseModel):
    """TLP routing policy.

    ``cloud_allowed`` lists TLP levels permitted to call third-party APIs
    (LLM / embedder). The default forbids AMBER+ from leaving the framework.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    cloud_allowed: frozenset[TLP] = Field(default_factory=lambda: frozenset({TLP.CLEAR, TLP.GREEN}))

    @model_validator(mode="after")
    def _no_amber_in_cloud(self) -> TlpRoutingPolicy:
        forbidden = {TLP.AMBER, TLP.AMBER_STRICT, TLP.RED}
        violating = self.cloud_allowed & forbidden
        if violating:
            raise ValueError(
                "TLP routing policy must not allow AMBER+ to cloud APIs "
                f"(got {sorted(t.value for t in violating)})"
            )
        return self


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


class Policy(BaseModel):
    """A versioned, content-hashed guardrail policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=200)
    version: int = Field(ge=1)
    issued_at: datetime
    scope_constraints: ScopeConstraints = Field(default_factory=ScopeConstraints)
    egress: EgressPolicy = Field(default_factory=EgressPolicy)
    approvals: ApprovalRequirements = Field(default_factory=ApprovalRequirements)
    tlp: TlpRoutingPolicy = Field(default_factory=TlpRoutingPolicy)
    signature: str | None = Field(
        default=None,
        description="Detached HMAC/Ed25519 signature over content_hash().",
    )

    @field_validator("issued_at")
    @classmethod
    def _ensure_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("issued_at must be timezone-aware")
        return v

    # ------------------------------------------------------------------ #
    # Hashing + signing
    # ------------------------------------------------------------------ #

    def canonical_json(self) -> str:
        """JSON encoding used for content hashing.

        Excludes the ``signature`` field so signing is deterministic.
        """
        payload: dict[str, Any] = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def content_hash(self) -> str:
        """SHA-256 hex over the canonical (signature-free) JSON."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def sign(self, *, key: bytes) -> Policy:
        """Return a copy with ``signature`` set to HMAC-SHA256 over the hash."""
        if not key:
            raise ValueError("signing key must be non-empty")
        sig = hmac.new(key, self.content_hash().encode("ascii"), hashlib.sha256).hexdigest()
        return self.model_copy(update={"signature": sig})

    def verify(self, *, key: bytes) -> bool:
        """Verify the HMAC signature with a constant-time comparison."""
        if self.signature is None:
            return False
        expected = hmac.new(key, self.content_hash().encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)
