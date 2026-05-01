"""Canonical Pydantic models for Threat-Emulation.

Design principles
-----------------
* Every public boundary uses these models. Vendor formats (STIX, KEV, vendor
  PDFs) are normalised into these structures by ``intel/normalizers``.
* Models are immutable where reasonable (``model_config = ConfigDict(frozen=True)``)
  to keep audit hashes stable.
* All identifiers are explicit (UUIDs or namespaced strings); no implicit
  database row-ids leak across modules.
* Anything that crosses the egress boundary carries a ``TLP`` and a
  ``Source``; the retriever and audit layers refuse to operate on objects
  missing this provenance.
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

from threat_emulation.schemas.enums import (
    TLP,
    ConfidenceLevel,
    DestructivenessTier,
    EmulationBackend,
    RunPhase,
    SourceTier,
)

# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #

# MITRE ATT&CK technique IDs: T1059, T1059.001, etc.
TechniqueId = Annotated[
    str,
    Field(
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="MITRE ATT&CK technique ID (e.g. T1059 or T1059.001)",
    ),
]

# MITRE ATT&CK group ID: G0016 (APT29), etc.
GroupId = Annotated[
    str,
    Field(
        pattern=r"^G\d{4}$",
        description="MITRE ATT&CK group ID (e.g. G0016)",
    ),
]


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Source / Provenance
# --------------------------------------------------------------------------- #


class Source(BaseModel):
    """An ingested intelligence source.

    Used as provenance on every retrieved chunk. The ``tier`` and ``tlp`` fields
    drive both prioritisation weighting and egress policy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=200)
    tier: SourceTier
    tlp: TLP = TLP.CLEAR
    url: HttpUrl | None = None
    published_at: datetime | None = None
    license: str | None = Field(
        default=None,
        description="Source license / redistribution terms (e.g. CC-BY-4.0).",
    )

    @field_validator("published_at")
    @classmethod
    def _ensure_tz(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("published_at must be timezone-aware")
        return v


# --------------------------------------------------------------------------- #
# TTP / Indicator / Actor
# --------------------------------------------------------------------------- #


class TTP(BaseModel):
    """A normalised MITRE ATT&CK Tactic-Technique-Procedure observation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: TechniqueId
    name: str = Field(min_length=1, max_length=200)
    tactic: str = Field(min_length=1, description="ATT&CK tactic, e.g. 'execution'")
    description: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    sources: tuple[Source, ...] = Field(default_factory=tuple)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @model_validator(mode="after")
    def _check_seen_order(self) -> TTP:
        if self.first_seen and self.last_seen and self.first_seen > self.last_seen:
            raise ValueError("first_seen must be <= last_seen")
        return self


class Indicator(BaseModel):
    """An IoC bound to a TTP and source."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    type: Literal["ipv4", "ipv6", "domain", "url", "sha256", "md5", "filename"]
    value: str = Field(min_length=1, max_length=2048)
    tlp: TLP = TLP.CLEAR
    sources: tuple[Source, ...] = Field(default_factory=tuple)
    associated_ttps: tuple[TechniqueId, ...] = Field(default_factory=tuple)


class Actor(BaseModel):
    """A threat actor / intrusion set with alias reconciliation.

    The ``aliases`` field is the source of truth for vendor-naming chaos
    (APT29 / Cozy Bear / Midnight Blizzard / Nobelium / UNC2452).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    primary_name: str = Field(min_length=1, max_length=200)
    attack_group_id: GroupId | None = None
    aliases: frozenset[str] = Field(default_factory=frozenset)
    sectors_targeted: tuple[str, ...] = Field(default_factory=tuple)
    countries_targeted: tuple[str, ...] = Field(
        default_factory=tuple,
        description="ISO 3166-1 alpha-2 country codes",
    )
    techniques: tuple[TechniqueId, ...] = Field(default_factory=tuple)
    sources: tuple[Source, ...] = Field(default_factory=tuple)


# --------------------------------------------------------------------------- #
# Scope / Scope-of-Engagement
# --------------------------------------------------------------------------- #


class Scope(BaseModel):
    """The targets and tests permitted for a run.

    Enforced by ``guardrails.preflight``: any out-of-scope target or
    not-allowlisted test triggers a ``PolicyViolation`` *before* the lab is
    provisioned.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    targets_cidr: tuple[IPv4Network | IPv6Network, ...] = Field(default_factory=tuple)
    targets_hostnames: tuple[str, ...] = Field(default_factory=tuple)
    cloud_account_ids: tuple[str, ...] = Field(default_factory=tuple)
    test_allowlist: frozenset[str] = Field(
        default_factory=frozenset,
        description="Allowed test identifiers (e.g. ART GUIDs, Stratus attack IDs).",
    )
    max_destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL
    egress_allowed: bool = False

    @model_validator(mode="after")
    def _at_least_one_target(self) -> Scope:
        if not self.targets_cidr and not self.targets_hostnames and not self.cloud_account_ids:
            raise ValueError(
                "Scope must declare at least one target (cidr, hostname, or cloud account)"
            )
        return self


class ScopeOfEngagement(BaseModel):
    """Signed scope-of-engagement document.

    Hard requirement: every run binds to a ScopeOfEngagement; its hash is
    embedded in every audit event for chain-of-custody.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    organization: str = Field(min_length=1, max_length=200)
    authorized_by: str = Field(min_length=1, max_length=200)
    valid_from: datetime
    valid_until: datetime
    scope: Scope
    signature: str = Field(
        min_length=1,
        description="Detached cryptographic signature over the canonical JSON form.",
    )
    signature_algorithm: Literal["ed25519", "ecdsa-p256", "rsa-pss-sha256"] = "ed25519"

    @model_validator(mode="after")
    def _check_validity_window(self) -> ScopeOfEngagement:
        if self.valid_from >= self.valid_until:
            raise ValueError("valid_from must be earlier than valid_until")
        if self.valid_from.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("valid_from / valid_until must be timezone-aware")
        return self

    def is_active(self, at: datetime | None = None) -> bool:
        """Whether the engagement window covers ``at`` (default: now, UTC)."""
        moment = at or _utcnow()
        if moment.tzinfo is None:
            raise ValueError("'at' must be timezone-aware")
        return self.valid_from <= moment <= self.valid_until


# --------------------------------------------------------------------------- #
# Campaign — the unit of emulation
# --------------------------------------------------------------------------- #


class CampaignStep(BaseModel):
    """A single ordered step in a campaign chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    order: int = Field(ge=0)
    technique_id: TechniqueId
    backend: EmulationBackend
    test_id: str = Field(min_length=1, description="Backend-specific test identifier.")
    destructiveness: DestructivenessTier = DestructivenessTier.OBSERVATIONAL
    rationale: str = Field(
        default="",
        description="Planner's explanation linking this step to retrieved intel.",
    )
    cited_source_ids: tuple[UUID, ...] = Field(default_factory=tuple)


class Campaign(BaseModel):
    """An ordered TTP chain bound to an actor profile and scope.

    The unit of emulation. Atomic tests in isolation are not emulation - a
    Campaign captures adversary-style sequencing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    actor_id: UUID | None = None
    scope_id: UUID
    steps: tuple[CampaignStep, ...] = Field(min_length=1)
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _check_step_ordering(self) -> Campaign:
        orders = [s.order for s in self.steps]
        if orders != sorted(orders):
            raise ValueError("Campaign steps must be supplied in ascending order")
        if len(set(orders)) != len(orders):
            raise ValueError("Campaign step orders must be unique")
        return self

    @property
    def max_destructiveness(self) -> DestructivenessTier:
        """Highest destructiveness tier present in the chain."""
        ranking = {
            DestructivenessTier.OBSERVATIONAL: 0,
            DestructivenessTier.INTRUSIVE: 1,
            DestructivenessTier.DESTRUCTIVE: 2,
        }
        return max(self.steps, key=lambda s: ranking[s.destructiveness]).destructiveness


# --------------------------------------------------------------------------- #
# Run record
# --------------------------------------------------------------------------- #


class RunRecord(BaseModel):
    """The lifecycle record for a single emulation run.

    Mutable across phase transitions but every transition emits an immutable
    AuditEvent. The ``scope_of_engagement_hash`` MUST be present on any
    non-PLANNING phase.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    campaign_id: UUID
    scope_of_engagement_hash: str = Field(
        min_length=1,
        description="SHA-256 hex of the canonical ScopeOfEngagement JSON.",
    )
    phase: RunPhase = RunPhase.PLANNING
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None
    dry_run: bool = True
    operator: str = Field(
        min_length=1,
        description="OIDC subject of the operator who initiated the run.",
    )
    approvers: tuple[str, ...] = Field(
        default_factory=tuple,
        description="OIDC subjects of approvers (>=2 required for destructive).",
    )
    artefacts_uri: AnyUrl | None = None

    @model_validator(mode="after")
    def _check_completion(self) -> RunRecord:
        terminal = {RunPhase.COMPLETED, RunPhase.KILLED, RunPhase.FAILED}
        if self.phase in terminal and self.completed_at is None:
            raise ValueError(f"completed_at required when phase={self.phase.value}")
        if self.phase not in terminal and self.completed_at is not None:
            raise ValueError(f"completed_at must be unset while phase={self.phase.value}")
        return self


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


class AuditEvent(BaseModel):
    """An immutable, Merkle-chainable audit event.

    Every transition, retrieval, tool call, approval, execution, and teardown
    emits one of these. Events are hashed in sequence; the chain is exported
    to a transparency log (Sigstore Rekor) and to WORM storage.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    sequence: int = Field(ge=0, description="Monotonic per-run sequence number.")
    timestamp: datetime = Field(default_factory=_utcnow)
    event_type: str = Field(
        min_length=1,
        max_length=64,
        description="e.g. 'intel.ingest', 'agent.tool_call', 'execution.start'",
    )
    actor: str = Field(min_length=1, description="OIDC subject or 'system'.")
    payload_hash: str = Field(
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 hex of the canonical payload JSON.",
    )
    previous_hash: str = Field(
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 of the previous AuditEvent (genesis = 64 zeros).",
    )
    scope_of_engagement_hash: str = Field(
        pattern=r"^[a-f0-9]{64}$",
        description="Bound scope-of-engagement hash.",
    )
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _ensure_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return v
