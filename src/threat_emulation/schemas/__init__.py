"""Canonical Pydantic schemas shared across the framework.

Every public boundary in the framework speaks these models. Vendor formats
(STIX, KEV, vendor PDFs) are normalised into these structures by the
``intel/normalizers`` layer; everything downstream — RAG, planner, executor,
reporter, audit — only operates on the canonical types defined here.
"""

from threat_emulation.schemas.enums import (
    TLP,
    ConfidenceLevel,
    DestructivenessTier,
    EmulationBackend,
    RunPhase,
    SourceTier,
)
from threat_emulation.schemas.models import (
    TTP,
    Actor,
    AuditEvent,
    Campaign,
    CampaignStep,
    Indicator,
    RunRecord,
    Scope,
    ScopeOfEngagement,
    Source,
)

__all__ = [
    "TLP",
    "TTP",
    "Actor",
    "AuditEvent",
    "Campaign",
    "CampaignStep",
    "ConfidenceLevel",
    "DestructivenessTier",
    "EmulationBackend",
    "Indicator",
    "RunPhase",
    "RunRecord",
    "Scope",
    "ScopeOfEngagement",
    "Source",
    "SourceTier",
]
