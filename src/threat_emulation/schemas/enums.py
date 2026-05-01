"""Enumerations used across the canonical schemas."""

from __future__ import annotations

from enum import StrEnum


class TLP(StrEnum):
    """Traffic Light Protocol 2.0 classifications.

    Routed at the retriever boundary: AMBER+ never leaves the framework via
    third-party APIs (embeddings or LLMs).
    """

    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"

    @property
    def restricted(self) -> bool:
        """True when content must not egress to third-party APIs."""
        return self in {TLP.AMBER, TLP.AMBER_STRICT, TLP.RED}


class ConfidenceLevel(StrEnum):
    """Admiralty-style confidence used by CTI normalisers."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceTier(StrEnum):
    """Trust tier applied by the prioritisation engine.

    Higher tiers carry more weight when a technique is corroborated by multiple
    sources. Configured per-deployment in ``config/sources.yaml``.
    """

    GOVERNMENT = "government"
    VENDOR = "vendor"
    COMMUNITY = "community"
    INTERNAL = "internal"
    OPEN_BLOG = "open_blog"


class DestructivenessTier(StrEnum):
    """Tiering for emulation tests.

    ``DESTRUCTIVE`` requires 2-person integrity approval; ``INTRUSIVE`` requires
    a single signed approval; ``OBSERVATIONAL`` may run after pre-flight checks.
    """

    OBSERVATIONAL = "observational"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


class EmulationBackend(StrEnum):
    """Emulation adapters available to the executor."""

    ATOMIC_RED_TEAM = "atomic_red_team"
    STRATUS_RED_TEAM = "stratus_red_team"
    CALDERA = "caldera"


class RunPhase(StrEnum):
    """Lifecycle phases of an emulation run."""

    PLANNING = "planning"
    PROVISIONING = "provisioning"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    REPORTING = "reporting"
    TEARDOWN = "teardown"
    COMPLETED = "completed"
    KILLED = "killed"
    FAILED = "failed"
