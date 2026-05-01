"""Typed Pydantic blackboard for the planner agent.

The blackboard is **immutable**: every tool call returns a *new* state so the
audit log can capture before/after content hashes for the call. This matches
the hard rule from CLAUDE.md that every tool call is persisted with input and
output hashes.

The blackboard intentionally carries small, structured data only - the full
:class:`Chunk` corpus and graph live in the retriever and graph modules, and
the blackboard references them by id where needed.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from threat_emulation.schemas import Scope
from threat_emulation.schemas.enums import TLP

_ZERO = "0" * 64


class RetrievedChunkRef(BaseModel):
    """A reference to a chunk surfaced by the retriever."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: UUID
    source_name: str
    tlp: TLP
    score: float
    signals: frozenset[str] = Field(default_factory=frozenset)
    technique_ids: tuple[str, ...] = Field(default_factory=tuple)
    excerpt: str = Field(default="", max_length=512)


class ScoredTechnique(BaseModel):
    """A candidate technique with the prioritisation score and its components."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str
    tactic: str | None = None
    score: float
    components: tuple[tuple[str, float], ...] = Field(
        default_factory=tuple,
        description="Named score components, e.g. (('cti_freq', 0.4), ...).",
    )
    cited_chunk_ids: tuple[UUID, ...] = Field(default_factory=tuple)
    cited_actors: tuple[str, ...] = Field(default_factory=tuple)


class ToolCallRecord(BaseModel):
    """An audit-grade record of a single tool invocation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=0)
    tool_name: str
    started_at: datetime
    finished_at: datetime
    input_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    error: str | None = None


class BlackboardState(BaseModel):
    """Immutable shared state for the planner tool-use loop."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    brief: str = Field(min_length=1, max_length=8192)
    actor_node: str | None = None
    scope: Scope
    retrieved: tuple[RetrievedChunkRef, ...] = Field(default_factory=tuple)
    candidate_techniques: tuple[str, ...] = Field(default_factory=tuple)
    scored: tuple[ScoredTechnique, ...] = Field(default_factory=tuple)
    proposed_chain: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Ordered technique ids for the proposed Campaign.",
    )
    approval_requested: bool = False
    approval_reason: str = ""
    history: tuple[ToolCallRecord, ...] = Field(default_factory=tuple)

    @property
    def restricted(self) -> bool:
        """True if any retrieved chunk is TLP:AMBER+.

        Used by the LLM client to refuse forwarding restricted material to a
        third-party API.
        """
        return any(r.tlp.restricted for r in self.retrieved)

    def with_updates(self, **changes: Any) -> BlackboardState:
        """Return a new BlackboardState with ``changes`` applied."""
        data = self.model_dump()
        data.update(changes)
        return BlackboardState.model_validate(data)

    def append_history(self, record: ToolCallRecord) -> BlackboardState:
        """Append an audit record to ``history``."""
        return self.with_updates(history=(*self.history, record))


def hash_payload(payload: Any) -> str:
    """Stable SHA-256 hash of an arbitrary JSON-serialisable payload.

    Pydantic models are dumped via ``model_dump_json`` (sort_keys=True). Plain
    objects are coerced via :func:`json.dumps` with ``default=str``.
    """
    import json

    if isinstance(payload, BaseModel):
        encoded = payload.model_dump_json()
    else:
        encoded = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def genesis_hash() -> str:
    """The all-zero hash used as the starting ``previous_hash`` per run."""
    return _ZERO


def utcnow() -> datetime:
    return datetime.now(UTC)
