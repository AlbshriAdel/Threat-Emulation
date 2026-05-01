"""Vector store abstraction with an in-memory implementation.

The :class:`VectorStore` interface is small on purpose: ``upsert`` + ``search``.
The :class:`InMemoryVectorStore` is used by tests and the dev smoke path.
A Qdrant adapter will live alongside this in Phase 1.5 / Phase 2.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from uuid import UUID

from threat_emulation.rag.chunking import Chunk
from threat_emulation.rag.embedder import Vector


@dataclass(frozen=True)
class VectorRecord:
    """A stored chunk plus its dense vector."""

    chunk: Chunk
    vector: Vector


@dataclass(frozen=True)
class ScoredChunk:
    """A chunk returned by retrieval with a similarity score."""

    chunk: Chunk
    score: float
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)


class VectorStore(ABC):
    """Vector store interface."""

    @abstractmethod
    def upsert(self, records: Iterable[VectorRecord]) -> None:
        """Insert or update records by chunk id."""

    @abstractmethod
    def search(self, query: Vector, *, top_k: int = 10) -> list[ScoredChunk]:
        """Return the ``top_k`` nearest records by cosine similarity."""

    @abstractmethod
    def __len__(self) -> int: ...

    @abstractmethod
    def get(self, chunk_id: UUID) -> Chunk | None: ...


class InMemoryVectorStore(VectorStore):
    """Simple in-memory vector store using cosine similarity."""

    def __init__(self) -> None:
        self._records: dict[UUID, VectorRecord] = {}

    def upsert(self, records: Iterable[VectorRecord]) -> None:
        for record in records:
            self._records[record.chunk.id] = record

    def search(self, query: Vector, *, top_k: int = 10) -> list[ScoredChunk]:
        if top_k <= 0:
            return []
        if not self._records:
            return []
        scored: list[tuple[float, VectorRecord]] = []
        for record in self._records.values():
            score = _cosine(query, record.vector)
            scored.append((score, record))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [ScoredChunk(chunk=record.chunk, score=score) for score, record in scored[:top_k]]

    def get(self, chunk_id: UUID) -> Chunk | None:
        record = self._records.get(chunk_id)
        return record.chunk if record else None

    def __len__(self) -> int:
        return len(self._records)


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b):
        raise ValueError("vector dimensions must match")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)
