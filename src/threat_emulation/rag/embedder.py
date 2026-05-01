"""Embedding interface with TLP routing.

Two stacks are supported (per ADR-0001 D3):

* a *cloud* embedder (e.g. Voyage, OpenAI) used for ``TLP:CLEAR`` / ``TLP:GREEN``,
* a *local* embedder (e.g. ``bge-m3`` via sentence-transformers) used for
  ``TLP:AMBER`` and stricter.

The :class:`TlpRoutingEmbedder` enforces this routing **at the embedder
boundary**, not at the retriever, so any caller that wires a single embedder
into the retriever cannot accidentally exfiltrate restricted text.
"""

from __future__ import annotations

import hashlib
import math
from abc import ABC, abstractmethod
from collections.abc import Sequence

from threat_emulation.rag.chunking import Chunk
from threat_emulation.schemas.enums import TLP

Vector = tuple[float, ...]


class Embedder(ABC):
    """Embedder interface."""

    @property
    @abstractmethod
    def dim(self) -> int:
        """The vector dimensionality the embedder produces."""

    @property
    def egress_third_party(self) -> bool:
        """True if calling :meth:`embed` would egress data to a third-party API.

        Concrete cloud embedders (voyage, openai) override this to ``True``.
        Local embedders return ``False``.
        """
        return False

    @abstractmethod
    def embed(self, texts: Sequence[str]) -> list[Vector]:
        """Embed a batch of strings."""

    def embed_chunks(self, chunks: Sequence[Chunk]) -> list[Vector]:
        """Embed a batch of chunks; subclasses do not normally override."""
        return self.embed([c.text for c in chunks])


class DummyEmbedder(Embedder):
    """Deterministic, zero-dependency embedder for tests.

    Produces a normalised vector seeded from a SHA-256 of the input text. Not
    semantically meaningful, but deterministic and dimension-stable, which is
    all unit tests need.
    """

    def __init__(self, dim: int = 32) -> None:
        if dim <= 0:
            raise ValueError("dim must be positive")
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    def embed(self, texts: Sequence[str]) -> list[Vector]:
        return [self._embed_one(t) for t in texts]

    def _embed_one(self, text: str) -> Vector:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        raw = [b - 128 for b in digest]
        repeated = (raw * ((self._dim // len(raw)) + 1))[: self._dim]
        norm = math.sqrt(sum(v * v for v in repeated)) or 1.0
        return tuple(v / norm for v in repeated)


class TlpRoutingEmbedder(Embedder):
    """Route embedding calls based on TLP.

    Args:
        cloud: Embedder used for ``TLP:CLEAR`` / ``TLP:GREEN``.
        local: Embedder used for ``TLP:AMBER`` and stricter. MUST NOT egress
            to a third-party API; ``ValueError`` is raised at construction
            time if the supplied local embedder claims otherwise.
    """

    def __init__(self, *, cloud: Embedder, local: Embedder) -> None:
        if cloud.dim != local.dim:
            raise ValueError(
                f"cloud and local embedders must agree on dim "
                f"(cloud={cloud.dim}, local={local.dim})"
            )
        if local.egress_third_party:
            raise ValueError(
                "Local embedder must not egress to third-party APIs (set egress_third_party=False)"
            )
        self._cloud = cloud
        self._local = local

    @property
    def dim(self) -> int:
        return self._cloud.dim

    @property
    def egress_third_party(self) -> bool:
        # Mixed: routing decides per-chunk. The retriever uses
        # ``embed_chunks`` to apply per-chunk routing.
        return self._cloud.egress_third_party

    def embed(self, texts: Sequence[str]) -> list[Vector]:
        # Without TLP context we conservatively use the local embedder.
        return self._local.embed(texts)

    def embed_chunks(self, chunks: Sequence[Chunk]) -> list[Vector]:
        results: list[Vector] = [()] * len(chunks)
        cloud_idx: list[int] = []
        local_idx: list[int] = []
        for i, chunk in enumerate(chunks):
            if chunk.tlp in {TLP.CLEAR, TLP.GREEN}:
                cloud_idx.append(i)
            else:
                local_idx.append(i)
        if cloud_idx:
            cloud_vecs = self._cloud.embed([chunks[i].text for i in cloud_idx])
            for i, vec in zip(cloud_idx, cloud_vecs, strict=True):
                results[i] = vec
        if local_idx:
            local_vecs = self._local.embed([chunks[i].text for i in local_idx])
            for i, vec in zip(local_idx, local_vecs, strict=True):
                results[i] = vec
        return results
