"""BM25 sparse retriever over canonical chunks.

Wraps the ``rank_bm25`` library so we get good sparse recall on technical
tokens (``T1059.001``, ``CVE-2024-12345``) that dense embeddings often blur.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from uuid import UUID

from rank_bm25 import BM25Okapi

from threat_emulation.rag.chunking import Chunk
from threat_emulation.rag.store import ScoredChunk

# Tokens preserve dotted technique IDs and CVE/MITRE-style identifiers.
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN.findall(text)]


class Bm25Index:
    """In-memory BM25 index over canonical chunks."""

    def __init__(self) -> None:
        self._chunks: dict[UUID, Chunk] = {}
        self._order: list[UUID] = []
        self._bm25: BM25Okapi | None = None

    def add(self, chunks: Iterable[Chunk]) -> None:
        added = False
        for chunk in chunks:
            if chunk.id in self._chunks:
                continue
            self._chunks[chunk.id] = chunk
            self._order.append(chunk.id)
            added = True
        if added:
            self._rebuild()

    def search(self, query: str, *, top_k: int = 10) -> list[ScoredChunk]:
        if top_k <= 0 or self._bm25 is None or not self._order:
            return []
        tokens = _tokenize(query)
        if not tokens:
            return []
        scores = self._bm25.get_scores(tokens)
        ranked = sorted(
            zip(self._order, scores, strict=True),
            key=lambda pair: pair[1],
            reverse=True,
        )
        return [
            ScoredChunk(chunk=self._chunks[cid], score=float(score))
            for cid, score in ranked[:top_k]
            if score > 0.0
        ]

    def __len__(self) -> int:
        return len(self._chunks)

    def _rebuild(self) -> None:
        corpus = [_tokenize(self._chunks[cid].text) for cid in self._order]
        self._bm25 = BM25Okapi(corpus)
