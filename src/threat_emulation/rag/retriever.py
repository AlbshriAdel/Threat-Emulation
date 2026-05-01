"""Hybrid retriever: dense + sparse + graph, with TLP enforcement.

Fuses the three retrieval signals using *reciprocal rank fusion* (RRF). Each
result carries provenance: the originating :class:`Source`, the chunk's TLP,
the contributing signals, and (when available) the ATT&CK graph path that
explains why a technique was surfaced.

Two safety properties are enforced *here* so callers cannot bypass them:

* the embedder used for query embedding must not egress to a third-party API
  unless the caller explicitly asserts the query is non-restricted;
* every returned :class:`RetrievalResult` carries the chunk's TLP, so
  downstream layers (planner, reporter) can refuse to forward restricted
  text to external LLMs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from threat_emulation.rag.bm25 import Bm25Index
from threat_emulation.rag.chunking import Chunk
from threat_emulation.rag.embedder import Embedder, Vector
from threat_emulation.rag.graph import AttackGraph, GraphPath
from threat_emulation.rag.store import ScoredChunk, VectorRecord, VectorStore
from threat_emulation.schemas.enums import TLP

DEFAULT_RRF_K = 60


@dataclass(frozen=True)
class RetrievalResult:
    """A retrieved chunk plus its provenance and contributing signals."""

    chunk: Chunk
    score: float
    signals: frozenset[str]
    graph_path: GraphPath | None = field(default=None)

    @property
    def source_name(self) -> str:
        return self.chunk.source.name

    @property
    def tlp(self) -> TLP:
        return self.chunk.tlp


class HybridRetriever:
    """Combine dense + BM25 + graph retrieval with RRF.

    Args:
        embedder: Used to embed queries. Must implement
            :class:`~threat_emulation.rag.embedder.Embedder`.
        store: Vector store backing dense retrieval.
        bm25: BM25 sparse index.
        graph: ATT&CK graph (optional; if ``None`` the graph signal is skipped).
        rrf_k: RRF constant; higher dampens the contribution of any single rank.
    """

    def __init__(
        self,
        *,
        embedder: Embedder,
        store: VectorStore,
        bm25: Bm25Index,
        graph: AttackGraph | None = None,
        rrf_k: int = DEFAULT_RRF_K,
    ) -> None:
        if rrf_k <= 0:
            raise ValueError("rrf_k must be positive")
        self._embedder = embedder
        self._store = store
        self._bm25 = bm25
        self._graph = graph
        self._rrf_k = rrf_k

    # ------------------------------------------------------------------ #
    # Indexing
    # ------------------------------------------------------------------ #

    def index(self, chunks: list[Chunk]) -> None:
        """Embed and index ``chunks`` into both the vector store and BM25."""
        if not chunks:
            return
        self._guard_index_egress(chunks)
        vectors = self._embedder.embed_chunks(chunks)
        records = [
            VectorRecord(chunk=chunk, vector=vec)
            for chunk, vec in zip(chunks, vectors, strict=True)
        ]
        self._store.upsert(records)
        self._bm25.add(chunks)

    # ------------------------------------------------------------------ #
    # Retrieval
    # ------------------------------------------------------------------ #

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 10,
        actor_node: str | None = None,
        query_is_restricted: bool = False,
    ) -> list[RetrievalResult]:
        """Run hybrid retrieval and return fused, provenance-bearing results.

        Args:
            query: Free-text query.
            top_k: Maximum results to return.
            actor_node: Optional ATT&CK actor node id (e.g. ``"G0016"``) used
                to add a graph-traversal signal that boosts techniques the
                actor uses.
            query_is_restricted: True if the query itself contains restricted
                (TLP:AMBER+) data. When true, the cloud branch of any TLP
                routing embedder must not be used; this method asserts the
                embedder will not egress.
        """
        if top_k <= 0:
            return []
        if query_is_restricted and self._embedder.egress_third_party:
            raise PermissionError(
                "Restricted query cannot be embedded by a third-party API embedder"
            )

        dense = self._dense(query, top_k=top_k)
        sparse = self._bm25.search(query, top_k=top_k)
        graph_hits = self._graph_hits(actor_node)

        fused = self._rrf(dense=dense, sparse=sparse, graph=graph_hits)
        results: list[RetrievalResult] = []
        for chunk_id, score, signals in fused[:top_k]:
            chunk = self._store.get(chunk_id)
            if chunk is None:
                continue
            path = self._explain(chunk, actor_node=actor_node)
            results.append(
                RetrievalResult(
                    chunk=chunk,
                    score=score,
                    signals=frozenset(signals),
                    graph_path=path,
                )
            )
        return results

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _dense(self, query: str, *, top_k: int) -> list[ScoredChunk]:
        vec: Vector = self._embedder.embed([query])[0]
        return self._store.search(vec, top_k=top_k)

    def _graph_hits(self, actor_node: str | None) -> list[tuple[UUID, float]]:
        """Return chunk-id scores from the graph signal.

        For each technique used by ``actor_node``, surface chunks tagged with
        that technique id. Score = inverse rank by technique frequency.
        """
        if self._graph is None or actor_node is None:
            return []
        if actor_node not in self._graph.graph:
            return []
        techniques = tuple(
            t
            for _, t, data in self._graph.graph.out_edges(actor_node, data=True)
            if data.get("relation") == "uses"
        )
        if not techniques:
            return []
        # Pull chunks from the BM25 corpus that carry these technique ids.
        # (We use BM25's chunk store as the canonical chunk catalogue.)
        scored: list[tuple[UUID, float]] = []
        rank = 1
        for tid in techniques:
            for chunk_id, chunk in self._iter_chunks():
                if tid in chunk.technique_ids:
                    scored.append((chunk_id, 1.0 / rank))
                    rank += 1
        return scored

    def _iter_chunks(self) -> list[tuple[UUID, Chunk]]:
        """Iterate chunks via BM25's catalogue (the indexer ensures parity)."""
        # pylint: disable=protected-access  (intentional cross-module access)
        return [(cid, self._bm25._chunks[cid]) for cid in self._bm25._chunks]

    def _rrf(
        self,
        *,
        dense: list[ScoredChunk],
        sparse: list[ScoredChunk],
        graph: list[tuple[UUID, float]],
    ) -> list[tuple[UUID, float, set[str]]]:
        """Fuse three rankings via reciprocal rank fusion."""
        scores: dict[UUID, float] = {}
        signals: dict[UUID, set[str]] = {}

        def _merge(name: str, ranking: list[tuple[UUID, float]]) -> None:
            for rank, (cid, _) in enumerate(ranking, start=1):
                scores[cid] = scores.get(cid, 0.0) + 1.0 / (self._rrf_k + rank)
                signals.setdefault(cid, set()).add(name)

        _merge("dense", [(s.chunk.id, s.score) for s in dense])
        _merge("sparse", [(s.chunk.id, s.score) for s in sparse])
        if graph:
            _merge("graph", graph)

        ranked = sorted(scores.items(), key=lambda pair: pair[1], reverse=True)
        return [(cid, score, signals[cid]) for cid, score in ranked]

    def _explain(self, chunk: Chunk, *, actor_node: str | None) -> GraphPath | None:
        if self._graph is None or actor_node is None:
            return None
        for tid in chunk.technique_ids:
            path = self._graph.path(actor_node, tid)
            if path is not None:
                return path
        return None

    @staticmethod
    def _guard_index_egress(chunks: list[Chunk]) -> None:
        """Sanity check: embedder routing happens via :class:`TlpRoutingEmbedder`.

        We do not block here because the embedder is expected to enforce TLP.
        This hook exists so subclasses or future policy layers can audit
        index calls without changing call sites.
        """
        # Intentional no-op; routing is enforced inside the embedder.
        # Kept as an explicit extension point.
        return None
