"""Retrieval-Augmented Generation layer.

Hybrid retrieval combines:

* dense embeddings (cloud or local; routed by TLP),
* BM25 sparse retrieval (keyword precision: CVE IDs, technique IDs),
* a NetworkX ATT&CK graph (structural traversal: actor -> technique).

Every retrieval result carries provenance (source, TLP, graph path) so
downstream agents and reports can cite their evidence.
"""

from threat_emulation.rag.bm25 import Bm25Index
from threat_emulation.rag.chunking import Chunk, chunk_text
from threat_emulation.rag.embedder import (
    DummyEmbedder,
    Embedder,
    TlpRoutingEmbedder,
)
from threat_emulation.rag.graph import AttackGraph
from threat_emulation.rag.retriever import HybridRetriever, RetrievalResult
from threat_emulation.rag.store import InMemoryVectorStore, VectorRecord, VectorStore

__all__ = [
    "AttackGraph",
    "Bm25Index",
    "Chunk",
    "DummyEmbedder",
    "Embedder",
    "HybridRetriever",
    "InMemoryVectorStore",
    "RetrievalResult",
    "TlpRoutingEmbedder",
    "VectorRecord",
    "VectorStore",
    "chunk_text",
]
