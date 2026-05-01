"""Tests for the RAG layer: chunking, embedder, store, BM25, graph, retriever."""

from __future__ import annotations

import math
from collections.abc import Sequence

import pytest

from threat_emulation.rag import (
    AttackGraph,
    Bm25Index,
    Chunk,
    DummyEmbedder,
    Embedder,
    HybridRetriever,
    InMemoryVectorStore,
    TlpRoutingEmbedder,
    chunk_text,
)
from threat_emulation.rag.embedder import Vector
from threat_emulation.schemas import TTP, Actor, Source
from threat_emulation.schemas.enums import TLP, SourceTier


def _src(name: str = "MITRE ATT&CK", tlp: TLP = TLP.CLEAR) -> Source:
    return Source(name=name, tier=SourceTier.GOVERNMENT, tlp=tlp)


# --------------------------------------------------------------------------- #
# Chunking
# --------------------------------------------------------------------------- #


def test_chunk_text_returns_provenance_bearing_chunks() -> None:
    src = _src()
    text = "Para one.\n\nPara two with more words.\n\nPara three."
    chunks = chunk_text(text, source=src, target_chars=200)
    assert chunks
    for c in chunks:
        assert c.source is src
        assert c.tlp == TLP.CLEAR
        assert c.text


def test_chunk_text_respects_tlp_override() -> None:
    src = _src(tlp=TLP.CLEAR)
    chunks = chunk_text("Some text.", source=src, tlp=TLP.AMBER)
    assert all(c.tlp == TLP.AMBER for c in chunks)
    assert all(c.restricted for c in chunks)


def test_chunk_text_splits_long_paragraph() -> None:
    src = _src()
    long_para = "word " * 500  # ~2500 chars, single paragraph
    chunks = chunk_text(long_para, source=src, target_chars=400, overlap_chars=50)
    assert len(chunks) > 1
    for c in chunks:
        assert len(c.text) <= 400


def test_chunk_text_packs_short_paragraphs() -> None:
    src = _src()
    text = "\n\n".join(f"Paragraph {i}." for i in range(20))
    chunks = chunk_text(text, source=src, target_chars=200)
    assert len(chunks) < 20  # short paras should be packed


def test_chunk_text_validates_overlap() -> None:
    with pytest.raises(ValueError):
        chunk_text("x", source=_src(), target_chars=100, overlap_chars=100)


def test_chunk_text_handles_empty_input() -> None:
    assert chunk_text("", source=_src()) == []
    assert chunk_text("   \n\n  ", source=_src()) == []


# --------------------------------------------------------------------------- #
# Embedder + TLP routing
# --------------------------------------------------------------------------- #


class _FakeCloudEmbedder(Embedder):
    """Cloud embedder stub: records every call so we can assert egress."""

    def __init__(self, dim: int = 32) -> None:
        self._dim = dim
        self.calls: list[list[str]] = []

    @property
    def dim(self) -> int:
        return self._dim

    @property
    def egress_third_party(self) -> bool:
        return True

    def embed(self, texts: Sequence[str]) -> list[Vector]:
        self.calls.append(list(texts))
        return [tuple(0.1 for _ in range(self._dim)) for _ in texts]


def test_dummy_embedder_is_deterministic() -> None:
    emb = DummyEmbedder(dim=16)
    a = emb.embed(["hello"])[0]
    b = emb.embed(["hello"])[0]
    assert a == b
    assert len(a) == 16
    norm = math.sqrt(sum(x * x for x in a))
    assert norm == pytest.approx(1.0, rel=1e-6)


def test_tlp_routing_embedder_sends_clear_to_cloud() -> None:
    cloud = _FakeCloudEmbedder(dim=32)
    local = DummyEmbedder(dim=32)
    routed = TlpRoutingEmbedder(cloud=cloud, local=local)

    src = _src(tlp=TLP.CLEAR)
    chunks = chunk_text("hello world", source=src)
    routed.embed_chunks(chunks)

    assert cloud.calls, "CLEAR chunks should hit the cloud embedder"
    assert all("hello world" in t for call in cloud.calls for t in call)


def test_tlp_routing_embedder_keeps_amber_local() -> None:
    cloud = _FakeCloudEmbedder(dim=32)
    local = DummyEmbedder(dim=32)
    routed = TlpRoutingEmbedder(cloud=cloud, local=local)

    src = _src(tlp=TLP.AMBER)
    chunks = chunk_text("restricted intel", source=src)
    routed.embed_chunks(chunks)

    assert cloud.calls == [], "AMBER+ chunks must NEVER reach the cloud embedder"


def test_tlp_routing_embedder_rejects_egressing_local() -> None:
    cloud = _FakeCloudEmbedder(dim=32)
    bad_local = _FakeCloudEmbedder(dim=32)  # marks egress=True
    with pytest.raises(ValueError, match="must not egress"):
        TlpRoutingEmbedder(cloud=cloud, local=bad_local)


def test_tlp_routing_embedder_requires_dim_match() -> None:
    cloud = _FakeCloudEmbedder(dim=64)
    local = DummyEmbedder(dim=32)
    with pytest.raises(ValueError, match="dim"):
        TlpRoutingEmbedder(cloud=cloud, local=local)


def test_tlp_routing_embedder_falls_back_to_local_for_raw_strings() -> None:
    cloud = _FakeCloudEmbedder(dim=32)
    local = DummyEmbedder(dim=32)
    routed = TlpRoutingEmbedder(cloud=cloud, local=local)
    # No TLP context -> conservative path = local.
    routed.embed(["query without provenance"])
    assert cloud.calls == []


# --------------------------------------------------------------------------- #
# Vector store
# --------------------------------------------------------------------------- #


def test_in_memory_store_returns_top_k_by_cosine() -> None:
    src = _src()
    chunks = chunk_text("alpha bravo charlie delta echo foxtrot golf hotel", source=src)
    emb = DummyEmbedder(dim=16)
    vectors = emb.embed_chunks(chunks)
    store = InMemoryVectorStore()
    from threat_emulation.rag.store import VectorRecord

    store.upsert(VectorRecord(chunk=c, vector=v) for c, v in zip(chunks, vectors, strict=True))
    assert len(store) == len(chunks)

    query_vec = emb.embed([chunks[0].text])[0]
    results = store.search(query_vec, top_k=3)
    assert len(results) <= 3
    # Top result should be the chunk whose text matches the query.
    assert results[0].chunk.id == chunks[0].id


def test_in_memory_store_handles_empty_query() -> None:
    from uuid import UUID

    store = InMemoryVectorStore()
    assert store.search((0.1,) * 16, top_k=5) == []
    assert store.get(UUID("00000000-0000-0000-0000-000000000000")) is None


# --------------------------------------------------------------------------- #
# BM25
# --------------------------------------------------------------------------- #


def test_bm25_finds_exact_technique_id() -> None:
    src = _src()
    text = (
        "PowerShell is tracked as T1059.001 by MITRE.\n\n"
        "HTTPS C2 falls under T1071.001.\n\n"
        "Registry run keys map to T1547.001 for persistence.\n\n"
        "Process injection covers T1055 and its sub-techniques.\n\n"
        "OS credential dumping is T1003 and includes LSASS Memory T1003.001."
    )
    chunks = chunk_text(text, source=src, target_chars=80, overlap_chars=20)
    assert len(chunks) > 1, "BM25 needs a multi-chunk corpus to be meaningful"
    index = Bm25Index()
    index.add(chunks)

    results = index.search("T1059.001", top_k=5)
    assert results
    assert "T1059.001" in results[0].chunk.text


def test_bm25_handles_unknown_query() -> None:
    src = _src()
    chunks = chunk_text("Some text about PowerShell.", source=src)
    index = Bm25Index()
    index.add(chunks)
    assert index.search("nonexistent_zzzzz_token", top_k=5) == []


def test_bm25_dedupes_chunks_by_id() -> None:
    src = _src()
    chunks = chunk_text("Same chunk.", source=src)
    index = Bm25Index()
    index.add(chunks)
    index.add(chunks)
    assert len(index) == len(chunks)


# --------------------------------------------------------------------------- #
# Graph
# --------------------------------------------------------------------------- #


def _ttp(tid: str, tactic: str = "execution") -> TTP:
    return TTP(technique_id=tid, name=tid, tactic=tactic, sources=(_src(),))


def _actor(name: str, gid: str, techniques: tuple[str, ...]) -> Actor:
    return Actor(
        primary_name=name,
        attack_group_id=gid,
        techniques=techniques,
        sources=(_src(),),
    )


def test_graph_builds_actor_to_technique_edges() -> None:
    g = AttackGraph()
    g.add_techniques([_ttp("T1059"), _ttp("T1059.001"), _ttp("T1071.001")])
    g.add_actors(
        [
            _actor("APT29", "G0016", ("T1059.001", "T1071.001")),
            _actor("Lazarus", "G0032", ("T1059", "T1059.001")),
        ]
    )

    assert set(g.techniques_for_actor(_actor("APT29", "G0016", ("T1059.001",)))) == {
        "T1059.001",
        "T1071.001",
    }
    assert set(g.actors_for_technique("T1059.001")) == {"G0016", "G0032"}


def test_graph_technique_frequency_orders_by_actor_count() -> None:
    g = AttackGraph()
    g.add_techniques([_ttp("T1059"), _ttp("T1059.001"), _ttp("T1071.001")])
    g.add_actors(
        [
            _actor("APT29", "G0016", ("T1059.001", "T1071.001")),
            _actor("Lazarus", "G0032", ("T1059", "T1059.001")),
        ]
    )

    freq = g.technique_frequency()
    assert freq["T1059.001"] == 2
    assert freq["T1059"] == 1
    assert freq["T1071.001"] == 1


def test_graph_path_returns_none_for_missing_nodes() -> None:
    g = AttackGraph()
    g.add_techniques([_ttp("T1059")])
    assert g.path("G9999", "T1059") is None
    assert g.path("T1059", "T9999") is None


def test_graph_path_returns_actor_to_technique_path() -> None:
    g = AttackGraph()
    g.add_techniques([_ttp("T1059.001")])
    g.add_actors([_actor("APT29", "G0016", ("T1059.001",))])
    path = g.path("G0016", "T1059.001")
    assert path is not None
    assert path.nodes == ("G0016", "T1059.001")
    assert path.relations == ("uses",)


# --------------------------------------------------------------------------- #
# Hybrid retriever
# --------------------------------------------------------------------------- #


def _build_retriever(
    chunks: list[Chunk], graph: AttackGraph | None = None
) -> tuple[HybridRetriever, DummyEmbedder]:
    emb = DummyEmbedder(dim=32)
    store = InMemoryVectorStore()
    bm25 = Bm25Index()
    retriever = HybridRetriever(embedder=emb, store=store, bm25=bm25, graph=graph)
    retriever.index(chunks)
    return retriever, emb


def _tech_chunks() -> list[Chunk]:
    src = _src()
    text_a = "PowerShell is documented in MITRE ATT&CK as T1059.001 (execution)."
    text_b = "HTTPS C2 communication falls under T1071.001 (command-and-control)."
    text_c = "Persistence via registry run keys is T1547.001."
    chunks: list[Chunk] = []
    for txt, tids in (
        (text_a, ("T1059.001",)),
        (text_b, ("T1071.001",)),
        (text_c, ("T1547.001",)),
    ):
        for chunk in chunk_text(txt, source=src):
            chunks.append(
                Chunk(
                    id=chunk.id,
                    text=chunk.text,
                    source=chunk.source,
                    tlp=chunk.tlp,
                    technique_ids=tids,
                )
            )
    return chunks


def test_retriever_dense_signal_present() -> None:
    chunks = _tech_chunks()
    retriever, _ = _build_retriever(chunks)
    results = retriever.retrieve("PowerShell execution T1059.001", top_k=3)
    assert results
    assert any("dense" in r.signals for r in results)
    # Top result should mention T1059.001.
    assert "T1059.001" in results[0].chunk.text


def test_retriever_sparse_signal_finds_exact_id() -> None:
    chunks = _tech_chunks()
    retriever, _ = _build_retriever(chunks)
    results = retriever.retrieve("T1071.001", top_k=3)
    assert results
    assert any("sparse" in r.signals for r in results)


def test_retriever_graph_signal_explains_actor_traversal() -> None:
    chunks = _tech_chunks()
    graph = AttackGraph()
    graph.add_techniques(
        [_ttp("T1059.001"), _ttp("T1071.001"), _ttp("T1547.001", tactic="persistence")]
    )
    graph.add_actors([_actor("APT29", "G0016", ("T1059.001", "T1071.001"))])

    retriever, _ = _build_retriever(chunks, graph=graph)
    results = retriever.retrieve("APT29 activity", actor_node="G0016", top_k=3)
    assert results
    # At least one result carries a graph signal AND an explanation path.
    assert any("graph" in r.signals for r in results)
    explained = [r for r in results if r.graph_path is not None]
    assert explained
    assert explained[0].graph_path is not None
    assert explained[0].graph_path.nodes[0] == "G0016"


def test_retriever_results_carry_provenance() -> None:
    chunks = _tech_chunks()
    retriever, _ = _build_retriever(chunks)
    results = retriever.retrieve("PowerShell", top_k=3)
    for r in results:
        assert r.source_name == "MITRE ATT&CK"
        assert r.tlp == TLP.CLEAR


def test_retriever_blocks_restricted_query_on_egressing_embedder() -> None:
    cloud = _FakeCloudEmbedder(dim=32)
    local = DummyEmbedder(dim=32)
    routed = TlpRoutingEmbedder(cloud=cloud, local=local)
    # Use cloud directly as the embedder to simulate misconfiguration.
    retriever = HybridRetriever(
        embedder=cloud,
        store=InMemoryVectorStore(),
        bm25=Bm25Index(),
    )
    with pytest.raises(PermissionError, match="Restricted query"):
        retriever.retrieve("TLP:AMBER target list", query_is_restricted=True)
    # Routed embedder still claims egress (cloud branch exists), so it also blocks.
    retriever_routed = HybridRetriever(
        embedder=routed,
        store=InMemoryVectorStore(),
        bm25=Bm25Index(),
    )
    with pytest.raises(PermissionError):
        retriever_routed.retrieve("TLP:AMBER target list", query_is_restricted=True)


def test_retriever_zero_top_k_returns_empty() -> None:
    chunks = _tech_chunks()
    retriever, _ = _build_retriever(chunks)
    assert retriever.retrieve("anything", top_k=0) == []


def test_retriever_indexing_amber_chunks_uses_local_embedder() -> None:
    cloud = _FakeCloudEmbedder(dim=32)
    local = DummyEmbedder(dim=32)
    routed = TlpRoutingEmbedder(cloud=cloud, local=local)

    src = _src(tlp=TLP.AMBER)
    chunks = chunk_text("Restricted operator playbook.", source=src)
    retriever = HybridRetriever(
        embedder=routed,
        store=InMemoryVectorStore(),
        bm25=Bm25Index(),
    )
    retriever.index(chunks)
    assert cloud.calls == [], "AMBER+ chunks must never reach the cloud embedder"
