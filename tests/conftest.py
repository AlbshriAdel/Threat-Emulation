"""Shared test fixtures.

Provides a small, deterministic intel corpus + ATT&CK graph wired into a
HybridRetriever so multiple test modules can share the same scaffolding
without each one re-building everything from the STIX fixture.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from threat_emulation.intel.normalizers.attack import (
    AttackBundle,
    normalize_attack_bundle,
)
from threat_emulation.rag import (
    AttackGraph,
    Bm25Index,
    Chunk,
    DummyEmbedder,
    HybridRetriever,
    InMemoryVectorStore,
    chunk_text,
)
from threat_emulation.schemas import Source
from threat_emulation.schemas.enums import TLP, SourceTier

FIXTURES = Path(__file__).parent / "fixtures"

# Synthetic CTI corpus: each blob is a short writeup citing the technique IDs
# the attack_mini.json fixture defines. Designed so the heuristic planner can
# recover APT29's documented techniques (T1059.001, T1071.001).
_CTI_BLOBS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "APT29 (Cozy Bear / Midnight Blizzard) PowerShell loader analysis. "
        "The intrusion set has used PowerShell-based loaders to execute "
        "command-and-scripting payloads, mapping to MITRE ATT&CK T1059.001. "
        "Detection suggests reviewing PowerShell logs and AMSI alerts.",
        ("T1059.001",),
    ),
    (
        "APT29 HTTPS C2 traffic profile. Operators typically blend command-and-"
        "control with web-protocols at T1071.001 over TLS, often using legitimate "
        "cloud-hosted infrastructure. Detection pivots: TLS JA3 fingerprints, "
        "rare client cert chains.",
        ("T1071.001",),
    ),
    (
        "Lazarus Group cmd.exe staging. Operators staged cmd-based wrappers "
        "(T1059) before pivoting to PowerShell loaders (T1059.001). Background "
        "context for the broader execution tactic.",
        ("T1059", "T1059.001"),
    ),
    (
        "Generic registry persistence overview. Adversaries set Run keys for "
        "persistence under T1547.001. Not specific to the threat actor in scope.",
        ("T1547.001",),
    ),
    (
        "DNS tunneling background. Some intrusion sets exfiltrate via DNS, "
        "T1071.004. Not observed in APT29 reporting.",
        ("T1071.004",),
    ),
)


def _load_attack_bundle() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "attack_mini.json").read_text(encoding="utf-8"))
    return data


@pytest.fixture
def attack_source() -> Source:
    return Source(name="MITRE ATT&CK", tier=SourceTier.GOVERNMENT, tlp=TLP.CLEAR)


@pytest.fixture
def vendor_source() -> Source:
    return Source(name="vendor-report", tier=SourceTier.VENDOR, tlp=TLP.CLEAR)


@pytest.fixture
def attack_bundle(attack_source: Source) -> AttackBundle:
    raw = _load_attack_bundle()
    return normalize_attack_bundle(raw, source=attack_source)


@pytest.fixture
def attack_graph(attack_bundle: AttackBundle) -> AttackGraph:
    g = AttackGraph()
    g.add_techniques(attack_bundle.techniques)
    g.add_actors(attack_bundle.actors)
    return g


@pytest.fixture
def synthetic_corpus(vendor_source: Source) -> list[Chunk]:
    chunks: list[Chunk] = []
    for text, tids in _CTI_BLOBS:
        for c in chunk_text(text, source=vendor_source, target_chars=400):
            chunks.append(
                Chunk(
                    id=c.id,
                    text=c.text,
                    source=c.source,
                    tlp=c.tlp,
                    technique_ids=tids,
                )
            )
    return chunks


@pytest.fixture
def hybrid_retriever(synthetic_corpus: list[Chunk], attack_graph: AttackGraph) -> HybridRetriever:
    embedder = DummyEmbedder(dim=64)
    store = InMemoryVectorStore()
    bm25 = Bm25Index()
    retriever = HybridRetriever(embedder=embedder, store=store, bm25=bm25, graph=attack_graph)
    retriever.index(synthetic_corpus)
    return retriever
