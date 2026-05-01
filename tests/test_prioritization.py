"""Tests for the prioritization engine."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from threat_emulation.agent.prioritization import (
    PrioritizationWeights,
    score_techniques,
)
from threat_emulation.agent.state import RetrievedChunkRef
from threat_emulation.rag import AttackGraph
from threat_emulation.schemas.enums import TLP


def _ref(tids: tuple[str, ...], excerpt: str = "") -> RetrievedChunkRef:
    return RetrievedChunkRef(
        chunk_id=uuid4(),
        source_name="vendor",
        tlp=TLP.CLEAR,
        score=0.5,
        technique_ids=tids,
        excerpt=excerpt,
    )


def test_weights_default_is_balanced() -> None:
    w = PrioritizationWeights()
    assert w.cti_freq == 1.0
    assert w.kev_overlap == 1.0
    assert w.actor_ttp_match == 1.0
    assert w.detection_gap == 1.0


def test_weights_reject_all_zero() -> None:
    with pytest.raises(ValueError, match="At least one"):
        PrioritizationWeights(cti_freq=0.0, kev_overlap=0.0, actor_ttp_match=0.0, detection_gap=0.0)


def test_weights_from_yaml(tmp_path: Path) -> None:
    cfg = tmp_path / "w.yaml"
    cfg.write_text("cti_freq: 2.0\nkev_overlap: 0.5\n")
    w = PrioritizationWeights.from_yaml(cfg)
    assert w.cti_freq == 2.0
    assert w.kev_overlap == 0.5


def test_score_empty_candidates_returns_empty() -> None:
    assert score_techniques(candidates=[], retrieved=[]) == []


def test_score_returns_descending_by_score(attack_graph: AttackGraph) -> None:
    candidates = ["T1059.001", "T1071.001", "T1547.001"]
    refs = [
        _ref(("T1059.001",)),
        _ref(("T1059.001",)),
        _ref(("T1071.001",)),
    ]
    scored = score_techniques(
        candidates=candidates,
        retrieved=refs,
        graph=attack_graph,
        actor_node="G0016",
    )
    assert [s.technique_id for s in scored][:2] == ["T1059.001", "T1071.001"]
    # Each score must be in [0, 1].
    for s in scored:
        assert 0.0 <= s.score <= 1.0


def test_score_kev_overlap_uses_excerpt_text(attack_graph: AttackGraph) -> None:
    refs = [_ref(("T1059.001",), excerpt="Exploited via CVE-2024-3400")]
    scored = score_techniques(
        candidates=["T1059.001", "T1547.001"],
        retrieved=refs,
        graph=attack_graph,
        actor_node="G0016",
        kev_cves=frozenset({"CVE-2024-3400"}),
    )
    # T1059.001 should beat T1547.001 because of KEV overlap + actor match.
    top = scored[0]
    assert top.technique_id == "T1059.001"
    component_map = dict(top.components)
    assert component_map["kev_overlap"] == 1.0


def test_score_attaches_actor_provenance(attack_graph: AttackGraph) -> None:
    scored = score_techniques(
        candidates=["T1059.001"],
        retrieved=[_ref(("T1059.001",))],
        graph=attack_graph,
        actor_node="G0016",
    )
    assert scored[0].cited_actors == ("G0016",)


def test_score_detection_gap_signal(attack_graph: AttackGraph) -> None:
    scored = score_techniques(
        candidates=["T1547.001", "T1059.001"],
        retrieved=[_ref(("T1547.001",))],
        graph=attack_graph,
        detection_gaps=frozenset({"T1547.001"}),
    )
    # T1547.001 should benefit from the detection-gap component.
    top = scored[0]
    assert top.technique_id == "T1547.001"


def test_score_attaches_tactic_when_graph_provided(attack_graph: AttackGraph) -> None:
    scored = score_techniques(
        candidates=["T1059.001", "T1071.001"],
        retrieved=[_ref(("T1059.001",)), _ref(("T1071.001",))],
        graph=attack_graph,
    )
    tactic_map = {s.technique_id: s.tactic for s in scored}
    assert tactic_map["T1059.001"] == "execution"
    assert tactic_map["T1071.001"] == "command-and-control"
