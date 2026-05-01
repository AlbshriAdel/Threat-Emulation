"""Tests for the eval harness and metrics."""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_emulation.agent.tools.base import ToolDependencies
from threat_emulation.eval import (
    EvalCase,
    chain_plausibility,
    precision_at_k,
    recall_at_k,
    run_eval,
)
from threat_emulation.rag import AttackGraph, HybridRetriever

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# Metric primitives
# --------------------------------------------------------------------------- #


def test_precision_at_k_basic() -> None:
    assert precision_at_k(["a", "b", "c"], {"a", "b"}, k=2) == 1.0
    assert precision_at_k(["a", "b", "c"], {"a"}, k=3) == pytest.approx(1 / 3)


def test_precision_at_k_handles_empty() -> None:
    assert precision_at_k([], {"a"}, k=5) == 0.0
    assert precision_at_k(["a"], set(), k=5) == 0.0


def test_precision_at_k_rejects_zero_k() -> None:
    with pytest.raises(ValueError):
        precision_at_k(["a"], {"a"}, k=0)


def test_recall_at_k_basic() -> None:
    assert recall_at_k(["a", "b"], {"a", "b", "c"}, k=2) == pytest.approx(2 / 3)
    assert recall_at_k(["x"], {"y"}, k=5) == 0.0


def test_chain_plausibility_perfect_order() -> None:
    assert chain_plausibility(["initial-access", "execution", "command-and-control"]) == 1.0


def test_chain_plausibility_backwards_step_lowers_score() -> None:
    score = chain_plausibility(["execution", "initial-access", "command-and-control"])
    assert score < 1.0


def test_chain_plausibility_handles_unknowns() -> None:
    # Unknown / None entries are treated as plausible (no false penalty).
    assert chain_plausibility(["execution", None]) == 1.0
    assert chain_plausibility(["unknown-tactic", "execution"]) == 1.0


def test_chain_plausibility_short_chain() -> None:
    assert chain_plausibility([]) == 1.0
    assert chain_plausibility(["execution"]) == 1.0


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


def test_eval_case_loads_from_json() -> None:
    case = EvalCase.from_json(REPO_ROOT / "eval" / "datasets" / "apt29.json")
    assert case.id == "apt29-min"
    assert case.actor_node == "G0016"
    assert "T1059.001" in case.expected_techniques


def test_run_eval_against_apt29_meets_thresholds(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    case = EvalCase.from_json(REPO_ROOT / "eval" / "datasets" / "apt29.json")
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    report = run_eval([case], deps=deps)

    assert report.cases
    # Both expected APT29 techniques must appear in the predicted chain
    # (recall is the hard requirement; precision is a tunable threshold).
    case_result = report.cases[0]
    for expected in case.expected_techniques:
        assert expected in case_result.predicted
    assert case_result.recall_at_10 == 1.0
    # Default thresholds (precision@10 >= 0.30, plausibility >= 0.80) must hold.
    assert report.passes(), (
        "APT29 golden case must meet harness defaults: "
        f"p@10={report.mean_precision_at_10}, plausibility={report.mean_plausibility}"
    )


def test_eval_report_to_dict_structure(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    case = EvalCase.from_json(REPO_ROOT / "eval" / "datasets" / "apt29.json")
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    report = run_eval([case], deps=deps)
    payload = report.to_dict()
    assert "summary" in payload
    assert payload["summary"]["cases"] == 1
    assert isinstance(payload["cases"], list)
