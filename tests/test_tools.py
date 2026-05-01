"""Tests for the planner agent tools."""

from __future__ import annotations

from ipaddress import IPv4Network

import pytest

from threat_emulation.agent.state import BlackboardState, ScoredTechnique
from threat_emulation.agent.tools import (
    TOOL_REGISTRY,
    ProposeChainTool,
    RequestApprovalTool,
    RetrieveTool,
    ScoreTool,
)
from threat_emulation.agent.tools.base import ToolDependencies
from threat_emulation.rag import AttackGraph, HybridRetriever
from threat_emulation.schemas import Scope


def _state(actor_node: str | None = "G0016") -> BlackboardState:
    return BlackboardState(
        brief="Plan emulation for the named actor.",
        scope=Scope(targets_cidr=(IPv4Network("10.0.0.0/24"),)),
        actor_node=actor_node,
    )


def test_registry_has_expected_tools() -> None:
    assert set(TOOL_REGISTRY) == {
        "retrieve",
        "score",
        "propose_chain",
        "request_approval",
    }


def test_each_tool_exposes_a_json_input_schema() -> None:
    for cls in TOOL_REGISTRY.values():
        schema = cls.input_schema()
        assert schema["type"] == "object"
        assert "properties" in schema


def test_retrieve_tool_populates_blackboard(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    tool = RetrieveTool()
    state = _state()
    inputs = tool.InputModel.model_validate({"query": "APT29 PowerShell", "top_k": 5})
    result = tool.execute(state, deps, inputs)
    assert result.output.count > 0
    assert result.state is not state
    assert len(result.state.retrieved) == result.output.count


def test_retrieve_tool_dedupes_across_calls(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    tool = RetrieveTool()
    state = _state()
    inputs = tool.InputModel.model_validate({"query": "PowerShell", "top_k": 5})
    state = tool.execute(state, deps, inputs).state
    state = tool.execute(state, deps, inputs).state
    # Same chunks should not appear twice.
    ids = [r.chunk_id for r in state.retrieved]
    assert len(ids) == len(set(ids))


def test_retrieve_tool_requires_retriever_dep(attack_graph: AttackGraph) -> None:
    tool = RetrieveTool()
    deps = ToolDependencies(retriever=None, graph=attack_graph)
    inputs = tool.InputModel.model_validate({"query": "x"})
    with pytest.raises(RuntimeError, match="retriever"):
        tool.execute(_state(), deps, inputs)


def test_score_tool_derives_candidates_from_retrieved(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    state = _state()
    state = (
        RetrieveTool()
        .execute(
            state,
            deps,
            RetrieveTool.InputModel.model_validate({"query": "APT29 HTTPS", "top_k": 10}),
        )
        .state
    )
    score_tool = ScoreTool()
    result = score_tool.execute(
        state,
        deps,
        ScoreTool.InputModel.model_validate({"top_k": 5}),
    )
    assert result.output.scored
    assert all(0.0 <= s.score <= 1.0 for s in result.output.scored)


def test_propose_chain_orders_by_kill_chain() -> None:
    state = _state()
    scored = (
        ScoredTechnique(technique_id="T1071.001", tactic="command-and-control", score=0.9),
        ScoredTechnique(technique_id="T1059.001", tactic="execution", score=0.8),
        ScoredTechnique(technique_id="T1547.001", tactic="persistence", score=0.7),
    )
    state = state.with_updates(scored=scored)
    deps = ToolDependencies()
    result = ProposeChainTool().execute(
        state,
        deps,
        ProposeChainTool.InputModel.model_validate({"max_steps": 3}),
    )
    chain = list(result.output.chain)
    # execution before persistence before command-and-control.
    assert chain.index("T1059.001") < chain.index("T1547.001") < chain.index("T1071.001")


def test_propose_chain_handles_empty_score() -> None:
    state = _state()
    deps = ToolDependencies()
    result = ProposeChainTool().execute(state, deps, ProposeChainTool.InputModel.model_validate({}))
    assert result.output.chain == ()
    assert "No techniques" in result.output.rationale


def test_request_approval_sets_flag() -> None:
    state = _state()
    tool = RequestApprovalTool()
    result = tool.execute(
        state,
        ToolDependencies(),
        tool.InputModel.model_validate({"reason": "ready"}),
    )
    assert result.state.approval_requested is True
    assert result.state.approval_reason == "ready"


def test_propose_chain_drops_below_min_score() -> None:
    state = _state()
    scored = (ScoredTechnique(technique_id="T1059.001", tactic="execution", score=0.1),)
    state = state.with_updates(scored=scored)
    result = ProposeChainTool().execute(
        state,
        ToolDependencies(),
        ProposeChainTool.InputModel.model_validate({"min_score": 0.5}),
    )
    assert result.output.chain == ()
