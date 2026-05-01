"""Tests for HeuristicPlanner and AgenticPlanner."""

from __future__ import annotations

from ipaddress import IPv4Network

import pytest

from threat_emulation.agent.llm import (
    FakeLLMClient,
    Proposal,
    StopProposal,
    ToolCallProposal,
)
from threat_emulation.agent.planner import (
    AgenticPlanner,
    HeuristicPlanner,
)
from threat_emulation.agent.tools.base import ToolDependencies
from threat_emulation.rag import AttackGraph, HybridRetriever
from threat_emulation.schemas import Scope


def _scope() -> Scope:
    return Scope(targets_cidr=(IPv4Network("10.0.0.0/24"),))


def test_heuristic_planner_runs_full_loop(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    planner = HeuristicPlanner(deps=deps)
    out = planner.run(
        brief="Plan APT29 emulation focused on PowerShell and HTTPS C2.",
        scope=_scope(),
        actor_node="G0016",
    )
    assert out.campaign is not None
    assert len(out.state.history) == 4  # retrieve, score, propose, approve
    assert {h.tool_name for h in out.state.history} == {
        "retrieve",
        "score",
        "propose_chain",
        "request_approval",
    }
    assert out.state.approval_requested is True
    # APT29's two known techniques should be surfaced.
    assert "T1059.001" in out.state.proposed_chain
    assert "T1071.001" in out.state.proposed_chain


def test_heuristic_planner_records_input_output_hashes(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    out = HeuristicPlanner(deps=deps).run(brief="Test run", scope=_scope(), actor_node="G0016")
    for record in out.state.history:
        assert len(record.input_hash) == 64
        assert len(record.output_hash) == 64
        assert record.error is None


def test_heuristic_planner_builds_campaign_in_kill_chain_order(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    out = HeuristicPlanner(deps=deps).run(
        brief="APT29 PowerShell + HTTPS", scope=_scope(), actor_node="G0016"
    )
    assert out.campaign is not None
    chain = [step.technique_id for step in out.campaign.steps]
    if "T1059.001" in chain and "T1071.001" in chain:
        assert chain.index("T1059.001") < chain.index("T1071.001")


def test_heuristic_planner_with_unknown_actor(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    # An unknown actor still produces a plan based on the corpus + retrieval.
    out = HeuristicPlanner(deps=deps).run(
        brief="Generic execution and C2 emulation",
        scope=_scope(),
        actor_node="G9999",
    )
    assert out.state.approval_requested is True


def test_agentic_planner_drives_tool_calls_via_fake_llm(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    script: list[Proposal] = [
        ToolCallProposal(
            tool_name="retrieve",
            arguments={"query": "APT29 PowerShell HTTPS", "top_k": 10},
        ),
        ToolCallProposal(tool_name="score", arguments={"top_k": 10}),
        ToolCallProposal(tool_name="propose_chain", arguments={"max_steps": 5, "min_score": 0.0}),
        ToolCallProposal(tool_name="request_approval", arguments={"reason": "agent done"}),
        StopProposal(reason="finished"),
    ]
    planner = AgenticPlanner(deps=deps, llm=FakeLLMClient(script=script))
    out = planner.run(brief="agent run", scope=_scope(), actor_node="G0016")
    assert out.campaign is not None
    assert out.state.approval_requested is True


def test_agentic_planner_stops_on_unknown_tool(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    script: list[Proposal] = [ToolCallProposal(tool_name="bogus", arguments={})]
    planner = AgenticPlanner(deps=deps, llm=FakeLLMClient(script=script))
    with pytest.raises(ValueError, match="Unknown tool"):
        planner.run(brief="x", scope=_scope())


def test_agentic_planner_caps_iterations(
    hybrid_retriever: HybridRetriever, attack_graph: AttackGraph
) -> None:
    deps = ToolDependencies(retriever=hybrid_retriever, graph=attack_graph)
    # Repeat retrieve forever; cap at 3.
    script: list[Proposal] = [
        ToolCallProposal(tool_name="retrieve", arguments={"query": "x"}) for _ in range(10)
    ]
    planner = AgenticPlanner(deps=deps, llm=FakeLLMClient(script=script), max_iterations=3)
    out = planner.run(brief="x", scope=_scope(), actor_node="G0016")
    assert len(out.state.history) == 3
