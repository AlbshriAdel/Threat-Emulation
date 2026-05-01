"""Planner: drives the tool-use loop over the blackboard.

Two implementations:

* :class:`HeuristicPlanner` runs a fixed retrieve -> score -> propose_chain
  -> request_approval sequence. No LLM. Used by the eval harness, by CI,
  and as an air-gapped / TLP:AMBER+ fallback.
* :class:`AgenticPlanner` delegates the *order* of tool calls to an injected
  :class:`~threat_emulation.agent.llm.LLMClient`. Each tool call is still a
  typed, schema-validated operation on the same blackboard.

Both planners persist every tool call as a :class:`ToolCallRecord` on the
blackboard's ``history``, with input/output content hashes ready to flow
into the audit log (Phase 4).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from threat_emulation.agent.llm import LLMClient, StopProposal, ToolCallProposal
from threat_emulation.agent.state import (
    BlackboardState,
    ToolCallRecord,
    hash_payload,
    utcnow,
)
from threat_emulation.agent.tools import TOOL_REGISTRY, ToolBase
from threat_emulation.agent.tools.base import ToolDependencies
from threat_emulation.schemas import (
    Campaign,
    CampaignStep,
    DestructivenessTier,
    EmulationBackend,
    Scope,
)

DEFAULT_MAX_LOOP_ITERATIONS = 16


@dataclass(frozen=True)
class PlannerOutput:
    """Result of a planner run."""

    state: BlackboardState
    campaign: Campaign | None


# --------------------------------------------------------------------------- #
# Shared utilities
# --------------------------------------------------------------------------- #


def _run_tool(
    tool: ToolBase[Any, Any],
    state: BlackboardState,
    deps: ToolDependencies,
    arguments: dict[str, Any],
) -> BlackboardState:
    inputs = tool.InputModel.model_validate(arguments)
    started = utcnow()
    try:
        result = tool.execute(state, deps, inputs)
        finished = utcnow()
        record = ToolCallRecord(
            sequence=len(state.history),
            tool_name=tool.name,
            started_at=started,
            finished_at=finished,
            input_hash=hash_payload(inputs),
            output_hash=hash_payload(result.output),
            error=None,
        )
        return result.state.append_history(record)
    except Exception as exc:
        finished = utcnow()
        record = ToolCallRecord(
            sequence=len(state.history),
            tool_name=tool.name,
            started_at=started,
            finished_at=finished,
            input_hash=hash_payload(inputs),
            output_hash=hash_payload({"error": str(exc)}),
            error=str(exc),
        )
        return state.append_history(record)


def _build_campaign(state: BlackboardState, scope_id: str | None = None) -> Campaign | None:
    if not state.proposed_chain:
        return None
    steps = tuple(
        CampaignStep(
            order=i,
            technique_id=tid,
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            test_id=f"placeholder-{tid}",
            destructiveness=DestructivenessTier.OBSERVATIONAL,
            rationale=_rationale_for(state, tid),
            cited_source_ids=(),  # populated later when run-bound
        )
        for i, tid in enumerate(state.proposed_chain)
    )
    from uuid import UUID as _UUID

    sid = _UUID(scope_id) if scope_id else uuid4()
    return Campaign(
        name=f"campaign-{state.actor_node or 'generic'}",
        scope_id=sid,
        steps=steps,
    )


def _rationale_for(state: BlackboardState, technique_id: str) -> str:
    for s in state.scored:
        if s.technique_id == technique_id:
            comp = ", ".join(f"{n}={v:.2f}" for n, v in s.components)
            return f"score={s.score:.2f} ({comp})"
    return ""


# --------------------------------------------------------------------------- #
# Heuristic planner
# --------------------------------------------------------------------------- #


class HeuristicPlanner:
    """Pure-Python planner: retrieve -> score -> propose_chain -> request_approval."""

    def __init__(
        self,
        *,
        deps: ToolDependencies,
        retrieve_top_k: int = 20,
        score_top_k: int = 20,
        max_chain_steps: int = 5,
    ) -> None:
        self._deps = deps
        self._retrieve_top_k = retrieve_top_k
        self._score_top_k = score_top_k
        self._max_chain_steps = max_chain_steps

    def run(
        self,
        *,
        brief: str,
        scope: Scope,
        actor_node: str | None = None,
    ) -> PlannerOutput:
        state = BlackboardState(brief=brief, scope=scope, actor_node=actor_node)
        retrieve = TOOL_REGISTRY["retrieve"]()
        score = TOOL_REGISTRY["score"]()
        propose = TOOL_REGISTRY["propose_chain"]()
        approve = TOOL_REGISTRY["request_approval"]()

        state = _run_tool(
            retrieve,
            state,
            self._deps,
            {"query": brief, "top_k": self._retrieve_top_k},
        )
        state = _run_tool(score, state, self._deps, {"top_k": self._score_top_k})
        state = _run_tool(
            propose,
            state,
            self._deps,
            {"max_steps": self._max_chain_steps, "min_score": 0.0},
        )
        state = _run_tool(
            approve,
            state,
            self._deps,
            {"reason": "Heuristic plan ready for human review."},
        )
        return PlannerOutput(state=state, campaign=_build_campaign(state))


# --------------------------------------------------------------------------- #
# Agentic planner (LLM-driven tool order)
# --------------------------------------------------------------------------- #


class AgenticPlanner:
    """Tool-use loop driven by an injected LLM client.

    The LLM proposes the next tool call; the planner executes it (with type
    validation) and feeds the typed output back. The loop ends when the LLM
    proposes :class:`~threat_emulation.agent.llm.StopProposal` or when
    ``max_iterations`` is reached.
    """

    def __init__(
        self,
        *,
        deps: ToolDependencies,
        llm: LLMClient,
        max_iterations: int = DEFAULT_MAX_LOOP_ITERATIONS,
    ) -> None:
        self._deps = deps
        self._llm = llm
        self._max_iterations = max_iterations

    def run(
        self,
        *,
        brief: str,
        scope: Scope,
        actor_node: str | None = None,
    ) -> PlannerOutput:
        state = BlackboardState(brief=brief, scope=scope, actor_node=actor_node)
        last_output: dict[str, Any] | None = None
        tool_schemas = self._tool_schemas()
        for _ in range(self._max_iterations):
            proposal = self._llm.propose(
                state=state,
                last_output=last_output,
                tool_schemas=tool_schemas,
            )
            if isinstance(proposal, StopProposal):
                break
            assert isinstance(proposal, ToolCallProposal)
            tool_cls = TOOL_REGISTRY.get(proposal.tool_name)
            if tool_cls is None:
                raise ValueError(f"Unknown tool: {proposal.tool_name}")
            tool = tool_cls()
            previous_history_len = len(state.history)
            state = _run_tool(tool, state, self._deps, proposal.arguments)
            # Surface the latest output to the LLM as a dict.
            last_record = state.history[-1] if len(state.history) > previous_history_len else None
            last_output = (
                {"tool": last_record.tool_name, "output_hash": last_record.output_hash}
                if last_record
                else None
            )
        return PlannerOutput(state=state, campaign=_build_campaign(state))

    @staticmethod
    def _tool_schemas() -> list[dict[str, Any]]:
        return [
            {
                "name": cls.name,
                "description": cls.description,
                "input_schema": cls.input_schema(),
            }
            for cls in TOOL_REGISTRY.values()
        ]
