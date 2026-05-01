"""``score`` tool: apply weighted prioritisation to candidate techniques."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threat_emulation.agent.prioritization import score_techniques
from threat_emulation.agent.state import BlackboardState, ScoredTechnique
from threat_emulation.agent.tools.base import ToolBase, ToolDependencies, ToolResult


class ScoreInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidates: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Technique ids to score. If empty, derive candidates from "
        "retrieved chunks' technique_ids.",
    )
    top_k: int = Field(default=20, ge=1, le=200)


class ScoreOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scored: tuple[ScoredTechnique, ...]


class ScoreTool(ToolBase[ScoreInput, ScoreOutput]):
    name = "score"
    description = (
        "Apply the weighted prioritisation formula (CTI freq, KEV overlap, "
        "actor-TTP match, detection gap) to candidate techniques."
    )
    InputModel = ScoreInput
    OutputModel = ScoreOutput

    def execute(
        self,
        state: BlackboardState,
        deps: ToolDependencies,
        inputs: ScoreInput,
    ) -> ToolResult[ScoreOutput]:
        candidates = list(inputs.candidates) or _derive_candidates(state)
        scored = score_techniques(
            candidates=candidates,
            retrieved=list(state.retrieved),
            graph=deps.graph,
            actor_node=state.actor_node,
            kev_cves=deps.kev_cves,
            detection_gaps=deps.detection_gaps,
            weights=deps.weights,
        )
        truncated = tuple(scored[: inputs.top_k])
        new_state = state.with_updates(
            candidate_techniques=tuple(candidates),
            scored=truncated,
        )
        return ToolResult(state=new_state, output=ScoreOutput(scored=truncated))


def _derive_candidates(state: BlackboardState) -> list[str]:
    seen: dict[str, None] = {}
    for ref in state.retrieved:
        for tid in ref.technique_ids:
            seen.setdefault(tid, None)
    return list(seen)
