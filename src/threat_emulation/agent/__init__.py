"""Agent layer: blackboard state, tool-use schemas, planner.

The planner runs as a *tool-use loop* over a typed Pydantic blackboard
(no free-form chat) so every step is auditable and bounded in tokens. Two
planner implementations ship:

* :class:`HeuristicPlanner` - pure-Python, no LLM. Used by the eval harness
  and CI, and as a fallback when the LLM is unavailable or the deployment
  is air-gapped.
* :class:`AgenticPlanner` - same tool catalogue, but the *order* of tool
  calls is decided by an :class:`~threat_emulation.agent.llm.LLMClient`
  (Anthropic Claude in production, :class:`FakeLLMClient` in tests).
"""

from threat_emulation.agent.planner import (
    AgenticPlanner,
    HeuristicPlanner,
    PlannerOutput,
)
from threat_emulation.agent.state import BlackboardState, ScoredTechnique
from threat_emulation.agent.tools import TOOL_REGISTRY, ToolBase

__all__ = [
    "TOOL_REGISTRY",
    "AgenticPlanner",
    "BlackboardState",
    "HeuristicPlanner",
    "PlannerOutput",
    "ScoredTechnique",
    "ToolBase",
]
