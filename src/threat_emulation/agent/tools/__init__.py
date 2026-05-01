"""Planner agent tools.

Each tool is a typed, schema-bearing operation over the
:class:`~threat_emulation.agent.state.BlackboardState`. Tool input and output
shapes are Pydantic models; their JSON schemas double as Claude tool-use
schemas (no hand-written JSON).

The :data:`TOOL_REGISTRY` is the canonical catalogue; the planner looks up
tools by name and an :class:`LLMClient` exposes the schemas to Claude.
"""

from typing import Any

from threat_emulation.agent.tools.base import ToolBase, ToolResult
from threat_emulation.agent.tools.propose_chain import ProposeChainTool
from threat_emulation.agent.tools.request_approval import RequestApprovalTool
from threat_emulation.agent.tools.retrieve import RetrieveTool
from threat_emulation.agent.tools.score import ScoreTool

TOOL_REGISTRY: dict[str, type[ToolBase[Any, Any]]] = {
    cls.name: cls for cls in (RetrieveTool, ScoreTool, ProposeChainTool, RequestApprovalTool)
}

__all__ = [
    "TOOL_REGISTRY",
    "ProposeChainTool",
    "RequestApprovalTool",
    "RetrieveTool",
    "ScoreTool",
    "ToolBase",
    "ToolResult",
]
