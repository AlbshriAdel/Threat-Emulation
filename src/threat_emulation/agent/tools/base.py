"""Abstract tool base.

Every planner tool declares:

* a unique ``name``,
* a one-line ``description`` shown to the LLM,
* a Pydantic ``InputModel`` (input schema, doubles as Claude tool-use schema),
* a Pydantic ``OutputModel`` (output schema for type-safety + audit),
* an :meth:`execute` method that takes ``(state, deps, inputs)`` and returns
  a :class:`ToolResult` carrying the new state plus the typed output.

Dependencies (retriever, graph, etc.) are injected via a
:class:`ToolDependencies` bag rather than being captured at construction time
so the same tool class is reusable across runs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel

from threat_emulation.agent.state import BlackboardState

InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


@dataclass(frozen=True)
class ToolDependencies:
    """Injected dependencies available to tools.

    Tools may use any subset; missing optional deps are surfaced as a tool
    error rather than crashing the run.
    """

    retriever: Any | None = None  # threat_emulation.rag.retriever.HybridRetriever
    graph: Any | None = None  # threat_emulation.rag.graph.AttackGraph
    weights: Any | None = None  # threat_emulation.agent.prioritization.PrioritizationWeights
    kev_cves: frozenset[str] = frozenset()
    detection_gaps: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ToolResult(Generic[OutputT]):
    """The result of a tool call: new state + typed output."""

    state: BlackboardState
    output: OutputT


class ToolBase(ABC, Generic[InputT, OutputT]):
    """Abstract planner tool."""

    name: ClassVar[str]
    description: ClassVar[str]
    InputModel: ClassVar[type[BaseModel]]
    OutputModel: ClassVar[type[BaseModel]]

    @classmethod
    def input_schema(cls) -> dict[str, Any]:
        """JSON schema for the input payload (Claude tool-use compatible)."""
        return cls.InputModel.model_json_schema()

    @classmethod
    def output_schema(cls) -> dict[str, Any]:
        """JSON schema for the output payload."""
        return cls.OutputModel.model_json_schema()

    @abstractmethod
    def execute(
        self,
        state: BlackboardState,
        deps: ToolDependencies,
        inputs: InputT,
    ) -> ToolResult[OutputT]:
        """Run the tool, returning the new state and typed output."""


def assert_dep(value: Any, name: str) -> Any:
    """Raise ``RuntimeError`` if a required dependency is missing."""
    if value is None:
        raise RuntimeError(f"Tool requires dependency '{name}' but it is not configured")
    return value
