"""LLM client wrapper for the agentic planner.

Defines a tight :class:`LLMClient` interface that the planner drives in a
tool-use loop. Two implementations ship:

* :class:`FakeLLMClient` - deterministic, used by tests and the eval harness.
  It replays a pre-scripted sequence of tool calls.
* :class:`AnthropicLLMClient` - production wrapper around the Anthropic SDK
  with prompt caching and tool-use schemas. Imported lazily so the rest of the
  framework is usable without the ``anthropic`` package present at import time.

The planner decides when to stop (e.g. when ``proposed_chain`` is non-empty
and approval has been requested); the LLM only proposes the next tool call.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from threat_emulation.agent.state import BlackboardState


@dataclass(frozen=True)
class ToolCallProposal:
    """A proposed next tool call."""

    tool_name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class StopProposal:
    """The LLM is done; no more tool calls."""

    reason: str = ""


Proposal = ToolCallProposal | StopProposal


class LLMClient(ABC):
    """Abstract LLM client driving a tool-use loop."""

    @abstractmethod
    def propose(
        self,
        *,
        state: BlackboardState,
        last_output: dict[str, Any] | None,
        tool_schemas: list[dict[str, Any]],
    ) -> Proposal:
        """Propose the next action: a tool call or a stop signal."""


@dataclass
class FakeLLMClient(LLMClient):
    """A scripted client that replays a fixed sequence of tool calls.

    Useful for tests and eval scenarios where determinism is required.
    The ``script`` is consumed in order; once exhausted, :meth:`propose`
    returns :class:`StopProposal`.
    """

    script: Sequence[Proposal] = field(default_factory=list)
    _iter: Iterator[Proposal] = field(init=False)

    def __post_init__(self) -> None:
        self._iter = iter(self.script)

    def propose(
        self,
        *,
        state: BlackboardState,
        last_output: dict[str, Any] | None,
        tool_schemas: list[dict[str, Any]],
    ) -> Proposal:
        del state, last_output, tool_schemas
        return next(self._iter, StopProposal(reason="script exhausted"))


class AnthropicLLMClient(LLMClient):
    """Production Anthropic Claude client with prompt caching.

    Imported on demand to keep the ``anthropic`` package optional at import
    time. The caller is responsible for setting ``ANTHROPIC_API_KEY``.

    Per CLAUDE.md hard rules: this client refuses to forward state when any
    retrieved chunk is TLP:AMBER+ - in that case the planner must use a local
    LLM or stay in heuristic mode.
    """

    def __init__(
        self,
        *,
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 1024,
        system_prompt: str | None = None,
    ) -> None:
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover - import guard
            raise RuntimeError(
                "AnthropicLLMClient requires the 'anthropic' package. "
                "Install with: uv add anthropic"
            ) from exc
        self._model = model
        self._max_tokens = max_tokens
        self._system_prompt = system_prompt or _DEFAULT_SYSTEM_PROMPT

    def propose(
        self,
        *,
        state: BlackboardState,
        last_output: dict[str, Any] | None,
        tool_schemas: list[dict[str, Any]],
    ) -> Proposal:
        if state.restricted:
            raise PermissionError(
                "Blackboard contains TLP:AMBER+ data; refusing to forward to a "
                "third-party API. Use a local LLM or remain in heuristic mode."
            )
        # The full Anthropic call site is intentionally left as a thin
        # implementation surface for Phase 2.5 / Phase 3 once an integration
        # test environment with cached fixtures is in place. The shape is:
        #
        #   import anthropic
        #   client = anthropic.Anthropic()
        #   response = client.messages.create(
        #       model=self._model,
        #       max_tokens=self._max_tokens,
        #       system=[{"type": "text", "text": self._system_prompt,
        #                "cache_control": {"type": "ephemeral"}}],
        #       tools=tool_schemas,
        #       messages=_build_messages(state, last_output),
        #   )
        #   return _parse_response(response)
        raise NotImplementedError(
            "AnthropicLLMClient.propose is wired in Phase 2.5 with cassette tests"
        )


_DEFAULT_SYSTEM_PROMPT = (
    "You are the planner agent for a defensive-research threat-emulation "
    "framework. Use the supplied tools to (1) retrieve relevant intel, "
    "(2) score candidate techniques, (3) propose an ordered TTP chain, and "
    "(4) request approval. Never assume tool calls succeed - read the typed "
    "outputs. Refuse to operate on out-of-scope targets."
)
