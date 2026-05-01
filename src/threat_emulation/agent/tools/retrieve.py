"""``retrieve`` tool: query the hybrid retriever and write results to state."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threat_emulation.agent.state import BlackboardState, RetrievedChunkRef
from threat_emulation.agent.tools.base import (
    ToolBase,
    ToolDependencies,
    ToolResult,
    assert_dep,
)


class RetrieveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=4096)
    top_k: int = Field(default=10, ge=1, le=50)
    use_actor_node: bool = Field(
        default=True,
        description="If true, the planner's actor_node is forwarded for graph traversal.",
    )
    query_is_restricted: bool = Field(
        default=False,
        description="Set true if the query contains TLP:AMBER+ data.",
    )


class RetrieveOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    count: int
    chunks: tuple[RetrievedChunkRef, ...]


class RetrieveTool(ToolBase[RetrieveInput, RetrieveOutput]):
    name = "retrieve"
    description = (
        "Retrieve top-K threat-intel chunks via the hybrid retriever "
        "(dense + BM25 + ATT&CK graph). Always returns provenance."
    )
    InputModel = RetrieveInput
    OutputModel = RetrieveOutput

    def execute(
        self,
        state: BlackboardState,
        deps: ToolDependencies,
        inputs: RetrieveInput,
    ) -> ToolResult[RetrieveOutput]:
        retriever = assert_dep(deps.retriever, "retriever")
        actor_node = state.actor_node if inputs.use_actor_node else None
        results = retriever.retrieve(
            inputs.query,
            top_k=inputs.top_k,
            actor_node=actor_node,
            query_is_restricted=inputs.query_is_restricted,
        )
        refs = tuple(
            RetrievedChunkRef(
                chunk_id=r.chunk.id,
                source_name=r.chunk.source.name,
                tlp=r.chunk.tlp,
                score=float(r.score),
                signals=frozenset(r.signals),
                technique_ids=tuple(r.chunk.technique_ids),
                excerpt=r.chunk.text[:512],
            )
            for r in results
        )
        # Append: a tool call adds to the corpus rather than replacing it.
        merged = _dedupe_by_chunk(state.retrieved + refs)
        new_state = state.with_updates(retrieved=merged)
        output = RetrieveOutput(count=len(refs), chunks=refs)
        return ToolResult(state=new_state, output=output)


def _dedupe_by_chunk(refs: tuple[RetrievedChunkRef, ...]) -> tuple[RetrievedChunkRef, ...]:
    seen: dict[str, RetrievedChunkRef] = {}
    for ref in refs:
        seen[str(ref.chunk_id)] = ref
    return tuple(seen.values())
