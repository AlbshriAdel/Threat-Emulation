"""``propose_chain`` tool: order scored techniques into a kill-chain campaign."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threat_emulation.agent.state import BlackboardState
from threat_emulation.agent.tools.base import ToolBase, ToolDependencies, ToolResult

# Canonical MITRE ATT&CK Enterprise tactic order (v15+).
KILL_CHAIN_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
_TACTIC_RANK: dict[str, int] = {t: i for i, t in enumerate(KILL_CHAIN_ORDER)}


class ProposeChainInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_steps: int = Field(default=5, ge=1, le=20)
    min_score: float = Field(default=0.0, ge=0.0, le=1.0)


class ProposeChainOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chain: tuple[str, ...]
    rationale: str = Field(default="")


class ProposeChainTool(ToolBase[ProposeChainInput, ProposeChainOutput]):
    name = "propose_chain"
    description = (
        "Order top-scored techniques into a kill-chain-coherent Campaign "
        "(reconnaissance -> ... -> impact). Returns the ordered technique ids."
    )
    InputModel = ProposeChainInput
    OutputModel = ProposeChainOutput

    def execute(
        self,
        state: BlackboardState,
        deps: ToolDependencies,
        inputs: ProposeChainInput,
    ) -> ToolResult[ProposeChainOutput]:
        del deps  # No external deps needed; ordering is pure.
        eligible = [s for s in state.scored if s.score >= inputs.min_score]
        if not eligible:
            output = ProposeChainOutput(
                chain=(),
                rationale="No techniques met the minimum score threshold.",
            )
            new_state = state.with_updates(proposed_chain=())
            return ToolResult(state=new_state, output=output)

        # Sort by (tactic kill-chain rank ascending, score descending). Unknown
        # tactics sort last so the agent surfaces them but doesn't break the
        # ordering invariant.
        eligible.sort(
            key=lambda s: (
                _TACTIC_RANK.get(s.tactic or "", len(KILL_CHAIN_ORDER)),
                -s.score,
            )
        )
        # Dedupe by tactic so the chain spans phases instead of stacking.
        chain: list[str] = []
        seen_tactics: set[str] = set()
        leftover: list[str] = []
        for s in eligible:
            tactic = s.tactic or "unknown"
            if tactic in seen_tactics:
                leftover.append(s.technique_id)
                continue
            chain.append(s.technique_id)
            seen_tactics.add(tactic)
            if len(chain) >= inputs.max_steps:
                break
        # Backfill with high-score leftovers if the chain is short.
        for tid in leftover:
            if len(chain) >= inputs.max_steps:
                break
            chain.append(tid)

        rationale = _explain(eligible[: len(chain)])
        output = ProposeChainOutput(chain=tuple(chain), rationale=rationale)
        new_state = state.with_updates(proposed_chain=tuple(chain))
        return ToolResult(state=new_state, output=output)


def _explain(top: list) -> str:  # type: ignore[type-arg]
    parts = [f"{s.technique_id} ({s.tactic or 'unknown'}, score={s.score:.2f})" for s in top]
    return "Selected: " + "; ".join(parts) if parts else ""
