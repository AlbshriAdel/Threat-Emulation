"""Eval harness: run a planner against golden CTI cases and score the output."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from threat_emulation.agent.planner import HeuristicPlanner, PlannerOutput
from threat_emulation.agent.tools.base import ToolDependencies
from threat_emulation.eval.metrics import (
    chain_plausibility,
    precision_at_k,
    recall_at_k,
)
from threat_emulation.schemas import Scope

DEFAULT_PRECISION_AT_10_THRESHOLD = 0.30
DEFAULT_PLAUSIBILITY_THRESHOLD = 0.80


class EvalCase(BaseModel):
    """A single golden CTI -> expected-TTP case."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    brief: str = Field(min_length=1)
    actor_node: str | None = None
    expected_techniques: tuple[str, ...] = Field(min_length=1)
    notes: str = ""

    @classmethod
    def from_json(cls, path: Path | str) -> EvalCase:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


@dataclass(frozen=True)
class EvalCaseResult:
    """Per-case metrics."""

    case_id: str
    predicted: tuple[str, ...]
    expected: tuple[str, ...]
    precision_at_5: float
    precision_at_10: float
    recall_at_10: float
    plausibility: float


@dataclass(frozen=True)
class EvalReport:
    """Aggregated eval report across cases."""

    cases: tuple[EvalCaseResult, ...] = field(default_factory=tuple)

    @property
    def mean_precision_at_10(self) -> float:
        return _mean(c.precision_at_10 for c in self.cases)

    @property
    def mean_recall_at_10(self) -> float:
        return _mean(c.recall_at_10 for c in self.cases)

    @property
    def mean_plausibility(self) -> float:
        return _mean(c.plausibility for c in self.cases)

    def passes(
        self,
        *,
        precision_at_10: float = DEFAULT_PRECISION_AT_10_THRESHOLD,
        plausibility: float = DEFAULT_PLAUSIBILITY_THRESHOLD,
    ) -> bool:
        return (
            self.mean_precision_at_10 >= precision_at_10 and self.mean_plausibility >= plausibility
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "cases": len(self.cases),
                "mean_precision_at_10": self.mean_precision_at_10,
                "mean_recall_at_10": self.mean_recall_at_10,
                "mean_plausibility": self.mean_plausibility,
            },
            "cases": [
                {
                    "id": c.case_id,
                    "predicted": list(c.predicted),
                    "expected": list(c.expected),
                    "precision_at_5": c.precision_at_5,
                    "precision_at_10": c.precision_at_10,
                    "recall_at_10": c.recall_at_10,
                    "plausibility": c.plausibility,
                }
                for c in self.cases
            ],
        }


def run_eval(
    cases: list[EvalCase],
    *,
    deps: ToolDependencies,
    scope: Scope | None = None,
) -> EvalReport:
    """Run the heuristic planner against each case and aggregate metrics.

    The planner is deterministic, so the eval is reproducible across runs.
    """
    scope = scope or _default_eval_scope()
    planner = HeuristicPlanner(deps=deps)
    case_results: list[EvalCaseResult] = []
    for case in cases:
        output: PlannerOutput = planner.run(
            brief=case.brief,
            scope=scope,
            actor_node=case.actor_node,
        )
        predicted = list(output.state.proposed_chain)
        # Build a parallel tactic list for plausibility from the scored output.
        tactic_by_tid: dict[str, str | None] = {
            s.technique_id: s.tactic for s in output.state.scored
        }
        chain_tactics = [tactic_by_tid.get(tid) for tid in predicted]
        case_results.append(
            EvalCaseResult(
                case_id=case.id,
                predicted=tuple(predicted),
                expected=tuple(case.expected_techniques),
                precision_at_5=precision_at_k(predicted, case.expected_techniques, k=5),
                precision_at_10=precision_at_k(predicted, case.expected_techniques, k=10),
                recall_at_10=recall_at_k(predicted, case.expected_techniques, k=10),
                plausibility=chain_plausibility(chain_tactics),
            )
        )
    return EvalReport(cases=tuple(case_results))


def _default_eval_scope() -> Scope:
    return Scope(
        targets_cidr=(IPv4Network("10.0.0.0/24"),),
        test_allowlist=frozenset({"placeholder-T1059", "placeholder-T1059.001"}),
    )


def _mean(values: Iterable[float]) -> float:
    items = list(values)
    return sum(items) / len(items) if items else 0.0
