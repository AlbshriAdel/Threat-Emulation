"""Metrics for the planner eval harness."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import pairwise

from threat_emulation.agent.tools.propose_chain import KILL_CHAIN_ORDER

_TACTIC_RANK: dict[str, int] = {t: i for i, t in enumerate(KILL_CHAIN_ORDER)}


def precision_at_k(predicted: list[str], expected: Iterable[str], *, k: int) -> float:
    """Fraction of the top-K predicted items that appear in ``expected``."""
    if k <= 0:
        raise ValueError("k must be positive")
    if not predicted:
        return 0.0
    expected_set = set(expected)
    if not expected_set:
        return 0.0
    top = predicted[:k]
    hits = sum(1 for tid in top if tid in expected_set)
    return hits / len(top)


def recall_at_k(predicted: list[str], expected: Iterable[str], *, k: int) -> float:
    """Fraction of expected items present in the top-K predictions."""
    if k <= 0:
        raise ValueError("k must be positive")
    expected_set = set(expected)
    if not expected_set:
        return 0.0
    top = set(predicted[:k])
    hits = sum(1 for tid in expected_set if tid in top)
    return hits / len(expected_set)


def chain_plausibility(
    chain_tactics: list[str | None],
) -> float:
    """Kill-chain ordering coherence in ``[0, 1]``.

    Defined as the fraction of consecutive tactic pairs whose ranks are
    non-decreasing (i.e. the chain doesn't wander backwards through phases).
    Pairs involving an unknown tactic count as plausible (we don't punish
    missing data).
    """
    if len(chain_tactics) < 2:
        return 1.0
    ok = 0
    total = 0
    for prev, nxt in pairwise(chain_tactics):
        if prev is None or nxt is None:
            ok += 1
            total += 1
            continue
        prev_rank = _TACTIC_RANK.get(prev)
        next_rank = _TACTIC_RANK.get(nxt)
        if prev_rank is None or next_rank is None or prev_rank <= next_rank:
            ok += 1
        total += 1
    return ok / total if total else 1.0
