"""Offline evaluation harness for the planner.

Runs the planner against golden CTI -> expected-TTP datasets and reports:

* ``precision@k`` and ``recall@k`` (k = 5, 10),
* ``chain_plausibility`` (kill-chain ordering coherence).

Per ADR-0001 D10 the harness is a CI quality gate: a regression is a
non-blocking warning; a crash is blocking; every Claude model upgrade re-runs
the harness before being made default.
"""

from threat_emulation.eval.harness import EvalCase, EvalReport, run_eval
from threat_emulation.eval.metrics import (
    chain_plausibility,
    precision_at_k,
    recall_at_k,
)

__all__ = [
    "EvalCase",
    "EvalReport",
    "chain_plausibility",
    "precision_at_k",
    "recall_at_k",
    "run_eval",
]
