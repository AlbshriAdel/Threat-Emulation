"""Defensive-research-grade guardrails.

Three pieces:

* :mod:`policy` - Pydantic policy DSL. Versioned, content-hashed, optionally
  signed. Replaces OPA/Rego per ADR-0001 D7.
* :mod:`preflight` - pipeline of checks evaluated against a candidate run.
  Layers on top of the executor's lightweight pre-flight by adding policy
  and 2-person-integrity gates.
* :mod:`killswitch` - dual-channel kill-switch (API endpoint + signal-file
  watcher) per CLAUDE.md hard rule 7.
"""

from threat_emulation.guardrails.killswitch import (
    KillReason,
    KillSwitch,
    SignalFileWatcher,
)
from threat_emulation.guardrails.policy import (
    ApprovalRequirements,
    EgressPolicy,
    Policy,
    PolicyViolation,
    ScopeConstraints,
)

# NOTE: PreflightChecker is intentionally NOT re-exported here. It depends on
# threat_emulation.auth.twopi, which itself imports from
# threat_emulation.guardrails.policy. Importing PreflightChecker via the
# package init would create a circular import. Callers should use
# ``from threat_emulation.guardrails.preflight import PreflightChecker``.

__all__ = [
    "ApprovalRequirements",
    "EgressPolicy",
    "KillReason",
    "KillSwitch",
    "Policy",
    "PolicyViolation",
    "ScopeConstraints",
    "SignalFileWatcher",
]
