"""Emulation execution layer.

Defines the :class:`EmulationAdapter` interface and ships three adapters:

* :class:`AtomicRedTeamAdapter` (default: dry-run; live mode requires pwsh
  and Invoke-AtomicTest in the lab).
* :class:`StratusRedTeamAdapter` - cloud TTPs (stub in Phase 3).
* :class:`CalderaAdapter` - multi-step adversary operations (stub in Phase 3).

The :class:`Executor` orchestrates a campaign across one or more adapters
inside a provisioned :class:`~threat_emulation.lab.LabHandle`, with default
deny-by-default egress and a verified teardown.
"""

from threat_emulation.emulation.adapter import (
    EmulationAdapter,
    ExecutionOutcome,
    ExecutionRequest,
    ExecutionResult,
)
from threat_emulation.emulation.atomic import AtomicRedTeamAdapter
from threat_emulation.emulation.caldera import CalderaAdapter
from threat_emulation.emulation.executor import (
    CampaignResult,
    Executor,
    ExecutorOptions,
)
from threat_emulation.emulation.stratus import StratusRedTeamAdapter

__all__ = [
    "AtomicRedTeamAdapter",
    "CalderaAdapter",
    "CampaignResult",
    "EmulationAdapter",
    "ExecutionOutcome",
    "ExecutionRequest",
    "ExecutionResult",
    "Executor",
    "ExecutorOptions",
    "StratusRedTeamAdapter",
]
