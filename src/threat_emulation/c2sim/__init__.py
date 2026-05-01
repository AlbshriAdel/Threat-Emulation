"""C2 traffic containment.

The lab is deny-by-default: any C2-style traffic from emulation tests must
terminate at an :class:`EgressSink`. Two implementations:

* :class:`InetSimSink` - emits a minimal INetSim config and exposes a
  capture-log query so the executor can attest to what (if anything)
  reached the sink during a run.
* :class:`InMemoryEgressSink` - a test sink that records connection
  attempts in process memory.

Per CLAUDE.md hard rule 3: "NEVER egress real internet from the lab."
"""

from threat_emulation.c2sim.inetsim import (
    EgressAttempt,
    EgressSink,
    InetSimSink,
    InMemoryEgressSink,
    render_inetsim_config,
)

__all__ = [
    "EgressAttempt",
    "EgressSink",
    "InMemoryEgressSink",
    "InetSimSink",
    "render_inetsim_config",
]
