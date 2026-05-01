"""Source-specific collectors.

A collector is responsible for *fetching* raw intel from a source. Parsing /
normalisation lives in :mod:`threat_emulation.intel.normalizers` to keep
network code separate from data-shape code (and easier to test).
"""

from threat_emulation.intel.collectors.attack import AttackStixCollector
from threat_emulation.intel.collectors.base import Collector, CollectorResult
from threat_emulation.intel.collectors.kev import KevCollector

__all__ = [
    "AttackStixCollector",
    "Collector",
    "CollectorResult",
    "KevCollector",
]
