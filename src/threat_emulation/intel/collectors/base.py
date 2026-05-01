"""Abstract collector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from threat_emulation.schemas import Source


@dataclass(frozen=True)
class CollectorResult:
    """The output of a collector run.

    ``raw`` is the unparsed payload (e.g. a STIX bundle dict, a list of KEV
    rows). Normalisers convert these into canonical schema types. The
    collector also returns a :class:`Source` so provenance stays attached
    end-to-end.
    """

    source: Source
    raw: Any


class Collector(ABC):
    """A source-specific intelligence collector.

    Subclasses implement :meth:`collect` (sync) or override :meth:`acollect`
    for async I/O. The default :meth:`acollect` falls back to :meth:`collect`.
    """

    @abstractmethod
    def collect(self) -> CollectorResult:
        """Fetch and return raw intel."""

    async def acollect(self) -> CollectorResult:
        """Async fetch. Defaults to calling the sync :meth:`collect`."""
        return self.collect()
