"""MITRE ATT&CK STIX 2.1 bundle collector.

Loads a STIX 2.1 bundle either from a local file path or via HTTP. The
canonical upstream bundle is at:

    https://github.com/mitre-attack/attack-stix-data

We read the bundle as opaque JSON; STIX-aware parsing is in the normaliser
(:mod:`threat_emulation.intel.normalizers.attack`). This keeps the collector
small and free of the heavyweight ``stix2`` dependency.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from threat_emulation.intel.collectors.base import Collector, CollectorResult
from threat_emulation.schemas import Source
from threat_emulation.schemas.enums import TLP, SourceTier

_DEFAULT_NAME = "MITRE ATT&CK"


class AttackStixCollector(Collector):
    """Load a STIX 2.1 bundle from a file path or URL.

    Exactly one of ``path`` or ``url`` must be provided.
    """

    def __init__(
        self,
        *,
        path: Path | str | None = None,
        url: str | None = None,
        timeout: float = 30.0,
        source: Source | None = None,
    ) -> None:
        if (path is None) == (url is None):
            raise ValueError("Provide exactly one of 'path' or 'url'")
        self._path = Path(path) if path is not None else None
        self._url = url
        self._timeout = timeout
        self._source = source or Source(
            name=_DEFAULT_NAME,
            tier=SourceTier.GOVERNMENT,
            tlp=TLP.CLEAR,
            url=url,
        )

    def collect(self) -> CollectorResult:
        if self._path is not None:
            raw = self._read_file(self._path)
        else:
            assert self._url is not None
            raw = self._fetch(self._url)
        if not isinstance(raw, dict) or raw.get("type") != "bundle":
            raise ValueError("ATT&CK bundle must be a STIX 2.1 'bundle' object")
        return CollectorResult(source=self._source, raw=raw)

    @staticmethod
    def _read_file(path: Path) -> dict[str, Any]:
        with path.open(encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
        return data

    def _fetch(self, url: str) -> dict[str, Any]:
        response = httpx.get(url, timeout=self._timeout)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data
