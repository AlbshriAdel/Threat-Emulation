"""CISA Known Exploited Vulnerabilities (KEV) collector.

The canonical upstream feed is at:

    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

We fetch the JSON as-is; mapping to canonical types happens in the normaliser.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from threat_emulation.intel.collectors.base import Collector, CollectorResult
from threat_emulation.schemas import Source
from threat_emulation.schemas.enums import TLP, SourceTier

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_NAME = "CISA KEV"


class KevCollector(Collector):
    """Fetch the CISA KEV catalog from a file path or HTTP URL."""

    def __init__(
        self,
        *,
        path: Path | str | None = None,
        url: str | None = None,
        timeout: float = 30.0,
        source: Source | None = None,
    ) -> None:
        if path is None and url is None:
            url = CISA_KEV_URL
        if path is not None and url is not None:
            raise ValueError("Provide either 'path' or 'url', not both")
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
        if not isinstance(raw, dict) or "vulnerabilities" not in raw:
            raise ValueError("KEV feed must include a 'vulnerabilities' key")
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
