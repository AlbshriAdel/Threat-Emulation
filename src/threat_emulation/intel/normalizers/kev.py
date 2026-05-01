"""Normalise the CISA KEV catalog to canonical Indicator records.

Each row in the KEV ``vulnerabilities`` array becomes an :class:`Indicator`
of type ``cve`` (we tag it via ``filename`` since the canonical Indicator
type literal does not include CVE; the CVE id lives in ``value`` and the
vendor / product context is folded in for retrieval keyword recall).

In a future ADR we may extend Indicator's type literal to include ``cve``;
for now we use ``filename`` as a structural placeholder while preserving
the full CVE id for BM25 matching.
"""

from __future__ import annotations

from typing import Any

from threat_emulation.schemas import Indicator, Source
from threat_emulation.schemas.enums import TLP


def normalize_kev_feed(
    feed: dict[str, Any], *, source: Source, tlp: TLP = TLP.CLEAR
) -> tuple[Indicator, ...]:
    """Convert a CISA KEV feed dict into canonical Indicator records."""
    rows = feed.get("vulnerabilities")
    if not isinstance(rows, list):
        raise ValueError("KEV feed must contain a 'vulnerabilities' list")

    indicators: list[Indicator] = []
    for row in rows:
        cve_id = row.get("cveID")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        vendor = str(row.get("vendorProject", "")).strip()
        product = str(row.get("product", "")).strip()
        name = str(row.get("vulnerabilityName", "")).strip()
        value = " | ".join(part for part in (cve_id, vendor, product, name) if part)
        indicators.append(
            Indicator(
                type="filename",
                value=value[:2048],
                tlp=tlp,
                sources=(source,),
            )
        )
    return tuple(indicators)
