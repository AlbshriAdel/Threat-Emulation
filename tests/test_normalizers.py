"""Tests for intel normalizers."""

from __future__ import annotations

import json
from pathlib import Path

from threat_emulation.intel.normalizers import (
    normalize_attack_bundle,
    normalize_kev_feed,
)
from threat_emulation.schemas import Source
from threat_emulation.schemas.enums import TLP, SourceTier

FIXTURES = Path(__file__).parent / "fixtures"


def _gov_source(name: str) -> Source:
    return Source(name=name, tier=SourceTier.GOVERNMENT, tlp=TLP.CLEAR)


# --------------------------------------------------------------------------- #
# ATT&CK
# --------------------------------------------------------------------------- #


def test_normalize_attack_bundle_extracts_techniques_and_actors() -> None:
    raw = json.loads((FIXTURES / "attack_mini.json").read_text())
    bundle = normalize_attack_bundle(raw, source=_gov_source("MITRE ATT&CK"))

    technique_ids = {t.technique_id for t in bundle.techniques}
    assert technique_ids == {"T1059", "T1059.001", "T1071", "T1071.001"}
    # Deprecated technique is skipped.
    assert "T9999" not in technique_ids

    actor_names = {a.primary_name for a in bundle.actors}
    assert actor_names == {"APT29", "Lazarus Group"}


def test_normalize_attack_bundle_links_actors_to_techniques() -> None:
    raw = json.loads((FIXTURES / "attack_mini.json").read_text())
    bundle = normalize_attack_bundle(raw, source=_gov_source("MITRE ATT&CK"))

    apt29 = next(a for a in bundle.actors if a.primary_name == "APT29")
    assert apt29.attack_group_id == "G0016"
    assert "Cozy Bear" in apt29.aliases
    assert "Midnight Blizzard" in apt29.aliases
    assert "APT29" not in apt29.aliases  # primary name excluded
    assert set(apt29.techniques) == {"T1059.001", "T1071.001"}

    lazarus = next(a for a in bundle.actors if a.primary_name == "Lazarus Group")
    assert lazarus.attack_group_id == "G0032"
    assert set(lazarus.techniques) == {"T1059", "T1059.001"}


def test_normalize_attack_bundle_preserves_source_provenance() -> None:
    raw = json.loads((FIXTURES / "attack_mini.json").read_text())
    src = _gov_source("MITRE ATT&CK")
    bundle = normalize_attack_bundle(raw, source=src)
    for ttp in bundle.techniques:
        assert src in ttp.sources
    for actor in bundle.actors:
        assert src in actor.sources


def test_normalize_attack_bundle_rejects_non_bundle() -> None:
    import pytest

    with pytest.raises(ValueError, match="bundle"):
        normalize_attack_bundle({"type": "not-bundle"}, source=_gov_source("x"))


# --------------------------------------------------------------------------- #
# KEV
# --------------------------------------------------------------------------- #


def test_normalize_kev_feed_produces_indicator_per_row() -> None:
    raw = json.loads((FIXTURES / "kev_mini.json").read_text())
    indicators = normalize_kev_feed(raw, source=_gov_source("CISA KEV"))
    assert len(indicators) == 3
    cves = [i.value.split(" | ")[0] for i in indicators]
    assert "CVE-2021-44228" in cves
    assert "CVE-2023-23397" in cves
    assert "CVE-2024-3400" in cves
    for ind in indicators:
        assert ind.tlp == TLP.CLEAR
        assert ind.sources[0].tier == SourceTier.GOVERNMENT


def test_normalize_kev_feed_skips_rows_without_cve() -> None:
    feed = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-1234", "vendorProject": "v", "product": "p"},
            {"vendorProject": "no-cve"},
            {"cveID": "", "vendorProject": "empty"},
        ]
    }
    indicators = normalize_kev_feed(feed, source=_gov_source("CISA KEV"))
    assert len(indicators) == 1


def test_normalize_kev_feed_propagates_tlp() -> None:
    raw = json.loads((FIXTURES / "kev_mini.json").read_text())
    indicators = normalize_kev_feed(raw, source=_gov_source("CISA KEV"), tlp=TLP.AMBER)
    for ind in indicators:
        assert ind.tlp == TLP.AMBER
        assert ind.tlp.restricted
