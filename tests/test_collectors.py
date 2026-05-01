"""Tests for intel collectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_emulation.intel.collectors import AttackStixCollector, KevCollector

FIXTURES = Path(__file__).parent / "fixtures"


def test_attack_collector_loads_bundle_from_path() -> None:
    collector = AttackStixCollector(path=FIXTURES / "attack_mini.json")
    result = collector.collect()
    assert result.raw["type"] == "bundle"
    assert isinstance(result.raw["objects"], list)
    assert result.source.name == "MITRE ATT&CK"


def test_attack_collector_requires_exactly_one_source() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        AttackStixCollector()
    with pytest.raises(ValueError, match="exactly one"):
        AttackStixCollector(path="/tmp/x.json", url="https://example.invalid/x.json")


def test_attack_collector_rejects_non_bundle(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"type": "not-a-bundle"}')
    with pytest.raises(ValueError, match="bundle"):
        AttackStixCollector(path=bad).collect()


def test_kev_collector_loads_from_path() -> None:
    collector = KevCollector(path=FIXTURES / "kev_mini.json")
    result = collector.collect()
    assert "vulnerabilities" in result.raw
    assert len(result.raw["vulnerabilities"]) == 3
    assert result.source.name == "CISA KEV"


def test_kev_collector_rejects_both_path_and_url(tmp_path: Path) -> None:
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    with pytest.raises(ValueError, match="not both"):
        KevCollector(path=bad, url="https://example.invalid/kev.json")


def test_kev_collector_rejects_malformed_feed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(ValueError, match="vulnerabilities"):
        KevCollector(path=bad).collect()
