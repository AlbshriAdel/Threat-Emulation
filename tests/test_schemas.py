"""Unit tests for the canonical Pydantic schemas."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from uuid import uuid4

import pytest
from pydantic import ValidationError

from threat_emulation.schemas import (
    TLP,
    TTP,
    Actor,
    AuditEvent,
    Campaign,
    ConfidenceLevel,
    DestructivenessTier,
    EmulationBackend,
    Indicator,
    RunPhase,
    RunRecord,
    Scope,
    ScopeOfEngagement,
    Source,
    SourceTier,
)
from threat_emulation.schemas.models import CampaignStep

ZERO_HASH = "0" * 64
SAMPLE_HASH = "a" * 64


def _source(tlp: TLP = TLP.CLEAR) -> Source:
    return Source(name="MITRE ATT&CK", tier=SourceTier.GOVERNMENT, tlp=tlp)


def _scope() -> Scope:
    return Scope(
        targets_cidr=(IPv4Network("10.0.0.0/24"),),
        test_allowlist=frozenset({"art-T1059-1"}),
        max_destructiveness=DestructivenessTier.OBSERVATIONAL,
    )


# --------------------------------------------------------------------------- #
# TLP
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("tlp", "expected"),
    [
        (TLP.CLEAR, False),
        (TLP.GREEN, False),
        (TLP.AMBER, True),
        (TLP.AMBER_STRICT, True),
        (TLP.RED, True),
    ],
)
def test_tlp_restricted_flag(tlp: TLP, expected: bool) -> None:
    assert tlp.restricted is expected


# --------------------------------------------------------------------------- #
# Source
# --------------------------------------------------------------------------- #


def test_source_rejects_naive_published_at() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Source(
            name="x",
            tier=SourceTier.OPEN_BLOG,
            published_at=datetime(2026, 1, 1),
        )


def test_source_is_frozen() -> None:
    s = _source()
    with pytest.raises(ValidationError):
        s.name = "mutated"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# TTP
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tid", ["T1059", "T1059.001", "T1003.008"])
def test_ttp_accepts_valid_ids(tid: str) -> None:
    ttp = TTP(technique_id=tid, name="x", tactic="execution")
    assert ttp.technique_id == tid


@pytest.mark.parametrize("tid", ["t1059", "T105", "T10599", "T1059.1", "1059"])
def test_ttp_rejects_malformed_ids(tid: str) -> None:
    with pytest.raises(ValidationError):
        TTP(technique_id=tid, name="x", tactic="execution")


def test_ttp_seen_order_validated() -> None:
    earlier = datetime(2026, 1, 1, tzinfo=UTC)
    later = datetime(2026, 2, 1, tzinfo=UTC)
    with pytest.raises(ValidationError, match="first_seen"):
        TTP(
            technique_id="T1059",
            name="x",
            tactic="execution",
            first_seen=later,
            last_seen=earlier,
        )


def test_ttp_default_confidence_is_medium() -> None:
    ttp = TTP(technique_id="T1059", name="x", tactic="execution")
    assert ttp.confidence == ConfidenceLevel.MEDIUM


# --------------------------------------------------------------------------- #
# Indicator
# --------------------------------------------------------------------------- #


def test_indicator_carries_tlp_and_sources() -> None:
    src = _source(TLP.AMBER)
    ind = Indicator(
        type="domain",
        value="evil.example",
        tlp=TLP.AMBER,
        sources=(src,),
        associated_ttps=("T1071.001",),
    )
    assert ind.tlp.restricted
    assert ind.sources[0].tier == SourceTier.GOVERNMENT


# --------------------------------------------------------------------------- #
# Actor
# --------------------------------------------------------------------------- #


def test_actor_alias_reconciliation() -> None:
    actor = Actor(
        primary_name="APT29",
        attack_group_id="G0016",
        aliases=frozenset({"Cozy Bear", "Midnight Blizzard", "Nobelium"}),
        techniques=("T1059.001", "T1071.001"),
    )
    assert "Midnight Blizzard" in actor.aliases
    assert actor.attack_group_id == "G0016"


def test_actor_rejects_bad_group_id() -> None:
    with pytest.raises(ValidationError):
        Actor(primary_name="x", attack_group_id="APT29")


# --------------------------------------------------------------------------- #
# Scope / ScopeOfEngagement
# --------------------------------------------------------------------------- #


def test_scope_requires_at_least_one_target() -> None:
    with pytest.raises(ValidationError, match="at least one target"):
        Scope()


def test_scope_with_hostnames_only_is_valid() -> None:
    Scope(targets_hostnames=("lab-01.internal",))


def test_scope_of_engagement_active_window() -> None:
    now = datetime.now(UTC)
    soe = ScopeOfEngagement(
        organization="Acme",
        authorized_by="ciso@acme.example",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        scope=_scope(),
        signature="deadbeef",
    )
    assert soe.is_active(now) is True
    assert soe.is_active(now + timedelta(days=2)) is False


def test_scope_of_engagement_rejects_inverted_window() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="valid_from"):
        ScopeOfEngagement(
            organization="Acme",
            authorized_by="x",
            valid_from=now,
            valid_until=now - timedelta(seconds=1),
            scope=_scope(),
            signature="x",
        )


def test_scope_of_engagement_rejects_naive_datetimes() -> None:
    with pytest.raises(ValidationError):
        ScopeOfEngagement(
            organization="Acme",
            authorized_by="x",
            valid_from=datetime(2026, 1, 1),
            valid_until=datetime(2026, 2, 1),
            scope=_scope(),
            signature="x",
        )


def test_scope_of_engagement_is_active_requires_aware_arg() -> None:
    now = datetime.now(UTC)
    soe = ScopeOfEngagement(
        organization="Acme",
        authorized_by="x",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        scope=_scope(),
        signature="x",
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        soe.is_active(datetime(2026, 1, 1))


# --------------------------------------------------------------------------- #
# Campaign
# --------------------------------------------------------------------------- #


def _step(order: int, tier: DestructivenessTier) -> CampaignStep:
    return CampaignStep(
        order=order,
        technique_id="T1059.001",
        backend=EmulationBackend.ATOMIC_RED_TEAM,
        test_id=f"art-T1059-{order}",
        destructiveness=tier,
    )


def test_campaign_max_destructiveness() -> None:
    c = Campaign(
        name="apt29-min",
        scope_id=uuid4(),
        steps=(
            _step(0, DestructivenessTier.OBSERVATIONAL),
            _step(1, DestructivenessTier.INTRUSIVE),
            _step(2, DestructivenessTier.DESTRUCTIVE),
        ),
    )
    assert c.max_destructiveness == DestructivenessTier.DESTRUCTIVE


def test_campaign_requires_ascending_step_order() -> None:
    with pytest.raises(ValidationError, match="ascending"):
        Campaign(
            name="bad",
            scope_id=uuid4(),
            steps=(
                _step(1, DestructivenessTier.OBSERVATIONAL),
                _step(0, DestructivenessTier.OBSERVATIONAL),
            ),
        )


def test_campaign_rejects_duplicate_step_orders() -> None:
    with pytest.raises(ValidationError, match="unique"):
        Campaign(
            name="dup",
            scope_id=uuid4(),
            steps=(
                _step(0, DestructivenessTier.OBSERVATIONAL),
                _step(0, DestructivenessTier.OBSERVATIONAL),
            ),
        )


def test_campaign_requires_at_least_one_step() -> None:
    with pytest.raises(ValidationError):
        Campaign(name="empty", scope_id=uuid4(), steps=())


# --------------------------------------------------------------------------- #
# RunRecord
# --------------------------------------------------------------------------- #


def test_run_record_completed_phase_requires_completed_at() -> None:
    with pytest.raises(ValidationError, match="completed_at required"):
        RunRecord(
            campaign_id=uuid4(),
            scope_of_engagement_hash=SAMPLE_HASH,
            phase=RunPhase.COMPLETED,
            operator="alice@acme.example",
        )


def test_run_record_non_terminal_phase_rejects_completed_at() -> None:
    with pytest.raises(ValidationError, match="completed_at must be unset"):
        RunRecord(
            campaign_id=uuid4(),
            scope_of_engagement_hash=SAMPLE_HASH,
            phase=RunPhase.EXECUTING,
            operator="alice@acme.example",
            completed_at=datetime.now(UTC),
        )


def test_run_record_default_is_dry_run() -> None:
    rec = RunRecord(
        campaign_id=uuid4(),
        scope_of_engagement_hash=SAMPLE_HASH,
        operator="alice@acme.example",
    )
    assert rec.dry_run is True
    assert rec.phase == RunPhase.PLANNING


# --------------------------------------------------------------------------- #
# AuditEvent
# --------------------------------------------------------------------------- #


def test_audit_event_genesis_uses_zero_previous_hash() -> None:
    evt = AuditEvent(
        run_id=uuid4(),
        sequence=0,
        event_type="run.start",
        actor="system",
        payload_hash=SAMPLE_HASH,
        previous_hash=ZERO_HASH,
        scope_of_engagement_hash=SAMPLE_HASH,
    )
    assert evt.previous_hash == ZERO_HASH


def test_audit_event_rejects_non_hex_payload_hash() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            run_id=uuid4(),
            sequence=0,
            event_type="run.start",
            actor="system",
            payload_hash="not-a-hash",
            previous_hash=ZERO_HASH,
            scope_of_engagement_hash=SAMPLE_HASH,
        )


def test_audit_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        AuditEvent(
            run_id=uuid4(),
            sequence=0,
            timestamp=datetime(2026, 1, 1),
            event_type="run.start",
            actor="system",
            payload_hash=SAMPLE_HASH,
            previous_hash=ZERO_HASH,
            scope_of_engagement_hash=SAMPLE_HASH,
        )


def test_audit_event_is_frozen() -> None:
    evt = AuditEvent(
        run_id=uuid4(),
        sequence=0,
        event_type="run.start",
        actor="system",
        payload_hash=SAMPLE_HASH,
        previous_hash=ZERO_HASH,
        scope_of_engagement_hash=SAMPLE_HASH,
    )
    with pytest.raises(ValidationError):
        evt.sequence = 1  # type: ignore[misc]
