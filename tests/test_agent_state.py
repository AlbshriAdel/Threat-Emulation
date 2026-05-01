"""Tests for the agent blackboard state."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Network
from uuid import uuid4

import pytest

from threat_emulation.agent.state import (
    BlackboardState,
    RetrievedChunkRef,
    ToolCallRecord,
    genesis_hash,
    hash_payload,
)
from threat_emulation.schemas import Scope
from threat_emulation.schemas.enums import TLP


def _scope() -> Scope:
    return Scope(targets_cidr=(IPv4Network("10.0.0.0/24"),))


def test_blackboard_starts_empty() -> None:
    state = BlackboardState(brief="hello", scope=_scope())
    assert state.retrieved == ()
    assert state.scored == ()
    assert state.proposed_chain == ()
    assert state.history == ()
    assert state.approval_requested is False


def test_blackboard_with_updates_returns_new_instance() -> None:
    state = BlackboardState(brief="hello", scope=_scope())
    new = state.with_updates(approval_requested=True)
    assert new is not state
    assert state.approval_requested is False
    assert new.approval_requested is True


def test_blackboard_restricted_flag_tracks_amber_chunks() -> None:
    state = BlackboardState(brief="x", scope=_scope())
    assert state.restricted is False
    ref = RetrievedChunkRef(
        chunk_id=uuid4(),
        source_name="vendor",
        tlp=TLP.AMBER,
        score=0.5,
    )
    new = state.with_updates(retrieved=(ref,))
    assert new.restricted is True


def test_blackboard_append_history_preserves_order() -> None:
    state = BlackboardState(brief="x", scope=_scope())
    now = datetime.now(UTC)
    record = ToolCallRecord(
        sequence=0,
        tool_name="retrieve",
        started_at=now,
        finished_at=now,
        input_hash="a" * 64,
        output_hash="b" * 64,
    )
    new = state.append_history(record)
    assert len(new.history) == 1
    assert new.history[0].sequence == 0


def test_genesis_hash_is_zeroes() -> None:
    assert genesis_hash() == "0" * 64


def test_hash_payload_is_stable_across_dict_orderings() -> None:
    a = hash_payload({"a": 1, "b": 2})
    b = hash_payload({"b": 2, "a": 1})
    assert a == b


def test_hash_payload_handles_pydantic_models() -> None:
    state = BlackboardState(brief="hello", scope=_scope())
    h1 = hash_payload(state)
    h2 = hash_payload(state)
    assert h1 == h2
    assert len(h1) == 64


def test_blackboard_rejects_extra_fields() -> None:
    with pytest.raises(ValueError):
        BlackboardState(brief="x", scope=_scope(), bogus=True)  # type: ignore[call-arg]
