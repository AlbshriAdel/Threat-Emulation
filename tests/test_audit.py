"""Tests for the audit pipeline (Merkle, log, transparency, WORM)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from threat_emulation.audit import (
    AuditLog,
    FilesystemWormExporter,
    OfflineTransparencyLog,
    merkle_root,
    proof_for,
    verify_inclusion,
)

# --------------------------------------------------------------------------- #
# Merkle
# --------------------------------------------------------------------------- #


def _h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_merkle_root_empty_uses_sha256_of_empty_string() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_merkle_root_single_leaf_returns_leaf() -> None:
    leaf = _h("a")
    assert merkle_root([leaf]) == leaf


def test_merkle_root_is_deterministic() -> None:
    leaves = [_h(c) for c in "abcde"]
    assert merkle_root(leaves) == merkle_root(leaves)


def test_merkle_proof_verifies_for_each_leaf() -> None:
    leaves = [_h(c) for c in "abcdefg"]
    root = merkle_root(leaves)
    for i in range(len(leaves)):
        proof = proof_for(leaves, i)
        assert proof.root == root
        assert verify_inclusion(proof) is True


def test_merkle_proof_rejects_tampering() -> None:
    leaves = [_h(c) for c in "abcdef"]
    proof = proof_for(leaves, 2)
    bad = type(proof)(
        leaf_index=proof.leaf_index,
        leaf_hash=_h("z"),  # tampered leaf
        siblings=proof.siblings,
        directions=proof.directions,
        root=proof.root,
    )
    assert verify_inclusion(bad) is False


def test_merkle_proof_rejects_invalid_index() -> None:
    leaves = [_h("a")]
    with pytest.raises(IndexError):
        proof_for(leaves, 5)


# --------------------------------------------------------------------------- #
# AuditLog
# --------------------------------------------------------------------------- #


SOE_HASH = "f" * 64


def _log() -> AuditLog:
    return AuditLog(run_id=uuid4(), scope_of_engagement_hash=SOE_HASH)


def test_audit_log_genesis_has_zero_previous_hash() -> None:
    log = _log()
    event = log.append(event_type="run.start", actor="system", payload={"hello": "world"})
    assert event.sequence == 0
    assert event.previous_hash == "0" * 64
    assert event.scope_of_engagement_hash == SOE_HASH


def test_audit_log_chain_is_linked() -> None:
    log = _log()
    a = log.append(event_type="t", actor="x", payload={"i": 1})
    b = log.append(event_type="t", actor="x", payload={"i": 2})
    assert b.previous_hash != "0" * 64
    assert a.sequence == 0
    assert b.sequence == 1


def test_audit_log_verify_passes_on_clean_chain() -> None:
    log = _log()
    for i in range(5):
        log.append(event_type="t", actor="x", payload={"i": i})
    result = log.verify()
    assert result.valid is True
    assert result.events_checked == 5


def test_audit_log_detects_payload_tampering() -> None:
    log = _log()
    log.append(event_type="t", actor="x", payload={"i": 1})
    log.append(event_type="t", actor="x", payload={"i": 2})
    # Tamper with the second event's payload after the fact.
    target = log.events[1]
    object.__setattr__(target, "payload", {"i": "tampered"})
    result = log.verify()
    assert result.valid is False
    assert result.first_invalid_sequence == 1


def test_audit_log_rejects_invalid_soe_hash() -> None:
    with pytest.raises(ValueError, match="64-char"):
        AuditLog(run_id=uuid4(), scope_of_engagement_hash="short")


def test_audit_log_rejects_naive_timestamp() -> None:
    log = _log()
    with pytest.raises(ValueError, match="timezone-aware"):
        log.append(
            event_type="t",
            actor="x",
            timestamp=datetime(2026, 1, 1),
        )


def test_audit_log_merkle_root_changes_on_append() -> None:
    log = _log()
    log.append(event_type="t", actor="x")
    r1 = log.merkle_root()
    log.append(event_type="t", actor="x")
    r2 = log.merkle_root()
    assert r1 != r2


# --------------------------------------------------------------------------- #
# Offline transparency log
# --------------------------------------------------------------------------- #


def test_offline_transparency_log_dedupes_same_hash() -> None:
    tlog = OfflineTransparencyLog()
    h = "a" * 64
    a = tlog.submit(h)
    b = tlog.submit(h)
    assert a.log_index == b.log_index
    assert len(tuple(tlog.entries())) == 1


def test_offline_transparency_log_increments_indices() -> None:
    tlog = OfflineTransparencyLog()
    a = tlog.submit("a" * 64)
    b = tlog.submit("b" * 64)
    assert (a.log_index, b.log_index) == (0, 1)


def test_offline_transparency_log_rejects_short_hash() -> None:
    tlog = OfflineTransparencyLog()
    with pytest.raises(ValueError, match="64-char"):
        tlog.submit("short")


def test_offline_transparency_log_lookup_and_verify() -> None:
    tlog = OfflineTransparencyLog()
    entry = tlog.submit("c" * 64)
    assert tlog.lookup("c" * 64) == entry
    assert tlog.verify(entry) is True


# --------------------------------------------------------------------------- #
# Filesystem WORM
# --------------------------------------------------------------------------- #


def test_filesystem_worm_export_writes_and_seals(tmp_path: Path) -> None:
    log = _log()
    log.append(event_type="run.start", actor="system", payload={"x": 1})
    log.append(event_type="run.complete", actor="system", payload={"x": 2})

    rekor = OfflineTransparencyLog()
    entry = rekor.submit(log.merkle_root())

    exporter = FilesystemWormExporter(root=tmp_path)
    record = exporter.export(
        run_id=log.run_id,
        events=log.events,
        merkle_root=log.merkle_root(),
        rekor_entry=entry,
    )

    path = Path(record.path)
    assert path.exists()
    assert record.bytes_written > 0
    body = json.loads(path.read_text())
    assert body["merkle_root"] == log.merkle_root()
    assert body["rekor"]["log_index"] == entry.log_index
    assert len(body["events"]) == 2


def test_filesystem_worm_refuses_overwrite(tmp_path: Path) -> None:
    log = _log()
    log.append(event_type="t", actor="x")
    rekor = OfflineTransparencyLog()
    entry = rekor.submit(log.merkle_root())
    exporter = FilesystemWormExporter(root=tmp_path)
    exporter.export(
        run_id=log.run_id,
        events=log.events,
        merkle_root=log.merkle_root(),
        rekor_entry=entry,
    )
    with pytest.raises(FileExistsError):
        exporter.export(
            run_id=log.run_id,
            events=log.events,
            merkle_root=log.merkle_root(),
            rekor_entry=entry,
        )


def test_filesystem_worm_export_roundtrips_with_log_verify(tmp_path: Path) -> None:
    log = _log()
    for i in range(3):
        log.append(
            event_type="step.executed",
            actor="system",
            payload={"step": i},
            timestamp=datetime(2026, 5, 1, 12, i, tzinfo=UTC),
        )
    assert log.verify().valid is True
