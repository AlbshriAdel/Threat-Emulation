"""Merkle-chained audit log over typed AuditEvent records.

Wraps the canonical :class:`~threat_emulation.schemas.AuditEvent` schema and
enforces the chain invariant: ``previous_hash`` of event N equals the SHA-256
of event N-1's canonical payload, and event 0's ``previous_hash`` is the
genesis hash (64 zeros).

Verification recomputes the chain end-to-end and reports the first mismatch
(if any), so callers can pinpoint tampering in stored or replayed logs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from threat_emulation.audit.merkle import merkle_root
from threat_emulation.schemas import AuditEvent

GENESIS_PREVIOUS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditLogVerification:
    """Outcome of replaying a chain end-to-end."""

    valid: bool
    events_checked: int
    first_invalid_sequence: int | None = None
    error: str | None = None


def canonical_payload_hash(payload: dict[str, Any]) -> str:
    """SHA-256 hex over the canonical JSON of an audit payload."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _event_chain_hash(event: AuditEvent) -> str:
    """Hash that the *next* event records as its previous_hash.

    Defined over a stable subset of fields (sequence, payload_hash,
    timestamp, scope_of_engagement_hash, previous_hash) so re-serialising
    elsewhere doesn't change the chain.
    """
    chained = {
        "sequence": event.sequence,
        "payload_hash": event.payload_hash,
        "timestamp": event.timestamp.isoformat(),
        "scope_of_engagement_hash": event.scope_of_engagement_hash,
        "previous_hash": event.previous_hash,
    }
    return canonical_payload_hash(chained)


@dataclass
class AuditLog:
    """Append-only, Merkle-chained log bound to a single run."""

    run_id: UUID
    scope_of_engagement_hash: str
    _events: list[AuditEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.scope_of_engagement_hash) != 64:
            raise ValueError("scope_of_engagement_hash must be 64-char SHA-256 hex")

    def append(
        self,
        *,
        event_type: str,
        actor: str,
        payload: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEvent:
        """Append a new event with the correct chain linkage and return it."""
        body: dict[str, Any] = payload or {}
        ts = timestamp or datetime.now(UTC)
        if ts.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        previous = _event_chain_hash(self._events[-1]) if self._events else GENESIS_PREVIOUS_HASH
        event = AuditEvent(
            run_id=self.run_id,
            sequence=len(self._events),
            timestamp=ts,
            event_type=event_type,
            actor=actor,
            payload_hash=canonical_payload_hash(body),
            previous_hash=previous,
            scope_of_engagement_hash=self.scope_of_engagement_hash,
            payload=body,
        )
        self._events.append(event)
        return event

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def merkle_root(self) -> str:
        """Merkle root over per-event chain hashes."""
        leaves = [_event_chain_hash(e) for e in self._events]
        return merkle_root(leaves)

    def verify(self) -> AuditLogVerification:
        """Walk the chain; return verification status."""
        previous = GENESIS_PREVIOUS_HASH
        for i, event in enumerate(self._events):
            if event.sequence != i:
                return AuditLogVerification(
                    valid=False,
                    events_checked=i,
                    first_invalid_sequence=i,
                    error=f"sequence mismatch: expected {i}, got {event.sequence}",
                )
            if event.previous_hash != previous:
                return AuditLogVerification(
                    valid=False,
                    events_checked=i,
                    first_invalid_sequence=i,
                    error=(
                        f"chain break at sequence {i}: previous_hash "
                        f"{event.previous_hash[:8]}... != expected {previous[:8]}..."
                    ),
                )
            recomputed = canonical_payload_hash(event.payload)
            if recomputed != event.payload_hash:
                return AuditLogVerification(
                    valid=False,
                    events_checked=i,
                    first_invalid_sequence=i,
                    error=f"payload hash mismatch at sequence {i}",
                )
            if event.scope_of_engagement_hash != self.scope_of_engagement_hash:
                return AuditLogVerification(
                    valid=False,
                    events_checked=i,
                    first_invalid_sequence=i,
                    error=f"scope binding mismatch at sequence {i}",
                )
            previous = _event_chain_hash(event)
        return AuditLogVerification(valid=True, events_checked=len(self._events))
