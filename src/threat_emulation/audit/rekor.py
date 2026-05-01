"""Transparency log interface and offline implementation.

The :class:`TransparencyLog` interface mirrors the subset of Sigstore Rekor
operations the framework needs: submit a Merkle root and verify an
inclusion proof. The :class:`OfflineTransparencyLog` is the in-memory
implementation used by tests, the eval harness, and air-gapped deployments
where the upstream Rekor public-good instance is unreachable.

A live :class:`RekorClient` lands in Phase 4.5 with cassette-based HTTP
tests so the wire format is locked down.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class RekorEntry:
    """An entry submitted to the transparency log."""

    log_index: int
    body_hash: str
    submitted_at: datetime


class TransparencyLog(ABC):
    """Sigstore Rekor-style transparency log."""

    @abstractmethod
    def submit(self, body_hash: str) -> RekorEntry:
        """Submit a hash and return its log entry."""

    @abstractmethod
    def lookup(self, body_hash: str) -> RekorEntry | None:
        """Return the entry for ``body_hash`` if it exists, else None."""

    @abstractmethod
    def entries(self) -> Iterable[RekorEntry]:
        """Iterate all submitted entries in submission order."""

    def verify(self, entry: RekorEntry) -> bool:
        """True if ``entry`` is recorded in the log with matching body_hash."""
        recorded = self.lookup(entry.body_hash)
        if recorded is None:
            return False
        return recorded.log_index == entry.log_index


@dataclass
class OfflineTransparencyLog(TransparencyLog):
    """Append-only in-memory transparency log."""

    _entries: list[RekorEntry] = field(default_factory=list)
    _by_hash: dict[str, RekorEntry] = field(default_factory=dict)

    def submit(self, body_hash: str) -> RekorEntry:
        if not isinstance(body_hash, str) or len(body_hash) != 64:
            raise ValueError("body_hash must be 64-char SHA-256 hex")
        existing = self._by_hash.get(body_hash)
        if existing is not None:
            return existing
        entry = RekorEntry(
            log_index=len(self._entries),
            body_hash=body_hash,
            submitted_at=datetime.now(UTC),
        )
        self._entries.append(entry)
        self._by_hash[body_hash] = entry
        return entry

    def lookup(self, body_hash: str) -> RekorEntry | None:
        return self._by_hash.get(body_hash)

    def entries(self) -> Iterable[RekorEntry]:
        return tuple(self._entries)

    def head_hash(self) -> str:
        """SHA-256 over the concatenation of recorded body hashes.

        Useful for snapshot diffing in tests.
        """
        joined = "".join(e.body_hash for e in self._entries)
        return hashlib.sha256(joined.encode("ascii")).hexdigest()
