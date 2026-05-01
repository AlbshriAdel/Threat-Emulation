"""WORM (Write-Once-Read-Many) export of audit batches.

A :class:`WormExporter` writes a finalised batch of audit events plus the
batch's Merkle root + transparency-log inclusion proof to a storage tier
that resists modification. The default :class:`FilesystemWormExporter`:

* writes the batch JSON to a unique path under the export root,
* sets the file mode to ``0o440`` after writing so the running user can
  read but not modify it (an attacker with root or with ``chmod`` on the
  user can still tamper - production deployments use S3 Object Lock or
  an immutable volume to back this stop-gap).

A live S3 Object Lock exporter lands in Phase 4.5 with cassette tests.
"""

from __future__ import annotations

import json
import os
import stat
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from threat_emulation.audit.rekor import RekorEntry
from threat_emulation.schemas import AuditEvent


@dataclass(frozen=True)
class ExportRecord:
    """Metadata returned after a successful export."""

    run_id: UUID
    path: str
    bytes_written: int
    merkle_root: str
    rekor_log_index: int
    completed_at: datetime
    sealed: bool
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)


class WormExporter(ABC):
    """Write-once exporter for audit batches."""

    @abstractmethod
    def export(
        self,
        *,
        run_id: UUID,
        events: Iterable[AuditEvent],
        merkle_root: str,
        rekor_entry: RekorEntry,
    ) -> ExportRecord:
        """Persist a finalised audit batch."""


class FilesystemWormExporter(WormExporter):
    """WORM exporter backed by a directory on the local filesystem."""

    def __init__(self, *, root: Path | str, file_mode: int = 0o440) -> None:
        self._root = Path(root)
        self._file_mode = file_mode
        self._root.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        *,
        run_id: UUID,
        events: Iterable[AuditEvent],
        merkle_root: str,
        rekor_entry: RekorEntry,
    ) -> ExportRecord:
        if len(merkle_root) != 64:
            raise ValueError("merkle_root must be 64-char SHA-256 hex")
        events_list = [e.model_dump(mode="json") for e in events]
        body = {
            "run_id": str(run_id),
            "merkle_root": merkle_root,
            "rekor": {
                "log_index": rekor_entry.log_index,
                "body_hash": rekor_entry.body_hash,
                "submitted_at": rekor_entry.submitted_at.isoformat(),
            },
            "events": events_list,
        }
        encoded = json.dumps(body, sort_keys=True, indent=2)
        path = self._root / f"{run_id}.json"
        if path.exists():
            raise FileExistsError(f"refusing to overwrite existing WORM export at {path}")
        path.write_text(encoded, encoding="utf-8")
        sealed = self._seal(path)
        return ExportRecord(
            run_id=run_id,
            path=str(path),
            bytes_written=len(encoded.encode("utf-8")),
            merkle_root=merkle_root,
            rekor_log_index=rekor_entry.log_index,
            completed_at=datetime.now(UTC),
            sealed=sealed,
            metadata=(("backend", "filesystem"),),
        )

    def _seal(self, path: Path) -> bool:
        """Best-effort chmod to make the file read-only for owner / group."""
        try:
            os.chmod(path, self._file_mode & (stat.S_IRUSR | stat.S_IRGRP))
        except OSError:
            return False
        return True
