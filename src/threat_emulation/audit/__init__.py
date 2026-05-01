"""Tamper-evident audit pipeline.

Per ADR-0001 D9 the audit pipeline has three stages:

1. :class:`AuditLog` builds a Merkle-chained sequence of typed
   :class:`~threat_emulation.schemas.AuditEvent` records, one per
   significant action (intel ingest, retrieval, agent tool call, approval,
   execution, teardown).
2. The Merkle root is published to a :class:`TransparencyLog`. The default
   :class:`OfflineTransparencyLog` is in-memory (tests, air-gapped). A
   :class:`RekorClient` adapter lands in Phase 4.5 with cassette tests.
3. Batches export to a :class:`WormExporter`. The default
   :class:`FilesystemWormExporter` writes append-only files and chmods
   them ``0o440`` so the artefact is immutable to the running user.
"""

from threat_emulation.audit.log import (
    AuditLog,
    AuditLogVerification,
)
from threat_emulation.audit.merkle import (
    InclusionProof,
    merkle_root,
    proof_for,
    verify_inclusion,
)
from threat_emulation.audit.rekor import (
    OfflineTransparencyLog,
    RekorEntry,
    TransparencyLog,
)
from threat_emulation.audit.worm import (
    ExportRecord,
    FilesystemWormExporter,
    WormExporter,
)

__all__ = [
    "AuditLog",
    "AuditLogVerification",
    "ExportRecord",
    "FilesystemWormExporter",
    "InclusionProof",
    "OfflineTransparencyLog",
    "RekorEntry",
    "TransparencyLog",
    "WormExporter",
    "merkle_root",
    "proof_for",
    "verify_inclusion",
]
