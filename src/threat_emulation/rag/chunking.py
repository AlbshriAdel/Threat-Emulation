"""Text chunking with provenance.

A :class:`Chunk` is the smallest retrievable unit. It carries (a) the chunk
text, (b) the originating :class:`Source`, and (c) the TLP. Without all
three the retriever refuses to operate on it (see :mod:`rag.retriever`).

Chunking is paragraph-aware with a configurable target size and overlap. We
deliberately keep this simple - production deployments can swap a smarter
splitter behind the same dataclass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from threat_emulation.schemas import Source
from threat_emulation.schemas.enums import TLP

_PARAGRAPH = re.compile(r"\n\s*\n")
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class Chunk:
    """A retrievable text chunk with full provenance."""

    id: UUID
    text: str
    source: Source
    tlp: TLP
    technique_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @property
    def restricted(self) -> bool:
        """True when the chunk's TLP forbids egress to third-party APIs."""
        return self.tlp.restricted


def chunk_text(
    text: str,
    *,
    source: Source,
    tlp: TLP | None = None,
    target_chars: int = 800,
    overlap_chars: int = 100,
    technique_ids: tuple[str, ...] = (),
) -> list[Chunk]:
    """Split ``text`` into provenance-bearing chunks.

    Splits on paragraph boundaries first, then packs paragraphs into chunks of
    roughly ``target_chars``. If a paragraph exceeds ``target_chars`` it is
    further split on whitespace with ``overlap_chars`` overlap between pieces.

    Args:
        text: Raw text to chunk.
        source: Provenance for every produced chunk.
        tlp: TLP override; defaults to the source's TLP.
        target_chars: Target chunk length in characters (1 <= target).
        overlap_chars: Overlap between forced sub-splits (0 <= overlap < target).
        technique_ids: Optional ATT&CK technique tags to apply to every chunk.
    """
    if target_chars <= 0:
        raise ValueError("target_chars must be positive")
    if overlap_chars < 0 or overlap_chars >= target_chars:
        raise ValueError("overlap_chars must satisfy 0 <= overlap < target_chars")
    effective_tlp = tlp or source.tlp

    paragraphs = [p.strip() for p in _PARAGRAPH.split(text) if p.strip()]
    if not paragraphs:
        return []

    chunks: list[str] = []
    buffer = ""
    for para in paragraphs:
        para = _WHITESPACE.sub(" ", para)
        if len(para) > target_chars:
            if buffer:
                chunks.append(buffer)
                buffer = ""
            chunks.extend(_split_long(para, target_chars, overlap_chars))
            continue
        candidate = f"{buffer}\n\n{para}".strip() if buffer else para
        if len(candidate) <= target_chars:
            buffer = candidate
        else:
            if buffer:
                chunks.append(buffer)
            buffer = para
    if buffer:
        chunks.append(buffer)

    return [
        Chunk(
            id=uuid4(),
            text=body,
            source=source,
            tlp=effective_tlp,
            technique_ids=tuple(technique_ids),
        )
        for body in chunks
    ]


def _split_long(paragraph: str, target: int, overlap: int) -> list[str]:
    pieces: list[str] = []
    step = max(1, target - overlap)
    for start in range(0, len(paragraph), step):
        piece = paragraph[start : start + target].strip()
        if piece:
            pieces.append(piece)
        if start + target >= len(paragraph):
            break
    return pieces
