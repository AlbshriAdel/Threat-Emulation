"""Minimal SHA-256 Merkle tree.

Self-contained so the audit layer doesn't pull in a crypto dep for the simple
case. Leaves are SHA-256 hex strings (the per-event payload hashes); inner
nodes are SHA-256 over the concatenation of their children. Odd-count layers
duplicate the last node (RFC 6962 style) so trees of any size produce a
deterministic root.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class InclusionProof:
    """A Merkle inclusion proof for a leaf at a given index."""

    leaf_index: int
    leaf_hash: str
    siblings: tuple[str, ...]
    directions: tuple[Literal["L", "R"], ...]
    root: str


def _sha(data: str) -> str:
    return hashlib.sha256(data.encode("ascii")).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Return the SHA-256 hex Merkle root over a list of hex leaves.

    Empty input returns the SHA-256 of the empty string (RFC 6962 convention).
    """
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    layer = list(leaves)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [_sha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def proof_for(leaves: list[str], index: int) -> InclusionProof:
    """Build an inclusion proof for ``leaves[index]``."""
    if not leaves:
        raise ValueError("cannot build a proof over zero leaves")
    if index < 0 or index >= len(leaves):
        raise IndexError(f"leaf index {index} out of range for {len(leaves)} leaves")
    layer = list(leaves)
    siblings: list[str] = []
    directions: list[Literal["L", "R"]] = []
    pos = index
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        sibling_pos = pos ^ 1
        siblings.append(layer[sibling_pos])
        directions.append("R" if pos % 2 == 0 else "L")
        layer = [_sha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        pos //= 2
    return InclusionProof(
        leaf_index=index,
        leaf_hash=leaves[index],
        siblings=tuple(siblings),
        directions=tuple(directions),
        root=layer[0],
    )


def verify_inclusion(proof: InclusionProof) -> bool:
    """Verify ``proof`` recomputes the recorded root."""
    if len(proof.siblings) != len(proof.directions):
        return False
    cursor = proof.leaf_hash
    for sibling, direction in zip(proof.siblings, proof.directions, strict=True):
        cursor = _sha(cursor + sibling) if direction == "R" else _sha(sibling + cursor)
    return cursor == proof.root
