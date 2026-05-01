"""Weighted, transparent technique prioritisation.

The score is a linear combination of named components so a human reviewer
can audit *why* a technique was prioritised. Weights are loaded from
``config/prioritization.yaml`` (or a ``PrioritizationWeights`` instance) - never
hard-coded. Time-decay on CTI recency keeps stale intel from dominating.

    score(T) = w1 * cti_freq(T)
             + w2 * kev_overlap(T)
             + w3 * actor_ttp_match(T)
             + w4 * detection_gap(T)

Component normalisation: each component is rescaled to ``[0, 1]`` across the
candidate pool so weights are interpretable and comparable.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from threat_emulation.agent.state import RetrievedChunkRef, ScoredTechnique
from threat_emulation.rag.graph import AttackGraph

DEFAULT_HALF_LIFE_DAYS = 90.0


class PrioritizationWeights(BaseModel):
    """Weights for the prioritisation linear combination.

    All weights default to ``1.0``. The final score is normalised to ``[0, 1]``
    after weighting, so absolute weight values matter only relative to one
    another.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    cti_freq: float = Field(default=1.0, ge=0.0)
    kev_overlap: float = Field(default=1.0, ge=0.0)
    actor_ttp_match: float = Field(default=1.0, ge=0.0)
    detection_gap: float = Field(default=1.0, ge=0.0)
    half_life_days: float = Field(default=DEFAULT_HALF_LIFE_DAYS, gt=0.0)

    @model_validator(mode="after")
    def _at_least_one_nonzero(self) -> PrioritizationWeights:
        if (
            self.cti_freq == 0.0
            and self.kev_overlap == 0.0
            and self.actor_ttp_match == 0.0
            and self.detection_gap == 0.0
        ):
            raise ValueError("At least one prioritisation weight must be > 0")
        return self

    @classmethod
    def from_yaml(cls, path: Path | str) -> PrioritizationWeights:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)


def score_techniques(
    *,
    candidates: list[str],
    retrieved: list[RetrievedChunkRef],
    graph: AttackGraph | None = None,
    actor_node: str | None = None,
    kev_cves: frozenset[str] = frozenset(),
    detection_gaps: frozenset[str] = frozenset(),
    weights: PrioritizationWeights | None = None,
    now: datetime | None = None,
) -> list[ScoredTechnique]:
    """Compute scored techniques for the supplied candidates.

    Args:
        candidates: Technique ids to score.
        retrieved: Retrieved chunk references (used for CTI frequency + citations).
        graph: Optional ATT&CK graph (used for actor-TTP matching).
        actor_node: Optional actor node id for the actor-TTP-match component.
        kev_cves: CVE ids present in the KEV catalog (used as a coarse signal).
        detection_gaps: Technique ids known to lack detection coverage.
        weights: Prioritisation weights; defaults to all-ones.
        now: Reference time for time-decay; defaults to UTC now.

    Returns:
        Scored techniques in descending score order.
    """
    if not candidates:
        return []
    weights = weights or PrioritizationWeights()
    now = now or datetime.now(UTC)

    raw_components: dict[str, dict[str, float]] = {tid: {} for tid in candidates}
    cited_chunks: dict[str, set[str]] = {tid: set() for tid in candidates}
    cited_actors: dict[str, set[str]] = {tid: set() for tid in candidates}

    # CTI frequency with time-decay.
    cti_counts = _cti_frequency(
        candidates, retrieved, half_life_days=weights.half_life_days, now=now
    )
    for tid, count in cti_counts.items():
        raw_components[tid]["cti_freq"] = count
    for ref in retrieved:
        for tid in ref.technique_ids:
            if tid in candidates:
                cited_chunks[tid].add(str(ref.chunk_id))

    # KEV overlap: 1 if any retrieved chunk for this technique mentions a KEV CVE.
    for tid in candidates:
        overlap = 0.0
        for ref in retrieved:
            if tid not in ref.technique_ids:
                continue
            if any(cve.lower() in ref.excerpt.lower() for cve in kev_cves):
                overlap = 1.0
                break
        raw_components[tid]["kev_overlap"] = overlap

    # Actor-TTP match: 1 if the actor is known to use the technique, else 0.
    actor_techniques: frozenset[str] = frozenset()
    if graph is not None and actor_node is not None and actor_node in graph.graph:
        actor_techniques = frozenset(
            t
            for _, t, data in graph.graph.out_edges(actor_node, data=True)
            if data.get("relation") == "uses"
        )
    for tid in candidates:
        match = 1.0 if tid in actor_techniques else 0.0
        raw_components[tid]["actor_ttp_match"] = match
        if match and actor_node is not None:
            cited_actors[tid].add(actor_node)

    # Detection gap: 1 if the technique is in the gap set.
    for tid in candidates:
        raw_components[tid]["detection_gap"] = 1.0 if tid in detection_gaps else 0.0

    normalised = _normalise_components(raw_components)

    weight_map: Mapping[str, float] = {
        "cti_freq": weights.cti_freq,
        "kev_overlap": weights.kev_overlap,
        "actor_ttp_match": weights.actor_ttp_match,
        "detection_gap": weights.detection_gap,
    }
    weight_total = sum(weight_map.values()) or 1.0

    scored: list[ScoredTechnique] = []
    tactic_lookup = _tactic_lookup(graph)
    for tid in candidates:
        comps = normalised[tid]
        weighted = sum(weight_map[name] * comps[name] for name in weight_map)
        final = weighted / weight_total  # always in [0, 1]
        scored.append(
            ScoredTechnique(
                technique_id=tid,
                tactic=tactic_lookup.get(tid),
                score=final,
                components=tuple(sorted(comps.items())),
                cited_chunk_ids=(),  # populated below
                cited_actors=tuple(sorted(cited_actors[tid])),
            )
        )
    # Fill cited_chunk_ids by re-creating the model (frozen).
    from uuid import UUID as _UUID

    enriched: list[ScoredTechnique] = []
    for s in scored:
        cids = tuple(_UUID(c) for c in sorted(cited_chunks[s.technique_id]))
        enriched.append(s.model_copy(update={"cited_chunk_ids": cids}))
    enriched.sort(key=lambda s: s.score, reverse=True)
    return enriched


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _cti_frequency(
    candidates: list[str],
    retrieved: list[RetrievedChunkRef],
    *,
    half_life_days: float,
    now: datetime,
) -> dict[str, float]:
    counts: dict[str, float] = dict.fromkeys(candidates, 0.0)
    for ref in retrieved:
        # The state-level RetrievedChunkRef does not carry source published_at;
        # we treat each citation as recent (decay = 1.0). When the planner is
        # given dated retrieval results, a future change will weight per chunk.
        decay = _decay(now, now, half_life_days)
        for tid in ref.technique_ids:
            if tid in counts:
                counts[tid] += decay
    return counts


def _decay(reference: datetime, observed: datetime, half_life_days: float) -> float:
    """Exponential decay; returns 1.0 when ``observed == reference``."""
    if half_life_days <= 0:
        return 1.0
    delta: timedelta = reference - observed
    age_days = max(0.0, delta.total_seconds() / 86400.0)
    return math.exp(-math.log(2) * age_days / half_life_days)


def _normalise_components(
    raw: dict[str, dict[str, float]],
) -> dict[str, dict[str, float]]:
    """Min-max normalise each component independently to ``[0, 1]``."""
    component_names = next(iter(raw.values()), {}).keys()
    maxima: dict[str, float] = dict.fromkeys(component_names, 0.0)
    for comps in raw.values():
        for name, value in comps.items():
            if value > maxima[name]:
                maxima[name] = value
    out: dict[str, dict[str, float]] = {}
    for tid, comps in raw.items():
        out[tid] = {
            name: (value / maxima[name]) if maxima[name] > 0 else 0.0
            for name, value in comps.items()
        }
    return out


def _tactic_lookup(graph: AttackGraph | None) -> dict[str, str]:
    """Return a {technique_id -> tactic} map from the graph (if provided)."""
    if graph is None:
        return {}
    out: dict[str, str] = {}
    for node, attrs in graph.graph.nodes(data=True):
        if attrs.get("kind") != "technique":
            continue
        tactic = attrs.get("tactic")
        if isinstance(tactic, str):
            out[node] = tactic
    return out
