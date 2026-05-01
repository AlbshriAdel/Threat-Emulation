"""Normalise MITRE ATT&CK STIX 2.1 bundles to canonical Pydantic models.

The relevant STIX object types are:

* ``attack-pattern``  -> :class:`TTP`
* ``intrusion-set``   -> :class:`Actor`
* ``relationship``    -> used to link Actors to TTPs (``relationship_type=uses``)
* ``malware`` / ``tool`` / ``course-of-action`` -> ignored at this layer
  (handled later by the graph builder).

We do not depend on the ``stix2`` library: the STIX bundle is a JSON object,
and we only need a tiny subset of fields. This keeps dependencies light and
makes the parser easy to test with synthetic fixtures.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from threat_emulation.schemas import TTP, Actor, Source
from threat_emulation.schemas.enums import ConfidenceLevel

ATTACK_FRAMEWORK_NAMES = frozenset({"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"})


@dataclass(frozen=True)
class AttackBundle:
    """Canonical view of an ATT&CK STIX bundle."""

    techniques: tuple[TTP, ...] = field(default_factory=tuple)
    actors: tuple[Actor, ...] = field(default_factory=tuple)


def normalize_attack_bundle(bundle: dict[str, Any], *, source: Source) -> AttackBundle:
    """Convert a STIX 2.1 bundle into canonical TTPs + Actors.

    Args:
        bundle: STIX bundle dict (``{"type": "bundle", "objects": [...]}``).
        source: Provenance attached to every produced object.

    Raises:
        ValueError: if ``bundle`` is not a STIX bundle.
    """
    if bundle.get("type") != "bundle":
        raise ValueError("Expected a STIX 2.1 'bundle' object")
    objects: list[dict[str, Any]] = list(bundle.get("objects", []))

    technique_by_stix_id: dict[str, TTP] = {}
    actor_by_stix_id: dict[str, dict[str, Any]] = {}

    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        otype = obj.get("type")
        if otype == "attack-pattern":
            ttp = _attack_pattern_to_ttp(obj, source)
            if ttp is not None:
                technique_by_stix_id[obj["id"]] = ttp
        elif otype == "intrusion-set":
            actor_by_stix_id[obj["id"]] = obj

    actor_ttps: dict[str, list[str]] = {sid: [] for sid in actor_by_stix_id}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref")
        tgt = obj.get("target_ref")
        if src in actor_by_stix_id and tgt in technique_by_stix_id:
            actor_ttps[src].append(technique_by_stix_id[tgt].technique_id)

    actors = tuple(
        _intrusion_set_to_actor(actor_by_stix_id[sid], actor_ttps[sid], source)
        for sid in actor_by_stix_id
    )
    return AttackBundle(
        techniques=tuple(technique_by_stix_id.values()),
        actors=actors,
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _attack_pattern_to_ttp(obj: dict[str, Any], source: Source) -> TTP | None:
    technique_id = _external_id(obj.get("external_references", []), ATTACK_FRAMEWORK_NAMES)
    if technique_id is None:
        return None
    tactic = _tactic_from_kill_chain(obj.get("kill_chain_phases", []))
    if tactic is None:
        return None
    return TTP(
        technique_id=technique_id,
        name=str(obj.get("name", technique_id)),
        tactic=tactic,
        description=str(obj.get("description", "")),
        confidence=ConfidenceLevel.HIGH,
        sources=(source,),
        first_seen=_parse_dt(obj.get("created")),
        last_seen=_parse_dt(obj.get("modified")),
    )


def _intrusion_set_to_actor(obj: dict[str, Any], techniques: list[str], source: Source) -> Actor:
    primary_name = str(obj.get("name", "unknown"))
    aliases = frozenset({str(a) for a in obj.get("aliases", []) if str(a) != primary_name})
    group_id = _external_id(obj.get("external_references", []), ATTACK_FRAMEWORK_NAMES)
    return Actor(
        primary_name=primary_name,
        attack_group_id=group_id,
        aliases=aliases,
        techniques=tuple(dict.fromkeys(techniques)),
        sources=(source,),
    )


def _external_id(refs: Iterable[dict[str, Any]], frameworks: frozenset[str]) -> str | None:
    for ref in refs:
        if ref.get("source_name") in frameworks:
            ext_id = ref.get("external_id")
            if isinstance(ext_id, str):
                return ext_id
    return None


def _tactic_from_kill_chain(phases: Iterable[dict[str, Any]]) -> str | None:
    for phase in phases:
        if phase.get("kill_chain_name") in ATTACK_FRAMEWORK_NAMES:
            name = phase.get("phase_name")
            if isinstance(name, str):
                return name
    return None


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    cleaned = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
