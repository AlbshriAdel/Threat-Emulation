"""ATT&CK graph: actors and techniques as a directed graph.

Nodes carry a ``kind`` attribute (``actor`` or ``technique``); edges carry
a ``relation`` attribute (``uses``). Built directly from the canonical
:class:`Actor` / :class:`TTP` models so the graph is a pure projection of
the canonical schema, not a parallel data model.

The graph supports the planner's "actor -> technique" traversal, ranking
techniques by inbound actor count, and exporting subgraph paths used as
provenance in retrieval results.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

import networkx as nx

from threat_emulation.schemas import TTP, Actor


@dataclass(frozen=True)
class GraphPath:
    """A path through the ATT&CK graph used as provenance."""

    nodes: tuple[str, ...]
    relations: tuple[str, ...]


class AttackGraph:
    """Directed multigraph over canonical ATT&CK objects."""

    def __init__(self) -> None:
        self._g: nx.MultiDiGraph[str] = nx.MultiDiGraph()

    def add_techniques(self, techniques: Iterable[TTP]) -> None:
        for ttp in techniques:
            self._g.add_node(
                ttp.technique_id,
                kind="technique",
                name=ttp.name,
                tactic=ttp.tactic,
            )

    def add_actors(self, actors: Iterable[Actor]) -> None:
        for actor in actors:
            actor_node = self._actor_node_id(actor)
            self._g.add_node(
                actor_node,
                kind="actor",
                name=actor.primary_name,
                aliases=tuple(sorted(actor.aliases)),
                attack_group_id=actor.attack_group_id,
            )
            for technique_id in actor.techniques:
                if technique_id not in self._g:
                    # Forward-declare the technique node; will be enriched if /
                    # when the technique is added explicitly.
                    self._g.add_node(technique_id, kind="technique")
                self._g.add_edge(actor_node, technique_id, relation="uses")

    def techniques_for_actor(self, actor: Actor) -> tuple[str, ...]:
        actor_node = self._actor_node_id(actor)
        if actor_node not in self._g:
            return ()
        return tuple(
            target
            for _, target, data in self._g.out_edges(actor_node, data=True)
            if data.get("relation") == "uses"
        )

    def actors_for_technique(self, technique_id: str) -> tuple[str, ...]:
        if technique_id not in self._g:
            return ()
        return tuple(
            sorted(
                src
                for src, _, data in self._g.in_edges(technique_id, data=True)
                if data.get("relation") == "uses"
            )
        )

    def technique_frequency(self) -> dict[str, int]:
        """How many actors use each technique. Higher = more cross-actor signal."""
        freq: dict[str, int] = {}
        for node, attrs in self._g.nodes(data=True):
            if attrs.get("kind") != "technique":
                continue
            freq[node] = self._g.in_degree(node)
        return freq

    def path(self, source: str, target: str) -> GraphPath | None:
        """Return the shortest path from ``source`` to ``target`` if any."""
        if source not in self._g or target not in self._g:
            return None
        try:
            nodes = nx.shortest_path(self._g, source=source, target=target)
        except nx.NetworkXNoPath:
            return None
        relations: list[str] = []
        for prev, nxt in pairwise(nodes):
            edge_data = self._g.get_edge_data(prev, nxt) or {}
            # MultiDiGraph: pick the first edge's relation.
            first = next(iter(edge_data.values()), {})
            relations.append(str(first.get("relation", "")))
        return GraphPath(nodes=tuple(nodes), relations=tuple(relations))

    def __len__(self) -> int:
        return self._g.number_of_nodes()

    @property
    def graph(self) -> nx.MultiDiGraph[str]:
        """Read-only access to the underlying NetworkX graph."""
        return self._g

    @staticmethod
    def _actor_node_id(actor: Actor) -> str:
        if actor.attack_group_id:
            return actor.attack_group_id
        return f"actor:{actor.primary_name}"
