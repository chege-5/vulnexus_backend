from __future__ import annotations

"""Threat knowledge graph primitives for correlated findings and security intelligence."""

from dataclasses import dataclass, field
from typing import Any

from app.services.integrations.cache import cache


@dataclass(slots=True)
class GraphNode:
    id: str
    kind: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


class ThreatKnowledgeGraph:
    def __init__(self, namespace: str = "threat-graph") -> None:
        self.namespace = namespace
        self._graphs: dict[str, dict[str, list[dict[str, Any]]]] = {}

    async def load(self, graph_id: str) -> dict[str, list[dict[str, Any]]]:
        cached = await cache.get_json(cache.build_key(self.namespace, graph_id))
        if cached:
            self._graphs[graph_id] = cached
            return cached
        return self._graphs.setdefault(graph_id, {"nodes": [], "edges": []})

    async def save(self, graph_id: str) -> dict[str, list[dict[str, Any]]]:
        graph = self._graphs.setdefault(graph_id, {"nodes": [], "edges": []})
        await cache.set_json(cache.build_key(self.namespace, graph_id), graph)
        return graph

    async def add_node(self, graph_id: str, node: GraphNode) -> None:
        graph = self._graphs.setdefault(graph_id, {"nodes": [], "edges": []})
        if not any(item["id"] == node.id for item in graph["nodes"]):
            graph["nodes"].append({"id": node.id, "kind": node.kind, "label": node.label, "metadata": node.metadata})
        await self.save(graph_id)

    async def add_edge(self, graph_id: str, edge: GraphEdge) -> None:
        graph = self._graphs.setdefault(graph_id, {"nodes": [], "edges": []})
        if not any(
            item["source"] == edge.source and item["target"] == edge.target and item["relation"] == edge.relation
            for item in graph["edges"]
        ):
            graph["edges"].append({"source": edge.source, "target": edge.target, "relation": edge.relation, "weight": edge.weight, "metadata": edge.metadata})
        await self.save(graph_id)

    async def link(self, graph_id: str, left: GraphNode, right: GraphNode, relation: str, *, weight: float = 1.0, metadata: dict[str, Any] | None = None) -> None:
        await self.add_node(graph_id, left)
        await self.add_node(graph_id, right)
        await self.add_edge(graph_id, GraphEdge(source=left.id, target=right.id, relation=relation, weight=weight, metadata=metadata or {}))

    async def query(self, graph_id: str, *, kind: str | None = None, relation: str | None = None) -> list[dict[str, Any]]:
        graph = await self.load(graph_id)
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        if kind:
            nodes = [node for node in nodes if node.get("kind") == kind]
        if relation:
            edges = [edge for edge in edges if edge.get("relation") == relation]
        return [{"nodes": nodes, "edges": edges}]


threat_graph = ThreatKnowledgeGraph()
