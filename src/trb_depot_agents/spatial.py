from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from heapq import heappop, heappush
from typing import Any


@dataclass(frozen=True)
class Track:
    track_id: str
    capacity: int


@dataclass(frozen=True)
class Route:
    route_id: str
    origin: str
    destination: str
    resources: tuple[str, ...]
    edge_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class SpatialNode:
    node_id: str
    node_type: str = "generic"


@dataclass(frozen=True)
class SpatialEdge:
    edge_id: str
    origin: str
    destination: str
    resources: tuple[str, ...] = ()
    travel_s: int = 0
    disabled: bool = False


@dataclass(frozen=True)
class Occupation:
    object_id: str
    resource_id: str
    start_s: int
    end_s: int


@dataclass
class SpatialModel:
    tracks: dict[str, Track]
    routes: dict[str, Route]
    incompatible_resource_pairs: set[frozenset[str]] = field(default_factory=set)
    nodes: dict[str, SpatialNode] = field(default_factory=dict)
    edges: dict[str, SpatialEdge] = field(default_factory=dict)
    switch_locks: set[frozenset[str]] = field(default_factory=set)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SpatialModel":
        tracks = {
            item["track_id"]: Track(item["track_id"], int(item["capacity"]))
            for item in payload.get("tracks", [])
        }
        routes = {
            item["route_id"]: Route(
                item["route_id"],
                item["origin"],
                item["destination"],
                tuple(item.get("resources", [])),
                tuple(item.get("edge_ids", [])),
            )
            for item in payload.get("routes", [])
        }
        pairs = {
            frozenset(map(str, item))
            for item in payload.get("incompatible_resource_pairs", [])
        }
        nodes = {
            item["node_id"]: SpatialNode(item["node_id"], str(item.get("node_type", "generic")))
            for item in payload.get("nodes", [])
        }
        edges = {
            item["edge_id"]: SpatialEdge(
                item["edge_id"],
                item["origin"],
                item["destination"],
                tuple(item.get("resources", [])),
                int(item.get("travel_s", 0)),
                bool(item.get("disabled", False)),
            )
            for item in payload.get("edges", [])
        }
        locks = {frozenset(map(str, item)) for item in payload.get("switch_locks", [])}
        for route in routes.values():
            nodes.setdefault(route.origin, SpatialNode(route.origin))
            nodes.setdefault(route.destination, SpatialNode(route.destination))
        return cls(
            tracks=tracks,
            routes=routes,
            incompatible_resource_pairs=pairs,
            nodes=nodes,
            edges=edges,
            switch_locks=locks,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tracks": [
                {"track_id": item.track_id, "capacity": item.capacity}
                for item in sorted(self.tracks.values(), key=lambda item: item.track_id)
            ],
            "routes": [
                {
                    "route_id": item.route_id,
                    "origin": item.origin,
                    "destination": item.destination,
                    "resources": list(item.resources),
                    "edge_ids": list(item.edge_ids),
                }
                for item in sorted(self.routes.values(), key=lambda item: item.route_id)
            ],
            "nodes": [
                {"node_id": item.node_id, "node_type": item.node_type}
                for item in sorted(self.nodes.values(), key=lambda item: item.node_id)
            ],
            "edges": [
                {
                    "edge_id": item.edge_id,
                    "origin": item.origin,
                    "destination": item.destination,
                    "resources": list(item.resources),
                    "travel_s": item.travel_s,
                    "disabled": item.disabled,
                }
                for item in sorted(self.edges.values(), key=lambda item: item.edge_id)
            ],
            "incompatible_resource_pairs": [
                sorted(item)
                for item in sorted(
                    self.incompatible_resource_pairs,
                    key=lambda item: tuple(sorted(item)),
                )
            ],
            "switch_locks": [
                sorted(item)
                for item in sorted(
                    self.switch_locks,
                    key=lambda item: tuple(sorted(item)),
                )
            ],
        }

    def fingerprint(self) -> str:
        from .integrity import sha256_digest

        return sha256_digest(self.to_dict())


@dataclass(frozen=True)
class SpatialFailure:
    failure_type: str
    object_ids: tuple[str, ...]
    resource_id: str | None = None


class SpatialChecker:
    def __init__(self, model: SpatialModel) -> None:
        self.model = model

    @staticmethod
    def _overlap(left: Occupation, right: Occupation) -> bool:
        return max(left.start_s, right.start_s) < min(left.end_s, right.end_s)

    def check_route(
        self,
        *,
        object_id: str,
        route_id: str,
        origin: str,
        destination: str,
    ) -> list[SpatialFailure]:
        route = self.model.routes.get(route_id)
        if route is None:
            return [SpatialFailure("unknown_route", (object_id,), route_id)]
        if route.origin != origin or route.destination != destination:
            return [SpatialFailure("route_endpoint", (object_id,), route_id)]
        if route.edge_ids:
            return self.check_route_continuity(
                object_id=object_id,
                edge_ids=list(route.edge_ids),
                origin=origin,
                destination=destination,
            )
        return []

    def shortest_path(
        self,
        origin: str,
        destination: str,
        *,
        disabled_resources: set[str] | None = None,
        disabled_edges: set[str] | None = None,
        start_s: int = 0,
        occupations: list[Occupation] | None = None,
    ) -> tuple[str, ...] | None:
        disabled = disabled_resources or set()
        blocked_edges = disabled_edges or set()
        occupied = occupations or []
        graph: dict[str, list[SpatialEdge]] = defaultdict(list)
        for edge in self.model.edges.values():
            if (
                edge.disabled
                or edge.edge_id in blocked_edges
                or set(edge.resources) & disabled
            ):
                continue
            graph[edge.origin].append(edge)
        queue: list[tuple[int, str, tuple[str, ...]]] = [(0, origin, ())]
        best: dict[str, int] = {}
        while queue:
            cost, node, path = heappop(queue)
            if node == destination:
                return path
            if node in best and best[node] <= cost:
                continue
            best[node] = cost
            for edge in graph.get(node, []):
                # 防退化：零时长边会绕过时间占用检查，公开图搜索至少按一个离散时间单位处理。
                weight = max(edge.travel_s, 1)
                entry_s = start_s + cost
                exit_s = entry_s + weight
                if any(
                    occupation.resource_id in edge.resources
                    and max(entry_s, occupation.start_s)
                    < min(exit_s, occupation.end_s)
                    for occupation in occupied
                ):
                    continue
                heappush(
                    queue,
                    (cost + weight, edge.destination, (*path, edge.edge_id)),
                )
        return None

    def check_route_continuity(
        self,
        *,
        object_id: str,
        edge_ids: list[str],
        origin: str,
        destination: str,
    ) -> list[SpatialFailure]:
        if not edge_ids:
            return [SpatialFailure("route_continuity", (object_id,), None)]
        edges: list[SpatialEdge] = []
        for edge_id in edge_ids:
            edge = self.model.edges.get(edge_id)
            if edge is None:
                return [SpatialFailure("unknown_edge", (object_id,), edge_id)]
            edges.append(edge)
        disabled_edge = next((edge for edge in edges if edge.disabled), None)
        if disabled_edge is not None:
            return [
                SpatialFailure(
                    "disabled_edge",
                    (object_id,),
                    disabled_edge.edge_id,
                )
            ]
        if edges[0].origin != origin or edges[-1].destination != destination:
            return [SpatialFailure("route_endpoint", (object_id,), "|".join(edge_ids))]
        for left, right in zip(edges, edges[1:]):
            if left.destination != right.origin:
                return [SpatialFailure("route_continuity", (object_id,), f"{left.edge_id}|{right.edge_id}")]
        return []

    def route_resources(self, route_id: str) -> tuple[str, ...]:
        route = self.model.routes.get(route_id)
        if route is None:
            return ()
        resources = list(route.resources)
        for edge_id in route.edge_ids:
            edge = self.model.edges.get(edge_id)
            if edge:
                resources.extend(edge.resources)
        return tuple(dict.fromkeys(resources))

    def route_edges(self, route_id: str) -> tuple[str, ...]:
        route = self.model.routes.get(route_id)
        return route.edge_ids if route else ()

    def check_occupations(
        self,
        occupations: list[Occupation],
    ) -> list[SpatialFailure]:
        failures: list[SpatialFailure] = []
        by_resource: dict[str, list[Occupation]] = defaultdict(list)
        for item in occupations:
            if item.end_s <= item.start_s:
                failures.append(
                    SpatialFailure(
                        "invalid_occupation_interval",
                        (item.object_id,),
                        item.resource_id,
                    )
                )
                continue
            by_resource[item.resource_id].append(item)
        for resource_id, rows in by_resource.items():
            rows.sort(key=lambda item: (item.start_s, item.end_s, item.object_id))
            for index, left in enumerate(rows):
                for right in rows[index + 1 :]:
                    if right.start_s >= left.end_s:
                        break
                    if self._overlap(left, right):
                        failures.append(
                            SpatialFailure(
                                "resource_overlap",
                                (left.object_id, right.object_id),
                                resource_id,
                            )
                        )
        resources = sorted(by_resource)
        for index, left_id in enumerate(resources):
            for right_id in resources[index + 1 :]:
                pair = frozenset((left_id, right_id))
                if (
                    pair not in self.model.incompatible_resource_pairs
                    and pair not in self.model.switch_locks
                ):
                    continue
                for left in by_resource[left_id]:
                    for right in by_resource[right_id]:
                        if self._overlap(left, right):
                            failures.append(
                                SpatialFailure(
                                    "incompatible_resources",
                                    (left.object_id, right.object_id),
                                    f"{left_id}|{right_id}",
                                )
                            )
        return failures

    def check_track_capacity(
        self,
        intervals: list[dict[str, Any]],
    ) -> list[SpatialFailure]:
        failures: list[SpatialFailure] = []
        known_tracks = set(self.model.tracks)
        for item in intervals:
            track_id = str(item.get("track_id", ""))
            if track_id and track_id not in known_tracks:
                failures.append(
                    SpatialFailure(
                        "unknown_track",
                        (str(item.get("object_id", "")),),
                        track_id,
                    )
                )
        for track_id, track in self.model.tracks.items():
            rows = [item for item in intervals if item.get("track_id") == track_id]
            boundaries = sorted(
                {int(item["start_s"]) for item in rows}
                | {int(item["end_s"]) for item in rows}
            )
            for time_s in boundaries:
                active = [
                    str(item["object_id"])
                    for item in rows
                    if int(item["start_s"]) <= time_s < int(item["end_s"])
                ]
                if len(active) > track.capacity:
                    failures.append(
                        SpatialFailure("track_capacity", tuple(sorted(active)), track_id)
                    )
                    break
        return failures
