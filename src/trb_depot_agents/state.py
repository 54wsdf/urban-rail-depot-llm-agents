from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Protocol

from .contracts import Action, CandidatePlan
from .integrity import state_digest


@dataclass
class OperatingState:
    version: str
    trainsets: dict[str, dict[str, Any]]
    services: dict[str, dict[str, Any]]
    work_orders: dict[str, dict[str, Any]] = field(default_factory=dict)
    boundaries: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "OperatingState":
        return cls(
            version=str(payload["version"]),
            trainsets=deepcopy(dict(payload.get("trainsets", {}))),
            services=deepcopy(dict(payload.get("services", {}))),
            work_orders=deepcopy(dict(payload.get("work_orders", {}))),
            boundaries={key: int(value) for key, value in payload.get("boundaries", {}).items()},
            metadata=deepcopy(dict(payload.get("metadata", {}))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "trainsets": deepcopy(self.trainsets),
            "services": deepcopy(self.services),
            "work_orders": deepcopy(self.work_orders),
            "boundaries": dict(self.boundaries),
            "metadata": deepcopy(self.metadata),
        }

    def digest(self) -> str:
        # 防退化：状态提交必须可绑定到摘要，不能只依赖易误传的版本字符串。
        return state_digest(self)


class StateStore(Protocol):
    def read(self) -> OperatingState:
        ...

    def compare_and_swap(
        self,
        *,
        expected_version: str,
        expected_digest: str,
        successor: OperatingState,
    ) -> bool:
        ...


class InMemoryStateStore:
    def __init__(self, state: OperatingState) -> None:
        self._state = OperatingState.from_dict(state.to_dict())
        self._lock = RLock()

    def read(self) -> OperatingState:
        with self._lock:
            return OperatingState.from_dict(self._state.to_dict())

    def compare_and_swap(
        self,
        *,
        expected_version: str,
        expected_digest: str,
        successor: OperatingState,
    ) -> bool:
        with self._lock:
            if (
                self._state.version != expected_version
                or self._state.digest() != expected_digest
            ):
                return False
            # 防退化：状态存储必须在同一锁域内验证版本与摘要后整体替换，不能拆成先检查后写入的竞态窗口。
            self._state = OperatingState.from_dict(successor.to_dict())
            return True


class StateReplay:
    def ordered_actions(self, plan: CandidatePlan) -> list[Action]:
        action_ids = [action.action_id for action in plan.actions]
        if len(action_ids) != len(set(action_ids)):
            # 防退化：状态重放是独立公共入口，不能依赖上游曾经去重；重复标识必须在任何重放前显式失败。
            raise ValueError("Action graph contains duplicate action_id values")
        actions = {action.action_id: action for action in plan.actions}
        pending = set(actions)
        completed: set[str] = set()
        ordered: list[Action] = []
        while pending:
            ready = sorted(
                (
                    actions[action_id]
                    for action_id in pending
                    if set(actions[action_id].predecessors) <= completed
                ),
                key=lambda action: (action.start_s, action.action_id),
            )
            if not ready:
                raise ValueError("Action graph contains a cycle or unknown predecessor")
            for action in ready:
                ordered.append(action)
                completed.add(action.action_id)
                pending.remove(action.action_id)
        return ordered

    def preview(self, state: OperatingState, plan: CandidatePlan) -> OperatingState:
        successor = OperatingState.from_dict(state.to_dict())
        for action in self.ordered_actions(plan):
            self._apply(successor, action)
        successor.metadata["source_plan_id"] = plan.plan_id
        return successor

    def _apply(self, state: OperatingState, action: Action) -> None:
        metadata = action.metadata
        if action.action_type == "assign_trainset":
            service_id = str(metadata["service_id"])
            state.services[service_id]["trainset_id"] = action.trainset_id
        elif action.action_type == "change_departure_order":
            service_id = str(metadata["service_id"])
            state.services[service_id]["departure_order"] = int(metadata["departure_order"])
        elif action.action_type in {"set_outbound_route", "set_receiving_route"}:
            service_id = str(metadata["service_id"])
            state.services[service_id]["route_id"] = action.route_id
        elif action.action_type == "assign_work_window":
            work_id = str(metadata["work_order_id"])
            state.work_orders[work_id]["start_s"] = action.start_s
            state.work_orders[work_id]["end_s"] = action.end_s
        elif action.action_type in {
            "dispatch_trainset",
            "place_arriving_trainset",
            "clear_blocker",
            "move_to_temporary_position",
            "move_to_terminal_position",
        }:
            # 防退化：到达落位必须由统一移动分支同时更新位置和可用时间，勿恢复后续不可达的重复分支。
            if not action.trainset_id or action.trainset_id not in state.trainsets:
                raise KeyError(action.trainset_id)
            state.trainsets[action.trainset_id]["location"] = action.to_location
            state.trainsets[action.trainset_id]["available_s"] = action.end_s
        elif action.action_type in {
            "adjust_departure_boundary",
            "adjust_return_boundary",
            "adjust_local_service_order",
        }:
            boundary_id = str(metadata["boundary_id"])
            state.boundaries[boundary_id] = int(metadata.get("time_s", action.start_s))
        else:
            raise ValueError(f"Unsupported action type: {action.action_type}")
