"""Operating responsibilities and exclusive action ownership."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import Role


@dataclass(frozen=True)
class RoleContract:
    role: Role
    organization: str
    responsibility: str
    owned_actions: frozenset[str]
    hard_commitments: tuple[str, ...]
    operating_consequences: tuple[str, ...]


ROLE_CONTRACTS: dict[Role, RoleContract] = {
    Role.OCC: RoleContract(
        role=Role.OCC,
        organization="Operations Control Centre",
        responsibility="line service, departure and return boundary times, and local line response",
        owned_actions=frozenset(
            {"adjust_departure_boundary", "adjust_return_boundary", "adjust_local_service_order"}
        ),
        hard_commitments=("authorized adjustment window", "line service continuity"),
        operating_consequences=("service loss", "line delay", "downstream boundary change"),
    ),
    Role.DEPARTURE: RoleContract(
        role=Role.DEPARTURE,
        organization="Depot Control Centre",
        responsibility="trainset assignment, departure order, and outbound route",
        owned_actions=frozenset(
            {"assign_trainset", "change_departure_order", "set_outbound_route", "dispatch_trainset"}
        ),
        hard_commitments=("service coverage", "technical eligibility", "outbound route access"),
        operating_consequences=("departure delay", "later circulation change", "track conflict"),
    ),
    Role.ARRIVAL: RoleContract(
        role=Role.ARRIVAL,
        organization="Depot Control Centre",
        responsibility="receiving route, track placement, inspection, and later work linkage",
        owned_actions=frozenset(
            {"set_receiving_route", "place_arriving_trainset", "assign_work_window"}
        ),
        hard_commitments=("receiving access", "track capacity", "required work continuity"),
        operating_consequences=("arrival waiting", "later departure impact", "work disruption"),
    ),
    Role.PROACTIVE_SHUNTING: RoleContract(
        role=Role.PROACTIVE_SHUNTING,
        organization="Depot Control Centre",
        responsibility="clearance, temporary placement, and terminal placement around a protected task",
        owned_actions=frozenset(
            {"clear_blocker", "move_to_temporary_position", "move_to_terminal_position"}
        ),
        hard_commitments=("protected task remains owned by its service role", "temporary occupation closes"),
        operating_consequences=("additional moves", "throat occupation", "terminal placement impact"),
    ),
}


def owns(role: Role, action_type: str) -> bool:
    return action_type in ROLE_CONTRACTS[role].owned_actions

