"""The twelve event-triggered directed paths between four operating roles."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import Role


@dataclass(frozen=True)
class DirectedPath:
    sender: Role
    recipient: Role
    activation_condition: str
    exchanged_object: str


DIRECTED_PATHS: tuple[DirectedPath, ...] = (
    DirectedPath(
        Role.DEPARTURE,
        Role.PROACTIVE_SHUNTING,
        "departure trainset is blocked or the outbound route is unreachable",
        "blocker, clearance route, temporary position, and protected departure",
    ),
    DirectedPath(
        Role.DEPARTURE,
        Role.ARRIVAL,
        "trainset substitution, order, or route changes receiving, placement, work, or later circulation",
        "trainset, track position, work window, and later commitment",
    ),
    DirectedPath(
        Role.DEPARTURE,
        Role.OCC,
        "depot-side revision still cannot meet the departure boundary or line-service condition",
        "departure boundary, service order, and feasible depot response",
    ),
    DirectedPath(
        Role.ARRIVAL,
        Role.PROACTIVE_SHUNTING,
        "receiving route, track placement, or work access is blocked",
        "blocker, clearance route, temporary position, and protected arrival",
    ),
    DirectedPath(
        Role.ARRIVAL,
        Role.DEPARTURE,
        "terminal placement or work changes the next departure or trainset-service match",
        "trainset lineage, next departure, and outbound capacity",
    ),
    DirectedPath(
        Role.ARRIVAL,
        Role.OCC,
        "the OCC-released return window cannot be realized in the depot",
        "return boundary, receiving route, and feasible placement window",
    ),
    DirectedPath(
        Role.PROACTIVE_SHUNTING,
        Role.DEPARTURE,
        "the protected task is a departure and its owner must revise and re-sign it",
        "clearance chain, released route, and protected departure",
    ),
    DirectedPath(
        Role.PROACTIVE_SHUNTING,
        Role.ARRIVAL,
        "the protected task is an arrival, placement, or work linkage",
        "clearance chain, released route, and affected arrival commitment",
    ),
    DirectedPath(
        Role.PROACTIVE_SHUNTING,
        Role.OCC,
        "the movement chain cannot close within the current line boundary",
        "shunting window, boundary time, and terminal closure condition",
    ),
    DirectedPath(
        Role.OCC,
        Role.DEPARTURE,
        "departure time, line order, or service condition changes",
        "new departure boundary and affected outbound commitments",
    ),
    DirectedPath(
        Role.OCC,
        Role.ARRIVAL,
        "return release or line arrival time changes",
        "new return boundary and affected receiving commitments",
    ),
    DirectedPath(
        Role.OCC,
        Role.PROACTIVE_SHUNTING,
        "a line-boundary change alters a clearance window, conflict, or partial order",
        "new boundary, protected task, and proactive-shunting window",
    ),
)

PATH_INDEX = {(path.sender, path.recipient): path for path in DIRECTED_PATHS}


def path_between(sender: Role, recipient: Role) -> DirectedPath:
    """Return the declared directed path or raise for an invalid self-message."""
    if sender == recipient:
        raise ValueError("A directed role message must have different sender and recipient")
    return PATH_INDEX[(sender, recipient)]

