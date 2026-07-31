"""Build and check one synthetic proactive-shunting chain."""

from trb_depot_agents import (
    Action,
    AdmissionContext,
    CandidatePlan,
    Role,
    SafetyAdmissionChecker,
    SpatialModel,
)
from trb_depot_agents.contracts import ResourceClaim
from trb_depot_agents.integrity import state_digest


def build_plan() -> CandidatePlan:
    clearance = Action(
        action_id="A1",
        action_type="clear_blocker",
        owner=Role.PROACTIVE_SHUNTING,
        trainset_id="TRAIN-A",
        start_s=0,
        end_s=30,
        from_location="BERTH-A",
        to_location="TEMP-01",
        route_id="ROUTE-CLEAR",
        protected_action_id="A2",
        phase="clearance",
        resources=[ResourceClaim("THROAT-01", 0, 30)],
    )
    departure = Action(
        action_id="A2",
        action_type="dispatch_trainset",
        owner=Role.DEPARTURE,
        trainset_id="TRAIN-B",
        start_s=35,
        end_s=65,
        from_location="BERTH-B",
        to_location="LINE-BOUNDARY",
        route_id="ROUTE-OUT",
        predecessors=["A1"],
        resources=[ResourceClaim("THROAT-01", 35, 65)],
    )
    settlement = Action(
        action_id="A3",
        action_type="move_to_terminal_position",
        owner=Role.PROACTIVE_SHUNTING,
        trainset_id="TRAIN-A",
        start_s=70,
        end_s=100,
        from_location="TEMP-01",
        to_location="BERTH-A",
        route_id="ROUTE-SETTLE",
        protected_action_id="A2",
        phase="terminal_placement",
        predecessors=["A2"],
        resources=[ResourceClaim("THROAT-01", 70, 100)],
    )
    return CandidatePlan(
        plan_id="SYN-PLAN-001",
        event_id="SYN-BLOCKED-DEPARTURE-001",
        state_version="synthetic-v1",
        actions=[clearance, departure, settlement],
        known_entities={
            "TRAIN-A",
            "TRAIN-B",
            "BERTH-A",
            "BERTH-B",
            "TEMP-01",
            "LINE-BOUNDARY",
            "ROUTE-CLEAR",
            "ROUTE-OUT",
            "ROUTE-SETTLE",
        },
        metadata={
            "service_lifecycle_valid": True,
            "service_lifecycle": {
                "CYCLE-001": [
                    "departure",
                    "line_service",
                    "return_release",
                    "arrival",
                    "terminal_closure",
                    "next_departure",
                ]
            },
            "work_continuity_valid": True,
            "work_continuity_evidence": {
                "A2": {
                    "evidence_id": "SYN-WORK-001",
                    "protected_action_id": "A2",
                    "state_version": "synthetic-v1",
                    "preserved_work_orders": [],
                }
            },
            "temporary_occupations_open": 0,
            "terminal_state_complete": True,
        },
    )


def build_state() -> dict:
    return {
        "version": "synthetic-v1",
        "trainsets": {
            "TRAIN-A": {"location": "BERTH-A", "available_s": 0},
            "TRAIN-B": {"location": "BERTH-B", "available_s": 0},
        },
        "services": {},
        "work_orders": {},
        "boundaries": {},
        "metadata": {},
    }


def build_spatial_model() -> SpatialModel:
    return SpatialModel.from_dict(
        {
            "tracks": [],
            "routes": [
                {
                    "route_id": "ROUTE-CLEAR",
                    "origin": "BERTH-A",
                    "destination": "TEMP-01",
                    "resources": ["THROAT-01"],
                },
                {
                    "route_id": "ROUTE-OUT",
                    "origin": "BERTH-B",
                    "destination": "LINE-BOUNDARY",
                    "resources": ["THROAT-01"],
                },
                {
                    "route_id": "ROUTE-SETTLE",
                    "origin": "TEMP-01",
                    "destination": "BERTH-A",
                    "resources": ["THROAT-01"],
                },
            ],
        }
    )


if __name__ == "__main__":
    state = build_state()
    certificate = SafetyAdmissionChecker().check(
        build_plan(),
        "synthetic-v1",
        context=AdmissionContext(
            state_projection=state,
            state_digest=state_digest(state),
            spatial_model=build_spatial_model(),
        ),
    )
    print(f"accepted={certificate.accepted}")
    print(f"passed_gates={','.join(certificate.passed_gates)}")
