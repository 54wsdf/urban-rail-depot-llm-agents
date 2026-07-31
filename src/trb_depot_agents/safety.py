"""Generator-blind deterministic admission for public contract inspection."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from .admission import (
    AdmissionContext,
    AdmissionPolicyPipeline,
    EvidenceRecord,
    GateReport,
    GateSpecification,
)
from .communication import PATH_INDEX
from .contracts import AdmissionCertificate, CandidatePlan, GateFailure, Role
from .evidence import SiteSafetyAdapter, SiteSafetyRequest
from .integrity import certificate_digest, plan_digest, sha256_digest
from .ledger import (
    CommitmentLedger,
    message_evidence_complete,
    message_evidence_ids,
)
from .roles import owns
from .spatial import Occupation
from .state import StateReplay

Gate = Callable[[CandidatePlan, str, AdmissionContext], list[GateFailure]]

MOVEMENT_ACTION_TYPES = {
    "dispatch_trainset",
    "place_arriving_trainset",
    "clear_blocker",
    "move_to_temporary_position",
    "move_to_terminal_position",
}
COMPLETE_STATE_FIELDS = {"version", "trainsets", "services"}


GATE_SPECS: dict[str, GateSpecification] = {
    "G1": GateSpecification("G1", "unique action ids and executable DAG", "identity", feedback_role=None),
    "G2": GateSpecification("G2", "state version and digest binding", "identity", depends_on=("G1",), retriable=False, escalation="rebase_plan"),
    "G3": GateSpecification("G3", "entity reference grounding", "grounding", depends_on=("G2",)),
    "G4": GateSpecification("G4", "action ownership and message authority", "authority", depends_on=("G3",)),
    "G5": GateSpecification("G5", "preconditions and blocking objections", "authority", depends_on=("G4",), escalation="owner_revision"),
    "G6": GateSpecification("G6", "movement and route continuity", "spatial", depends_on=("G1", "G3")),
    "G7": GateSpecification("G7", "same-train, track capacity, and ordering", "spatial", depends_on=("G6",)),
    "G8": GateSpecification("G8", "route resources, throat exclusion, and switch locks", "spatial", depends_on=("G6",)),
    "G9": GateSpecification("G9", "service lifecycle", "service", depends_on=("G2", "G3")),
    "G10": GateSpecification("G10", "trainset lineage and technical eligibility", "service", depends_on=("G3", "G9")),
    "G11": GateSpecification("G11", "proactive-shunting compound chain", "compound", depends_on=("G4", "G6", "G8")),
    "G12": GateSpecification("G12", "terminal closure and replayability", "closure", depends_on=("G5", "G7", "G9", "G10", "G11")),
}


def _ordered_gate_ids() -> tuple[str, ...]:
    for gate_id, spec in GATE_SPECS.items():
        unknown = set(spec.depends_on) - set(GATE_SPECS)
        if unknown:
            raise RuntimeError(
                f"Safety gate {gate_id} depends on unknown gates: {sorted(unknown)}"
            )
    pending = set(GATE_SPECS)
    completed: set[str] = set()
    ordered: list[str] = []
    while pending:
        ready = sorted(
            (
                gate_id
                for gate_id in pending
                if set(GATE_SPECS[gate_id].depends_on) <= completed
            ),
            key=lambda gate_id: int(gate_id[1:]),
        )
        if not ready:
            raise RuntimeError("Safety gate dependency graph contains a cycle or unknown gate")
        gate_id = ready[0]
        pending.remove(gate_id)
        completed.add(gate_id)
        ordered.append(gate_id)
    # 防退化：十二道门必须按声明的依赖图装配，不能恢复为另一处手写顺序并产生规范漂移。
    return tuple(ordered)


def _feedback_role(plan: CandidatePlan, failure: GateFailure) -> str:
    if failure.action_id:
        for action in plan.actions:
            if action.action_id == failure.action_id:
                return action.owner.value
    if failure.gate_id in {"G2", "G9"}:
        return Role.OCC.value
    return Role.PROACTIVE_SHUNTING.value if failure.gate_id in {"G8", "G11", "G12"} else Role.DEPARTURE.value


def _g1_unique_action_id_and_dag(plan: CandidatePlan, _: str, __: AdmissionContext) -> list[GateFailure]:
    failures: list[GateFailure] = []
    if not plan.actions:
        # 防退化：运营方案必须包含显式动作；空列表不能作为已生成且可执行的计划通过准入。
        failures.append(GateFailure("G1", "candidate plan contains no operating action"))
    seen: set[str] = set()
    action_ids = {action.action_id for action in plan.actions}
    for action in plan.actions:
        if not action.action_id or action.action_id in seen:
            failures.append(GateFailure("G1", "action_id is missing or duplicated", action.action_id))
        seen.add(action.action_id)
        if not action.action_type or action.end_s <= action.start_s:
            failures.append(GateFailure("G1", "incomplete or invalid action information", action.action_id))
        resource_ids: set[str] = set()
        for claim in action.resources:
            if not claim.resource_id or claim.end_s <= claim.start_s:
                failures.append(
                    GateFailure(
                        "G1",
                        "resource claim is incomplete or has an invalid interval",
                        action.action_id,
                        claim.resource_id,
                    )
                )
            if claim.resource_id in resource_ids:
                failures.append(
                    GateFailure(
                        "G1",
                        "resource is claimed more than once by the same action",
                        action.action_id,
                        claim.resource_id,
                    )
                )
            resource_ids.add(claim.resource_id)
        for predecessor in action.predecessors:
            if predecessor not in action_ids:
                failures.append(GateFailure("G1", "unknown predecessor in action DAG", action.action_id, predecessor))
    if not failures:
        try:
            StateReplay().ordered_actions(plan)
        except ValueError as exc:
            failures.append(GateFailure("G1", str(exc)))
    return failures


def _g2_current_state_binding(plan: CandidatePlan, live_version: str, context: AdmissionContext) -> list[GateFailure]:
    failures: list[GateFailure] = []
    if plan.state_version != live_version:
        failures.append(GateFailure("G2", "candidate plan is bound to a stale state version"))
    missing_state_fields = sorted(COMPLETE_STATE_FIELDS - set(context.state_projection))
    if missing_state_fields:
        # 防退化：准入状态必须由完整投影和服务器重算摘要共同绑定，不能恢复成调用方只提交版本字符串即可通过。
        failures.append(
            GateFailure(
                "G2",
                f"authoritative state projection lacks required fields: {missing_state_fields}",
            )
        )
    elif str(context.state_projection["version"]) != live_version:
        failures.append(
            GateFailure("G2", "authoritative state projection version does not match live version")
        )
    if not context.state_digest:
        failures.append(GateFailure("G2", "authoritative state digest is unavailable"))
    if (
        context.submitted_state_digest
        and context.state_digest
        and context.submitted_state_digest != context.state_digest
    ):
        failures.append(
            GateFailure(
                "G2",
                "submitted state digest does not match the supplied state projection",
            )
        )
    if (
        context.submitted_plan_digest
        and context.plan_digest
        and context.submitted_plan_digest != context.plan_digest
    ):
        # 防退化：调用者提交的摘要只能作为比较保护值，不能替代对候选计划的真实摘要计算。
        failures.append(
            GateFailure(
                "G2",
                "submitted plan digest does not match the candidate plan",
            )
        )
    expected_digest = plan.metadata.get("state_digest")
    if expected_digest and not context.state_digest:
        failures.append(GateFailure("G2", "live state digest is unavailable for the declared guard"))
    elif expected_digest and expected_digest != context.state_digest:
        failures.append(GateFailure("G2", "candidate plan state digest does not match live projection"))
    expected_plan_digest = plan.metadata.get("plan_digest")
    if expected_plan_digest and not context.plan_digest:
        failures.append(GateFailure("G2", "submitted plan digest is unavailable for the declared guard"))
    elif expected_plan_digest and expected_plan_digest != context.plan_digest:
        failures.append(GateFailure("G2", "candidate plan digest guard does not match submitted plan"))
    return failures


def _g3_event_entity_relations(plan: CandidatePlan, _: str, __: AdmissionContext) -> list[GateFailure]:
    failures: list[GateFailure] = []
    for action in plan.actions:
        for entity in (action.trainset_id, action.from_location, action.to_location, action.route_id):
            if entity and entity not in plan.known_entities:
                failures.append(GateFailure("G3", f"unknown operating entity: {entity}", action.action_id))
    return failures


def _g4_action_ownership(plan: CandidatePlan, _: str, __: AdmissionContext) -> list[GateFailure]:
    failures = [
        GateFailure("G4", "action is not owned by the declared role", action.action_id)
        for action in plan.actions
        if not owns(action.owner, action.action_type)
    ]
    actions = {action.action_id: action for action in plan.actions}
    message_ids: set[str] = set()
    ledger: CommitmentLedger | None = None
    ledger_payload = plan.metadata.get("commitment_ledger", [])
    if ledger_payload:
        try:
            ledger = CommitmentLedger.from_payload(list(ledger_payload))
        except (KeyError, TypeError, ValueError):
            ledger = None
    for message in plan.messages:
        if not message.message_id or message.message_id in message_ids:
            failures.append(
                GateFailure("G4", "message_id is missing or duplicated", message.message_id)
            )
        message_ids.add(message.message_id)
        if message.event_id != plan.event_id or message.state_version != plan.state_version:
            failures.append(
                GateFailure(
                    "G4",
                    "message is not bound to the candidate event and state",
                    message.message_id,
                )
            )
        if (message.sender, message.recipient) not in PATH_INDEX:
            failures.append(GateFailure("G4", "message uses an undeclared directed role path", message.message_id))
        if not message_evidence_complete(message):
            failures.append(GateFailure("G4", "message lacks required objection or counterproposal evidence", message.message_id))
        if (
            message.message_type.value == "counterproposal"
            and message.resolves_objection_id
        ):
            failures.append(
                GateFailure(
                    "G4",
                    "counterproposal cannot close a blocking objection before owner revision",
                    message.message_id,
                )
            )
        if (
            message.message_type.value
            in {"objection", "counterproposal", "owner_revision", "dependency_replay"}
            and (
                ledger is None
                or not message.affected_commitment
                or message.affected_commitment not in ledger.records
            )
        ):
            failures.append(
                GateFailure(
                    "G4",
                    "coordination message references no authoritative commitment",
                    message.message_id,
                )
            )
        if message.message_type.value == "owner_revision":
            challenged = actions.get(str(message.challenged_action_id))
            if challenged is None:
                failures.append(
                    GateFailure(
                        "G4",
                        "owner revision references an unknown action",
                        message.message_id,
                    )
                )
            elif message.sender is not challenged.owner:
                # 防退化：修订消息必须由被修订动作的责任人发出，不能只依赖消息类型名称取得修改权。
                failures.append(
                    GateFailure(
                        "G4",
                        "owner revision sender does not own the challenged action",
                        message.message_id,
                    )
                )
            elif challenged not in message.alternative_actions:
                failures.append(
                    GateFailure(
                        "G4",
                        "owner revision replacement does not match the candidate action",
                        message.message_id,
                    )
                )
        if (
            ledger is not None
            and message.affected_commitment
            and message.affected_commitment in ledger.records
            and message.message_type.value in {"owner_revision", "dependency_replay"}
        ):
            commitment = ledger.records[message.affected_commitment]
            if commitment.owner is not message.sender:
                failures.append(
                    GateFailure(
                        "G4",
                        "commitment-changing message was not issued by the commitment owner",
                        message.message_id,
                    )
                )
            if not set(commitment.evidence_ids) & message_evidence_ids(message):
                failures.append(
                    GateFailure(
                        "G4",
                        "commitment-changing message is not bound to ledger evidence",
                        message.message_id,
                    )
                )
        for alternative in message.alternative_actions:
            if not owns(alternative.owner, alternative.action_type):
                failures.append(
                    GateFailure(
                        "G4",
                        "counterproposal contains an action outside its declared owner namespace",
                        alternative.action_id,
                    )
                )
    revision_messages = {
        (message.sender.value, message.challenged_action_id)
        for message in plan.messages
        if message.message_type.value == "owner_revision"
        and message.challenged_action_id
        and message_evidence_complete(message)
    }
    raw_owner_revisions = plan.metadata.get("owner_revisions", [])
    if not isinstance(raw_owner_revisions, list):
        failures.append(GateFailure("G4", "owner revision record is not a list"))
        raw_owner_revisions = []
    for revision in raw_owner_revisions:
        if not isinstance(revision, dict):
            failures.append(GateFailure("G4", "owner revision record is malformed"))
            continue
        key = (str(revision.get("role", "")), str(revision.get("action_id", "")))
        if key not in revision_messages:
            failures.append(
                GateFailure(
                    "G4",
                    "recorded owner revision lacks a bound owner-revision message",
                    key[1] or None,
                )
            )
    return failures


def _g5_action_preconditions(plan: CandidatePlan, _: str, __: AdmissionContext) -> list[GateFailure]:
    failures = [
        GateFailure("G5", "action precondition failed", action.action_id)
        for action in plan.actions
        if action.metadata.get("preconditions_met") is False
    ]
    opened_objections = [
        message.objection_id
        for message in plan.messages
        if message.message_type.value == "objection"
        and message.objection_id
        and message_evidence_complete(message)
    ]
    duplicate_objections = sorted(
        objection_id
        for objection_id in set(opened_objections)
        if opened_objections.count(objection_id) > 1
    )
    failures.extend(
        GateFailure("G5", "blocking objection id was opened more than once", item)
        for item in duplicate_objections
    )
    resolution_sequence = [
        message
        for message in plan.messages
        if message.message_type.value == "owner_revision"
        and message.resolves_objection_id
        and message_evidence_complete(message)
    ]
    resolution_ids = [
        str(message.resolves_objection_id) for message in resolution_sequence
    ]
    failures.extend(
        GateFailure("G5", "blocking objection has more than one owner revision", item)
        for item in sorted(
            objection_id
            for objection_id in set(resolution_ids)
            if resolution_ids.count(objection_id) > 1
        )
    )
    resolution_messages = {
        str(message.resolves_objection_id): message
        for message in resolution_sequence
    }
    resolved_objections = set(resolution_messages)
    unknown_resolutions = sorted(resolved_objections - set(opened_objections))
    failures.extend(
        GateFailure("G5", "resolution references an unknown blocking objection", item)
        for item in unknown_resolutions
    )
    opening_messages = {
        str(message.objection_id): message
        for message in plan.messages
        if message.message_type.value == "objection"
        and message.objection_id
        and message_evidence_complete(message)
    }
    for objection_id in resolved_objections - set(unknown_resolutions):
        opening = opening_messages[objection_id]
        resolution = resolution_messages[objection_id]
        if (
            opening.challenged_action_id != resolution.challenged_action_id
            or opening.affected_commitment != resolution.affected_commitment
        ):
            failures.append(
                GateFailure(
                    "G5",
                    "owner revision does not resolve the challenged action and commitment",
                    objection_id,
                )
            )
    derived_unresolved = set(opened_objections) - resolved_objections
    declared_unresolved = set(plan.unresolved_blocking_objections)
    if derived_unresolved != declared_unresolved:
        # 防退化：未解决异议列表只能是消息日志的兼容视图，不能由模型或 HTTP 调用方独立改写。
        failures.append(
            GateFailure(
                "G5",
                "blocking-objection view does not match the directed message record",
            )
        )
    failures.extend(
        GateFailure("G5", "blocking objection remains unresolved", item)
        for item in sorted(derived_unresolved)
    )
    ledger_payload = plan.metadata.get("commitment_ledger", [])
    if ledger_payload:
        try:
            ledger = CommitmentLedger.from_payload(list(ledger_payload))
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(GateFailure("G5", f"invalid commitment ledger: {exc}"))
        else:
            action_owners = {action.action_id: action.owner for action in plan.actions}
            failures.extend(
                GateFailure("G5", f"commitment ledger violation: {item}")
                for item in ledger.validate(
                    action_owners=action_owners,
                    state_version=plan.state_version,
                )
            )
    return failures


def _g6_movement_continuity(plan: CandidatePlan, _: str, context: AdmissionContext) -> list[GateFailure]:
    failures: list[GateFailure] = []
    movement_actions = [
        action for action in plan.actions if action.action_type in MOVEMENT_ACTION_TYPES
    ]
    if movement_actions and context.spatial_model is None:
        # 防退化：带进路的移动动作缺少空间模型时必须拒绝，不能把“未检查”解释成“检查通过”。
        failures.append(
            GateFailure(
                "G6",
                "spatial evidence is required for movement actions",
                movement_actions[0].action_id,
            )
        )
    for action in plan.actions:
        if action.action_type not in MOVEMENT_ACTION_TYPES:
            continue
        if not action.from_location or not action.to_location or not action.route_id:
            failures.append(GateFailure("G6", "movement endpoint or route is missing", action.action_id))
            continue
        if context.spatial_model:
            checker = context.spatial_model
            if hasattr(checker, "model"):
                spatial_checker = checker
            else:
                from .spatial import SpatialChecker

                spatial_checker = SpatialChecker(checker)
            for failure in spatial_checker.check_route(
                object_id=action.action_id,
                route_id=action.route_id,
                origin=action.from_location,
                destination=action.to_location,
            ):
                failures.append(GateFailure("G6", failure.failure_type, action.action_id, failure.resource_id))
            edge_path = action.metadata.get("edge_path")
            if edge_path:
                for failure in spatial_checker.check_route_continuity(
                    object_id=action.action_id,
                    edge_ids=list(map(str, edge_path)),
                    origin=action.from_location,
                    destination=action.to_location,
                ):
                    failures.append(GateFailure("G6", failure.failure_type, action.action_id, failure.resource_id))
    return failures


def _g7_trainset_order_capacity(plan: CandidatePlan, _: str, context: AdmissionContext) -> list[GateFailure]:
    failures = [
        GateFailure("G7", "trainset order or capacity condition failed", action.action_id)
        for action in plan.actions
        if action.metadata.get("order_capacity_valid") is False
    ]
    by_trainset: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for action in plan.actions:
        if action.trainset_id:
            by_trainset[action.trainset_id].append((action.start_s, action.end_s, action.action_id))
    for rows in by_trainset.values():
        rows.sort()
        for left, right in zip(rows, rows[1:]):
            if left[1] > right[0]:
                failures.append(GateFailure("G7", f"same trainset overlap between {left[2]} and {right[2]}", right[2]))
    if context.spatial_model and context.track_intervals:
        from .spatial import SpatialChecker

        spatial_checker = context.spatial_model if hasattr(context.spatial_model, "model") else SpatialChecker(context.spatial_model)
        for failure in spatial_checker.check_track_capacity(context.track_intervals):
            failures.append(GateFailure("G7", failure.failure_type, None, failure.resource_id))
    return failures


def _g8_route_space_resource_exclusion(plan: CandidatePlan, _: str, context: AdmissionContext) -> list[GateFailure]:
    claims: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    occupations: list[Occupation] = []
    spatial_checker = None
    if context.spatial_model:
        from .spatial import SpatialChecker

        spatial_checker = context.spatial_model if hasattr(context.spatial_model, "model") else SpatialChecker(context.spatial_model)
    for action in plan.actions:
        windows = {claim.resource_id: (claim.start_s, claim.end_s) for claim in action.resources}
        if spatial_checker and action.route_id:
            for resource_id in spatial_checker.route_resources(action.route_id):
                windows[resource_id] = (action.start_s, action.end_s)
        for resource_id, (start_s, end_s) in windows.items():
            claims[resource_id].append((start_s, end_s, action.action_id))
            occupations.append(Occupation(action.action_id, resource_id, start_s, end_s))
    failures: list[GateFailure] = []
    if spatial_checker is None:
        for resource_id, intervals in claims.items():
            intervals.sort()
            for left, right in zip(intervals, intervals[1:]):
                if left[1] > right[0]:
                    failures.append(
                        GateFailure(
                            "G8",
                            f"exclusive resource overlap between {left[2]} and {right[2]}",
                            right[2],
                            resource_id,
                        )
                    )
    if spatial_checker:
        for failure in spatial_checker.check_occupations(occupations):
            failures.append(GateFailure("G8", failure.failure_type, failure.object_ids[-1] if failure.object_ids else None, failure.resource_id))
    return failures


def _g9_service_lifecycle(plan: CandidatePlan, _: str, __: AdmissionContext) -> list[GateFailure]:
    if plan.metadata.get("service_lifecycle_valid") is False:
        return [GateFailure("G9", "service lifecycle is incomplete or out of order")]
    failures: list[GateFailure] = []
    canonical_order = {
        "departure": 0,
        "line_service": 1,
        "return_release": 2,
        "arrival": 3,
        "terminal_closure": 4,
        "next_departure": 5,
    }
    lifecycle = plan.metadata.get("service_lifecycle")
    if not isinstance(lifecycle, dict) or not lifecycle:
        # 防退化：生命周期证据必须显式进入已签计划，不能用缺省布尔值代替跨周期闭合。
        return [GateFailure("G9", "service lifecycle evidence is unavailable")]
    required_stages = set(canonical_order)
    for cycle_id, stages in lifecycle.items():
        if not isinstance(stages, (list, tuple)):
            failures.append(
                GateFailure(
                    "G9",
                    f"service cycle {cycle_id} has a malformed stage sequence",
                )
            )
            continue
        stage_names = list(map(str, stages))
        unknown = [stage for stage in stage_names if stage not in canonical_order]
        if unknown:
            failures.append(
                GateFailure(
                    "G9",
                    f"service cycle {cycle_id} contains unknown stages: {unknown}",
                )
            )
            continue
        positions = [canonical_order[stage] for stage in stage_names]
        if positions != sorted(positions) or len(positions) != len(set(positions)):
            failures.append(
                GateFailure(
                    "G9",
                    f"service cycle {cycle_id} is out of order or repeats a stage",
                )
            )
        missing = sorted(required_stages - set(stage_names))
        if missing:
            failures.append(
                GateFailure(
                    "G9",
                    f"service cycle {cycle_id} lacks lifecycle stages: {missing}",
                )
            )
    return failures


def _g10_lineage_eligibility(plan: CandidatePlan, _: str, context: AdmissionContext) -> list[GateFailure]:
    failures = [
        GateFailure("G10", "trainset lineage or technical eligibility failed", action.action_id)
        for action in plan.actions
        if action.metadata.get("lineage_eligible") is False
    ]
    trainsets = dict(context.state_projection.get("trainsets", {}))
    for action in plan.actions:
        if action.trainset_id and action.trainset_id not in trainsets:
            failures.append(
                GateFailure(
                    "G10",
                    "referenced trainset is absent from the authoritative state",
                    action.action_id,
                )
            )
            continue
        required = set(map(str, action.metadata.get("required_capabilities", [])))
        if not action.trainset_id or not required or action.trainset_id not in trainsets:
            continue
        available = set(
            map(str, dict(trainsets[action.trainset_id]).get("capabilities", []))
        )
        missing = sorted(required - available)
        if missing:
            failures.append(
                GateFailure(
                    "G10",
                    f"trainset lacks required capabilities: {missing}",
                    action.action_id,
                )
            )
    return failures


def _g11_proactive_shunting_work_continuity(plan: CandidatePlan, _: str, __: AdmissionContext) -> list[GateFailure]:
    failures: list[GateFailure] = []
    actions = {action.action_id: action for action in plan.actions}
    protected = {
        action.protected_action_id
        for action in plan.actions
        if action.protected_action_id
    }
    raw_work_evidence = plan.metadata.get("work_continuity_evidence")
    work_evidence: dict[str, Any] = (
        dict(raw_work_evidence) if isinstance(raw_work_evidence, dict) else {}
    )
    if protected and not isinstance(raw_work_evidence, dict):
        failures.append(
            GateFailure(
                "G11",
                "work-continuity evidence is unavailable for proactive shunting",
            )
        )
    chains: dict[str, list] = defaultdict(list)
    for action in plan.actions:
        if action.protected_action_id:
            chains[action.protected_action_id].append(action)
    for protected_id in protected:
        raw_continuity_record = work_evidence.get(protected_id, {})
        continuity_record = (
            dict(raw_continuity_record)
            if isinstance(raw_continuity_record, dict)
            else {}
        )
        if (
            continuity_record.get("protected_action_id") != protected_id
            or continuity_record.get("state_version") != plan.state_version
            or not continuity_record.get("evidence_id")
        ):
            failures.append(
                GateFailure(
                    "G11",
                    "work-continuity evidence is not bound to the protected action and state",
                    protected_id,
                )
            )
        protected_action = actions.get(protected_id)
        if protected_action is None:
            failures.append(
                GateFailure(
                    "G11",
                    "proactive-shunting chain references an unknown protected action",
                    protected_id,
                )
            )
            continue
        if protected_action.owner not in {Role.DEPARTURE, Role.ARRIVAL}:
            failures.append(
                GateFailure(
                    "G11",
                    "protected movement must remain owned by Departure or Arrival",
                    protected_id,
                )
            )
        chain_actions = chains[protected_id]
        invalid_owner = next(
            (
                action
                for action in chain_actions
                if action.owner is not Role.PROACTIVE_SHUNTING
            ),
            None,
        )
        if invalid_owner is not None:
            failures.append(
                GateFailure(
                    "G11",
                    "compound shunting-chain actions must be owned by Proactive-Shunting",
                    invalid_owner.action_id,
                )
            )
        phases = [action.phase for action in chain_actions if action.phase]
        duplicate_phases = sorted(
            phase
            for phase in set(phases)
            if phases.count(phase) > 1
        )
        for phase in duplicate_phases:
            # 防退化：复合链的阶段必须唯一，不能让后写动作静默覆盖同阶段的前一个动作。
            failures.append(
                GateFailure(
                    "G11",
                    f"compound shunting chain contains duplicate phase: {phase}",
                    protected_id,
                )
            )
        phase_actions = {
            action.phase: action
            for action in chain_actions
            if action.phase
        }
        if not {"clearance", "terminal_placement"}.issubset(phase_actions):
            failures.append(
                GateFailure(
                    "G11",
                    "proactive-shunting chain lacks clearance or terminal placement",
                    protected_id,
                )
            )
            continue
        clearance = phase_actions["clearance"]
        terminal = phase_actions["terminal_placement"]
        if clearance.end_s > protected_action.start_s:
            failures.append(
                GateFailure(
                    "G11",
                    "clearance does not finish before the protected movement",
                    clearance.action_id,
                )
            )
        if terminal.start_s < protected_action.end_s:
            failures.append(
                GateFailure(
                    "G11",
                    "terminal placement starts before the protected movement finishes",
                    terminal.action_id,
                )
            )
        if clearance.action_id not in protected_action.predecessors:
            failures.append(
                GateFailure(
                    "G11",
                    "protected movement is not ordered after its clearance action",
                    protected_id,
                )
            )
        if protected_id not in terminal.predecessors:
            failures.append(
                GateFailure(
                    "G11",
                    "terminal placement is not ordered after the protected movement",
                    terminal.action_id,
                )
            )
        blocker_ids = {
            action.trainset_id
            for action in chains[protected_id]
            if action.trainset_id
        }
        if len(blocker_ids) > 1:
            failures.append(
                GateFailure(
                    "G11",
                    "clearance and terminal placement refer to different blocker trainsets",
                    protected_id,
                )
            )
        if clearance.to_location != terminal.from_location:
            failures.append(
                GateFailure(
                    "G11",
                    "temporary placement is not continuous across the shunting chain",
                    terminal.action_id,
                )
            )
    if plan.metadata.get("work_continuity_valid") is False:
        failures.append(GateFailure("G11", "required work continuity failed"))
    return failures


def _g12_terminal_closure(plan: CandidatePlan, _: str, context: AdmissionContext) -> list[GateFailure]:
    failures: list[GateFailure] = []
    missing_state_fields = sorted(COMPLETE_STATE_FIELDS - set(context.state_projection))
    if missing_state_fields:
        # 防退化：终态闭合必须实际重放到完整状态，不能因状态投影缺失而跳过后继状态构造。
        failures.append(
            GateFailure(
                "G12",
                f"successor-state replay lacks required fields: {missing_state_fields}",
            )
        )
    if plan.metadata.get("temporary_occupations_open") != 0:
        failures.append(GateFailure("G12", "temporary shunting occupation remains open"))
    if plan.metadata.get("terminal_state_complete") is not True:
        failures.append(GateFailure("G12", "terminal operating state is incomplete"))
    raw_required = plan.metadata.get("required_commitments", [])
    if not isinstance(raw_required, (list, tuple, set)):
        failures.append(GateFailure("G12", "required commitment record is malformed"))
        raw_required = []
    required = list(map(str, raw_required))
    if len(plan.replayed_commitments) != len(set(plan.replayed_commitments)):
        failures.append(GateFailure("G12", "dependency-replay view contains duplicates"))
    ledger_payload = plan.metadata.get("commitment_ledger", [])
    replay_messages = {
        message.affected_commitment
        for message in plan.messages
        if message.message_type.value == "dependency_replay"
        and message.affected_commitment
    }
    declared_replays = set(plan.replayed_commitments)
    if declared_replays != replay_messages:
        # 防退化：重放列表只能由 dependency-replay 消息推导，不能作为另一套可独立声明的事实源。
        failures.append(
            GateFailure(
                "G12",
                "dependency-replay view does not match the directed message record",
            )
        )
    if required or plan.replayed_commitments:
        if not ledger_payload:
            failures.append(GateFailure("G12", "commitment ledger is required for dependency replay"))
        else:
            try:
                ledger = CommitmentLedger.from_payload(list(ledger_payload))
            except (KeyError, TypeError, ValueError):
                failures.append(GateFailure("G12", "commitment ledger cannot prove dependency replay"))
            else:
                for commitment_id in plan.replayed_commitments:
                    if commitment_id not in ledger.records:
                        failures.append(
                            GateFailure(
                                "G12",
                                "replayed commitment is absent from the commitment ledger",
                                commitment_id,
                            )
                        )
                    elif commitment_id not in replay_messages:
                        failures.append(
                            GateFailure(
                                "G12",
                                "replayed commitment lacks a dependency-replay message",
                                commitment_id,
                            )
                        )
    missing = [item for item in required if item not in set(plan.replayed_commitments)]
    failures.extend(
        GateFailure("G12", "required dependency commitment was not replayed", item)
        for item in missing
    )
    if not failures:
        try:
            StateReplay().ordered_actions(plan)
        except ValueError as exc:
            failures.append(GateFailure("G12", f"plan is not replayable: {exc}"))
    state_projection = context.state_projection
    if not failures and COMPLETE_STATE_FIELDS <= set(state_projection):
        try:
            from .state import OperatingState

            successor = StateReplay().preview(
                OperatingState.from_dict(state_projection),
                plan,
            )
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(
                GateFailure("G12", f"complete successor state cannot be constructed: {exc}")
            )
        else:
            if successor.metadata.get("temporary_occupations_open", 0):
                failures.append(
                    GateFailure(
                        "G12",
                        "successor state retains an open temporary occupation",
                    )
                )
    return failures


_GATE_FUNCTIONS: dict[str, Gate] = {
    "G1": _g1_unique_action_id_and_dag,
    "G2": _g2_current_state_binding,
    "G3": _g3_event_entity_relations,
    "G4": _g4_action_ownership,
    "G5": _g5_action_preconditions,
    "G6": _g6_movement_continuity,
    "G7": _g7_trainset_order_capacity,
    "G8": _g8_route_space_resource_exclusion,
    "G9": _g9_service_lifecycle,
    "G10": _g10_lineage_eligibility,
    "G11": _g11_proactive_shunting_work_continuity,
    "G12": _g12_terminal_closure,
}

GATES: tuple[tuple[str, str, Gate], ...] = tuple(
    (gate_id, GATE_SPECS[gate_id].name, _GATE_FUNCTIONS[gate_id])
    for gate_id in _ordered_gate_ids()
)


class SafetyAdmissionChecker:
    """Apply every gate without consulting the plan generator."""

    def __init__(
        self,
        *,
        site_safety_adapter: SiteSafetyAdapter | None = None,
        required_site_gates: tuple[str, ...] = (),
    ) -> None:
        unknown = set(required_site_gates) - set(GATE_SPECS)
        if unknown:
            raise ValueError(f"unknown required site safety gates: {sorted(unknown)}")
        self.site_safety_adapter = site_safety_adapter
        self.required_site_gates = frozenset(required_site_gates)

    def check(
        self,
        plan: CandidatePlan,
        live_state_version: str,
        *,
        context: AdmissionContext | None = None,
    ) -> AdmissionCertificate:
        admission_context = context or AdmissionContext()
        admission_context.plan_digest = admission_context.plan_digest or plan_digest(plan)
        failures: list[GateFailure] = []
        passed: list[str] = []
        reports: list[GateReport] = []
        evidence_records: list[EvidenceRecord] = []
        spatial_source = admission_context.spatial_model
        if spatial_source is not None and hasattr(spatial_source, "model"):
            spatial_source = spatial_source.model
        spatial_fingerprint = (
            spatial_source.fingerprint()
            if spatial_source is not None and hasattr(spatial_source, "fingerprint")
            else None
        )
        for gate_id, _, gate in GATES:
            spec = GATE_SPECS[gate_id]
            current = gate(plan, live_state_version, admission_context)
            gate_evidence: list[EvidenceRecord] = []
            if gate_id in self.required_site_gates:
                if self.site_safety_adapter is None:
                    current.append(
                        GateFailure(
                            gate_id,
                            "required site safety adapter is not configured",
                        )
                    )
                else:
                    try:
                        decision = self.site_safety_adapter.evaluate(
                            SiteSafetyRequest(
                                gate_id=gate_id,
                                plan=plan,
                                live_state_version=live_state_version,
                                plan_digest=admission_context.plan_digest,
                                state_digest=admission_context.state_digest or "",
                                state_projection=admission_context.state_projection,
                                spatial_model=admission_context.spatial_model,
                            )
                        )
                    except Exception:
                        current.append(
                            GateFailure(
                                gate_id,
                                "site safety adapter did not produce a valid decision",
                            )
                        )
                    else:
                        valid_digest = (
                            len(decision.evidence_digest) == 64
                            and all(character in "0123456789abcdef" for character in decision.evidence_digest)
                        )
                        if (
                            decision.gate_id != gate_id
                            or not decision.evidence_id
                            or not valid_digest
                            or decision.plan_digest != admission_context.plan_digest
                            or decision.state_digest != (admission_context.state_digest or "")
                        ):
                            current.append(
                                GateFailure(
                                    gate_id,
                                    "site safety decision is not bound to the requested gate",
                                )
                            )
                        else:
                            gate_evidence.append(
                                EvidenceRecord(
                                    gate_id=gate_id,
                                    evidence_type="site-safety",
                                    digest=decision.evidence_digest,
                                    summary=decision.summary,
                                )
                            )
                            if not decision.accepted:
                                current.append(
                                    GateFailure(
                                        gate_id,
                                        "site safety adapter rejected the candidate plan",
                                    )
                                )
            failure_payload = [
                {
                    "gate_id": item.gate_id,
                    "reason": item.reason,
                    "action_id": item.action_id,
                    "resource_id": item.resource_id,
                }
                for item in current
            ]
            evidence = EvidenceRecord(
                gate_id=gate_id,
                evidence_type="gate-input",
                digest=sha256_digest(
                    {
                        "plan_id": plan.plan_id,
                        "plan_digest": admission_context.plan_digest,
                        "submitted_plan_digest": admission_context.submitted_plan_digest,
                        "state_version": live_state_version,
                        "state_digest": admission_context.state_digest,
                        "submitted_state_digest": admission_context.submitted_state_digest,
                        "gate_id": gate_id,
                        "depends_on": spec.depends_on,
                        "track_intervals": admission_context.track_intervals,
                        "spatial_fingerprint": spatial_fingerprint,
                        "policy": admission_context.policy,
                        "failures": failure_payload,
                    }
                ),
                summary=f"{spec.phase}:{spec.name}",
            )
            evidence_records.append(evidence)
            evidence_records.extend(gate_evidence)
            if current:
                failures.extend(current)
            else:
                passed.append(gate_id)
            feedback_role = _feedback_role(plan, current[0]) if current else spec.feedback_role
            reports.append(
                GateReport(
                    gate_id=gate_id,
                    phase=spec.phase,
                    passed=not current,
                    depends_on=spec.depends_on,
                    hard_gate=spec.hard_gate,
                    failures=[item.reason for item in current],
                    evidence=[evidence, *gate_evidence],
                    feedback_role=feedback_role,
                    retriable=spec.retriable,
                    escalation=spec.escalation,
                )
            )
        policy_result = AdmissionPolicyPipeline().evaluate(reports, admission_context.policy)
        # 防退化：十二道确定性门是唯一准入判据；软风险信号只能用于候选排序和人工复核。
        accepted = not failures
        payload = {
            "plan_id": plan.plan_id,
            "accepted": accepted,
            "checked_state_version": live_state_version,
            "checked_plan_digest": admission_context.plan_digest,
            "checked_state_digest": admission_context.state_digest or "",
            "passed_gates": passed,
            "failures": failures,
            "gate_reports": reports,
            "policy_result": policy_result,
        }
        digest = certificate_digest(payload)
        return AdmissionCertificate(
            plan_id=plan.plan_id,
            accepted=accepted,
            checked_state_version=live_state_version,
            passed_gates=passed,
            failures=failures,
            gate_reports=[
                {
                    "gate_id": report.gate_id,
                    "phase": report.phase,
                    "passed": report.passed,
                    "depends_on": list(report.depends_on),
                    "hard_gate": report.hard_gate,
                    "failures": report.failures,
                    "evidence": [item.__dict__ for item in report.evidence],
                    "feedback_role": report.feedback_role,
                    "retriable": report.retriable,
                    "escalation": report.escalation,
                }
                for report in reports
            ],
            evidence_records=[item.__dict__ for item in evidence_records],
            certificate_digest=digest,
            checked_plan_digest=admission_context.plan_digest,
            checked_state_digest=admission_context.state_digest or "",
            retriable=any(report.retriable for report in reports if not report.passed),
            escalation={
                report.gate_id: report.escalation
                for report in reports
                if not report.passed and report.escalation
            },
            policy_result=policy_result,
        )
