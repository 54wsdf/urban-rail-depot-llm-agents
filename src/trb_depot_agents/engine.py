from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .admission import AdmissionContext
from .communication import path_between
from .contracts import (
    Action,
    AgentRequest,
    CandidatePlan,
    DirectedMessage,
    GateFailure,
    MessageType,
    OperatingEvent,
    ResourceClaim,
    Role,
)
from .prompts import prompt_for
from .providers.base import AgentProvider
from .registry import AdmissionCheckerProtocol
from .roles import owns
from .safety import SafetyAdmissionChecker
from .ledger import CommitmentLedger, CommitmentRecord, message_evidence_complete
from .integrity import plan_digest, state_digest


@dataclass(frozen=True)
class EpisodeBudget:
    max_model_calls: int = 8
    max_rounds: int = 4
    max_messages: int = 24
    max_owner_revisions: int = 12
    max_replayed_commitments: int = 32

    def __post_init__(self) -> None:
        values = {
            "max_model_calls": self.max_model_calls,
            "max_rounds": self.max_rounds,
            "max_messages": self.max_messages,
            "max_owner_revisions": self.max_owner_revisions,
            "max_replayed_commitments": self.max_replayed_commitments,
        }
        invalid = [name for name, value in values.items() if value < 1]
        if invalid:
            raise ValueError(f"episode budgets must be positive: {invalid}")


@dataclass
class EpisodeResult:
    status: str
    plan: CandidatePlan
    certificate: dict[str, Any] | None
    model_calls: int
    rounds: int
    usage: dict[str, int] = field(default_factory=dict)
    error: str | None = None


def _role(value: str | Role) -> Role:
    return value if isinstance(value, Role) else Role(value)


def _action(payload: dict[str, Any]) -> Action:
    return Action(
        action_id=str(payload["action_id"]),
        action_type=str(payload["action_type"]),
        owner=_role(payload["owner"]),
        trainset_id=payload.get("trainset_id"),
        start_s=int(payload["start_s"]),
        end_s=int(payload["end_s"]),
        from_location=payload.get("from_location"),
        to_location=payload.get("to_location"),
        route_id=payload.get("route_id"),
        protected_action_id=payload.get("protected_action_id"),
        phase=payload.get("phase"),
        predecessors=list(payload.get("predecessors", [])),
        resources=[
            ResourceClaim(
                resource_id=str(item["resource_id"]),
                start_s=int(item["start_s"]),
                end_s=int(item["end_s"]),
            )
            for item in payload.get("resources", [])
        ],
        metadata=dict(payload.get("metadata", {})),
    )


class AgentNetwork:
    def __init__(
        self,
        provider: AgentProvider,
        checker: AdmissionCheckerProtocol | None = None,
    ) -> None:
        self.provider = provider
        self.checker = checker or SafetyAdmissionChecker()

    def run(
        self,
        *,
        event: OperatingEvent,
        state_projection: dict[str, Any],
        plan: CandidatePlan,
        response_schema: dict[str, Any] | None = None,
        budget: EpisodeBudget | None = None,
        spatial_model: Any | None = None,
        track_intervals: list[dict[str, Any]] | None = None,
        policy: dict[str, Any] | None = None,
    ) -> EpisodeResult:
        limits = budget or EpisodeBudget()
        if (
            event.event_id != plan.event_id
            or event.state_version != plan.state_version
        ):
            # 防退化：协调回合必须与候选计划绑定同一事件和状态，不能等到消息生成后才暴露跨事件污染。
            return EpisodeResult(
                "invalid_event_binding",
                plan,
                None,
                0,
                0,
                {},
                "event and candidate plan use different identities",
            )
        state_projection = dict(state_projection)
        raw_state_digest = state_projection.pop("state_digest", None)
        submitted_state_digest = str(raw_state_digest) if raw_state_digest else None
        computed_state_digest = state_digest(state_projection)
        queue: list[tuple[Role, dict[str, Any] | None]] = [
            (event.responsible_role, None)
        ]
        model_calls = 0
        rounds = 0
        usage: dict[str, int] = {}
        message_index = 0
        owner_revision_count = 0
        initial_action_ids = [action.action_id for action in plan.actions]
        if len(initial_action_ids) != len(set(initial_action_ids)):
            # 防退化：初始计划必须先保留原始序列完成唯一性检查，不能先转字典再让重复动作静默消失。
            return EpisodeResult(
                "invalid_plan_identity",
                plan,
                None,
                model_calls,
                rounds,
                usage,
                "duplicate action_id in initial candidate plan",
            )
        action_index = {action.action_id: action for action in plan.actions}
        try:
            commitment_ledger = CommitmentLedger.from_payload(
                list(plan.metadata.get("commitment_ledger", []))
            )
        except (KeyError, TypeError, ValueError) as exc:
            return EpisodeResult(
                "invalid_commitment_ledger",
                plan,
                None,
                model_calls,
                rounds,
                usage,
                str(exc),
            )

        while queue and model_calls < limits.max_model_calls and rounds < limits.max_rounds:
            role, incoming = queue.pop(0)
            request_state = dict(state_projection)
            request_state["state_digest"] = computed_state_digest
            if incoming:
                request_state["incoming"] = incoming
            response = self.provider.generate(
                AgentRequest(
                    role=role,
                    system_instruction=prompt_for(role),
                    event=event,
                    state_projection=request_state,
                    candidate_plan=plan.to_dict(),
                    response_schema=response_schema or {},
                )
            )
            model_calls += 1
            rounds = max(rounds, int(incoming.get("round", 0)) + 1 if incoming else 1)
            for key, value in response.usage.items():
                if isinstance(value, int):
                    usage[key] = usage.get(key, 0) + value
            try:
                output = json.loads(response.content)
            except json.JSONDecodeError as exc:
                return EpisodeResult(
                    "invalid_response",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    str(exc),
                )

            action_batch = [
                _action(raw_action) for raw_action in output.get("actions", [])
            ]
            batch_ids = [action.action_id for action in action_batch]
            if len(batch_ids) != len(set(batch_ids)):
                return EpisodeResult(
                    "invalid_response",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    "duplicate action_id in one agent response",
                )
            revised_action_ids: set[str] = set()
            for action in action_batch:
                if action.owner != role or not owns(role, action.action_type):
                    return EpisodeResult(
                        "owner_violation",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                        action.action_id,
                    )
                is_revision = action.action_id in action_index
                if is_revision and action_index[action.action_id].owner != role:
                    # 防退化：动作标识属于原所有者，其他角色不能用同一 action_id 替换成自己的动作并绕过 owner revision。
                    return EpisodeResult(
                        "owner_violation",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                        action.action_id,
                    )
                action_index[action.action_id] = action
                if is_revision:
                    revised_action_ids.add(action.action_id)
                    owner_revision_count += 1
                    plan.metadata.setdefault("owner_revisions", []).append(
                        {
                            "role": role.value,
                            "action_id": action.action_id,
                            "round": rounds,
                        }
                    )
                else:
                    plan.metadata.setdefault("action_submissions", []).append(
                        {
                            "role": role.value,
                            "action_id": action.action_id,
                            "round": rounds,
                        }
                    )
                if owner_revision_count > limits.max_owner_revisions:
                    return EpisodeResult(
                        "revision_budget_exhausted",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                        action.action_id,
                    )
            plan.actions = list(action_index.values())
            if output.get("commitment_ledger"):
                commitments_before_round = set(commitment_ledger.records)
                try:
                    for raw_record in output["commitment_ledger"]:
                        record = CommitmentRecord.from_dict(dict(raw_record))
                        owned_action = (
                            action_index.get(record.action_id)
                            if record.action_id is not None
                            else None
                        )
                        if (
                            record.owner is not role
                            or owned_action is None
                            or owned_action.owner is not role
                            or record.state_version != plan.state_version
                            or not record.evidence_ids
                        ):
                            raise ValueError(
                                f"commitment is not bound to the current owner action: {record.commitment_id}"
                            )
                        commitment_ledger.add(record)
                except (KeyError, TypeError, ValueError) as exc:
                    return EpisodeResult(
                        "invalid_commitment_ledger",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                        str(exc),
                    )
                plan.metadata["commitment_ledger"] = [
                    item.to_dict() for item in commitment_ledger.records.values()
                ]
            else:
                commitments_before_round = set(commitment_ledger.records)

            outgoing = output.get("messages", [])
            round_messages: list[DirectedMessage] = []
            for raw_message in outgoing:
                if message_index >= limits.max_messages:
                    return EpisodeResult(
                        "message_budget_exhausted",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                    )
                recipient = _role(raw_message["recipient"])
                path_between(role, recipient)
                message_index += 1
                message = DirectedMessage(
                    message_id=f"{event.event_id}-M{message_index:03d}",
                    sender=role,
                    recipient=recipient,
                    message_type=MessageType(raw_message["message_type"]),
                    state_version=plan.state_version,
                    event_id=event.event_id,
                    objection_id=raw_message.get("objection_id"),
                    resolves_objection_id=raw_message.get("resolves_objection_id"),
                    challenged_action_id=raw_message.get("challenged_action_id"),
                    affected_commitment=raw_message.get("affected_commitment"),
                    evidence=dict(raw_message.get("evidence", {})),
                    released_or_reassigned_resource=dict(
                        raw_message.get("released_or_reassigned_resource", {})
                    ),
                    # 防退化：反提案中的替代动作必须随消息保留，不能在角色转发时只留下文字条件。
                    alternative_actions=[
                        _action(item)
                        for item in raw_message.get("alternative_actions", [])
                    ],
                    acceptance_condition=dict(raw_message.get("acceptance_condition", {})),
                )
                plan.messages.append(message)
                round_messages.append(message)
                queue.append(
                    (
                        recipient,
                        {
                            "round": rounds,
                            "message": raw_message,
                            "sender": role.value,
                        },
                    )
                )

            revision_proofs = {
                message.challenged_action_id
                for message in round_messages
                if message.message_type is MessageType.OWNER_REVISION
                and message.sender is role
                and message.challenged_action_id is not None
                and message_evidence_complete(message)
                and any(
                    alternative == action_index.get(message.challenged_action_id)
                    for alternative in message.alternative_actions
                )
            }
            missing_revision_proofs = sorted(revised_action_ids - revision_proofs)
            if missing_revision_proofs:
                # 防退化：责任人改动必须伴随可核对的 owner-revision 消息，不能只改 action_index 后补一条统计记录。
                return EpisodeResult(
                    "invalid_owner_revision_evidence",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    ",".join(missing_revision_proofs),
                )

            requested_open = set(map(str, output.get("open_blocking_objections", [])))
            evidenced_open = {
                message.objection_id
                for message in round_messages
                if message.message_type is MessageType.OBJECTION
                and message.objection_id
                and message_evidence_complete(message)
            }
            if requested_open - evidenced_open:
                return EpisodeResult(
                    "invalid_objection_evidence",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    ",".join(sorted(requested_open - evidenced_open)),
                )
            for objection_id in sorted(requested_open):
                if objection_id not in plan.unresolved_blocking_objections:
                    plan.unresolved_blocking_objections.append(objection_id)

            requested_resolved = set(
                map(str, output.get("resolve_blocking_objections", []))
            )
            unknown_resolutions = requested_resolved - set(
                plan.unresolved_blocking_objections
            )
            if unknown_resolutions:
                return EpisodeResult(
                    "invalid_objection_resolution",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    ",".join(sorted(unknown_resolutions)),
                )
            resolution_sequence = [
                message
                for message in round_messages
                if message.message_type is MessageType.OWNER_REVISION
                and message.resolves_objection_id
                and message_evidence_complete(message)
            ]
            resolution_ids = [
                str(message.resolves_objection_id) for message in resolution_sequence
            ]
            if len(resolution_ids) != len(set(resolution_ids)):
                return EpisodeResult(
                    "invalid_objection_resolution",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    "one objection has more than one owner revision",
                )
            resolution_messages = {
                str(message.resolves_objection_id): message
                for message in resolution_sequence
            }
            evidenced_resolved = set(resolution_messages)
            if requested_resolved - evidenced_resolved:
                return EpisodeResult(
                    "invalid_objection_resolution",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    ",".join(sorted(requested_resolved - evidenced_resolved)),
                )
            opening_messages = {
                str(message.objection_id): message
                for message in plan.messages
                if message.message_type is MessageType.OBJECTION
                and message.objection_id
                and message_evidence_complete(message)
            }
            for objection_id in requested_resolved:
                if objection_id not in opening_messages:
                    return EpisodeResult(
                        "invalid_objection_resolution",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                        objection_id,
                    )
                opening = opening_messages[objection_id]
                resolution = resolution_messages[objection_id]
                if (
                    opening.challenged_action_id != resolution.challenged_action_id
                    or opening.affected_commitment != resolution.affected_commitment
                ):
                    return EpisodeResult(
                        "invalid_objection_resolution",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                        objection_id,
                    )
            plan.unresolved_blocking_objections = [
                item
                for item in plan.unresolved_blocking_objections
                if item not in requested_resolved
            ]

            requested_replays = set(map(str, output.get("replay_commitments", [])))
            replay_messages = {
                message.affected_commitment: message
                for message in round_messages
                if message.message_type is MessageType.DEPENDENCY_REPLAY
                and message.affected_commitment
                and message_evidence_complete(message)
            }
            if requested_replays != set(replay_messages):
                return EpisodeResult(
                    "invalid_dependency_replay",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                    "replay list and dependency-replay messages differ",
                )
            for commitment_id in sorted(requested_replays):
                replay_record = commitment_ledger.records.get(commitment_id)
                if (
                    replay_record is None
                    or commitment_id not in commitments_before_round
                    or replay_messages[commitment_id].sender is not replay_record.owner
                ):
                    return EpisodeResult(
                        "invalid_dependency_replay",
                        plan,
                        None,
                        model_calls,
                        rounds,
                        usage,
                        commitment_id,
                    )
                if commitment_id not in plan.replayed_commitments:
                    plan.replayed_commitments.append(commitment_id)
            if len(plan.replayed_commitments) > limits.max_replayed_commitments:
                return EpisodeResult(
                    "replay_budget_exhausted",
                    plan,
                    None,
                    model_calls,
                    rounds,
                    usage,
                )
            # 防退化：依赖重放必须同时由账本、责任人消息和计划状态证明，不能只接受模型返回的字符串列表。

            if not queue and not plan.unresolved_blocking_objections:
                certificate = self.checker.check(
                    plan,
                    event.state_version,
                    context=AdmissionContext(
                        state_projection=state_projection,
                        # 防退化：episode 证书绑定实际投影和最终计划的重算摘要，不能沿用模型输入中的自声明摘要。
                        state_digest=computed_state_digest,
                        plan_digest=plan_digest(plan),
                        submitted_state_digest=submitted_state_digest,
                        spatial_model=spatial_model,
                        track_intervals=list(track_intervals or []),
                        policy=dict(policy or {}),
                    ),
                )
                if certificate.accepted:
                    return EpisodeResult(
                        "admitted",
                        plan,
                        asdict(certificate),
                        model_calls,
                        rounds,
                        usage,
                    )
                queue.extend(
                    self._checker_targets(
                        event.responsible_role,
                        plan,
                        certificate.failures,
                        rounds,
                    )
                )

        return EpisodeResult(
            "budget_exhausted",
            plan,
            None,
            model_calls,
            rounds,
            usage,
        )

    @staticmethod
    def _checker_targets(
        initial_role: Role,
        plan: CandidatePlan,
        failures: list[GateFailure],
        round_index: int,
    ) -> list[tuple[Role, dict[str, Any]]]:
        actions = {action.action_id: action for action in plan.actions}
        targets: list[tuple[Role, dict[str, Any]]] = []
        seen: set[Role] = set()
        for failure in failures:
            owner = (
                actions[failure.action_id].owner
                if failure.action_id and failure.action_id in actions
                else initial_role
            )
            if owner in seen:
                continue
            seen.add(owner)
            targets.append(
                (
                    owner,
                    {
                        "round": round_index,
                        "checker_feedback": {
                            "gate_id": failure.gate_id,
                            "reason": failure.reason,
                            "action_id": failure.action_id,
                            "resource_id": failure.resource_id,
                        },
                    },
                )
            )
        return targets
