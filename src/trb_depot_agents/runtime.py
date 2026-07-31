"""Event-driven directed coordination without a fixed four-role pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import count

from .communication import path_between
from .contracts import Action, CandidatePlan, DirectedMessage, MessageType, OperatingEvent, Role
from .ledger import CommitmentLedger, message_evidence_complete


@dataclass
class EventDrivenCoordinator:
    """Maintain directed messages, owner revisions, and dependency replay.

    This class records the public coordination contract. Model-specific decision
    generation is delegated to an AgentProvider.
    """

    event: OperatingEvent
    plan: CandidatePlan
    active_role: Role = field(init=False)
    _sequence: count = field(default_factory=lambda: count(1), init=False, repr=False)

    def __post_init__(self) -> None:
        self.active_role = self.event.responsible_role
        if self.plan.event_id != self.event.event_id:
            raise ValueError("Event and candidate plan must share the same event_id")
        if self.plan.state_version != self.event.state_version:
            raise ValueError("Event and candidate plan must share the same state version")

    def send(
        self,
        recipient: Role,
        message_type: MessageType,
        *,
        objection_id: str | None = None,
        resolves_objection_id: str | None = None,
        challenged_action_id: str | None = None,
        affected_commitment: str | None = None,
        evidence: dict | None = None,
        released_or_reassigned_resource: dict | None = None,
        alternative_actions: list[Action] | None = None,
        acceptance_condition: dict | None = None,
    ) -> DirectedMessage:
        sender = self.active_role
        path_between(sender, recipient)
        message = DirectedMessage(
            message_id=f"{self.event.event_id}-M{next(self._sequence):03d}",
            sender=sender,
            recipient=recipient,
            message_type=message_type,
            state_version=self.plan.state_version,
            event_id=self.event.event_id,
            objection_id=objection_id,
            resolves_objection_id=resolves_objection_id,
            challenged_action_id=challenged_action_id,
            affected_commitment=affected_commitment,
            evidence=evidence or {},
            released_or_reassigned_resource=released_or_reassigned_resource or {},
            alternative_actions=alternative_actions or [],
            acceptance_condition=acceptance_condition or {},
        )
        if not message_evidence_complete(message):
            raise ValueError("directed message lacks the evidence required by its type")
        if message_type in {
            MessageType.OBJECTION,
            MessageType.COUNTERPROPOSAL,
            MessageType.OWNER_REVISION,
            MessageType.DEPENDENCY_REPLAY,
        }:
            ledger = CommitmentLedger.from_payload(
                list(self.plan.metadata.get("commitment_ledger", []))
            )
            record = (
                ledger.records.get(affected_commitment)
                if affected_commitment
                else None
            )
            if record is None:
                raise ValueError("directed message references no authoritative commitment")
            if (
                message_type in {MessageType.OWNER_REVISION, MessageType.DEPENDENCY_REPLAY}
                and record.owner is not sender
            ):
                raise PermissionError("only the commitment owner may revise or replay it")
        if (
            message_type is MessageType.OBJECTION
            and objection_id in self.plan.unresolved_blocking_objections
        ):
            raise ValueError("blocking objection id is already open")
        if (
            message_type is MessageType.COUNTERPROPOSAL
            and resolves_objection_id
        ):
            # 防退化：反提案只能形成交换条件，不能越过动作所有者修订直接清除阻断性异议。
            raise ValueError("counterproposal cannot close a blocking objection")
        if (
            message_type is MessageType.OWNER_REVISION
            and resolves_objection_id
            and resolves_objection_id not in self.plan.unresolved_blocking_objections
        ):
            raise ValueError("owner revision resolves no open objection")
        if message_type is MessageType.OWNER_REVISION and resolves_objection_id:
            opening = next(
                (
                    item
                    for item in self.plan.messages
                    if item.message_type is MessageType.OBJECTION
                    and item.objection_id == resolves_objection_id
                ),
                None,
            )
            if (
                opening is None
                or opening.challenged_action_id != challenged_action_id
                or opening.affected_commitment != affected_commitment
            ):
                raise ValueError(
                    "owner revision is not bound to the challenged action and commitment"
                )
        self.plan.messages.append(message)
        if message_type is MessageType.OBJECTION and objection_id:
            self.plan.unresolved_blocking_objections.append(objection_id)
        if message_type is MessageType.OWNER_REVISION and resolves_objection_id:
            self.plan.unresolved_blocking_objections.remove(resolves_objection_id)
        if message_type is MessageType.DEPENDENCY_REPLAY and affected_commitment:
            if affected_commitment not in self.plan.replayed_commitments:
                self.plan.replayed_commitments.append(affected_commitment)
        self.active_role = recipient
        return message

    def owner_revision(self, action_id: str, owner: Role) -> None:
        action = next((item for item in self.plan.actions if item.action_id == action_id), None)
        if action is None:
            raise KeyError(action_id)
        if action.owner != owner:
            raise PermissionError("Only the action owner may revise an action")
        # 防退化：兼容入口只负责把控制权交还责任人；实际替换必须经 apply_owner_revision 写入消息证据。
        self.active_role = owner

    def apply_owner_revision(
        self,
        replacement: Action,
        *,
        recipient: Role,
        affected_commitment: str,
        evidence: dict,
        resolves_objection_id: str | None = None,
    ) -> DirectedMessage:
        current = next(
            (
                item
                for item in self.plan.actions
                if item.action_id == replacement.action_id
            ),
            None,
        )
        if current is None:
            raise KeyError(replacement.action_id)
        if current.owner is not self.active_role or replacement.owner is not current.owner:
            raise PermissionError("only the active action owner may apply a revision")
        message = self.send(
            recipient,
            MessageType.OWNER_REVISION,
            resolves_objection_id=resolves_objection_id,
            challenged_action_id=current.action_id,
            affected_commitment=affected_commitment,
            evidence=evidence,
            alternative_actions=[replacement],
        )
        self.plan.actions = [
            replacement if item.action_id == replacement.action_id else item
            for item in self.plan.actions
        ]
        self.plan.metadata.setdefault("owner_revisions", []).append(
            {
                "role": replacement.owner.value,
                "action_id": replacement.action_id,
                "message_id": message.message_id,
            }
        )
        return message

    def replay(self, commitment_ids: list[str]) -> None:
        evidenced = {
            message.affected_commitment
            for message in self.plan.messages
            if message.message_type is MessageType.DEPENDENCY_REPLAY
            and message.affected_commitment
            and message_evidence_complete(message)
        }
        for commitment_id in commitment_ids:
            if commitment_id not in evidenced:
                # 防退化：便捷重放入口只能投影已存在的 dependency-replay 消息，不能自行制造已重放状态。
                raise ValueError(f"commitment lacks dependency-replay evidence: {commitment_id}")
            if commitment_id not in self.plan.replayed_commitments:
                self.plan.replayed_commitments.append(commitment_id)

    @property
    def ready_for_admission(self) -> bool:
        return not self.plan.unresolved_blocking_objections
