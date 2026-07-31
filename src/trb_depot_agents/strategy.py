from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .contracts import Action, DirectedMessage, MessageType, Role


class ExchangeType(StrEnum):
    TRAINSET = "trainset"
    TIME = "time"
    TRACK = "track"
    ROUTE = "route"
    ORDER = "order"
    MOVEMENT_CHAIN = "movement_chain"


@dataclass(frozen=True)
class Counterproposal:
    sender: Role
    recipient: Role
    challenged_action_id: str
    affected_commitment: str
    exchange_type: ExchangeType
    released_or_reassigned_resource: dict[str, Any]
    alternative_actions: tuple[Action, ...]
    acceptance_condition: dict[str, Any]
    evidence: dict[str, Any]

    def to_message(
        self,
        *,
        message_id: str,
        event_id: str,
        state_version: str,
    ) -> DirectedMessage:
        return DirectedMessage(
            message_id=message_id,
            sender=self.sender,
            recipient=self.recipient,
            message_type=MessageType.COUNTERPROPOSAL,
            state_version=state_version,
            event_id=event_id,
            challenged_action_id=self.challenged_action_id,
            affected_commitment=self.affected_commitment,
            evidence=self.evidence,
            released_or_reassigned_resource={
                "type": self.exchange_type.value,
                **self.released_or_reassigned_resource,
            },
            alternative_actions=list(self.alternative_actions),
            acceptance_condition=self.acceptance_condition,
        )


def response_order(messages: list[DirectedMessage]) -> list[DirectedMessage]:
    return sorted(
        messages,
        key=lambda item: (
            int(item.evidence.get("affected_time_s", 2**31 - 1)),
            item.message_id,
        ),
    )

