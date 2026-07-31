from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass, field
from typing import Any

from .contracts import Action, DirectedMessage, Role


@dataclass(frozen=True)
class CommitmentRecord:
    commitment_id: str
    owner: Role
    action_id: str | None
    state_version: str
    evidence_ids: tuple[str, ...] = ()
    supersedes: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CommitmentRecord":
        return cls(
            commitment_id=str(payload["commitment_id"]),
            owner=Role(payload["owner"]),
            action_id=(
                str(payload["action_id"]) if payload.get("action_id") is not None else None
            ),
            state_version=str(payload["state_version"]),
            evidence_ids=tuple(map(str, payload.get("evidence_ids", []))),
            supersedes=(
                str(payload["supersedes"])
                if payload.get("supersedes") is not None
                else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["owner"] = self.owner.value
        return payload


@dataclass
class CommitmentLedger:
    records: dict[str, CommitmentRecord] = field(default_factory=dict)

    def add(self, record: CommitmentRecord) -> None:
        if record.commitment_id in self.records:
            raise ValueError(f"duplicate commitment_id: {record.commitment_id}")
        self.records[record.commitment_id] = record

    @classmethod
    def from_payload(cls, payload: list[dict[str, Any]]) -> "CommitmentLedger":
        ledger = cls()
        for item in payload:
            ledger.add(CommitmentRecord.from_dict(dict(item)))
        return ledger

    def validate(
        self,
        *,
        action_owners: dict[str, Role],
        state_version: str,
    ) -> list[str]:
        failures: list[str] = []
        for record in self.records.values():
            if record.state_version != state_version:
                failures.append(f"{record.commitment_id}:stale_state")
            if not record.evidence_ids:
                failures.append(f"{record.commitment_id}:missing_evidence")
            if record.action_id:
                expected_owner = action_owners.get(record.action_id)
                if expected_owner is None:
                    failures.append(f"{record.commitment_id}:unknown_action")
                elif expected_owner != record.owner:
                    failures.append(f"{record.commitment_id}:owner_mismatch")
            else:
                failures.append(f"{record.commitment_id}:missing_action")
            if record.supersedes and record.supersedes not in self.records:
                failures.append(f"{record.commitment_id}:unknown_superseded_commitment")
        return failures

    def replay_missing(self, required_ids: list[str], replayed_ids: list[str]) -> list[str]:
        replayed = set(replayed_ids)
        return [commitment_id for commitment_id in required_ids if commitment_id not in replayed]


def commitment_owner_for_action(action: Action) -> CommitmentRecord:
    return CommitmentRecord(
        commitment_id=f"{action.action_id}:owner",
        owner=action.owner,
        action_id=action.action_id,
        state_version=str(action.metadata.get("state_version", "")),
    )


def message_evidence_complete(message: DirectedMessage) -> bool:
    if message.message_type.value == "objection":
        return bool(
            message.objection_id
            and message.challenged_action_id
            and message.affected_commitment
            and message.evidence
        )
    if message.message_type.value == "counterproposal":
        return bool(
            message.challenged_action_id
            and message.affected_commitment
            and message.evidence
            and message.released_or_reassigned_resource
            and message.alternative_actions
            and message.acceptance_condition
        )
    if message.message_type.value == "owner_revision":
        return bool(
            message.challenged_action_id
            and message.affected_commitment
            and message.evidence
            and any(
                action.action_id == message.challenged_action_id
                and action.owner is message.sender
                for action in message.alternative_actions
            )
        )
    if message.message_type.value == "dependency_replay":
        return bool(message.affected_commitment and message.evidence)
    if message.message_type.value == "checker_feedback":
        return bool(message.evidence)
    return True


def message_evidence_ids(message: DirectedMessage) -> set[str]:
    raw_identifiers = message.evidence.get("evidence_ids", [])
    identifiers = (
        set(map(str, raw_identifiers))
        if isinstance(raw_identifiers, (list, tuple, set))
        else set()
    )
    if message.evidence.get("evidence_id") is not None:
        identifiers.add(str(message.evidence["evidence_id"]))
    return {item for item in identifiers if item}
