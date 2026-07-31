"""Typed public contracts used by the role-specific agent protocol."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Role(StrEnum):
    OCC = "occ"
    DEPARTURE = "departure"
    ARRIVAL = "arrival"
    PROACTIVE_SHUNTING = "proactive_shunting"


class MessageType(StrEnum):
    PROPOSAL = "proposal"
    OBJECTION = "objection"
    COUNTERPROPOSAL = "counterproposal"
    OWNER_REVISION = "owner_revision"
    DEPENDENCY_REPLAY = "dependency_replay"
    CHECKER_FEEDBACK = "checker_feedback"


@dataclass(frozen=True)
class OperatingEvent:
    event_id: str
    event_type: str
    responsible_role: Role
    state_version: str
    affected_entities: tuple[str, ...]
    description: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceClaim:
    resource_id: str
    start_s: int
    end_s: int


@dataclass
class Action:
    action_id: str
    action_type: str
    owner: Role
    trainset_id: str | None
    start_s: int
    end_s: int
    from_location: str | None = None
    to_location: str | None = None
    route_id: str | None = None
    protected_action_id: str | None = None
    phase: str | None = None
    predecessors: list[str] = field(default_factory=list)
    resources: list[ResourceClaim] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DirectedMessage:
    message_id: str
    sender: Role
    recipient: Role
    message_type: MessageType
    state_version: str
    event_id: str
    objection_id: str | None = None
    resolves_objection_id: str | None = None
    challenged_action_id: str | None = None
    affected_commitment: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    released_or_reassigned_resource: dict[str, Any] = field(default_factory=dict)
    alternative_actions: list[Action] = field(default_factory=list)
    acceptance_condition: dict[str, Any] = field(default_factory=dict)


@dataclass
class CandidatePlan:
    plan_id: str
    event_id: str
    state_version: str
    actions: list[Action]
    messages: list[DirectedMessage] = field(default_factory=list)
    unresolved_blocking_objections: list[str] = field(default_factory=list)
    replayed_commitments: list[str] = field(default_factory=list)
    known_entities: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["known_entities"] = sorted(self.known_entities)
        return payload


@dataclass(frozen=True)
class GateFailure:
    gate_id: str
    reason: str
    action_id: str | None = None
    resource_id: str | None = None


@dataclass
class AdmissionCertificate:
    plan_id: str
    accepted: bool
    checked_state_version: str
    passed_gates: list[str]
    failures: list[GateFailure]
    # 防退化：证书保留旧字段，同时新增逐门证据和摘要；不得退回只给 accepted 的黑盒结果。
    gate_reports: list[dict[str, Any]] = field(default_factory=list)
    evidence_records: list[dict[str, Any]] = field(default_factory=list)
    certificate_digest: str = ""
    checked_plan_digest: str = ""
    checked_state_digest: str = ""
    retriable: bool = False
    escalation: dict[str, Any] = field(default_factory=dict)
    policy_result: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentRequest:
    role: Role
    system_instruction: str
    event: OperatingEvent
    state_projection: dict[str, Any]
    candidate_plan: dict[str, Any]
    response_schema: dict[str, Any]


@dataclass(frozen=True)
class AgentResponse:
    content: str
    model: str
    usage: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
