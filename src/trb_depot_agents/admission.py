from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class GateSpecification:
    gate_id: str
    name: str
    phase: str
    depends_on: tuple[str, ...] = ()
    hard_gate: bool = True
    feedback_role: str | None = None
    retriable: bool = True
    escalation: str | None = None


@dataclass(frozen=True)
class EvidenceRecord:
    gate_id: str
    evidence_type: str
    digest: str
    summary: str


@dataclass
class GateReport:
    gate_id: str
    phase: str
    passed: bool
    depends_on: tuple[str, ...] = ()
    hard_gate: bool = True
    failures: list[str] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    feedback_role: str | None = None
    retriable: bool = True
    escalation: str | None = None


@dataclass
class AdmissionContext:
    state_projection: dict[str, Any] = field(default_factory=dict)
    state_digest: str | None = None
    plan_digest: str | None = None
    submitted_state_digest: str | None = None
    submitted_plan_digest: str | None = None
    spatial_model: Any | None = None
    track_intervals: list[dict[str, Any]] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)


class AdmissionPolicyPipeline:
    """Run optional soft policy scoring after hard gates have made the decision."""

    def evaluate(self, reports: list[GateReport], policy: dict[str, Any]) -> dict[str, Any]:
        hard_failures = [report.gate_id for report in reports if report.hard_gate and not report.passed]
        risk_score = float(policy.get("risk_score", 0.0)) if policy else 0.0
        max_risk_score = float(policy.get("max_risk_score", 1.0)) if policy else 1.0
        if not math.isfinite(risk_score) or not math.isfinite(max_risk_score):
            raise ValueError("admission policy risk values must be finite")
        if risk_score < 0.0 or max_risk_score < 0.0:
            raise ValueError("admission policy risk values must be non-negative")
        # 防退化：风险分只能作为排序和复核信号，不能覆盖 deterministic hard gate 的拒绝结论。
        return {
            "hard_failures": hard_failures,
            "risk_score": risk_score,
            "max_risk_score": max_risk_score,
            "risk_score_overrides_hard_gates": False,
            "within_advisory_risk_bound": risk_score <= max_risk_score,
            "admission_decision": not hard_failures,
        }
