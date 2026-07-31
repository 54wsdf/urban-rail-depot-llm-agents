from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .admission import AdmissionContext
from .contracts import AdmissionCertificate, CandidatePlan


class AdmissionCheckerProtocol(Protocol):
    def check(
        self,
        plan: CandidatePlan,
        live_state_version: str,
        *,
        context: AdmissionContext | None = None,
    ) -> AdmissionCertificate:
        ...


@dataclass
class MechanismRegistry:
    admission_checker: AdmissionCheckerProtocol
    shadow_checker: AdmissionCheckerProtocol | None = None
    canaries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def run_shadow(
        self,
        plan: CandidatePlan,
        live_state_version: str,
        context: AdmissionContext,
    ) -> dict[str, Any] | None:
        if self.shadow_checker is None:
            return None
        certificate = self.shadow_checker.check(plan, live_state_version, context=context)
        # 防退化：shadow lane 默认只产出可审计差异，不得接管 admission 的硬门结论。
        return {
            "accepted": certificate.accepted,
            "certificate_digest": certificate.certificate_digest,
            "passed_gates": certificate.passed_gates,
            "failure_count": len(certificate.failures),
        }

    def canary_status(self) -> dict[str, Any]:
        return {"enabled": bool(self.canaries), "items": dict(self.canaries)}
