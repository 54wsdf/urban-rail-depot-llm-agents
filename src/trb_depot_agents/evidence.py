"""Extension boundary for site-specific safety evidence.

The public package validates portable contracts and graph invariants.  A depot
can bind proprietary lifecycle, eligibility, work-continuity, or throat rules
through this protocol without placing those rules in the public repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .contracts import CandidatePlan


@dataclass(frozen=True)
class SiteSafetyRequest:
    gate_id: str
    plan: CandidatePlan
    live_state_version: str
    plan_digest: str
    state_digest: str
    state_projection: dict[str, Any]
    spatial_model: Any | None


@dataclass(frozen=True)
class SiteSafetyDecision:
    gate_id: str
    accepted: bool
    evidence_id: str
    evidence_digest: str
    plan_digest: str
    state_digest: str
    summary: str


class SiteSafetyAdapter(Protocol):
    """Return server-produced evidence for one configured hard gate."""

    def evaluate(self, request: SiteSafetyRequest) -> SiteSafetyDecision:
        ...
