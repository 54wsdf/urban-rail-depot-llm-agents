from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .admission import AdmissionContext
from .communication import DIRECTED_PATHS
from .contracts import (
    Action,
    AgentRequest,
    CandidatePlan,
    DirectedMessage,
    MessageType,
    OperatingEvent,
    ResourceClaim,
    Role,
)
from .integrity import plan_digest, state_digest
from .prompts import prompt_for
from .protected_spatial import ProtectedSpatialBundleLoader
from .providers.base import AgentProvider
from .registry import MechanismRegistry
from .roles import ROLE_CONTRACTS
from .safety import GATES, SafetyAdmissionChecker
from .settings import load_settings
from .spatial import SpatialModel
from .state import StateReplay, StateStore
from .engine import AgentNetwork, EpisodeBudget


def _role(value: str | Role) -> Role:
    return value if isinstance(value, Role) else Role(value)


def _event(payload: dict[str, Any]) -> OperatingEvent:
    return OperatingEvent(
        event_id=str(payload["event_id"]),
        event_type=str(payload["event_type"]),
        responsible_role=_role(payload["responsible_role"]),
        state_version=str(payload["state_version"]),
        affected_entities=tuple(map(str, payload.get("affected_entities", []))),
        description=str(payload.get("description", "")),
        attributes=dict(payload.get("attributes", {})),
    )


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


def _message(payload: dict[str, Any]) -> DirectedMessage:
    return DirectedMessage(
        message_id=str(payload["message_id"]),
        sender=_role(payload["sender"]),
        recipient=_role(payload["recipient"]),
        message_type=MessageType(payload["message_type"]),
        state_version=str(payload["state_version"]),
        event_id=str(payload["event_id"]),
        objection_id=payload.get("objection_id"),
        resolves_objection_id=payload.get("resolves_objection_id"),
        challenged_action_id=payload.get("challenged_action_id"),
        affected_commitment=payload.get("affected_commitment"),
        evidence=dict(payload.get("evidence", {})),
        released_or_reassigned_resource=dict(
            payload.get("released_or_reassigned_resource", {})
        ),
        alternative_actions=[
            _action(item) for item in payload.get("alternative_actions", [])
        ],
        acceptance_condition=dict(payload.get("acceptance_condition", {})),
    )


def _plan(payload: dict[str, Any]) -> CandidatePlan:
    return CandidatePlan(
        plan_id=str(payload["plan_id"]),
        event_id=str(payload["event_id"]),
        state_version=str(payload["state_version"]),
        actions=[_action(item) for item in payload.get("actions", [])],
        # 防退化：准入必须看到完整定向通信记录，不能在 API 反序列化时丢掉异议、反提案和责任人修订证据。
        messages=[_message(item) for item in payload.get("messages", [])],
        unresolved_blocking_objections=list(
            payload.get("unresolved_blocking_objections", [])
        ),
        replayed_commitments=list(payload.get("replayed_commitments", [])),
        known_entities=set(map(str, payload.get("known_entities", []))),
        metadata=dict(payload.get("metadata", {})),
    )


class DepotAgentAPI:
    def __init__(
        self,
        provider: AgentProvider | None = None,
        checker: SafetyAdmissionChecker | None = None,
        registry: MechanismRegistry | None = None,
        protected_loader: ProtectedSpatialBundleLoader | None = None,
        state_store: StateStore | None = None,
        default_spatial_model: SpatialModel | None = None,
    ) -> None:
        self.provider = provider
        primary_checker = checker or SafetyAdmissionChecker()
        self.registry = registry or MechanismRegistry(primary_checker)
        # 防退化：主准入必须从注册表唯一装配，不能让 API checker 与 registry checker 分裂成两套结论。
        self.checker = self.registry.admission_checker
        self.protected_loader = protected_loader or ProtectedSpatialBundleLoader()
        self.state_store = state_store
        self.default_spatial_model = default_spatial_model
        self.replay = StateReplay()

    def _spatial_model(self, payload: dict[str, Any]) -> SpatialModel | None:
        spatial_model = self.default_spatial_model
        if payload.get("protected_spatial_bundle"):
            protected_bundle = payload["protected_spatial_bundle"]
            if not isinstance(protected_bundle, dict):
                # 防退化：公共 HTTP 请求不得提交服务器本地路径，避免利用加密资产入口读取任意文件。
                raise TypeError("protected_spatial_bundle must be an inline envelope object")
            spatial_model = self.protected_loader.load(protected_bundle)
        elif payload.get("spatial_model"):
            spatial_model = SpatialModel.from_dict(dict(payload["spatial_model"]))
        return spatial_model

    def protocol(self) -> dict[str, Any]:
        return {
            "roles": [role.value for role in Role],
            "channels": [
                {
                    "sender": item.sender.value,
                    "recipient": item.recipient.value,
                    "condition": item.activation_condition,
                }
                for item in DIRECTED_PATHS
            ],
            "gates": [{"id": gate_id, "name": name} for gate_id, name, _ in GATES],
            "actions": {
                role.value: sorted(contract.owned_actions)
                for role, contract in ROLE_CONTRACTS.items()
            },
            "mechanisms": {
                "admission_context": ["state_digest", "plan_digest", "spatial_model", "policy"],
                "protected_spatial_bundle": "AES-GCM envelope loaded at runtime",
                "site_safety_adapter": "server-side protocol for proprietary hard-gate evidence",
                "required_site_gates": sorted(
                    getattr(self.checker, "required_site_gates", ())
                ),
                "shadow_lane": self.registry.shadow_checker is not None,
                "canaries": self.registry.canary_status(),
            },
        }

    def respond(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.provider is None:
            raise RuntimeError("No AgentProvider is configured")
        role = _role(payload["role"])
        request = AgentRequest(
            role=role,
            system_instruction=str(payload.get("system_instruction") or prompt_for(role)),
            event=_event(dict(payload["event"])),
            state_projection=dict(payload.get("state_projection", {})),
            candidate_plan=dict(payload.get("candidate_plan", {})),
            response_schema=dict(payload.get("response_schema", {})),
        )
        response = self.provider.generate(request)
        try:
            content: Any = json.loads(response.content)
        except json.JSONDecodeError as exc:
            # 防退化：角色响应契约要求 JSON；不得把普通文本包装成成功响应并掩盖模型输出错误。
            raise ValueError("AgentProvider returned invalid JSON") from exc
        return {"model": response.model, "content": content, "usage": response.usage}

    def episode(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.provider is None:
            raise RuntimeError("No AgentProvider is configured")
        event = _event(dict(payload["event"]))
        plan = _plan(dict(payload["plan"]))
        budget_payload = dict(payload.get("budget", {}))
        episode_defaults = load_settings().episode
        state_projection = dict(payload.get("state_projection", {}))
        if payload.get("asset_bundle_id"):
            state_projection["asset_bundle_id"] = str(payload["asset_bundle_id"])
        spatial_model = self._spatial_model(payload)
        result = AgentNetwork(self.provider, self.checker).run(
            event=event,
            state_projection=state_projection,
            plan=plan,
            response_schema=dict(payload.get("response_schema", {})),
            spatial_model=spatial_model,
            track_intervals=list(payload.get("track_intervals", [])),
            policy=dict(payload.get("policy", {})),
            budget=EpisodeBudget(
                max_model_calls=int(
                    budget_payload.get("max_model_calls", episode_defaults.max_model_calls)
                ),
                max_rounds=int(
                    budget_payload.get("max_rounds", episode_defaults.max_rounds)
                ),
                max_messages=int(
                    budget_payload.get("max_messages", episode_defaults.max_messages)
                ),
                max_owner_revisions=int(
                    budget_payload.get(
                        "max_owner_revisions",
                        episode_defaults.max_owner_revisions,
                    )
                ),
                max_replayed_commitments=int(
                    budget_payload.get(
                        "max_replayed_commitments",
                        episode_defaults.max_replayed_commitments,
                    )
                ),
            ),
        )
        return {
            "status": result.status,
            "plan": result.plan.to_dict(),
            "certificate": result.certificate,
            "model_calls": result.model_calls,
            "rounds": result.rounds,
            "usage": result.usage,
            "error": result.error,
        }

    def admit(self, payload: dict[str, Any]) -> dict[str, Any]:
        plan = _plan(dict(payload["plan"]))
        spatial_model = self._spatial_model(payload)
        state_projection = dict(payload.get("state_projection", {}))
        embedded_state_digest = state_projection.pop("state_digest", None)
        supplied_state_digest = (
            str(payload.get("state_digest") or embedded_state_digest or "")
            or None
        )
        supplied_plan_digest = str(payload.get("plan_digest", "")) or None
        computed_state_digest = (
            state_digest(state_projection)
            if state_projection
            else None
        )
        computed_plan_digest = plan_digest(plan)
        context = AdmissionContext(
            state_projection=state_projection,
            # 防退化：证书必须绑定实际序列化对象的摘要，不能把调用者声称的摘要直接当成已核验值。
            state_digest=computed_state_digest,
            plan_digest=computed_plan_digest,
            submitted_state_digest=supplied_state_digest,
            submitted_plan_digest=supplied_plan_digest,
            spatial_model=spatial_model,
            track_intervals=list(payload.get("track_intervals", [])),
            policy=dict(payload.get("policy", {})),
        )
        certificate = self.checker.check(
            plan,
            str(payload["live_state_version"]),
            context=context,
        )
        result = asdict(certificate)
        # 防退化：空间失败必须由 G6--G8 写入已签摘要的证书，不能在证书生成后另行改写 accepted。
        result["spatial_failures"] = [
            {
                "failure_type": item.reason,
                "object_ids": [item.action_id] if item.action_id else [],
                "resource_id": item.resource_id,
            }
            for item in certificate.failures
            if item.gate_id in {"G6", "G7", "G8"}
        ]
        shadow = self.registry.run_shadow(plan, str(payload["live_state_version"]), context)
        if shadow is not None:
            result["shadow_evaluation"] = shadow
        return result

    def commit(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.state_store is None:
            # 防退化：无服务器权威状态存储时只能拒绝提交，不能把请求体状态预览包装成原子提交成功。
            return {
                "committed": False,
                "reason": "state_store_not_configured",
            }
        required_guards = {
            "expected_state_version",
            "expected_state_digest",
            "expected_plan_digest",
        }
        missing_guards = sorted(required_guards - set(payload))
        if missing_guards:
            return {
                "committed": False,
                "reason": "missing_compare_and_swap_guards",
                "missing": missing_guards,
            }
        state = self.state_store.read()
        plan = _plan(dict(payload["plan"]))
        live_state_digest = state_digest(state)
        expected_state_version = payload.get("expected_state_version")
        if expected_state_version and str(expected_state_version) != state.version:
            return {
                "committed": False,
                "reason": "state_version_compare_and_swap_failed",
                "current_state_version": state.version,
            }
        expected_state_digest = payload.get("expected_state_digest")
        if expected_state_digest and str(expected_state_digest) != live_state_digest:
            return {
                "committed": False,
                "reason": "state_digest_compare_and_swap_failed",
                "current_state_digest": live_state_digest,
            }
        submitted_digest = payload.get("expected_plan_digest")
        current_plan_digest = plan_digest(plan)
        if submitted_digest and str(submitted_digest) != current_plan_digest:
            # 防退化：计划摘要不一致应在解密受保护空间包和执行十二道门之前快速拒绝。
            return {
                "committed": False,
                "reason": "plan_digest_compare_and_swap_failed",
                "current_plan_digest": current_plan_digest,
            }
        admission_payload = {
            "plan": payload["plan"],
            "live_state_version": state.version,
            "state_digest": live_state_digest,
            "state_projection": state.to_dict(),
        }
        if "spatial_model" in payload:
            admission_payload["spatial_model"] = payload["spatial_model"]
        if "protected_spatial_bundle" in payload:
            admission_payload["protected_spatial_bundle"] = payload["protected_spatial_bundle"]
        if "track_intervals" in payload:
            admission_payload["track_intervals"] = payload["track_intervals"]
        if "policy" in payload:
            admission_payload["policy"] = payload["policy"]
        certificate = self.admit(admission_payload)
        if not certificate["accepted"]:
            return {"committed": False, "certificate": certificate}
        successor = self.replay.preview(state, plan)
        successor.version = str(payload.get("next_state_version", f"{state.version}+1"))
        if not self.state_store.compare_and_swap(
            expected_version=state.version,
            expected_digest=live_state_digest,
            successor=successor,
        ):
            return {
                "committed": False,
                "reason": "state_store_compare_and_swap_failed",
                "certificate": certificate,
            }
        return {
            "committed": True,
            "certificate": certificate,
            "successor_state": successor.to_dict(),
            "commit_guard": {
                "previous_state_version": state.version,
                "previous_state_digest": live_state_digest,
                "plan_digest": plan_digest(plan),
                "next_state_version": successor.version,
                "next_state_digest": state_digest(successor),
            },
        }
