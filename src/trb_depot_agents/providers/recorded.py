from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from ..contracts import AgentRequest, AgentResponse, Role


class RecordedAgentProvider:
    def __init__(self, responses: dict[Role, list[dict[str, Any]]]) -> None:
        self.responses = {
            role: deque(items)
            for role, items in responses.items()
        }

    @classmethod
    def from_directory(cls, directory: str | Path) -> "RecordedAgentProvider":
        grouped: dict[Role, list[dict[str, Any]]] = defaultdict(list)
        for path in sorted(Path(directory).glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            role = Role(payload["role"])
            grouped[role].append(payload)
        return cls(dict(grouped))

    def generate(self, request: AgentRequest) -> AgentResponse:
        if request.role not in self.responses or not self.responses[request.role]:
            raise LookupError(f"No recorded response for role: {request.role.value}")
        payload = self.responses[request.role][0]
        recorded_event = (
            payload.get("event_id")
            or dict(payload.get("event", {})).get("event_id")
            or dict(payload.get("request", {})).get("event_id")
        )
        recorded_state = (
            payload.get("state_version")
            or dict(payload.get("event", {})).get("state_version")
            or dict(payload.get("request", {})).get("state_version")
        )
        # 防退化：录制响应若声明事件或状态版本，必须与当前请求一致，不能跨案例或跨状态串用。
        if recorded_event and str(recorded_event) != request.event.event_id:
            raise ValueError("Recorded response event_id does not match the request")
        if recorded_state and str(recorded_state) != request.event.state_version:
            raise ValueError("Recorded response state_version does not match the request")
        payload = self.responses[request.role].popleft()
        content = payload.get("content", payload.get("response", payload))
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False)
        return AgentResponse(
            content=content,
            model=str(payload.get("model", "recorded-agent")),
            usage=dict(payload.get("usage", {})),
            raw=payload,
        )
