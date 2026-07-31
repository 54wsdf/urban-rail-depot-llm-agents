"""Optional OpenAI-compatible API boundary with environment-only credentials."""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen

from ..contracts import AgentRequest, AgentResponse


class OpenAICompatibleProvider:
    """Call an OpenAI-compatible chat-completions endpoint.

    The adapter is intentionally small. It does not implement the scientific
    protocol itself and it never decides whether a plan is safe.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout_s: int = 120,
    ) -> None:
        resolved_base_url = (
            base_url
            if base_url is not None
            else os.environ.get("DEPOT_AGENT_BASE_URL", "")
        )
        self.base_url = resolved_base_url.rstrip("/")
        self.api_key = api_key or os.getenv("DEPOT_AGENT_API_KEY", "")
        self.model = model or os.getenv("DEPOT_AGENT_MODEL", "")
        self.timeout_s = timeout_s
        if not self.base_url or not self.api_key or not self.model:
            raise ValueError(
                "Set DEPOT_AGENT_BASE_URL, DEPOT_AGENT_API_KEY, and DEPOT_AGENT_MODEL"
            )

    def generate(self, request: AgentRequest) -> AgentResponse:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": request.system_instruction},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "role": request.role,
                            "event": request.event.__dict__,
                            "state_projection": request.state_projection,
                            "candidate_plan": request.candidate_plan,
                            "response_schema": request.response_schema,
                        },
                        ensure_ascii=False,
                        default=str,
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
        }
        req = Request(
            f"{self.base_url}/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=self.timeout_s) as response:
            raw = json.loads(response.read().decode("utf-8"))
        content = raw["choices"][0]["message"]["content"]
        return AgentResponse(
            content=content,
            model=str(raw.get("model", self.model)),
            usage=dict(raw.get("usage", {})),
            raw=raw,
        )
