"""Framework-neutral provider contracts."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from ..contracts import AgentRequest, AgentResponse


@runtime_checkable
class AgentProvider(Protocol):
    def generate(self, request: AgentRequest) -> AgentResponse:
        """Generate one role response from a typed request."""


class CallableProvider:
    """Connect any framework or local model through a Python callable."""

    def __init__(self, invoke: Callable[[AgentRequest], AgentResponse | dict | str], model: str = "callable"):
        self.invoke = invoke
        self.model = model

    def generate(self, request: AgentRequest) -> AgentResponse:
        result = self.invoke(request)
        if isinstance(result, AgentResponse):
            return result
        if isinstance(result, str):
            return AgentResponse(content=result, model=self.model)
        if isinstance(result, dict):
            content = result.get("content", result)
            # 防退化：框架回调可直接返回结构化角色结果，不能因缺少外层 content 字段而静默变成空响应。
            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False)
            return AgentResponse(
                content=content,
                model=str(result.get("model", self.model)),
                usage=dict(result.get("usage", {})),
                raw=result,
            )
        raise TypeError("Provider callable must return AgentResponse, dict, or str")
