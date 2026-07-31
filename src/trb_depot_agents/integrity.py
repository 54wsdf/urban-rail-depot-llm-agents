from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


def stable_json(payload: Any) -> str:
    def default(value: Any) -> Any:
        if is_dataclass(value):
            return asdict(value)
        if isinstance(value, set):
            return sorted(value)
        if isinstance(value, Enum):
            return value.value
        raise TypeError(f"Unsupported digest value: {type(value)!r}")

    return json.dumps(payload, default=default, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_digest(payload: Any) -> str:
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()


def plan_digest(plan: Any) -> str:
    payload = deepcopy(plan.to_dict() if hasattr(plan, "to_dict") else plan)
    if isinstance(payload, dict) and isinstance(payload.get("metadata"), dict):
        # 防退化：摘要保护值不能参与自身摘要，否则任何合法 plan_digest 都会形成不可满足的自引用。
        payload["metadata"].pop("plan_digest", None)
        payload["metadata"].pop("certificate_digest", None)
    return sha256_digest(payload)


def state_digest(state: Any) -> str:
    return sha256_digest(state.to_dict() if hasattr(state, "to_dict") else state)


def certificate_digest(payload: dict[str, Any]) -> str:
    public_payload = {key: value for key, value in payload.items() if key != "certificate_digest"}
    return sha256_digest(public_payload)
