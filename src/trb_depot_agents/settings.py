from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AssetSettings:
    root: str = "data/in"


@dataclass(frozen=True)
class EpisodeSettings:
    max_model_calls: int = 8
    max_rounds: int = 4
    max_messages: int = 24
    max_owner_revisions: int = 12
    max_replayed_commitments: int = 32


@dataclass(frozen=True)
class APISettings:
    host: str = "127.0.0.1"
    port: int = 8080


@dataclass(frozen=True)
class Settings:
    assets: AssetSettings
    episode: EpisodeSettings
    api: APISettings


def _section(payload: dict[str, Any], name: str) -> dict[str, Any]:
    value = payload.get(name, {})
    return dict(value) if isinstance(value, dict) else {}


def load_settings(path: str | Path | None = None) -> Settings:
    """Load repository defaults and then apply explicit environment overrides."""

    configured = path or os.getenv("DEPOT_AGENT_CONFIG")
    source = Path(configured) if configured else Path("config/defaults.toml")
    payload: dict[str, Any] = {}
    if source.is_file():
        payload = tomllib.loads(source.read_text(encoding="utf-8"))

    asset_values = _section(payload, "assets")
    episode_values = _section(payload, "episode")
    api_values = _section(payload, "api")

    # 防退化：公开仓的配置文件必须进入真实启动链，环境变量只覆盖配置，不得恢复为两套互不相干的默认值。
    return Settings(
        assets=AssetSettings(
            root=os.getenv(
                "DEPOT_AGENT_DATA_ROOT",
                str(asset_values.get("root", AssetSettings.root)),
            )
        ),
        episode=EpisodeSettings(
            max_model_calls=int(
                os.getenv(
                    "DEPOT_AGENT_MAX_MODEL_CALLS",
                    episode_values.get("max_model_calls", EpisodeSettings.max_model_calls),
                )
            ),
            max_rounds=int(
                os.getenv(
                    "DEPOT_AGENT_MAX_ROUNDS",
                    episode_values.get("max_rounds", EpisodeSettings.max_rounds),
                )
            ),
            max_messages=int(
                os.getenv(
                    "DEPOT_AGENT_MAX_MESSAGES",
                    episode_values.get("max_messages", EpisodeSettings.max_messages),
                )
            ),
            max_owner_revisions=int(
                os.getenv(
                    "DEPOT_AGENT_MAX_OWNER_REVISIONS",
                    episode_values.get(
                        "max_owner_revisions",
                        EpisodeSettings.max_owner_revisions,
                    ),
                )
            ),
            max_replayed_commitments=int(
                os.getenv(
                    "DEPOT_AGENT_MAX_REPLAYED_COMMITMENTS",
                    episode_values.get(
                        "max_replayed_commitments",
                        EpisodeSettings.max_replayed_commitments,
                    ),
                )
            ),
        ),
        api=APISettings(
            host=os.getenv("DEPOT_AGENT_HOST", str(api_values.get("host", APISettings.host))),
            port=int(os.getenv("DEPOT_AGENT_PORT", api_values.get("port", APISettings.port))),
        ),
    )
