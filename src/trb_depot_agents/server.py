from __future__ import annotations

import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .api import DepotAgentAPI
from .providers.openai_compatible import OpenAICompatibleProvider
from .providers.recorded import RecordedAgentProvider
from .protected_spatial import ProtectedSpatialBundleLoader
from .settings import load_settings
from .state import InMemoryStateStore, OperatingState

MAX_REQUEST_BYTES = int(os.getenv("DEPOT_AGENT_MAX_REQUEST_BYTES", "2097152"))
HTTP_TOKEN = os.getenv("DEPOT_AGENT_HTTP_TOKEN")


def _make_api() -> DepotAgentAPI:
    protected_loader = ProtectedSpatialBundleLoader()
    protected_bundle_path = os.getenv("DEPOT_AGENT_PROTECTED_SPATIAL_BUNDLE")
    default_spatial_model = (
        protected_loader.load(protected_bundle_path)
        if protected_bundle_path
        else None
    )
    initial_state_path = os.getenv("DEPOT_AGENT_INITIAL_STATE")
    state_store = None
    if initial_state_path:
        with open(initial_state_path, encoding="utf-8") as handle:
            state_store = InMemoryStateStore(
                OperatingState.from_dict(json.load(handle))
            )
    # 防退化：真实咽喉只允许由服务器受控环境路径装载，公共 HTTP 请求不能指定本地文件。
    replay_dir = os.getenv("DEPOT_AGENT_REPLAY_DIR")
    if replay_dir:
        return DepotAgentAPI(
            provider=RecordedAgentProvider.from_directory(replay_dir),
            protected_loader=protected_loader,
            state_store=state_store,
            default_spatial_model=default_spatial_model,
        )
    try:
        return DepotAgentAPI(
            provider=OpenAICompatibleProvider(),
            protected_loader=protected_loader,
            state_store=state_store,
            default_spatial_model=default_spatial_model,
        )
    except ValueError:
        return DepotAgentAPI(
            protected_loader=protected_loader,
            state_store=state_store,
            default_spatial_model=default_spatial_model,
        )


class Handler(BaseHTTPRequestHandler):
    api = _make_api()

    def _authorized(self) -> bool:
        if not HTTP_TOKEN:
            return True
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {HTTP_TOKEN}"
        return secrets.compare_digest(supplied, expected)

    def _write(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self._authorized():
            self._write(401, {"error": "unauthorized"})
            return
        if self.path == "/v1/protocol":
            self._write(200, self.api.protocol())
            return
        self._write(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._write(401, {"error": "unauthorized"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > MAX_REQUEST_BYTES:
                # 防退化：参考 HTTP 服务只接受有界 JSON，请求体缺失或过大时不得继续读取和解析。
                self._write(413, {"error": "request_size_rejected"})
                return
            body = self.rfile.read(size)
            payload = json.loads(body or b"{}")
            if self.path == "/v1/respond":
                result = self.api.respond(payload)
            elif self.path == "/v1/episode":
                result = self.api.episode(payload)
            elif self.path == "/v1/admission":
                result = self.api.admit(payload)
            elif self.path == "/v1/commit":
                result = self.api.commit(payload)
            else:
                self._write(404, {"error": "not_found"})
                return
            if (
                self.path == "/v1/commit"
                and result.get("reason") == "state_store_not_configured"
            ):
                self._write(503, result)
                return
            self._write(200, result)
        except Exception:
            # 防退化：HTTP 错误不得回显密钥标识、受保护包路径或空间规则校验细节。
            self._write(400, {"error": "request_rejected"})

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    settings = load_settings().api
    if settings.host not in {"127.0.0.1", "localhost", "::1"} and not HTTP_TOKEN:
        # 防退化：付费模型和提交入口不得在无认证时绑定外部网卡；本地参考模式仍保持零配置可运行。
        raise RuntimeError(
            "DEPOT_AGENT_HTTP_TOKEN is required when binding a non-loopback host"
        )
    ThreadingHTTPServer((settings.host, settings.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
