"""
Host-side allowed-peer gateway -> small threaded HTTP server bound to docker gateway IP. Allows LLM requests and proxy requests.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from security.containment_layer.infrastructure.protected_resources import ProtectedFixture
from security.containment_layer.infrastructure.resource_proxies import ResourceProxyBundle


DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


@dataclass
class GatewayState:
    """
    Gateway state, including the proxy bundle.
    """
    fixture: ProtectedFixture
    openrouter_api_key: str
    openrouter_base_url: str = DEFAULT_OPENROUTER_BASE_URL
    request_timeout_s: float = 120.0

    def __post_init__(self) -> None:
        self.proxies = ResourceProxyBundle(self.fixture)
        self.llm_requests = 0
        self.proxy_requests: list[dict[str, Any]] = []

    def dispatch_proxy(self, resource: str, verb: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not resource.isidentifier() or not verb.isidentifier() or verb.startswith("_"):
            return {"ok": False, "data": {}, "error": "invalid proxy resource or verb"}
        try:
            proxy = self.proxies.get(resource)
        except ValueError as exc:
            return {"ok": False, "data": {}, "error": str(exc)}
        method = getattr(proxy, verb, None)
        if method is None or not callable(method):
            return {"ok": False, "data": {}, "error": f"unknown proxy verb: {resource}.{verb}"}
        try:
            response = method(**payload)
        except (TypeError, ValueError) as exc:
            return {"ok": False, "data": {}, "error": f"invalid proxy request: {exc}"}
        self.proxy_requests.append({"resource": resource, "verb": verb, "ok": response.ok})
        return response.to_dict()

    def relay_llm(self, path: str, payload: bytes) -> tuple[int, bytes]:
        if not self.openrouter_api_key:
            return 503, _json_bytes({"error": "OPENROUTER_API_KEY is not configured on the host gateway"})
        target = self.openrouter_base_url.rstrip("/") + path.removeprefix("/v1")
        request = urllib.request.Request(
            target,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.openrouter_api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "DelftClaw-E2E/1.0",
            },
            method="POST",
        )
        self.llm_requests += 1
        try:
            with urllib.request.urlopen(request, timeout=self.request_timeout_s) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except urllib.error.URLError as exc:
            return 502, _json_bytes({"error": f"OpenRouter relay failed: {exc.reason}"})


class AllowedPeerGateway:
    def __init__(self, state: GatewayState, host: str, port: int) -> None:
        handler = _handler_for(state)
        self.server = ThreadingHTTPServer((host, port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, name="vukzero-e2e-gateway", daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _handler_for(state: GatewayState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, _json_bytes({"ok": True}))
                return
            self._send(404, _json_bytes({"error": "not found"}))

        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path.startswith("/v1/"):
                status, response = state.relay_llm(self.path, body)
                self._send(status, response)
                return
            if self.path.startswith("/proxy/"):
                parts = self.path.strip("/").split("/")
                if len(parts) != 3:
                    self._send(404, _json_bytes({"ok": False, "error": "invalid proxy path"}))
                    return
                try:
                    payload = json.loads(body or b"{}")
                except json.JSONDecodeError:
                    self._send(400, _json_bytes({"ok": False, "error": "request body must be JSON"}))
                    return
                if not isinstance(payload, dict):
                    self._send(400, _json_bytes({"ok": False, "error": "request body must be an object"}))
                    return
                self._send(200, _json_bytes(state.dispatch_proxy(parts[1], parts[2], payload)))
                return
            self._send(404, _json_bytes({"error": "not found"}))

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def _send(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, default=str, sort_keys=True).encode("utf-8")
