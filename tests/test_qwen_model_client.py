from __future__ import annotations

from typing import Any

import pytest

from security.integration.model_config import ModelRuntimeConfig
from security.integration.qwen_client import ChatTurn, QwenModelClient


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"status={self.status_code}")


def test_health_uses_reachable_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_get(url: str, timeout: float = 0, headers: dict[str, str] | None = None) -> _FakeResponse:
        calls.append(url)
        if url.endswith("/health"):
            return _FakeResponse(404, {})
        return _FakeResponse(200, {"ok": True})

    monkeypatch.setattr("httpx.get", fake_get)

    client = QwenModelClient(ModelRuntimeConfig(base_url="http://gpu-node:8000/v1", model="qwen", api_key="k"))
    assert client.health() is True
    assert any(url.endswith("/v1/models") for url in calls)


def test_list_models(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: float) -> _FakeResponse:
        assert url.endswith("/v1/models")
        return _FakeResponse(200, {"data": [{"id": "qwen-a"}, {"id": "qwen-b"}]})

    monkeypatch.setattr("httpx.get", fake_get)

    client = QwenModelClient(ModelRuntimeConfig(base_url="http://gpu-node:8000/v1", model="qwen", api_key="k"))
    assert client.list_models() == ["qwen-a", "qwen-b"]


def test_quick_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(url: str, headers: dict[str, str], json: dict[str, Any], timeout: float) -> _FakeResponse:
        assert url.endswith("/v1/chat/completions")
        assert json["messages"][0]["content"] == "hello"
        return _FakeResponse(200, {"choices": [{"message": {"content": "world"}}]})

    monkeypatch.setattr("httpx.post", fake_post)

    client = QwenModelClient(ModelRuntimeConfig(base_url="http://gpu-node:8000/v1", model="qwen", api_key="k"))
    assert client.quick_prompt("hello") == "world"


def test_chat_raises_for_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(url: str, headers: dict[str, str], json: dict[str, Any], timeout: float) -> _FakeResponse:
        return _FakeResponse(500, {})

    monkeypatch.setattr("httpx.post", fake_post)

    client = QwenModelClient(ModelRuntimeConfig(base_url="http://gpu-node:8000/v1", model="qwen", api_key="k"))
    with pytest.raises(RuntimeError):
        client.chat([ChatTurn(role="user", content="x")])

