"""OpenAI-compatible client for remote Qwen endpoints (vLLM/Ollama bridge)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from security.integration.model_config import ModelRuntimeConfig, load_model_runtime_config


@dataclass(frozen=True)
class ChatTurn:
    """One chat message passed to the model endpoint."""

    role: str
    content: str


class QwenModelClient:
    """Thin wrapper around OpenAI-compatible HTTP endpoints for Qwen inference."""

    def __init__(self, config: ModelRuntimeConfig | None = None, timeout: float = 30.0) -> None:
        self.config = config or load_model_runtime_config()
        self.timeout = timeout

    def health(self) -> bool:
        """Return True when the configured model endpoint is reachable."""
        base = self.config.base_url.rstrip("/")
        candidates = [f"{base}/health", f"{base}/v1/models", base]
        for url in candidates:
            try:
                response = httpx.get(url, timeout=self.timeout)
                if response.status_code < 400:
                    return True
            except httpx.HTTPError:
                continue
        return False

    def list_models(self) -> list[str]:
        """Return model ids from /v1/models when available."""
        response = httpx.get(
            f"{self.config.base_url}/v1/models",
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data", []) if isinstance(payload, dict) else []
        ids: list[str] = []
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                ids.append(item["id"])
        return ids

    def chat(self, turns: list[ChatTurn], temperature: float = 0.0) -> dict[str, Any]:
        """Call /v1/chat/completions and return the raw JSON response."""
        payload = {
            "model": self.config.model,
            "messages": [{"role": t.role, "content": t.content} for t in turns],
            "temperature": temperature,
        }
        response = httpx.post(
            f"{self.config.base_url}/v1/chat/completions",
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def quick_prompt(self, prompt: str) -> str:
        """Run one-turn user prompt and return the first completion text."""
        reply = self.chat([ChatTurn(role="user", content=prompt)])
        choices = reply.get("choices", []) if isinstance(reply, dict) else []
        if not choices:
            return ""
        first = choices[0]
        if not isinstance(first, dict):
            return ""
        message = first.get("message", {})
        if not isinstance(message, dict):
            return ""
        content = message.get("content", "")
        return content if isinstance(content, str) else ""

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
