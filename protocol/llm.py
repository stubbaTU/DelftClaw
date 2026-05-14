"""LLM client used by the overlay compiler.

A ``Protocol`` (``LLMClient``) decouples the compiler from any specific
provider; ``OpenAICompatibleClient`` talks to vLLM / TGI / llama.cpp /
any OpenAI-compatible endpoint over HTTP, and ``StubLLMClient`` returns
hand-authored Python sources keyed by the prompt's ``community_id`` so
the compiler is testable without a live LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol


class LLMClient(Protocol):
    """Single-turn completion API the compiler needs."""

    model_id: str

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        """Return the assistant message text for the given system + user prompts."""
        ...


@dataclass
class StubLLMClient:
    """Returns a pre-recorded source string keyed by the overlay community_id (hex).

    Used for tests and the bootstrap echo overlay so the compiler pipeline
    can be exercised without a live LLM endpoint.
    """

    sources: Mapping[str, str]
    model_id: str = "stub-1"

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        # The compiler embeds ``community_id_hex=<hex>`` in the user prompt
        # so the stub can route. See ``compiler._build_user_prompt``.
        marker = "community_id_hex="
        idx = user.find(marker)
        if idx < 0:
            raise KeyError(f"StubLLMClient: prompt is missing '{marker}'")
        cid_hex = user[idx + len(marker):].split()[0].strip().rstrip(",.;")
        if cid_hex not in self.sources:
            raise KeyError(f"StubLLMClient: no recorded source for community_id={cid_hex}")
        return self.sources[cid_hex]


@dataclass
class OpenAICompatibleClient:
    """HTTP client for a /v1/chat/completions endpoint.

    Works with vLLM / TGI / llama.cpp servers and the OpenAI API itself.
    Synchronous on purpose — the compiler is invoked from contexts where
    the call is the dominant cost and a blocking HTTP round-trip is fine.
    """

    base_url: str            # e.g. "http://gpu-host:8000/v1"
    model_id: str            # e.g. "meta-llama/Llama-3.1-70B-Instruct"
    api_key: str = ""        # optional; many local servers ignore it
    temperature: float = 0.0  # determinism is the whole point
    timeout_s: float = 60.0

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        import json
        import urllib.request

        body = json.dumps({
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": max_tokens,
        }).encode("utf-8")

        url = self.base_url.rstrip("/") + "/chat/completions"
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]
