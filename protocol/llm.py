"""LLM client used by the overlay compiler.

A ``Protocol`` (``LLMClient``) decouples the compiler from any specific
provider; ``OpenAICompatibleClient`` talks to vLLM / TGI / llama.cpp /
any OpenAI-compatible endpoint over HTTP. Every overlay compilation goes
through a real LLM — there is no pre-recorded-source shortcut.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


class LLMClient(Protocol):
    """Single-turn completion API the compiler needs."""

    model_id: str

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        """Return the assistant message text for the given system + user prompts."""
        ...


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
    # Generous default: a loaded/throttled backend (e.g. Haiku via the proxy)
    # can take ~60s for one overlay compile. At the old 60s a working-but-slow
    # response timed out right at the line, failing the author action and
    # forcing a ~240s tick retry. One author call must comfortably fit one
    # slow compile, so headroom here is cheaper than a wasted tick.
    timeout_s: float = 150.0
    # Bounded retry on transient throttling (HTTP 429 / 503). The overlay
    # author path makes one real-LLM call per watchdog tick; without this a
    # single 429 fails the whole authoring action and the agent only retries
    # ~240s later (and sometimes goes off-script). We ride a brief per-minute
    # window WITHIN the call instead. NOT a fix for a hard daily/spend cap —
    # those keep 429-ing past these retries and surface the error as before.
    max_retries: int = 4
    retry_cap_s: float = 15.0  # never sleep longer than this on one retry

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
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
        headers = {
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
        }

        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                return payload["choices"][0]["message"]["content"]
            except urllib.error.HTTPError as exc:
                # Only transient throttling is retryable; everything else (4xx
                # auth/validation, 5xx other) propagates immediately.
                if exc.code not in (429, 503) or attempt == self.max_retries:
                    raise
                time.sleep(self._retry_delay(exc, attempt))
        # Unreachable: the loop either returns or raises on the final attempt.
        raise RuntimeError("OpenAICompatibleClient.complete: retry loop exhausted")

    def _retry_delay(self, exc: "urllib.error.HTTPError", attempt: int) -> float:
        """Seconds to wait before the next retry: honour a sane ``Retry-After``
        header, else exponential backoff. Both capped at ``retry_cap_s``."""
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        if retry_after and retry_after.strip().isdigit():
            return min(float(retry_after.strip()), self.retry_cap_s)
        return min(1.5 * (2 ** attempt), self.retry_cap_s)
