"""Async tool-call loop against an OpenAI-compatible chat-completions endpoint.

The loop talks to a local model served on the supervisor's GPU host (vLLM /
TGI / llama.cpp — anything that exposes ``/v1/chat/completions``). Each
turn either:

  - returns plain text (loop ends, return value is the text), or
  - emits one or more ``tool_calls`` (we dispatch each via the
    ``ToolRegistry`` and feed results back as ``role=tool`` messages on
    the next turn).

A ``StubToolLoopLLM`` is provided for tests — it scripts a sequence of
responses keyed by turn count, mirroring the production protocol.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from agent.tools import ToolRegistry


SYSTEM_PROMPT = """\
You are an autonomous OpenClaw agent operating on the DelftClaw P2P
network. Your tools let you list peers, pay donations from your Bitcoin
wallet, fetch + compile overlay descriptors over the wire, invoke
protocol messages on those overlays, and download / seed torrents.

When a peer offers an overlay you don't yet understand, fetch its
markdown descriptor with ``overlay_fetch_and_load`` first, then use
``overlay_invoke`` to send messages on the new overlay. The compiler
validates the descriptor against embedded test vectors before
activating it; if compilation fails, fall back to natural-language
messaging.

Be terse. When the user's question is answered, stop and produce a
single short reply.
"""


# ---------------------------------------------------------------------------
# Tool-aware LLM client protocol
# ---------------------------------------------------------------------------

class ToolLoopLLM(Protocol):
    """The LLM-facing surface ``run_tool_loop`` needs.

    ``complete_with_tools`` MUST follow OpenAI's chat-completions shape:
    given the messages array + tool specs, return a dict with the assistant
    message in ``"message"`` (with optional ``"tool_calls"`` list).
    """

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        ...


@dataclass
class OpenAICompatibleToolLLM:
    """Talks to an ``/v1/chat/completions`` endpoint with the ``tools=[...]`` param."""

    base_url: str
    model_id: str
    api_key: str = ""
    temperature: float = 0.0
    timeout_s: float = 120.0
    extra_body: dict[str, Any] = field(default_factory=dict)

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        import urllib.request

        payload = {
            "model": self.model_id,
            "messages": messages,
            "tools": tools,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
        }
        payload.update(self.extra_body)
        body = json.dumps(payload).encode("utf-8")
        url = self.base_url.rstrip("/") + "/chat/completions"
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "DelftClaw/1.0 (+https://github.com/delftclaw)",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            raise RuntimeError(
                f"HTTP {exc.code} from {url}: {body[:1000]}"
            ) from exc
        return {"message": payload["choices"][0]["message"]}


@dataclass
class StubToolLoopLLM:
    """Scripted responses for tests + offline development.

    ``responses`` is a list of message dicts in chat-completions form.
    The Nth call to ``complete_with_tools`` returns ``responses[N]``.
    """

    responses: list[dict[str, Any]]
    _cursor: int = 0

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        if self._cursor >= len(self.responses):
            raise RuntimeError("StubToolLoopLLM: ran out of scripted responses")
        msg = self.responses[self._cursor]
        self._cursor += 1
        return {"message": msg}


# ---------------------------------------------------------------------------
# Tool-call loop
# ---------------------------------------------------------------------------

async def run_tool_loop(
    user_query: str,
    llm: ToolLoopLLM,
    tools: ToolRegistry,
    *,
    system_prompt: str = SYSTEM_PROMPT,
    max_iterations: int = 10,
) -> str:
    """Drive the LLM until it returns plain text. Returns that final text."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query},
    ]

    for _ in range(max_iterations):
        result = llm.complete_with_tools(messages, tools.specs())
        msg = result["message"]
        # Always append the assistant message — tool-call replies must follow it.
        messages.append(msg)

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            return msg.get("content") or ""

        for call in tool_calls:
            fn = call["function"]
            name = fn["name"]
            args_raw = fn.get("arguments", "{}")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except json.JSONDecodeError as exc:
                args = {"_args_decode_error": str(exc)}
            tool_result = await tools.dispatch(name, args)
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "name": name,
                "content": json.dumps(tool_result, default=str),
            })

    return "(tool loop hit max_iterations without final text)"
