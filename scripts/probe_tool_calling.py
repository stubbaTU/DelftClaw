"""``python scripts/probe_tool_calling.py`` — does the LLM emit tool calls?

Bypasses scenarios / openclaw / MCP / SSH-tunnel and talks straight to
the local Ollama via its OpenAI-compatible /v1/chat/completions endpoint.
Verifies the fundamental capability: given a tool spec and a prompt that
should force tool use, does the model return a ``tool_calls`` array or
just text?

Usage::

    python scripts/probe_tool_calling.py                     # uses host.env's QWEN_MODEL
    python scripts/probe_tool_calling.py --model qwen3:8b    # explicit override
    python scripts/probe_tool_calling.py --base http://127.0.0.1:11434/v1

Exit codes:
  0 — model returned a tool_calls array (tool calling works)
  1 — model returned plain text only (tool calling does not work for this model)
  2 — request failed (network / model unavailable)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib import request, error

DEFAULT_BASE = "http://127.0.0.1:11434/v1"


def _load_host_env() -> dict[str, str]:
    """Best-effort: read configs/host.env to pick a sensible default model."""
    here = Path(__file__).resolve().parent.parent
    env_file = here / "configs" / "host.env"
    if not env_file.is_file():
        return {}
    out = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def _probe(base: str, model: str, *, force: bool, verbose: bool) -> int:
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a DelftClaw agent. You MUST call tools to perform "
                    "actions. Do not describe what you would do — emit the tool "
                    "call directly. Reply with the tool call ONLY."
                ),
            },
            {
                "role": "user",
                "content": "What is my wallet address? Call wallet_address.",
            },
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "wallet_address",
                    "description": "Return this agent's Bitcoin wallet address.",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            },
        ],
        "stream": False,
    }
    if force:
        # Some OpenAI-compatible endpoints honour ``"required"``;
        # Ollama documents ``"auto"`` and ``"none"``. We try ``required``
        # and fall back if the server complains.
        body["tool_choice"] = "required"

    url = base.rstrip("/") + "/chat/completions"
    print(f"→ POST {url}")
    print(f"  model:       {model}")
    print(f"  tool_choice: {body.get('tool_choice', 'auto')}")
    print(f"  prompt:      {body['messages'][-1]['content']}")
    print()

    req = request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer ollama",
        },
    )
    try:
        with request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:400]}")
        return 2
    except (error.URLError, TimeoutError, OSError) as exc:
        print(f"network error: {exc}")
        return 2

    if verbose:
        print(json.dumps(payload, indent=2)[:1500])
        print()

    try:
        message = payload["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        print(f"unexpected response shape: {payload}")
        return 2

    text = message.get("content") or ""
    tool_calls = message.get("tool_calls") or []

    print(f"← response.content (first 200 chars): {text[:200]!r}")
    print(f"← response.tool_calls count:          {len(tool_calls)}")
    for tc in tool_calls[:3]:
        fn = (tc or {}).get("function") or {}
        print(f"    -> {fn.get('name')}({fn.get('arguments')})")

    print()
    if tool_calls:
        print("VERDICT: model emits tool calls correctly. ✓")
        print("  If the live demo isn't calling tools, the bug is in the prompt /")
        print("  openclaw config / MCP wiring — not the model.")
        return 0
    else:
        print("VERDICT: model returned plain text, no tool_calls. ✗")
        print("  Either the model can't tool-call (try a different model)")
        print("  or the request shape is wrong for this endpoint.")
        return 1


def main(argv: list[str]) -> int:
    host_env = _load_host_env()
    default_base = host_env.get("QWEN_BASE_URL", DEFAULT_BASE)
    # The host.env points at the SSH tunnel (port 11500); for a direct
    # laptop test we want the bare Ollama port. If the URL looks like
    # the tunnel, hint at the direct port for clarity.
    if "11500" in default_base:
        default_base = default_base.replace("11500", "11434")
    default_model = host_env.get("QWEN_MODEL", "qwen2.5-coder:7b")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=default_base,
                        help=f"OpenAI-compatible base URL (default: {default_base})")
    parser.add_argument("--model", default=default_model,
                        help=f"model id (default: {default_model})")
    parser.add_argument("--no-force", action="store_true",
                        help="omit tool_choice='required' (use 'auto' instead)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print full JSON response")
    args = parser.parse_args(argv)

    return _probe(args.base, args.model, force=not args.no_force, verbose=args.verbose)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
