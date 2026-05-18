"""Tiny OpenAI-compatible proxy in front of an LLM provider.

Listens locally and forwards ``/v1/chat/completions`` (and a couple of
other GET endpoints) to the configured upstream (Anthropic's OpenAI-compat
endpoint by default). Multiple keys can be provided for round-robin
rotation; on 429/5xx a key is benched for ``--cooldown-seconds`` and the
next key tries. With a single paid key the rotation is a no-op.

Why this exists:

  * openclaw config takes ONE ``apiKey`` per provider; this proxy gives
    you a single stable URL to point it at regardless of how many real
    keys back it.
  * Centralises per-call logging (status, latency, key suffix) so demo
    runs are auditable from one place.

Run it on whichever box openclaw runs on:

    LLM_API_KEYS=sk-ant-... \\
        python scripts/llm_proxy.py --port 11600

Then point openclaw at ``http://127.0.0.1:11600/v1`` with any
non-empty placeholder ``apiKey`` — the real keys live here.

Configuration:

  ``--port`` (default 11600)
  ``--upstream`` (default https://api.anthropic.com/v1)
  ``--cooldown-seconds`` (default 60) — how long a key is benched after a 429

  ``LLM_API_KEYS`` env var: comma-separated list of keys. The proxy
  refuses to start if it's empty.

Logging:

  One line per upstream call:
    [proxy] POST /chat/completions key=sk-a…XX status=200 elapsed=412ms
  Failover lines:
    [proxy] key=sk-a…XX exhausted (429); cooldown=60s
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from dataclasses import dataclass, field

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

log = logging.getLogger("llm_proxy")


def _short_key(key: str) -> str:
    """Render a key as ``prefix…XX`` — safe for logs."""
    if len(key) < 8:
        return "***"
    return f"{key[:4]}…{key[-2:]}"


@dataclass
class KeyPool:
    """Round-robin pool of API keys with exhaustion tracking."""

    keys: list[str]
    cooldown_s: float
    _busy_until: dict[str, float] = field(default_factory=dict)
    _cursor: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        if not self.keys:
            raise ValueError("KeyPool needs at least one key")

    async def acquire(self) -> str | None:
        """Pick the next available key. Returns None if all are cooling down."""
        async with self._lock:
            now = time.monotonic()
            n = len(self.keys)
            for i in range(n):
                idx = (self._cursor + i) % n
                key = self.keys[idx]
                busy = self._busy_until.get(key, 0.0)
                if busy <= now:
                    self._cursor = (idx + 1) % n
                    return key
            return None  # all exhausted

    async def mark_exhausted(self, key: str, reason: str) -> None:
        async with self._lock:
            self._busy_until[key] = time.monotonic() + self.cooldown_s
            log.warning(
                "key=%s exhausted (%s); cooldown=%.0fs",
                _short_key(key), reason, self.cooldown_s,
            )

    def healthy(self) -> int:
        now = time.monotonic()
        return sum(1 for k in self.keys if self._busy_until.get(k, 0.0) <= now)

    def total(self) -> int:
        return len(self.keys)


# --- FastAPI app ------------------------------------------------------------

def build_app(pool: KeyPool, upstream: str) -> FastAPI:
    app = FastAPI()
    client = httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=10.0))

    @app.get("/healthz")
    async def healthz() -> dict:
        return {
            "ok": True,
            "keys_healthy": pool.healthy(),
            "keys_total": pool.total(),
            "upstream": upstream,
        }

    @app.api_route("/v1/{path:path}", methods=["GET", "POST"])
    async def passthrough(path: str, request: Request) -> Response:
        return await _forward(pool, client, upstream, path, request)

    # Also accept the path without the /v1 prefix so the proxy works with
    # clients that already strip it (or were configured with the base URL
    # ending in /v1 and append /chat/completions etc.).
    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def passthrough_no_v1(path: str, request: Request) -> Response:
        if path in {"healthz", "favicon.ico"}:
            return Response(status_code=404)
        return await _forward(pool, client, upstream, path, request)

    return app


async def _forward(
    pool: KeyPool,
    client: httpx.AsyncClient,
    upstream: str,
    path: str,
    request: Request,
) -> Response:
    """Try each available key in turn until one succeeds or we run out.

    When all keys are cooling down, wait briefly for one to recover
    instead of failing immediately — openclaw treats 503 as a hard
    error and bails out of the whole turn, which is the wrong call
    when the underlying issue is a transient minute-long rate window.
    """
    body = await request.body()
    method = request.method
    url = f"{upstream.rstrip('/')}/{path.lstrip('/')}"
    forwarded_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() in {"content-type", "accept"}
    }

    # If every key is cooling down at the moment of acquisition, sleep
    # in small slices and retry until one frees up or we run out of
    # patience. ``WAIT_BUDGET_S`` caps total wait per request so the
    # caller's own timeout (openclaw defaults ~150s) still wins.
    WAIT_BUDGET_S = 90.0
    SLICE_S = 1.5
    waited_for_key_s = 0.0

    tried = 0
    while True:
        key = await pool.acquire()
        if key is None:
            if waited_for_key_s >= WAIT_BUDGET_S:
                log.error(
                    "all keys cooling down for >%.0fs; returning 503 to caller",
                    waited_for_key_s,
                )
                return JSONResponse(
                    {"error": {"message": "all upstream keys exhausted; retry later",
                               "type": "proxy_no_keys_available"}},
                    status_code=503,
                )
            await asyncio.sleep(SLICE_S)
            waited_for_key_s += SLICE_S
            continue

        tried += 1
        t0 = time.monotonic()
        headers = {**forwarded_headers, "Authorization": f"Bearer {key}"}
        try:
            r = await client.request(method, url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000
            log.warning(
                "%s /%s key=%s transport_error=%s elapsed=%.0fms",
                method, path, _short_key(key), exc, elapsed_ms,
            )
            await pool.mark_exhausted(key, f"transport:{type(exc).__name__}")
            continue

        elapsed_ms = (time.monotonic() - t0) * 1000
        log.info(
            "%s /%s key=%s status=%d elapsed=%.0fms",
            method, path, _short_key(key), r.status_code, elapsed_ms,
        )

        # Bench the key on 429 / 5xx and try the next.
        if r.status_code == 429 or 500 <= r.status_code < 600:
            await pool.mark_exhausted(key, f"http_{r.status_code}")
            # Don't loop forever if all keys keep failing on this one
            # request — cap at len(pool) attempts.
            if tried >= pool.total():
                return Response(
                    content=r.content,
                    status_code=r.status_code,
                    media_type=r.headers.get("content-type"),
                )
            continue

        # Success (or any non-retryable 4xx) — pass through.
        return Response(
            content=r.content,
            status_code=r.status_code,
            media_type=r.headers.get("content-type"),
        )


# --- CLI --------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="OpenAI-compat LLM proxy with optional key rotation.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11600)
    parser.add_argument("--upstream",
                        default="https://api.anthropic.com/v1")
    parser.add_argument("--cooldown-seconds", type=float, default=60.0,
                        help="how long a key is benched after a 429/5xx. "
                             "60s matches a typical rolling per-minute window; "
                             "anything shorter risks retrying a still-throttled "
                             "key. The forward loop will wait up to 90s for "
                             "a free key.")
    args = parser.parse_args(argv)

    raw = os.environ.get("LLM_API_KEYS", "").strip()
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        print("set LLM_API_KEYS=key1[,key2,...] before starting the proxy",
              file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [proxy] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    log.info("starting on %s:%d  keys=%d  upstream=%s  cooldown=%.0fs",
             args.host, args.port, len(keys), args.upstream, args.cooldown_seconds)

    pool = KeyPool(keys=keys, cooldown_s=args.cooldown_seconds)
    app = build_app(pool, args.upstream)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
