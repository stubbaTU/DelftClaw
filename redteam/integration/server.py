"""HTTP front-end for :class:`SignedAppendOnlyLog` (FastAPI edition).

A small FastAPI application that exposes:

* ``GET  /health``                — liveness probe returning ``{"ok": true}``.
* ``POST /log``                   — append a signed event to the underlying
  log and return its ``entry_hash``.
* ``GET  /identity``              — node identity advert (identity_hash,
  pubkey_hex, network).
* ``GET  /head``                  — current chain head (``"GENESIS"`` if
  the log is empty).
* ``GET  /entries``               — incremental sync (``since=<hash>``,
  ``limit=<n>``); ``since="GENESIS"`` (or omitted) reads from the start.
* ``GET  /entries/{entry_hash}``  — single entry by chain hash, or 404.
* ``POST /entries``               — accept a foreign signed entry into the
  per-source peer cache.

Peer-cache scope (Layer 3 dev mode): the receiver does NOT splice
foreign entries into its own chain. Each accepted foreign entry is
appended to ``<peer_log_dir>/<source_id>.jsonl`` (one entry per line,
no header, no chain semantics on receive). The receiver's own chain is
left untouched. ``source_id`` is the foreign entry's ``reporter_id``.

The single factory exported here is :func:`build_app`, which returns a
configured ``FastAPI`` app. A single :class:`SignedAppendOnlyLog` is built
once inside :func:`build_app` and reused for every request, so the file
handle and chain state are shared across calls. For in-process tests, wrap
the app in ``fastapi.testclient.TestClient``; for a real bound port (CLI
or wire-level tests) use ``uvicorn.run`` (see :func:`main`).

Trust caveats (IMPORTANT — READ BEFORE DEPLOYING):

The crypto guarantees this server *does* provide:

* Every entry is Ed25519-signed by the local OpenClaw identity (the
  "reporter"), so the chain integrity binds entries to the server's
  identity.
* ``reporter_id`` is provably the server's identity hash — it cannot be
  forged by a caller because it is set server-side from
  ``identity.identity_hash``.

The crypto guarantees this server does **not** provide:

* ``subject_id`` is a pass-through string from the caller. The server
  does NOT cryptographically authenticate that the caller is in fact
  the named subject. Forgery resistance for ``subject_id`` requires a
  separate authentication layer above this primitive — e.g. HTTP
  signatures, client TLS certificates, or a handshake flow that proves
  knowledge of the subject's private key.
* The server-side severity table (``DEFAULT_SEVERITY_WEIGHTS``) only
  biases the *default* severity when the caller omits ``severity``. An
  explicit caller-supplied ``severity`` (including 0) always overrides
  the table — this primitive does not enforce severity authenticity.
  Closing that gap requires authenticated clients with allowlisted
  action sets, again above this primitive.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from identity.openclaw_identity import OpenClawIdentity
from redteam.integration.peer_transport import HttpPeerTransport, PeerTransport
from redteam.integration.pull_loop import run_pull_loop
from redteam.primitives.peer_log import PeerLog
from redteam.primitives.signed_log import SignedAppendOnlyLog
from shared.logging import get_logger

_log = get_logger(__name__)

# Maximum bytes accepted for a single POST body. Anything larger is rejected
# with 413 before any body read happens. 64 KiB is generous for an action-log
# payload but small enough to keep DoS surface bounded.
MAX_BODY_BYTES = 64 * 1024

# Default severity used when a POST /log body omits ``severity`` and the
# action name is not present in the table. 10 mirrors v-pejic's gateway
# default for unrecognised tool calls.
# Policy: unknown actions are treated as suspicious by default; benign
# actions opt-in to a lower severity via DEFAULT_SEVERITY_WEIGHTS.
DEFAULT_SEVERITY_FALLBACK = 10

# Server-side severity classification table. Keys are action strings the
# caller might pass; values are the default severity assigned when the
# caller omits ``severity`` from the POST body. The table biases the
# default severity toward sensible values — it does NOT prevent a caller
# from supplying their own severity, and an explicit caller-supplied
# ``severity`` (including 0) always overrides this table. This primitive
# does not enforce severity authenticity; that requires authenticated
# clients with allowlisted action sets above this layer.
DEFAULT_SEVERITY_WEIGHTS: dict[str, int] = {
    # Benign / expected actions — default to 0.
    "tool_execution_success": 0,
    "send_message": 0,
    "register_seedbox": 0,
    "broadcast_seedbox_donation": 0,
    "log_broadcast": 0,
    "receive_message": 0,
    # Mid-severity — suspicious or policy-violating but not catastrophic.
    "unauthorized_tool_request": 5,
    "log_spoof_attempt": 5,
    # High-severity — credential / key-material exfiltration.
    "exfiltrate_private_key": 10,
}

# Hosts that count as loopback. Anything else must be rejected at every
# entry point that opens a real listening socket: this server signs
# entries with the local OpenClaw identity and must never be reachable
# from the network.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

# Single source of truth for the methods we serve. Used both as the value
# for the `Allow` header on 405 / 204 responses and to set route methods.
_ALLOWED_METHODS = "GET, POST, OPTIONS"
_ALLOWED_METHODS_SET = {"GET", "POST", "OPTIONS"}


def resolve_severity(action: str, explicit: int | None) -> int:
    """Resolve the severity for an entry.

    An explicit caller-supplied ``severity`` (including 0) always wins;
    otherwise look up ``action`` in :data:`DEFAULT_SEVERITY_WEIGHTS` and
    fall back to :data:`DEFAULT_SEVERITY_FALLBACK` for unknown actions.
    Pulled out of the route handler so the policy is testable in
    isolation and easy to relocate when a non-HTTP writer also needs it.
    """
    if explicit is not None:
        return explicit
    return DEFAULT_SEVERITY_WEIGHTS.get(action, DEFAULT_SEVERITY_FALLBACK)


def check_loopback_host(host: str) -> None:
    """Raise ``ValueError`` if ``host`` is not a loopback alias.

    Centralises the policy that this server must never bind a non-loopback
    interface. Callers that open a real listening socket (the CLI, the
    test thread fixture) should invoke this before touching ``socket``.
    """
    if host not in LOOPBACK_HOSTS:
        raise ValueError(f"server must bind loopback; got host={host}")


class _LogEntryRequest(BaseModel):
    """Pydantic model for the POST /log body.

    ``model_config`` allows extra fields so unknown top-level keys are
    silently accepted (forward-compat). ``details`` is required to be a
    dict (not None / not a string) and ``action`` must be a non-empty
    string.

    Optional fields:

    * ``subject_id`` — the agent the entry is *about*. Defaults to the
      server's own identity hash when omitted (legacy "I logged Y"
      behavior). NOT cryptographically authenticated; see module
      docstring for the trust caveat.
    * ``severity`` — caller-supplied severity. Distinguishes ``None``
      ("not provided" → table lookup) from an explicit ``0`` ("caller
      wants severity 0"). DO NOT default this to 0 directly; the
      handler resolves the default from
      :data:`DEFAULT_SEVERITY_WEIGHTS`.
    * ``evidence`` — forensic context dict. Defaults to ``{}``.
    """

    action: str = Field(..., min_length=1)
    details: dict[str, Any]
    subject_id: str | None = Field(default=None, min_length=1)
    severity: int | None = Field(default=None, ge=0, le=10)
    evidence: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}

    @field_validator("severity", mode="before")
    @classmethod
    def _reject_bool_severity(cls, v):
        # Pydantic v2 silently coerces bool -> int because bool is an
        # int subclass. Catch True/False BEFORE the int coercion runs
        # (mode="before") so the ge/le bounds apply to a real int.
        if isinstance(v, bool):
            raise ValueError("severity must be int, not bool")
        return v


class _PeerEntryRequest(BaseModel):
    """Pydantic model for the POST /entries body (foreign signed entry).

    Loose by design: only the top-level shape is enforced here so a
    malformed *recursive* JSON body (deeply nested, malicious) is
    rejected at parse time. The real cryptographic verification happens
    inside :meth:`SignedAppendOnlyLog.verify_foreign_entry` via the
    :class:`PeerLog`. Required fields: ``version`` (int) and ``kind``
    (str). All other foreign-entry fields pass through unchanged via
    ``model_config = {"extra": "allow"}``.
    """

    version: int
    kind: str

    model_config = {"extra": "allow"}


class _BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversize requests via ``Content-Length`` before reading body.

    Only the *size cap* is enforced here; presence/parseability of the
    header is checked inside the route handler (so unsupported methods
    on a route still get a clean 405 from the router instead of an
    early 400 from this middleware). A header that parses as an integer
    larger than ``MAX_BODY_BYTES`` returns 413 immediately, without
    ever pulling the body off the wire.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                declared = int(cl)
            except ValueError:
                # Defer to route handler / parser to surface a 400.
                return await call_next(request)
            if declared > MAX_BODY_BYTES:
                return JSONResponse(
                    {"error": "request body too large"},
                    status_code=413,
                )
        return await call_next(request)


def _default_transport_factory() -> tuple[httpx.AsyncClient, PeerTransport]:
    """Default factory: build a fresh ``httpx.AsyncClient`` + wrap it.

    Returns ``(handle, transport)``. The handle is the AsyncClient
    itself, which the lifespan will ``aclose()`` on shutdown. Pulled
    out so :func:`build_app` callers can swap a different factory in
    (e.g. tests mounting an ASGITransport against an in-process app).
    """
    client = httpx.AsyncClient()
    return client, HttpPeerTransport(client)


def build_app(
    identity: OpenClawIdentity,
    log_path: "str | os.PathLike[str]",
    peer_log_dir: "str | os.PathLike[str] | None" = None,
    peers: list[str] | None = None,
    pull_interval: float = 5.0,
    pull_batch: int = 100,
    transport_factory: Callable[
        [], tuple[Any, PeerTransport]
    ] | None = None,
    enable_integrity_audit: bool = False,
) -> FastAPI:
    """Return a configured FastAPI app.

    The ``SignedAppendOnlyLog`` and ``PeerLog`` are built once here and
    captured by the route handlers, so every request reuses the same
    instances and the file handles / chain state stay shared. The
    reporter identity is likewise captured at build time — rotating
    ``identity`` requires rebuilding the app.

    ``peer_log_dir`` defaults to a ``peer_logs`` sibling of ``log_path``
    when omitted, so callers that don't care about peer-cache placement
    (e.g. legacy POST /log smoke tests) need not supply it.

    Pull-sync (Layer 3, optional):

    * ``peers`` — list of peer base URLs to pull from. ``None`` or
      empty disables the pull loop entirely (existing single-node
      behavior preserved).
    * ``pull_interval`` / ``pull_batch`` — driver knobs forwarded to
      :func:`redteam.integration.pull_loop.run_pull_loop`.
    * ``transport_factory`` — test injection seam. A zero-arg callable
      returning ``(handle, transport)`` where ``handle`` is whatever
      object the lifespan will ``aclose()`` (typically the underlying
      ``httpx.AsyncClient``) and ``transport`` is the
      :class:`PeerTransport` the loop drives. Defaults to a factory
      that builds a fresh ``httpx.AsyncClient`` + ``HttpPeerTransport``.
    """
    if identity is None:
        raise ValueError("identity must not be None")

    signed_log = SignedAppendOnlyLog(identity, log_path)
    reporter_id = str(identity.identity_hash)
    if peer_log_dir is None:
        peer_log_dir = str(Path(log_path).resolve().parent / "peer_logs")
    peer_log_kwargs: dict[str, Any] = {}
    if enable_integrity_audit:
        peer_log_kwargs["audit_log"] = signed_log
    peer_log = PeerLog(
        peer_log_dir, network=identity.network, own_id=reporter_id,
        **peer_log_kwargs,
    )

    # Pull-sync wiring: when ``peers`` is non-empty, spin up the pull
    # loop. Lifespan handler drives startup/shutdown under uvicorn.
    # For test harnesses (notably bare ``httpx.ASGITransport``) that
    # do not dispatch the ASGI lifespan protocol, the start/stop
    # coroutines are exposed on ``app.state`` so tests can drive them
    # explicitly. ``_started`` makes the start path idempotent.
    peer_urls = list(peers or [])
    for url in peer_urls:
        if not url.startswith(("http://", "https://")):
            raise ValueError(
                f"peer URL must use http:// or https:// scheme: {url!r}"
            )
    factory = transport_factory or _default_transport_factory

    # Mutable closure state so lifespan + state-exposed hooks share
    # one task without leaking module-level globals.
    _state: dict[str, Any] = {
        "task": None,
        "stop_event": None,
        "handle": None,
        "started": False,
    }

    async def _start_pull_loop() -> None:
        if _state["started"] or not peer_urls:
            return
        _state["started"] = True
        handle, transport = factory()
        stop_event = asyncio.Event()
        _state["handle"] = handle
        _state["stop_event"] = stop_event
        _state["task"] = asyncio.create_task(
            run_pull_loop(
                transport=transport,
                peer_urls=peer_urls,
                peer_log=peer_log,
                interval=pull_interval,
                batch=pull_batch,
                stop_event=stop_event,
            )
        )

    async def _stop_pull_loop() -> None:
        loop_task = _state.get("task")
        stop_event = _state.get("stop_event")
        handle = _state.get("handle")
        if loop_task is not None and stop_event is not None:
            stop_event.set()
            # Cap at 5s: the loop wakes immediately on ``stop_event.set()``
            # plus at most one in-flight iteration. Floor at 1s for tiny
            # test intervals. Without the cap, a large ``pull_interval``
            # (e.g. 60s) would block teardown for ~120s.
            shutdown_timeout = min(max(pull_interval * 2, 1.0), 5.0)
            try:
                await asyncio.wait_for(loop_task, timeout=shutdown_timeout)
            except asyncio.TimeoutError:
                loop_task.cancel()
                try:
                    await loop_task
                except (asyncio.CancelledError, Exception) as exc:
                    _log.warning(
                        "server.pull_loop_shutdown_timeout",
                        error=str(exc),
                        error_type=type(exc).__name__,
                    )
            except Exception as exc:
                # Loop crashed during shutdown — log and move on so
                # the rest of teardown still runs.
                _log.warning(
                    "server.pull_loop_crash_on_shutdown",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
        if handle is not None:
            aclose = getattr(handle, "aclose", None)
            if aclose is not None:
                try:
                    await aclose()
                except Exception as exc:
                    _log.warning(
                        "server.transport_close_failed",
                        error=str(exc),
                        error_type=type(exc).__name__,
                    )

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        await _start_pull_loop()
        try:
            yield
        finally:
            await _stop_pull_loop()

    app = FastAPI(lifespan=_lifespan)
    app.add_middleware(_BodySizeLimitMiddleware)
    # Test-driver hooks. ASGI test transports that don't dispatch the
    # lifespan protocol (e.g. bare ``httpx.ASGITransport``) call these
    # explicitly: ``await app.state.start_pull_loop()`` /
    # ``await app.state.stop_pull_loop()``. Both are idempotent and
    # no-op when ``peers`` is empty.
    app.state.start_pull_loop = _start_pull_loop
    app.state.stop_pull_loop = _stop_pull_loop

    # Per-route Allow header registry. Built from ``app.routes`` after
    # all routes are registered so the 405 handler can return the actual
    # method set for the request's path instead of a one-size-fits-all
    # default. Closure-captured by ``_http_exc_handler`` below.
    path_methods: dict[str, set[str]] = {}

    # ------------------------------------------------------------------
    # Exception handlers
    # ------------------------------------------------------------------

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Tests assert 400 on missing/invalid action, non-dict details, etc.
        # FastAPI's RequestValidationError.errors() returns Pydantic v2
        # error dicts. Two fields can hold non-JSON-serialisable values:
        # ``ctx`` may carry a raw exception object (e.g. the ValueError
        # raised by the bool-rejection validator), and ``input`` may
        # carry the raw request body as ``bytes`` when the JSON body
        # itself fails to decode. Strip both defensively.
        sanitized: list[dict[str, Any]] = []
        for err in exc.errors():
            cleaned = {
                k: v for k, v in err.items() if k not in ("ctx", "input")
            }
            sanitized.append(cleaned)
        return JSONResponse(
            {
                "error": "request validation failed",
                "detail": sanitized,
            },
            status_code=400,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        if exc.status_code == 405:
            # Per-route Allow header: look up methods registered for this
            # exact path. Falls back to the global allow-set only when
            # the path is unknown (e.g. an unrelated 405 produced
            # somewhere we didn't anticipate).
            allowed = path_methods.get(request.url.path)
            if allowed:
                allow_header = ", ".join(sorted(allowed))
            else:
                allow_header = _ALLOWED_METHODS
            return Response(
                status_code=405,
                headers={
                    "Allow": allow_header,
                    "Content-Length": "0",
                },
            )
        if exc.status_code == 404:
            return Response(status_code=404, headers={"Content-Length": "0"})
        # Default JSON for everything else.
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code
        )

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.get("/health")
    async def _health() -> dict[str, bool]:
        return {"ok": True}

    @app.options("/log")
    async def _log_options() -> Response:
        # Conventional non-CORS preflight: 204 + Allow header.
        # /log is POST-only (no GET) so the per-path allow set differs
        # from the multi-verb /entries route.
        return Response(
            status_code=204,
            headers={"Allow": "POST, OPTIONS", "Content-Length": "0"},
        )

    @app.post("/log")
    async def _post_log(body: _LogEntryRequest) -> JSONResponse:
        """Append a signed event to the underlying log.

        Trust caveat (see also module docstring): ``subject_id`` is a
        pass-through string from the caller. The server does NOT
        cryptographically authenticate that the caller is in fact the
        named subject. Forgery resistance for ``subject_id`` requires a
        separate authentication layer above this primitive (HTTP
        signatures, mTLS, or a handshake flow proving knowledge of the
        subject's private key). Likewise, the server-side severity table
        only biases the *default* when the caller omits ``severity`` —
        an explicit caller-supplied severity (including 0) always wins,
        and the primitive does not enforce severity authenticity.

        Body parsing and validation is handled by FastAPI: JSON parse
        errors and Pydantic validation failures are routed to
        ``_validation_handler`` and returned as 400. Oversize bodies are
        rejected with 413 by ``_BodySizeLimitMiddleware`` before this
        handler runs.
        """
        # Resolve subject_id: explicit caller value wins; otherwise default
        # to the server's own identity hash (legacy "I logged Y" semantics).
        # The reporter_id is ALWAYS the server's identity — a caller cannot
        # impersonate the signer.
        subject_id = body.subject_id or reporter_id

        # Resolve severity via the policy helper. Distinguishes "not
        # provided" (None → table lookup with fallback) from "explicit 0"
        # (caller forces severity 0).
        severity = resolve_severity(body.action, body.severity)

        try:
            entry = signed_log.append_event(
                reporter_id=reporter_id,
                subject_id=subject_id,
                action=body.action,
                details=body.details,
                severity=severity,
                evidence=body.evidence,
            )
        except Exception as exc:  # surface as 500, do not swallow
            _log.error(
                "server.append_event_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return JSONResponse(
                {"error": "failed to append event"}, status_code=500
            )

        return JSONResponse(
            {"entry_hash": entry["entry_hash"]}, status_code=200
        )

    # ------------------------------------------------------------------
    # Layer 3: peer-to-peer endpoints
    # ------------------------------------------------------------------

    @app.get("/identity")
    async def _get_identity() -> JSONResponse:
        """Node identity advert: identity_hash, hex pubkey, network."""
        return JSONResponse(
            {
                "identity_hash": reporter_id,
                "pubkey_hex": identity.public_key.hex(),
                "network": identity.network,
            },
            status_code=200,
        )

    @app.options("/identity")
    async def _identity_options() -> Response:
        # /identity only services GET (and OPTIONS for preflight).
        return Response(
            status_code=204,
            headers={"Allow": "GET, OPTIONS", "Content-Length": "0"},
        )

    @app.get("/head")
    async def _get_head() -> JSONResponse:
        """Current chain head (``"GENESIS"`` if the log is empty)."""
        return JSONResponse(
            {"head_hash": signed_log.latest_hash()}, status_code=200
        )

    @app.options("/head")
    async def _head_options() -> Response:
        return Response(
            status_code=204,
            headers={"Allow": "GET, OPTIONS", "Content-Length": "0"},
        )

    @app.get("/entries")
    async def _get_entries(
        since: str | None = None, limit: int = 100
    ) -> JSONResponse:
        """Incremental sync. ``since`` omitted ⇒ from genesis.

        ``since="GENESIS"`` is treated identically to omitting ``since``
        (symmetry with ``/head`` returning ``"GENESIS"`` on an empty
        chain). ``since`` set to any other value not present in the
        chain → 404. ``limit`` clamped to [0, 1000]; negative ``limit``
        → 400.
        """
        if limit < 0:
            return JSONResponse(
                {"error": "limit must be non-negative"}, status_code=400
            )
        limit = min(limit, 1000)

        all_entries = signed_log.read_entries()
        head_hash = signed_log.latest_hash()

        if since is None or since == "GENESIS":
            # "from start of chain" — symmetry with /head's GENESIS sentinel.
            sliced = all_entries
        else:
            start_index: int | None = None
            for idx, entry in enumerate(all_entries):
                if entry.get("entry_hash") == since:
                    start_index = idx + 1
                    break
            if start_index is None:
                # 404 — the cursor is not in our chain. Malformed-hex
                # cursors fall through here too: we don't pre-validate
                # shape, "not in chain" covers the case.
                return Response(status_code=404, headers={"Content-Length": "0"})
            sliced = all_entries[start_index:]

        return JSONResponse(
            {
                "entries": sliced[:limit],
                "head_hash": head_hash,
            },
            status_code=200,
        )

    @app.get("/entries/{entry_hash}")
    async def _get_entry_by_hash(entry_hash: str) -> JSONResponse:
        """Return a single entry by its chain hash, or 404."""
        for entry in signed_log.read_entries():
            if entry.get("entry_hash") == entry_hash:
                return JSONResponse(entry, status_code=200)
        return Response(status_code=404, headers={"Content-Length": "0"})

    @app.options("/entries/{entry_hash}")
    async def _entry_by_hash_options(entry_hash: str) -> Response:
        return Response(
            status_code=204,
            headers={"Allow": "GET, OPTIONS", "Content-Length": "0"},
        )

    @app.options("/entries")
    async def _entries_options() -> Response:
        return Response(
            status_code=204,
            headers={"Allow": _ALLOWED_METHODS, "Content-Length": "0"},
        )

    @app.post("/entries")
    async def _post_entries(body: _PeerEntryRequest) -> JSONResponse:
        """Accept a foreign signed entry into the per-source peer cache.

        Body is the full v2 entry dict. Top-level shape (``version``
        int + ``kind`` str) is enforced by Pydantic; full cryptographic
        verification (entry_hash, signature, identity binding, per-kind
        checks) is delegated to the ``PeerLog``. Same-identity
        submissions and verification failures return 400; success and
        idempotent duplicates return 200.
        """
        # ``model_dump(mode="python")`` collapses the Pydantic model
        # back into a plain dict, including any extra-allow fields, so
        # ``verify_foreign_entry`` sees the same shape it would have
        # seen pre-Pydantic.
        body_dict = body.model_dump(mode="python")

        try:
            stored, source_id, errors, duplicate = peer_log.accept_entry(
                body_dict
            )
        except Exception as exc:  # surface as 500, do not swallow
            _log.error(
                "server.peer_accept_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return JSONResponse(
                {"error": "failed to store foreign entry"}, status_code=500
            )

        if errors:
            return JSONResponse(
                {
                    "error": "foreign entry verification failed",
                    "detail": errors,
                },
                status_code=400,
            )

        return JSONResponse(
            {
                "stored": stored,
                "source_id": source_id,
                "duplicate": duplicate,
            },
            status_code=200,
        )

    # All routes registered. Capture the ``path -> {methods}`` map so the
    # 405 handler returns the right ``Allow`` for each path. Iterating
    # ``app.routes`` after registration is the only stable place we have
    # the full set; a route added later (none currently) would silently
    # fall back to the global default until this is rebuilt.
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or methods is None:
            continue
        bucket = path_methods.setdefault(path, set())
        bucket.update(methods)

    return app


def main() -> None:
    """Module CLI entry point. Used by ``python -m redteam.integration.server``.

    Loads / creates an :class:`OpenClawIdentity`, builds the FastAPI app,
    and serves it via ``uvicorn.run`` on a loopback host until interrupted.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="redteam.integration.server")
    parser.add_argument(
        "--log", default="signed.log", help="path to the signed log file"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8800)
    parser.add_argument(
        "--key-path",
        default=os.environ.get("OPENCLAW_KEY_PATH", "openclaw_priv.pem"),
    )
    parser.add_argument(
        "--network",
        default=os.environ.get("OPENCLAW_NETWORK", "MAINNET"),
    )
    parser.add_argument(
        "--peer-log-dir",
        default=None,
        help=(
            "directory for per-source foreign entry caches; "
            "defaults to <dir of --log>/peer_logs"
        ),
    )
    parser.add_argument(
        "--peers",
        default=None,
        help=(
            "comma-separated list of peer base URLs to pull from "
            "(e.g. http://127.0.0.1:8801,http://127.0.0.1:8802); "
            "omit / empty to disable pull sync"
        ),
    )
    parser.add_argument(
        "--pull-interval",
        type=float,
        default=5.0,
        help="seconds between pull cycles (default: 5.0)",
    )
    parser.add_argument(
        "--pull-batch",
        type=int,
        default=100,
        help="max entries pulled per peer per cycle (default: 100)",
    )
    args = parser.parse_args()

    # Defence in depth: refuse to bind a non-loopback host even if the
    # operator passes one explicitly. Same policy that previously lived
    # inside ``build_server``.
    check_loopback_host(args.host)

    identity = OpenClawIdentity(network=args.network, key_path=args.key_path)

    # Parse --peers into a clean list[str]; empty / None → no peers (no
    # pull loop). Trim whitespace and drop empty fragments so e.g.
    # ``--peers ""`` or ``--peers a,,b,`` behave sensibly.
    if args.peers:
        peer_list = [p.strip() for p in args.peers.split(",") if p.strip()]
        # Reject non-http(s) schemes at CLI parse time so the operator
        # gets a clean argparse error, not a deeper ValueError on app
        # construction. ``build_app`` enforces the same rule again as a
        # second line of defence for programmatic callers.
        for url in peer_list:
            if not url.startswith(("http://", "https://")):
                parser.error(
                    f"--peers entries must start with http:// or https://: "
                    f"{url!r}"
                )
    else:
        peer_list = None

    # Default peer-log dir derivation lives inside ``build_app`` (single
    # source of truth). Pass ``args.peer_log_dir`` straight through —
    # ``None`` lets ``build_app`` pick the sibling ``peer_logs/`` default.
    app = build_app(
        identity,
        args.log,
        args.peer_log_dir,
        peers=peer_list,
        pull_interval=args.pull_interval,
        pull_batch=args.pull_batch,
    )

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
