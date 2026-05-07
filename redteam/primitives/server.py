"""HTTP front-end for :class:`SignedAppendOnlyLog` (FastAPI edition).

A small FastAPI application that exposes:

* ``GET  /health`` — liveness probe returning ``{"ok": true}``.
* ``POST /log``    — append a signed event to the underlying log and return
  its ``entry_hash``.

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

from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from identity.openclaw_identity import OpenClawIdentity
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


def build_app(identity: OpenClawIdentity, log_path: str) -> FastAPI:
    """Return a configured FastAPI app.

    The ``SignedAppendOnlyLog`` is built once here and captured by the
    route handlers, so every request reuses the same instance and the
    file handle / chain state stays shared. The reporter identity is
    likewise captured at build time — rotating ``identity`` requires
    rebuilding the app.
    """
    if identity is None:
        raise ValueError("identity must not be None")

    signed_log = SignedAppendOnlyLog(identity, log_path)
    reporter_id = str(identity.identity_hash)

    app = FastAPI()
    app.add_middleware(_BodySizeLimitMiddleware)

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
            return Response(
                status_code=405,
                headers={
                    "Allow": _ALLOWED_METHODS,
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
        return Response(
            status_code=204,
            headers={"Allow": _ALLOWED_METHODS, "Content-Length": "0"},
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

        # Resolve severity. Distinguish "not provided" (None → table lookup
        # with fallback) from "explicit 0" (caller forces severity 0). The
        # ``is not None`` check is load-bearing: a falsy-but-explicit 0 is
        # honored, but an absent value falls through to the table.
        if body.severity is not None:
            severity = body.severity
        else:
            severity = DEFAULT_SEVERITY_WEIGHTS.get(
                body.action, DEFAULT_SEVERITY_FALLBACK
            )

        # ``evidence`` already defaults to {} via Pydantic's default_factory.
        evidence = body.evidence

        try:
            entry = signed_log.append_event(
                reporter_id=reporter_id,
                subject_id=subject_id,
                action=body.action,
                details=body.details,
                severity=severity,
                evidence=evidence,
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

    return app


def main() -> None:
    """Module CLI entry point. Used by ``python -m redteam.primitives.server``.

    Loads / creates an :class:`OpenClawIdentity`, builds the FastAPI app,
    and serves it via ``uvicorn.run`` on a loopback host until interrupted.
    """
    import argparse
    import os

    parser = argparse.ArgumentParser(prog="redteam.primitives.server")
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
    args = parser.parse_args()

    # Defence in depth: refuse to bind a non-loopback host even if the
    # operator passes one explicitly. Same policy that previously lived
    # inside ``build_server``.
    check_loopback_host(args.host)

    identity = OpenClawIdentity(network=args.network, key_path=args.key_path)
    app = build_app(identity, args.log)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
