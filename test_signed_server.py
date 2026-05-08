"""Tests for the SignedAppendOnlyLog HTTP server.

Most assertions are about the FastAPI app's behaviour and don't need a
real bound port — those use ``fastapi.testclient.TestClient`` against
``build_app(...)``. A few tests genuinely need wire-level control or
real cross-thread concurrency:

* ``test_post_log_oversize_body`` — checks the 413-before-body-read path
  on a real socket where the server may RST mid-write.
* ``test_concurrent_posts_chain_correctly`` — exercises the lock around
  ``SignedAppendOnlyLog.append_event``'s read-latest-then-append using
  truly concurrent client threads against a real listener.
* ``test_thread_server_binds_loopback`` — sanity-check that the real-port
  fixture binds a loopback host.

Those tests use the ``thread_server`` fixture, which spins up ``uvicorn``
on an ephemeral loopback port in a background thread. All other tests
use ``test_client`` (TestClient + ASGI transport) — no port, no thread
plumbing, much faster.
"""

from __future__ import annotations

import http.client
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Iterator, Optional

import pytest
import uvicorn
from fastapi.testclient import TestClient

from identity.openclaw_identity import OpenClawIdentity
from redteam.integration.server import (
    DEFAULT_SEVERITY_FALLBACK,
    DEFAULT_SEVERITY_WEIGHTS,
    LOOPBACK_HOSTS,
    MAX_BODY_BYTES,
    build_app,
    check_loopback_host,
)
from redteam.primitives.signed_log import SignedAppendOnlyLog


REPO_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers wrapping TestClient so test bodies stay readable.
# ---------------------------------------------------------------------------


def _post(
    client: TestClient,
    path: str,
    body,
    *,
    content_type: str = "application/json",
) -> tuple[int, Optional[dict], bytes]:
    """POST to ``path`` on ``client``. ``body`` is dict (JSON) or raw bytes.

    Returns ``(status, parsed_json_or_None, raw_bytes)`` to match the
    contract of the previous urllib-based helper.
    """
    if isinstance(body, dict):
        data = json.dumps(body).encode("utf-8")
    else:
        data = body
    resp = client.post(path, content=data, headers={"Content-Type": content_type})
    raw = resp.content
    try:
        return resp.status_code, resp.json(), raw
    except (json.JSONDecodeError, ValueError):
        return resp.status_code, None, raw


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
def app_ctx(tmp_path: Path):
    """Yield ``(app, identity, log_path)`` for in-process TestClient tests."""
    identity = OpenClawIdentity(
        network="MAINNET", key_path=str(tmp_path / "key.pem")
    )
    log_path = str(tmp_path / "log.jsonl")
    app = build_app(identity, log_path)
    yield app, identity, log_path


@pytest.fixture
def test_client(app_ctx) -> Iterator[tuple[TestClient, OpenClawIdentity, str]]:
    """Yield ``(client, identity, log_path)`` for in-process tests."""
    app, identity, log_path = app_ctx
    with TestClient(app) as client:
        yield client, identity, log_path


class _ThreadedUvicorn:
    """Minimal ``uvicorn.Server`` wrapper for tests that need a real port.

    Intentionally tiny: no stdlib ``ThreadingHTTPServer`` mimicry, no
    socket pre-binding. We start uvicorn in a daemon thread, poll
    ``server.started`` until True, then read ``server.servers[0]
    .sockets[0]`` for the bound address. ``stop()`` flips
    ``should_exit`` and joins the thread.
    """

    def __init__(self, app, host: str, port: int) -> None:
        check_loopback_host(host)
        self._config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
            loop="asyncio",
            lifespan="off",
            workers=1,
        )
        self._server = uvicorn.Server(self._config)
        # uvicorn tries to install SIGINT/SIGTERM handlers on serve(),
        # which fails outside the main thread on some platforms.
        self._server.install_signal_handlers = lambda: None  # type: ignore[assignment]
        self._thread: threading.Thread | None = None
        self.host: str = host
        self.port: int = port

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.run, daemon=True
        )
        self._thread.start()
        # Wait for uvicorn to actually be listening. ``server.started``
        # flips True after the socket is bound and accept() is running.
        deadline = time.monotonic() + 10.0
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn did not start within 10s")
            time.sleep(0.01)
        # Read back the bound port (port=0 resolves to a real port here).
        for srv in self._server.servers:
            for sock in srv.sockets:
                self.host, self.port = sock.getsockname()[:2]
                return

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)


@pytest.fixture
def thread_server(app_ctx):
    """Yield ``(base_url, identity, log_path)`` from a real bound uvicorn."""
    app, identity, log_path = app_ctx
    server = _ThreadedUvicorn(app, host="127.0.0.1", port=0)
    server.start()
    try:
        yield f"http://{server.host}:{server.port}", identity, log_path
    finally:
        server.stop()


def _hostport(base_url: str) -> tuple[str, int]:
    no_scheme = base_url.split("://", 1)[1]
    host, port = no_scheme.split(":", 1)
    return host, int(port)


# ---------------------------------------------------------------------------
# Original 9 tests — TestClient.
# ---------------------------------------------------------------------------


def test_health_endpoint_returns_ok(test_client) -> None:
    client, _identity, _log_path = test_client

    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_post_log_valid_returns_entry_hash(test_client) -> None:
    client, _identity, _log_path = test_client

    status, body, raw = _post(
        client, "/log", {"action": "test", "details": {"x": 1}}
    )

    assert status == 200
    assert body is not None
    assert raw  # body bytes are non-empty
    assert "entry_hash" in body
    entry_hash = body["entry_hash"]
    assert isinstance(entry_hash, str)
    assert len(entry_hash) == 64
    int(entry_hash, 16)  # all hex


def test_post_log_writes_real_signed_entry(test_client) -> None:
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "test", "details": {"x": 1}}
    )
    assert status == 200

    log = SignedAppendOnlyLog(identity, log_path)
    entries = log.read_entries()

    assert len(entries) == 1
    entry = entries[0]
    assert entry["action"] == "test"
    assert entry["details"] == {"x": 1}
    assert entry.get("signature")
    assert entry.get("reporter_pubkey")


def test_post_log_missing_action_returns_400(test_client) -> None:
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(client, "/log", {"details": {}})

    assert status == 400


def test_post_log_malformed_json_returns_400(test_client) -> None:
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(client, "/log", b"not json{")

    assert status == 400


def test_put_log_returns_405(test_client) -> None:
    client, _identity, _log_path = test_client

    resp = client.put("/log")

    assert resp.status_code == 405


def test_delete_log_returns_405(test_client) -> None:
    client, _identity, _log_path = test_client

    resp = client.delete("/log")

    assert resp.status_code == 405


def test_server_uses_injected_identity(test_client) -> None:
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "test", "details": {"x": 1}}
    )
    assert status == 200

    entries = SignedAppendOnlyLog(identity, log_path).read_entries()

    assert len(entries) == 1
    reporter_pubkey_hex = entries[0]["reporter_pubkey"]
    assert reporter_pubkey_hex == identity.public_key.hex()


def test_thread_server_binds_loopback(thread_server) -> None:
    """The real-port test fixture binds to a loopback host."""
    base_url, _identity, _log_path = thread_server
    host, _port = _hostport(base_url)

    assert host in LOOPBACK_HOSTS


# ---------------------------------------------------------------------------
# Multi-write + persistence
# ---------------------------------------------------------------------------


def test_multi_post_chain(test_client) -> None:
    """Five sequential POSTs all return fresh entry_hashes and chain correctly."""
    client, identity, log_path = test_client

    seen_hashes: list[str] = []
    for i in range(5):
        status, body, _raw = _post(
            client, "/log", {"action": f"step-{i}", "details": {"i": i}}
        )
        assert status == 200, body
        assert body is not None
        assert "entry_hash" in body
        seen_hashes.append(body["entry_hash"])

    # Every returned entry_hash should be unique (chain advances each call).
    assert len(set(seen_hashes)) == 5

    log = SignedAppendOnlyLog(identity, log_path)
    entries = log.read_entries()
    assert len(entries) == 5

    ok, errors = log.verify_integrity()
    assert ok, errors
    assert errors == []

    # The stored entry_hashes match what the server returned.
    assert [e["entry_hash"] for e in entries] == seen_hashes


def test_round_trip_with_verify_cli(test_client, tmp_path: Path) -> None:
    """POST 3 entries, then run `python -m redteam.primitives.verify` over the log."""
    client, _identity, log_path = test_client

    for i in range(3):
        status, _body, _raw = _post(
            client, "/log", {"action": f"a-{i}", "details": {"n": i}}
        )
        assert status == 200

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "redteam.primitives.verify",
            "--log",
            log_path,
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"verify CLI failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_concurrent_posts_chain_correctly(thread_server) -> None:
    """Two threads, 5 POSTs each, all started simultaneously with a barrier.

    Uses the real bound uvicorn (not TestClient) so the requests are
    actually dispatched concurrently from independent OS threads against
    a real socket. ``SignedAppendOnlyLog.append_event`` must take a lock
    around the read-latest-then-append sequence, otherwise two threads
    can both read the same ``previous_hash`` and produce two siblings —
    the chain breaks. This test catches that regression.
    """
    base_url, identity, log_path = thread_server

    barrier = threading.Barrier(2)
    errors: list[str] = []

    def worker(tag: str) -> None:
        # Each worker uses its own http.client connection so the requests
        # are genuinely independent.
        host, port = _hostport(base_url)
        barrier.wait()
        for i in range(5):
            try:
                conn = http.client.HTTPConnection(host, port, timeout=10)
                body = json.dumps(
                    {"action": f"{tag}-{i}", "details": {"i": i}}
                ).encode("utf-8")
                conn.request(
                    "POST",
                    "/log",
                    body=body,
                    headers={"Content-Type": "application/json"},
                )
                resp = conn.getresponse()
                resp.read()
                status = resp.status
                conn.close()
            except Exception as exc:
                errors.append(f"{tag}-{i}: {exc!r}")
                return
            if status != 200:
                errors.append(f"{tag}-{i}: status={status}")
                return

    t1 = threading.Thread(target=worker, args=("A",), daemon=True)
    t2 = threading.Thread(target=worker, args=("B",), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    assert not t1.is_alive() and not t2.is_alive(), "concurrent workers hung"
    assert errors == [], errors

    log = SignedAppendOnlyLog(identity, log_path)
    entries = log.read_entries()
    assert len(entries) == 10, f"expected 10 entries, got {len(entries)}"

    ok, verify_errors = log.verify_integrity()
    assert ok, verify_errors
    assert verify_errors == []


# ---------------------------------------------------------------------------
# Body validation
# ---------------------------------------------------------------------------


def test_post_log_empty_body(test_client) -> None:
    """Empty body must be rejected with 400.

    Pydantic now drives validation: an empty body fails JSON parsing
    (or, equivalently, fails the required-field check on the parsed
    object) and FastAPI's ``RequestValidationError`` is converted to a
    400 by ``_validation_handler``.
    """
    client, _identity, _log_path = test_client

    resp = client.post(
        "/log",
        content=b"",
        headers={"Content-Type": "application/json"},
    )

    assert resp.status_code == 400


def test_post_log_empty_json_object_rejected(test_client) -> None:
    """``{}`` must be rejected because ``action`` and ``details`` are required."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(client, "/log", {})

    assert status == 400


def test_post_log_oversize_body(thread_server) -> None:
    """Body larger than MAX_BODY_BYTES must yield 413.

    The server rejects with 413 *before* reading the body. On Windows,
    the race between client write and server close is messy: urllib
    raises ``ConnectionAbortedError``, and even raw sockets can see an
    empty read if the server's RST arrives between writes. We send the
    headers, then read the response immediately — once we have the
    status line, we're done.
    """
    base_url, _identity, _log_path = thread_server
    host, port = _hostport(base_url)

    big_value = "A" * (MAX_BODY_BYTES + 1)
    body = json.dumps({"action": "big", "details": {"x": big_value}}).encode(
        "utf-8"
    )
    headers = (
        b"POST /log HTTP/1.1\r\n"
        b"Host: " + host.encode("ascii") + b":" + str(port).encode("ascii") + b"\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(2)
    chunks: list[bytes] = []
    try:
        sock.sendall(headers)

        # Try to read the response immediately — the server should
        # respond to oversize Content-Length without reading the body.
        for _ in range(20):
            try:
                buf = sock.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not buf:
                break
            chunks.append(buf)
            joined = b"".join(chunks)
            if b"\r\n\r\n" in joined:
                break
    finally:
        try:
            sock.close()
        except OSError:
            pass

    response = b"".join(chunks)
    assert response, "server returned nothing for oversize body"
    status_line = response.split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    assert len(parts) >= 2, status_line
    assert parts[1] == b"413", status_line


# ---------------------------------------------------------------------------
# Body shape
# ---------------------------------------------------------------------------


def test_post_log_details_string(test_client) -> None:
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": "string-not-dict"}
    )

    assert status == 400


def test_post_log_details_null(test_client) -> None:
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(client, "/log", {"action": "x", "details": None})

    assert status == 400


def test_post_log_unknown_fields_accepted(test_client) -> None:
    """Forward-compat: extra top-level fields must not cause a 400."""
    client, _identity, _log_path = test_client

    status, body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "extra": "ignore"},
    )

    assert status == 200
    assert body is not None
    assert "entry_hash" in body


def test_post_log_wrong_content_type(test_client) -> None:
    """FastAPI requires application/json for body params; other types 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}},
        content_type="text/plain",
    )

    assert status == 400


# ---------------------------------------------------------------------------
# Method handling
# ---------------------------------------------------------------------------


def test_options_log_returns_204(test_client) -> None:
    client, _identity, _log_path = test_client

    resp = client.options("/log")

    assert resp.status_code == 204
    allow = resp.headers.get("allow")
    assert allow is not None
    methods = {m.strip() for m in allow.split(",")}
    # /log is POST-only (no GET); per-route Allow header reflects that.
    assert {"POST", "OPTIONS"}.issubset(methods)


def test_head_log_returns_405(test_client) -> None:
    client, _identity, _log_path = test_client

    resp = client.head("/log")

    assert resp.status_code == 405
    allow = resp.headers.get("allow")
    assert allow is not None
    methods = {m.strip() for m in allow.split(",")}
    assert {"POST", "OPTIONS"}.issubset(methods)


def test_patch_log_returns_405(test_client) -> None:
    client, _identity, _log_path = test_client

    resp = client.patch("/log", content=b"")

    assert resp.status_code == 405
    allow = resp.headers.get("allow")
    assert allow is not None
    methods = {m.strip() for m in allow.split(",")}
    assert {"POST", "OPTIONS"}.issubset(methods)


def test_unknown_path_returns_404(test_client) -> None:
    client, _identity, _log_path = test_client

    get_resp = client.get("/foo")
    assert get_resp.status_code == 404

    post_status, _body, _raw = _post(
        client, "/foo", {"action": "x", "details": {}}
    )
    assert post_status == 404


# ---------------------------------------------------------------------------
# Identity binding
# ---------------------------------------------------------------------------


def test_server_reporter_id_matches_identity_hash(test_client) -> None:
    """The reporter_id stored on the entry must be str(identity.identity_hash)."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": {}}
    )
    assert status == 200

    entries = SignedAppendOnlyLog(identity, log_path).read_entries()
    assert len(entries) == 1
    assert entries[0]["reporter_id"] == str(identity.identity_hash)


# ---------------------------------------------------------------------------
# Host validation
# ---------------------------------------------------------------------------


def test_check_loopback_host_rejects_non_loopback() -> None:
    """``check_loopback_host`` must refuse any non-loopback host."""
    with pytest.raises(ValueError):
        check_loopback_host("0.0.0.0")
    with pytest.raises(ValueError):
        check_loopback_host("192.168.1.1")
    with pytest.raises(ValueError):
        check_loopback_host("example.com")


def test_check_loopback_host_accepts_loopback_aliases() -> None:
    """All three loopback aliases must be accepted by the policy check."""
    for host in ("127.0.0.1", "localhost", "::1"):
        check_loopback_host(host)  # must not raise


# ---------------------------------------------------------------------------
# C3 — subject_id / severity / evidence plumbing
# ---------------------------------------------------------------------------


def _read_one_entry(identity: OpenClawIdentity, log_path: str) -> dict:
    """Read the (single) entry from a fixture's log file."""
    entries = SignedAppendOnlyLog(identity, log_path).read_entries()
    assert len(entries) == 1, f"expected 1 entry, got {len(entries)}"
    return entries[0]


def test_post_log_default_subject_id_matches_reporter_id(test_client) -> None:
    """When no subject_id is supplied, it defaults to the server's identity hash."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "test", "details": {}}
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["subject_id"] == str(identity.identity_hash)
    assert entry["subject_id"] == entry["reporter_id"]


def test_post_log_explicit_subject_id_used(test_client) -> None:
    """An explicit subject_id is recorded verbatim; reporter_id is unchanged."""
    client, identity, log_path = test_client

    explicit_subject = "deadbeef" * 8
    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "test", "details": {}, "subject_id": explicit_subject},
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["subject_id"] == explicit_subject
    # Caller cannot impersonate the signer — reporter_id stays the server's.
    assert entry["reporter_id"] == str(identity.identity_hash)


def test_post_log_default_severity_uses_table_for_known_action(test_client) -> None:
    """Action in the table with severity 0 → entry severity is 0."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "tool_execution_success", "details": {}}
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["severity"] == 0
    assert DEFAULT_SEVERITY_WEIGHTS["tool_execution_success"] == 0


def test_post_log_default_severity_uses_table_for_high_severity_action(
    test_client,
) -> None:
    """Action in the table with severity 10 → entry severity is 10."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "exfiltrate_private_key", "details": {}},
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["severity"] == 10
    assert DEFAULT_SEVERITY_WEIGHTS["exfiltrate_private_key"] == 10


def test_post_log_default_severity_uses_fallback_for_unknown_action(
    test_client,
) -> None:
    """Action not in the table → entry severity is DEFAULT_SEVERITY_FALLBACK."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "random_unrecognised_action_xyz", "details": {}},
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["severity"] == DEFAULT_SEVERITY_FALLBACK


def test_post_log_explicit_severity_overrides_table(test_client) -> None:
    """Explicit non-zero severity overrides the table default."""
    client, identity, log_path = test_client

    # Table would say 0; caller asks for 5.
    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "tool_execution_success", "details": {}, "severity": 5},
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["severity"] == 5


def test_post_log_explicit_severity_zero_preserved(test_client) -> None:
    """Explicit ``severity=0`` must NOT be conflated with "not provided".

    This is the critical test for the None-vs-0 distinction. The table
    would return 10 for ``exfiltrate_private_key``; the caller is forcing
    0 (perhaps because *they* think the action was benign in context).
    The server must honor the explicit 0, not fall through to the table.
    """
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {
            "action": "exfiltrate_private_key",
            "details": {},
            "severity": 0,
        },
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["severity"] == 0


def test_post_log_default_evidence_is_empty(test_client) -> None:
    """Without an explicit evidence field, entry["evidence"] is {}."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(client, "/log", {"action": "x", "details": {}})
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["evidence"] == {}


def test_post_log_explicit_evidence_used(test_client) -> None:
    """An explicit evidence dict is stored verbatim."""
    client, identity, log_path = test_client

    evidence = {"key": "value", "nested": [1, 2]}
    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "evidence": evidence},
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["evidence"] == evidence


def test_post_log_subject_id_not_authenticated(test_client) -> None:
    """Codifies the trust gap: server does NOT verify subject_id."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "subject_id": "somebodyelse"},
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    assert entry["subject_id"] == "somebodyelse"
    # Reporter is still the server itself.
    assert entry["reporter_id"] == str(identity.identity_hash)


def test_post_log_subject_id_must_be_string(test_client) -> None:
    """A non-string subject_id is rejected with 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": {}, "subject_id": 123}
    )

    assert status == 400


def test_post_log_severity_must_be_int(test_client) -> None:
    """A non-int severity is rejected with 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "severity": "high"},
    )

    assert status == 400


def test_post_log_evidence_must_be_dict(test_client) -> None:
    """A non-dict evidence is rejected with 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "evidence": "string"},
    )

    assert status == 400


def test_post_log_subject_id_signed_correctly(test_client) -> None:
    """Explicit subject_id is included in the signed canonical bytes."""
    client, identity, log_path = test_client

    explicit_subject = "00112233445566778899aabbccddeeff" * 2
    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "subject_id": explicit_subject},
    )
    assert status == 200

    log = SignedAppendOnlyLog(identity, log_path)
    ok, errors = log.verify_integrity()
    assert ok, errors
    assert errors == []

    entries = log.read_entries()
    assert len(entries) == 1
    assert entries[0]["subject_id"] == explicit_subject


def test_post_log_severity_signed_correctly(test_client, tmp_path: Path) -> None:
    """Severity is part of the hash chain: tampering breaks verify_integrity."""
    client, identity, log_path = test_client

    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "severity": 7},
    )
    assert status == 200

    log = SignedAppendOnlyLog(identity, log_path)
    ok, errors = log.verify_integrity()
    assert ok, errors

    # Tamper: rewrite the file with severity flipped 7 → 99.
    log_file = Path(log_path)
    raw_text = log_file.read_text(encoding="utf-8")
    lines = raw_text.splitlines()
    assert len(lines) >= 1
    entry = json.loads(lines[-1])
    assert entry["severity"] == 7
    entry["severity"] = 99
    lines[-1] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    log2 = SignedAppendOnlyLog(identity, log_path)
    ok2, errors2 = log2.verify_integrity()
    assert not ok2
    assert errors2  # at least one error must surface


def test_post_log_evidence_signed_correctly(test_client, tmp_path: Path) -> None:
    """Evidence is part of the hash chain: tampering breaks verify_integrity."""
    client, identity, log_path = test_client

    evidence = {"witness": "alice", "tx": "abc123"}
    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "evidence": evidence},
    )
    assert status == 200

    log = SignedAppendOnlyLog(identity, log_path)
    ok, errors = log.verify_integrity()
    assert ok, errors

    # Tamper: replace evidence with a different dict.
    log_file = Path(log_path)
    raw_text = log_file.read_text(encoding="utf-8")
    lines = raw_text.splitlines()
    entry = json.loads(lines[-1])
    assert entry["evidence"] == evidence
    entry["evidence"] = {"witness": "mallory", "tx": "deadbeef"}
    lines[-1] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    log2 = SignedAppendOnlyLog(identity, log_path)
    ok2, errors2 = log2.verify_integrity()
    assert not ok2
    assert errors2


# ---------------------------------------------------------------------------
# C3 review fixes — explicit-null severity, combined fields, subject_id tamper
# ---------------------------------------------------------------------------


def test_post_log_explicit_null_severity_uses_table(test_client) -> None:
    """Literal JSON ``null`` for severity is treated as "not provided"."""
    client, identity, log_path = test_client

    raw_body = b'{"action": "exfiltrate_private_key", "details": {}, "severity": null}'
    status, _body, _resp = _post(client, "/log", raw_body)
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    # Table lookup wins because severity was None, not explicit 0.
    assert entry["severity"] == 10
    assert DEFAULT_SEVERITY_WEIGHTS["exfiltrate_private_key"] == 10


def test_post_log_combined_fields_resolve_independently(test_client) -> None:
    """All optional fields set together must each land on the entry intact."""
    client, identity, log_path = test_client

    explicit_subject = "agent-x" * 8
    status, _body, _raw = _post(
        client,
        "/log",
        {
            "action": "register_seedbox",
            "details": {"seed_id": "vps-1"},
            "subject_id": explicit_subject,
            "severity": 7,
            "evidence": {"forensic": "data"},
        },
    )
    assert status == 200

    entry = _read_one_entry(identity, log_path)
    # subject_id: caller value, not server's identity hash.
    assert entry["subject_id"] == explicit_subject
    # severity: caller value (7), not the table's 0 for register_seedbox.
    assert entry["severity"] == 7
    # evidence: passed through verbatim.
    assert entry["evidence"] == {"forensic": "data"}
    # action + details intact.
    assert entry["action"] == "register_seedbox"
    assert entry["details"] == {"seed_id": "vps-1"}
    # reporter_id is still server-side, never the (different) subject_id.
    assert entry["reporter_id"] == str(identity.identity_hash)


def test_post_log_subject_id_signed_tamper_verify(test_client) -> None:
    """subject_id is part of the signed canonical bytes — tampering breaks verify."""
    client, identity, log_path = test_client

    explicit_subject = "deadbeef" * 8  # 64 hex chars
    status, _body, _raw = _post(
        client,
        "/log",
        {"action": "x", "details": {}, "subject_id": explicit_subject},
    )
    assert status == 200

    log = SignedAppendOnlyLog(identity, log_path)
    ok, errors = log.verify_integrity()
    assert ok, errors

    # Tamper: rewrite subject_id to a different (still well-formed) value.
    log_file = Path(log_path)
    raw_text = log_file.read_text(encoding="utf-8")
    lines = raw_text.splitlines()
    assert len(lines) >= 1
    entry = json.loads(lines[-1])
    assert entry["subject_id"] == explicit_subject
    entry["subject_id"] = "a" * 64
    lines[-1] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    log2 = SignedAppendOnlyLog(identity, log_path)
    ok2, errors2 = log2.verify_integrity()
    assert not ok2
    assert errors2  # at least one error must surface


# ---------------------------------------------------------------------------
# C3 review fixes — input validation: empty subject_id, bool severity, range
# ---------------------------------------------------------------------------


def test_post_log_empty_subject_id_rejected(test_client) -> None:
    """Empty-string subject_id must be rejected with 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": {}, "subject_id": ""}
    )
    assert status == 400


def test_post_log_bool_severity_rejected_true(test_client) -> None:
    """``severity: true`` must be rejected with 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": {}, "severity": True}
    )
    assert status == 400


def test_post_log_bool_severity_rejected_false(test_client) -> None:
    """``severity: false`` must also be rejected with 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": {}, "severity": False}
    )
    assert status == 400


def test_post_log_negative_severity_rejected(test_client) -> None:
    """Severity below 0 is out of the documented 0-10 range and must 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": {}, "severity": -1}
    )
    assert status == 400


def test_post_log_too_high_severity_rejected(test_client) -> None:
    """Severity above 10 is out of the documented 0-10 range and must 400."""
    client, _identity, _log_path = test_client

    status, _body, _raw = _post(
        client, "/log", {"action": "x", "details": {}, "severity": 99}
    )
    assert status == 400
