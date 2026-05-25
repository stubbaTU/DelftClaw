"""TDD red-step tests for ``redteam.integration.peer_transport``.

These tests intentionally fail until two things exist:

* ``redteam.integration.peer_transport.PeerTransport`` (a typing.Protocol
  with ``get_head``, ``get_entries_since``, ``get_identity``).
* ``redteam.integration.peer_transport.HttpPeerTransport`` — a concrete
  ``httpx.AsyncClient``-backed implementation of that protocol.

The transport layer is the dev-mode wire surface for pull sync. The
algorithm tests live in ``test_pull_loop.py``; this file only checks
that the HTTP transport speaks correctly to the existing FastAPI app
(``redteam.integration.server.build_app``) and that transport-level
errors (closed peer, bad URL, timeout) bubble out as ``httpx`` errors
rather than being silently swallowed.

All tests use ``httpx.AsyncClient(transport=httpx.ASGITransport(app=...))``
so the transport's HTTP calls land directly on the in-process app — no
real port, no thread plumbing. The ``peer_url`` passed to each transport
method is the AsyncClient's ``base_url`` (so URL joining lands on the
mounted app).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from identity.openclaw_identity import OpenClawIdentity
from redteam.integration.server import build_app
from redteam.primitives.signed_log import SignedAppendOnlyLog

# This import will fail in the red phase — the module does not exist yet.
from redteam.integration.peer_transport import (  # noqa: E402
    HttpPeerTransport,
    PeerTransport,
)


# ---------------------------------------------------------------------------
# Helpers (mirror the conventions in test_server_layer3.py / test_peer_log.py)
# ---------------------------------------------------------------------------


def _make_identity(
    tmp_path: Path,
    name: str = "server.pem",
    network: str = "MAINNET",
) -> OpenClawIdentity:
    return OpenClawIdentity(network=network, key_path=str(tmp_path / name))


def _make_app(
    tmp_path: Path,
    *,
    name: str = "server.pem",
    network: str = "MAINNET",
) -> tuple[FastAPI, OpenClawIdentity, str, str]:
    """Return ``(app, identity, log_path, peer_log_dir)``."""
    identity = _make_identity(tmp_path, name=name, network=network)
    log_path = str(tmp_path / "server.log")
    peer_log_dir = str(tmp_path / "peer_logs")
    app = build_app(identity, log_path, peer_log_dir)
    return app, identity, log_path, peer_log_dir


def _seed_log(
    log_path: str,
    identity: OpenClawIdentity,
    n: int = 3,
) -> list[dict]:
    wrapper = SignedAppendOnlyLog(identity, log_path)
    out: list[dict] = []
    for i in range(n):
        entry = wrapper.append_event(
            reporter_id=str(identity.identity_hash),
            subject_id=str(identity.identity_hash),
            action=f"seed_{i}",
            details={"i": i},
        )
        out.append(entry)
    return out


def _asgi_client(app: FastAPI) -> httpx.AsyncClient:
    """Build an httpx AsyncClient that dispatches into the ASGI app in-process."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )


# ---------------------------------------------------------------------------
# PeerTransport protocol — structural shape
# ---------------------------------------------------------------------------


def test_peer_transport_is_a_protocol() -> None:
    """``PeerTransport`` must be defined as a ``typing.Protocol`` (or runtime-checkable)."""
    # We don't enforce ``runtime_checkable`` strictly — but the symbol must
    # exist and be a class object that ``HttpPeerTransport`` claims to fit.
    assert isinstance(PeerTransport, type)


def test_http_peer_transport_implements_required_methods() -> None:
    """``HttpPeerTransport`` exposes the three protocol methods."""
    client = httpx.AsyncClient()
    transport = HttpPeerTransport(client, timeout=5.0)
    try:
        for attr in ("get_head", "get_entries_since", "get_identity"):
            assert hasattr(transport, attr), attr
            assert callable(getattr(transport, attr))
    finally:
        # synchronous teardown is fine here — we never made a request.
        pass


# ---------------------------------------------------------------------------
# get_head — happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_head_empty_log_returns_genesis(tmp_path: Path) -> None:
    """An empty log advertises ``GENESIS`` as its head over HTTP."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        head = await transport.get_head("http://test")

    assert head == "GENESIS"


@pytest.mark.asyncio
async def test_get_head_after_seed_returns_latest_hash(tmp_path: Path) -> None:
    """After N appends ``get_head`` returns the latest entry's hash."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=3)

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        head = await transport.get_head("http://test")

    assert head == entries[-1]["entry_hash"]


# ---------------------------------------------------------------------------
# get_entries_since — happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_entries_since_genesis_returns_all_entries(tmp_path: Path) -> None:
    """``since="GENESIS"`` returns every entry plus the current head_hash."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=3)

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        resp = await transport.get_entries_since(
            "http://test", since="GENESIS", limit=100
        )

    assert isinstance(resp, dict)
    assert "entries" in resp
    assert "head_hash" in resp
    assert len(resp["entries"]) == 3
    assert [e["entry_hash"] for e in resp["entries"]] == [
        e["entry_hash"] for e in entries
    ]
    assert resp["head_hash"] == entries[-1]["entry_hash"]


@pytest.mark.asyncio
async def test_get_entries_since_empty_log_returns_empty_entries(
    tmp_path: Path,
) -> None:
    """An empty peer returns ``entries=[]`` and ``head_hash="GENESIS"``."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        resp = await transport.get_entries_since(
            "http://test", since="GENESIS", limit=100
        )

    assert resp["entries"] == []
    assert resp["head_hash"] == "GENESIS"


@pytest.mark.asyncio
async def test_get_entries_since_known_hash_returns_subset_after(
    tmp_path: Path,
) -> None:
    """``since=<hash>`` returns only entries strictly after that hash."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=4)
    cursor = entries[1]["entry_hash"]

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        resp = await transport.get_entries_since(
            "http://test", since=cursor, limit=100
        )

    assert [e["entry_hash"] for e in resp["entries"]] == [
        entries[2]["entry_hash"],
        entries[3]["entry_hash"],
    ]
    assert resp["head_hash"] == entries[-1]["entry_hash"]


@pytest.mark.asyncio
async def test_get_entries_since_respects_limit(tmp_path: Path) -> None:
    """``limit=2`` caps the response to two entries."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    _seed_log(log_path, identity, n=5)

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        resp = await transport.get_entries_since(
            "http://test", since="GENESIS", limit=2
        )

    assert len(resp["entries"]) == 2


# ---------------------------------------------------------------------------
# get_identity — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_identity_returns_identity_hash_and_pubkey(tmp_path: Path) -> None:
    """``get_identity`` returns identity_hash, pubkey_hex, network."""
    app, identity, _log_path, _peer_log_dir = _make_app(tmp_path)

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        ident = await transport.get_identity("http://test")

    assert isinstance(ident, dict)
    assert ident["identity_hash"] == str(identity.identity_hash)
    assert ident["pubkey_hex"] == identity.public_key.hex()
    assert ident["network"] == identity.network


# ---------------------------------------------------------------------------
# Error paths — closed peer / bad URL / unreachable host
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name,extra_args",
    [
        ("get_head", ()),
        ("get_entries_since", ("GENESIS", 10)),
        ("get_identity", ()),
    ],
)
async def test_transport_method_against_unreachable_host_raises(
    method_name: str, extra_args: tuple
) -> None:
    """Each transport method must raise ``httpx.RequestError`` against an
    unreachable host. Pinned across all three methods at once so the
    contract ("don't swallow transport errors") can't regress on a
    single method.

    Uses ``127.0.0.1:1`` (TCP port 1 closed on loopback by convention)
    via a real-network AsyncClient — no ASGI mount.
    """
    async with httpx.AsyncClient(timeout=2.0) as client:
        transport = HttpPeerTransport(client, timeout=2.0)
        method = getattr(transport, method_name)
        with pytest.raises(httpx.RequestError):
            await method("http://127.0.0.1:1", *extra_args)


# ---------------------------------------------------------------------------
# Timeout flag wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timeout_constructor_argument_is_stored(tmp_path: Path) -> None:
    """The ``timeout`` constructor flag is preserved on the transport instance.

    We don't try to *trigger* a timeout (that's flaky in-process); we
    instead pin the value as an attribute so the green phase has a
    durable contract for "timeout is forwarded to httpx requests".
    """
    async with httpx.AsyncClient() as client:
        transport = HttpPeerTransport(client, timeout=3.5)
        # The implementation may store it on ``timeout`` or ``_timeout``;
        # accept either to avoid over-constraining naming.
        attr = getattr(transport, "timeout", None)
        if attr is None:
            attr = getattr(transport, "_timeout", None)
        assert attr == 3.5, (
            "HttpPeerTransport should preserve the timeout argument "
            "as either ``timeout`` or ``_timeout`` for inspection"
        )


# ---------------------------------------------------------------------------
# Round trip with a real foreign-entry-shaped response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_entries_since_rejects_oversized_batch() -> None:
    """A peer that ignores ``limit`` and returns >10x is refused.

    Defends against a hostile / buggy peer streaming an unbounded
    entries list into receiver memory. Cap is ``limit * 10``; one
    entry over the cap raises ``ValueError`` (which the pull-loop
    catches the same way as transport errors → log + skip-cycle).
    """
    requested_limit = 5
    cap = requested_limit * 10  # 50
    oversized_count = cap + 1   # 51 → must reject

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "entries": [{"entry_hash": f"hash_{i}"} for i in range(oversized_count)],
                "head_hash": f"hash_{oversized_count - 1}",
            },
        )

    inner = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=inner) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        with pytest.raises(ValueError, match=r"oversized batch"):
            await transport.get_entries_since(
                "http://peer", since="GENESIS", limit=requested_limit
            )


@pytest.mark.asyncio
async def test_get_entries_since_at_cap_is_accepted() -> None:
    """Exactly ``limit * 10`` entries is allowed (boundary stays inclusive).

    Pin the off-by-one: if a green-phase tweak changes ``>`` to ``>=``
    (or vice versa) the test surfaces it.
    """
    requested_limit = 5
    cap = requested_limit * 10  # 50

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "entries": [{"entry_hash": f"hash_{i}"} for i in range(cap)],
                "head_hash": f"hash_{cap - 1}",
            },
        )

    inner = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=inner) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        resp = await transport.get_entries_since(
            "http://peer", since="GENESIS", limit=requested_limit
        )
    assert len(resp["entries"]) == cap


@pytest.mark.asyncio
async def test_get_entries_since_returns_entry_dicts_acceptable_to_peer_log(
    tmp_path: Path,
) -> None:
    """Entries returned by the transport are full dicts (not just hashes).

    A full integration round trip — feed a returned entry into PeerLog and
    confirm it accepts. This pins the wire shape against the existing
    primitives so a green-phase change to ``/entries``'s response shape
    can't silently regress the algorithm.
    """
    from redteam.primitives.peer_log import PeerLog

    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=2)

    async with _asgi_client(app) as client:
        transport = HttpPeerTransport(client, timeout=5.0)
        resp = await transport.get_entries_since(
            "http://test", since="GENESIS", limit=100
        )

    assert len(resp["entries"]) == 2

    # Build a brand-new receiver with a different identity, then accept the
    # transport-returned entries. They must verify.
    own = _make_identity(tmp_path, name="receiver.pem")
    peer_log_dir = tmp_path / "peer_logs_receiver"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.identity_hash),
    )

    for entry in resp["entries"]:
        stored, source_id, errors, duplicate = peer_log.accept_entry(entry)
        assert stored is True, errors
        assert duplicate is False
        assert source_id == str(identity.identity_hash)

    # And both ended up under the right per-source file.
    expected_file = peer_log_dir / f"{identity.identity_hash}.jsonl"
    assert expected_file.exists()
    text = expected_file.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln]
    assert len(lines) == 2
    assert {e["entry_hash"] for e in entries} == {
        # parsed from the per-source file
        __import__("json").loads(ln)["entry_hash"]
        for ln in lines
    }
