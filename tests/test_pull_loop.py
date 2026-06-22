"""TDD red-step tests for ``signed_log.integration.pull_loop``.

These tests intentionally fail until two functions exist:

* ``pull_once(transport, peer_url, peer_log, last_known_hash, batch)``
  — single-shot algorithm; verifies / appends; returns
  ``(new_last_known_hash, appended_count, rejection_log)``.
* ``run_pull_loop(transport, peer_urls, peer_log, interval, batch,
  stop_event, initial_state=None)`` — the driver task that calls
  ``pull_once`` per peer per interval until ``stop_event.set()``.

The algorithm must be transport-agnostic — only ``PeerTransport`` is
touched. We test this with a hand-coded ``MockPeerTransport`` (no
``unittest.mock`` magic) that records every call (peer_url, since,
limit) and returns programmable responses. One small integration test
at the bottom uses ``HttpPeerTransport`` against an ASGI-mounted FastAPI
app via ``build_app(peers=[...])`` to confirm end-to-end convergence.

Algorithm decisions locked in here (per the design plan):

1. No-op when peer head unchanged — ``get_entries_since`` is NOT called.
2. First-time pull uses ``since="GENESIS"``.
3. Reject-and-stop on first verification failure within a batch — the
   loop does NOT keep iterating past a rejected entry.
4. Idempotent re-runs append zero entries.
5. Per-peer state (last_known_hash) advances across iterations.
6. ``initial_state`` seeds the per-peer cursor so first-iteration ``since``
   is the seeded value, not GENESIS.
7. One peer raising does NOT break the loop for other peers.
8. ``stop_event.set()`` causes a clean exit within ~one interval.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from identity.openclaw_identity import OpenClawIdentity
from signed_log.primitives.peer_log import PeerLog
from signed_log.primitives.signed_log import SignedAppendOnlyLog

# These imports will fail in the red phase — the modules / symbols don't
# exist yet. That's expected.
from signed_log.integration.pull_loop import (  # noqa: E402
    pull_once,
    run_pull_loop,
)


# ---------------------------------------------------------------------------
# Mock transport — explicit, hand-coded, records every call.
# ---------------------------------------------------------------------------


class MockPeerTransport:
    """A hand-coded PeerTransport that records calls and returns programmable
    responses.

    Avoids ``unittest.mock`` to stay readable and easy to reason about.
    Each call appends a tuple to ``self.calls``:

      * ``("get_head", peer_url)``
      * ``("get_entries_since", peer_url, since, limit)``
      * ``("get_identity", peer_url)``

    Programmable behavior:

      * ``heads[peer_url]`` — head hash to return on ``get_head``.
      * ``entries_responses[peer_url]`` — a list of dicts to return one-by-one
        on each ``get_entries_since`` call (FIFO; mutates as it pops).
        Falls back to ``default_entries_response`` once exhausted.
      * ``identities[peer_url]`` — identity dict to return on ``get_identity``.
      * ``raise_on[(method, peer_url)]`` — exception to raise instead of
        returning normally.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.heads: dict[str, str] = {}
        self.entries_responses: dict[str, list[dict]] = {}
        self.default_entries_response: dict = {
            "entries": [],
            "head_hash": "GENESIS",
        }
        self.identities: dict[str, dict] = {}
        self.raise_on: dict[tuple[str, str], BaseException] = {}

    async def get_head(self, peer_url: str) -> str:
        self.calls.append(("get_head", peer_url))
        if ("get_head", peer_url) in self.raise_on:
            raise self.raise_on[("get_head", peer_url)]
        return self.heads.get(peer_url, "GENESIS")

    async def get_entries_since(
        self, peer_url: str, since: str, limit: int
    ) -> dict:
        self.calls.append(("get_entries_since", peer_url, since, limit))
        if ("get_entries_since", peer_url) in self.raise_on:
            raise self.raise_on[("get_entries_since", peer_url)]
        bucket = self.entries_responses.get(peer_url, [])
        if bucket:
            return bucket.pop(0)
        return dict(self.default_entries_response)

    async def get_identity(self, peer_url: str) -> dict:
        self.calls.append(("get_identity", peer_url))
        if ("get_identity", peer_url) in self.raise_on:
            raise self.raise_on[("get_identity", peer_url)]
        return self.identities.get(
            peer_url,
            {"identity_hash": "0" * 64, "pubkey_hex": "00" * 32, "network": "MAINNET"},
        )


# ---------------------------------------------------------------------------
# Helpers — identity + entry construction
# ---------------------------------------------------------------------------


def _make_identity(
    tmp_path: Path,
    name: str = "key.pem",
    network: str = "MAINNET",
) -> OpenClawIdentity:
    return OpenClawIdentity(network=network, key_path=str(tmp_path / name))


def _foreign_entries(
    tmp_path: Path,
    *,
    name: str = "foreign.pem",
    n: int = 3,
    network: str = "MAINNET",
) -> tuple[OpenClawIdentity, list[dict]]:
    """Build a foreign identity + write ``n`` self entries; return the entries."""
    identity = _make_identity(tmp_path, name, network=network)
    log_path = str(tmp_path / f"{name}.log")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    out: list[dict] = []
    for i in range(n):
        entry = wrapper.append_event(
            reporter_id=str(identity.identity_hash),
            subject_id=str(identity.identity_hash),
            action=f"act_{i}",
            details={"i": i},
        )
        out.append(entry)
    return identity, out


def _new_peer_log(tmp_path: Path, *, dirname: str = "peer_logs") -> PeerLog:
    own = _make_identity(tmp_path, "receiver.pem")
    peer_log = PeerLog(
        str(tmp_path / dirname),
        network="MAINNET",
        own_id=str(own.identity_hash),
    )
    return peer_log


# ---------------------------------------------------------------------------
# pull_once — empty peer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_empty_peer_no_writes(tmp_path: Path) -> None:
    """Empty peer (head=GENESIS, entries=[]) → (GENESIS, 0, []), no writes."""
    transport = MockPeerTransport()
    transport.heads["http://peer"] = "GENESIS"
    transport.entries_responses["http://peer"] = [
        {"entries": [], "head_hash": "GENESIS"}
    ]
    peer_log = _new_peer_log(tmp_path)

    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=100,
    )

    assert new_last == "GENESIS"
    assert appended == 0
    assert rejections == []
    # No entries on disk.
    assert peer_log.list_sources() == []


# ---------------------------------------------------------------------------
# pull_once — fresh peer, all entries valid
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_fresh_peer_appends_all_entries(tmp_path: Path) -> None:
    """First-time pull from a peer with N valid entries appends all of them.

    Locks in algorithm decision #2: first-time pull uses ``since="GENESIS"``.
    """
    foreign_identity, entries = _foreign_entries(tmp_path, n=3)
    transport = MockPeerTransport()
    last_hash = entries[-1]["entry_hash"]
    transport.heads["http://peer"] = last_hash
    transport.entries_responses["http://peer"] = [
        {"entries": entries, "head_hash": last_hash}
    ]

    peer_log = _new_peer_log(tmp_path)
    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=100,
    )

    assert appended == 3
    assert rejections == []
    assert new_last == last_hash

    # And ``get_entries_since`` was called with ``since="GENESIS"``.
    entries_calls = [c for c in transport.calls if c[0] == "get_entries_since"]
    assert len(entries_calls) == 1
    _, _peer_url, since, _limit = entries_calls[0]
    assert since == "GENESIS"

    # And on disk: one per-source file with three lines.
    source_id = str(foreign_identity.identity_hash)
    assert peer_log.list_sources() == [source_id]
    out = peer_log.read_entries_for(source_id)
    assert [e["entry_hash"] for e in out] == [e["entry_hash"] for e in entries]


# ---------------------------------------------------------------------------
# pull_once — peer head unchanged → no-op (no /entries call)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_head_unchanged_skips_entries_call(tmp_path: Path) -> None:
    """If peer head == last_known_hash (and not GENESIS), don't issue /entries.

    Locks in algorithm decision #1: cheap no-op when nothing changed.
    The mock transport records calls; we assert ``get_entries_since`` was
    NEVER called.
    """
    transport = MockPeerTransport()
    head = "a" * 64
    transport.heads["http://peer"] = head
    # Even if entries response is set, it must NOT be consumed.
    transport.entries_responses["http://peer"] = [
        {"entries": [{"oops": "should_not_be_returned"}], "head_hash": head}
    ]

    peer_log = _new_peer_log(tmp_path)
    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=head,
        batch=100,
    )

    assert new_last == head
    assert appended == 0
    assert rejections == []

    # get_head was called, get_entries_since was NOT.
    methods = [c[0] for c in transport.calls]
    assert "get_head" in methods
    assert "get_entries_since" not in methods


# ---------------------------------------------------------------------------
# pull_once — reject-and-stop on first invalid entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_reject_and_stop_on_first_invalid_entry(
    tmp_path: Path,
) -> None:
    """Algorithm decision #3 — reject-and-stop.

    Two valid entries, one tampered entry in the middle, then one more
    valid entry. The loop must:

      * accept entries[0]
      * reject entries[1] (record errors, do NOT advance last_known beyond
        the last successfully-stored hash)
      * NOT touch entries[2]/entries[3]
      * Return ``new_last_known_hash == entries[0]["entry_hash"]``
        (so the next call retries from there).

    The error fragment for the verifier is checked specifically — vague
    "errors not empty" doesn't catch a regression where the wrong check
    fires.
    """
    foreign_identity, entries = _foreign_entries(tmp_path, n=4)

    # Tamper with entries[1]'s entry_hash so verify_foreign_entry rejects
    # with "entry_hash mismatch" specifically.
    tampered = dict(entries[1])
    h = tampered["entry_hash"]
    tampered["entry_hash"] = ("1" if h[0] == "0" else "0") + h[1:]

    served = [entries[0], tampered, entries[2], entries[3]]
    transport = MockPeerTransport()
    last_hash = entries[-1]["entry_hash"]
    transport.heads["http://peer"] = last_hash
    transport.entries_responses["http://peer"] = [
        {"entries": served, "head_hash": last_hash}
    ]

    peer_log = _new_peer_log(tmp_path)
    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=100,
    )

    # Exactly one stored — entries[0]. entries[1] tampered, [2] and [3] not
    # processed because we stopped.
    assert appended == 1
    # last_known advanced to the last-successfully-stored entry, NOT the
    # served head, NOT the tampered hash.
    assert new_last == entries[0]["entry_hash"]

    # Rejection log — exactly one rejection, and the error message must
    # mention entry_hash (the specific check that fires for this tamper).
    assert len(rejections) == 1
    rejected_hash, errs = rejections[0]
    assert rejected_hash == tampered["entry_hash"]
    assert any("entry_hash" in err for err in errs), errs

    # On-disk: only entries[0] is present.
    source_id = str(foreign_identity.identity_hash)
    stored_entries = peer_log.read_entries_for(source_id)
    assert len(stored_entries) == 1
    assert stored_entries[0]["entry_hash"] == entries[0]["entry_hash"]


# ---------------------------------------------------------------------------
# pull_once — bad-signature rejection surfaces the signature error string
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_signature_failure_surfaces_signature_error(
    tmp_path: Path,
) -> None:
    """Stamp a wrong-signature entry — error fragment must mention signature."""
    foreign_identity, entries = _foreign_entries(tmp_path, n=2)

    # Sign-then-rehash: entry_hash is computed over (entry minus signature
    # minus entry_hash), so we tamper with signature first, then recompute
    # entry_hash so the *only* failure surfaced is the signature one.
    import hashlib

    tampered = dict(entries[0])
    tampered["signature"] = "00" * 64
    hashable = dict(tampered)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    tampered["entry_hash"] = hashlib.sha256(
        json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    transport = MockPeerTransport()
    last_hash = entries[-1]["entry_hash"]
    transport.heads["http://peer"] = last_hash
    transport.entries_responses["http://peer"] = [
        {"entries": [tampered, entries[1]], "head_hash": last_hash}
    ]

    peer_log = _new_peer_log(tmp_path)
    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=100,
    )

    assert appended == 0
    # last_known did NOT advance (no successful stores at all).
    # Per algorithm decision #3, on first-rejection-no-prior-store we keep
    # the input cursor unchanged.
    assert new_last is None or new_last == "GENESIS"

    assert len(rejections) == 1
    _, errs = rejections[0]
    assert any("signature" in err.lower() for err in errs), errs


# ---------------------------------------------------------------------------
# pull_once — partial batch (returned < limit)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_partial_batch_returns_last_entry_hash(
    tmp_path: Path,
) -> None:
    """``limit=10`` but only 3 entries returned → all 3 stored, new_last is
    the last entry's hash (NOT the served peer head if they differ)."""
    foreign_identity, entries = _foreign_entries(tmp_path, n=3)
    transport = MockPeerTransport()
    last_hash = entries[-1]["entry_hash"]
    transport.heads["http://peer"] = last_hash
    transport.entries_responses["http://peer"] = [
        {"entries": entries, "head_hash": last_hash}
    ]

    peer_log = _new_peer_log(tmp_path)
    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=10,  # limit > entries returned
    )

    assert appended == 3
    assert rejections == []
    assert new_last == entries[-1]["entry_hash"]


# ---------------------------------------------------------------------------
# pull_once — idempotent re-run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_idempotent_second_call_zero_appends(tmp_path: Path) -> None:
    """Algorithm decision #4 — re-running ``pull_once`` after success appends 0.

    First call stores 3 entries. Second call (peer head unchanged) returns
    (head, 0, []) without even hitting the entries endpoint.
    """
    foreign_identity, entries = _foreign_entries(tmp_path, n=3)
    transport = MockPeerTransport()
    last_hash = entries[-1]["entry_hash"]
    transport.heads["http://peer"] = last_hash
    transport.entries_responses["http://peer"] = [
        {"entries": entries, "head_hash": last_hash},
        # Second call shouldn't pop this — included as a guard so a
        # regression surfaces by serving the wrong dataset.
        {"entries": list(entries), "head_hash": last_hash},
    ]

    peer_log = _new_peer_log(tmp_path)

    new_last_1, appended_1, _r1 = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=100,
    )
    assert appended_1 == 3
    assert new_last_1 == last_hash

    new_last_2, appended_2, rejections_2 = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=new_last_1,
        batch=100,
    )
    # Idempotent — head unchanged, nothing pulled, nothing rejected.
    assert new_last_2 == last_hash
    assert appended_2 == 0
    assert rejections_2 == []

    # Second call must NOT have re-issued get_entries_since (head unchanged).
    second_call_methods = [c[0] for c in transport.calls[2:]]
    assert "get_entries_since" not in second_call_methods


# ---------------------------------------------------------------------------
# pull_once — duplicate entry advances cursor (doesn't trigger reject-and-stop)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_duplicate_then_new_advances_past_duplicate(
    tmp_path: Path,
) -> None:
    """Duplicates are NOT rejections — cursor advances past them so later
    new entries in the same batch still get appended.

    Pin: a regression that lumps duplicates into the reject-and-stop path
    would silently break re-sync after a partial earlier sync (the next
    pull would always halt on the first re-served entry).
    """
    foreign_identity, entries = _foreign_entries(tmp_path, n=3)
    peer_log = _new_peer_log(tmp_path)

    # Simulate an earlier partial sync: entries[0] is already in PeerLog.
    stored_pre, _, errs_pre, dup_pre = peer_log.accept_entry(entries[0])
    assert stored_pre is True
    assert errs_pre == []
    assert dup_pre is False

    # Mock peer serves all three entries (including the already-stored one).
    last_hash = entries[-1]["entry_hash"]
    transport = MockPeerTransport()
    transport.heads["http://peer"] = last_hash
    transport.entries_responses["http://peer"] = [
        {"entries": entries, "head_hash": last_hash}
    ]

    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=100,
    )

    # entries[1] and entries[2] are newly stored; the duplicate is NOT
    # counted as an append, but it is also NOT counted as a rejection —
    # the loop must keep processing.
    assert appended == 2
    assert rejections == []
    # Cursor advances all the way to the last entry, NOT stuck at the dup.
    assert new_last == last_hash
    # All three entries persisted in source-order.
    on_disk = peer_log.read_entries_for(str(foreign_identity.identity_hash))
    assert [e["entry_hash"] for e in on_disk] == [
        e["entry_hash"] for e in entries
    ]


# ---------------------------------------------------------------------------
# pull_once — transport raises → exception bubbles
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_transport_get_head_raises_propagates(tmp_path: Path) -> None:
    """If transport.get_head raises, ``pull_once`` does NOT swallow it."""
    transport = MockPeerTransport()
    transport.raise_on[("get_head", "http://peer")] = httpx.ConnectError(
        "boom — peer down"
    )
    peer_log = _new_peer_log(tmp_path)

    with pytest.raises(httpx.RequestError):
        await pull_once(
            transport=transport,
            peer_url="http://peer",
            peer_log=peer_log,
            last_known_hash=None,
            batch=100,
        )


@pytest.mark.asyncio
async def test_pull_once_transport_get_entries_raises_propagates(
    tmp_path: Path,
) -> None:
    """If transport.get_entries_since raises, ``pull_once`` does NOT swallow it."""
    transport = MockPeerTransport()
    transport.heads["http://peer"] = "f" * 64  # different from last_known
    transport.raise_on[("get_entries_since", "http://peer")] = httpx.ReadTimeout(
        "slow"
    )
    peer_log = _new_peer_log(tmp_path)

    with pytest.raises(httpx.RequestError):
        await pull_once(
            transport=transport,
            peer_url="http://peer",
            peer_log=peer_log,
            last_known_hash=None,
            batch=100,
        )


# ---------------------------------------------------------------------------
# pull_once — same-identity guard observed via PeerLog.accept_entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_once_same_identity_entry_counted_as_rejection(
    tmp_path: Path,
) -> None:
    """If the peer returns an entry whose reporter_id == own_id, PeerLog
    rejects it (same-identity guard). The loop must observe that rejection
    and NOT count it as appended."""
    own = _make_identity(tmp_path, "own.pem")
    own_log_path = str(tmp_path / "own.log")
    wrapper = SignedAppendOnlyLog(own, own_log_path)
    own_entry = wrapper.append_event(
        reporter_id=str(own.identity_hash),
        subject_id=str(own.identity_hash),
        action="self_loop",
        details={"a": 1},
    )

    transport = MockPeerTransport()
    transport.heads["http://peer"] = own_entry["entry_hash"]
    transport.entries_responses["http://peer"] = [
        {"entries": [own_entry], "head_hash": own_entry["entry_hash"]}
    ]

    # PeerLog with own_id set — should reject the foreign-shaped own entry.
    peer_log = PeerLog(
        str(tmp_path / "peer_logs"),
        network="MAINNET",
        own_id=str(own.identity_hash),
    )

    new_last, appended, rejections = await pull_once(
        transport=transport,
        peer_url="http://peer",
        peer_log=peer_log,
        last_known_hash=None,
        batch=100,
    )

    assert appended == 0
    assert len(rejections) == 1
    # Source file must NOT exist (rejected entries don't write).
    assert peer_log.list_sources() == []


# ---------------------------------------------------------------------------
# run_pull_loop — two healthy peers, both populated within one interval
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_pull_loop_two_healthy_peers_both_synced(tmp_path: Path) -> None:
    """Both peers contribute entries inside one interval; loop exits cleanly
    via stop_event.set()."""
    id1, entries1 = _foreign_entries(tmp_path, name="p1.pem", n=2)
    id2, entries2 = _foreign_entries(tmp_path, name="p2.pem", n=3)

    transport = MockPeerTransport()
    transport.heads["http://p1"] = entries1[-1]["entry_hash"]
    transport.heads["http://p2"] = entries2[-1]["entry_hash"]
    transport.entries_responses["http://p1"] = [
        {"entries": entries1, "head_hash": entries1[-1]["entry_hash"]}
    ]
    transport.entries_responses["http://p2"] = [
        {"entries": entries2, "head_hash": entries2[-1]["entry_hash"]}
    ]

    peer_log = _new_peer_log(tmp_path)
    stop_event = asyncio.Event()

    async def _stopper() -> None:
        # Wait long enough for at least one full iteration of both peers.
        await asyncio.sleep(0.2)
        stop_event.set()

    loop_task = asyncio.create_task(
        run_pull_loop(
            transport=transport,
            peer_urls=["http://p1", "http://p2"],
            peer_log=peer_log,
            interval=0.05,
            batch=100,
            stop_event=stop_event,
        )
    )
    stopper = asyncio.create_task(_stopper())

    await asyncio.wait_for(asyncio.gather(loop_task, stopper), timeout=2.0)

    # Both peers' entries on disk.
    sources = set(peer_log.list_sources())
    assert sources == {str(id1.identity_hash), str(id2.identity_hash)}
    out1 = peer_log.read_entries_for(str(id1.identity_hash))
    out2 = peer_log.read_entries_for(str(id2.identity_hash))
    assert [e["entry_hash"] for e in out1] == [e["entry_hash"] for e in entries1]
    assert [e["entry_hash"] for e in out2] == [e["entry_hash"] for e in entries2]


# ---------------------------------------------------------------------------
# run_pull_loop — one peer raises, other healthy — healthy still synced
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_pull_loop_one_peer_raises_other_still_synced(
    tmp_path: Path,
) -> None:
    """A peer raising at the transport layer must not break the loop for others.

    Peer p1 raises on get_head every time. Peer p2 is healthy and serves
    entries. Within one interval the healthy peer's entries land in PeerLog,
    and the loop is still running (no exception escaped).
    """
    id2, entries2 = _foreign_entries(tmp_path, name="p2.pem", n=2)

    transport = MockPeerTransport()
    transport.raise_on[("get_head", "http://p1")] = httpx.ConnectError("p1 down")
    transport.heads["http://p2"] = entries2[-1]["entry_hash"]
    transport.entries_responses["http://p2"] = [
        {"entries": entries2, "head_hash": entries2[-1]["entry_hash"]}
    ]

    peer_log = _new_peer_log(tmp_path)
    stop_event = asyncio.Event()

    async def _stopper() -> None:
        await asyncio.sleep(0.25)
        stop_event.set()

    loop_task = asyncio.create_task(
        run_pull_loop(
            transport=transport,
            peer_urls=["http://p1", "http://p2"],
            peer_log=peer_log,
            interval=0.05,
            batch=100,
            stop_event=stop_event,
        )
    )
    stopper = asyncio.create_task(_stopper())

    # The loop must not raise — gather will surface any exception that
    # escaped run_pull_loop.
    await asyncio.wait_for(asyncio.gather(loop_task, stopper), timeout=2.0)

    # Healthy peer's entries are present on disk.
    sources = set(peer_log.list_sources())
    assert str(id2.identity_hash) in sources
    out2 = peer_log.read_entries_for(str(id2.identity_hash))
    assert [e["entry_hash"] for e in out2] == [e["entry_hash"] for e in entries2]


# ---------------------------------------------------------------------------
# run_pull_loop — stop_event triggers clean exit within ~one interval
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_pull_loop_stop_event_exits_cleanly(tmp_path: Path) -> None:
    """``stop_event.set()`` causes the loop to exit within ~one interval."""
    transport = MockPeerTransport()
    transport.heads["http://p"] = "GENESIS"
    transport.entries_responses["http://p"] = [
        {"entries": [], "head_hash": "GENESIS"}
    ]

    peer_log = _new_peer_log(tmp_path)
    stop_event = asyncio.Event()

    interval = 0.05
    loop_task = asyncio.create_task(
        run_pull_loop(
            transport=transport,
            peer_urls=["http://p"],
            peer_log=peer_log,
            interval=interval,
            batch=10,
            stop_event=stop_event,
        )
    )

    # Let one iteration kick off, then signal stop.
    await asyncio.sleep(interval * 2)
    stop_event.set()

    # Should exit within ~one interval. Be generous (1.0s) to avoid CI
    # flake but tight enough that a hung loop fails the assertion.
    await asyncio.wait_for(loop_task, timeout=1.0)
    assert loop_task.done()
    # And the task did not raise — ``await`` would have re-raised any error.


# ---------------------------------------------------------------------------
# run_pull_loop — per-peer state advances across iterations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_pull_loop_per_peer_state_advances(tmp_path: Path) -> None:
    """Across iterations, ``since`` for each peer advances to the last
    successfully-stored entry's hash.

    First batch returns entries[0:2]; second batch returns entries[2:4].
    The mock records every ``get_entries_since`` call; the second call's
    ``since`` must equal entries[1]["entry_hash"], not GENESIS.
    """
    foreign_identity, entries = _foreign_entries(tmp_path, n=4)

    transport = MockPeerTransport()
    # Heads advance: first only entries[1] is the head; then entries[3].
    # We model this by serving two responses in sequence and updating heads
    # via the ``heads`` dict between iterations using a small wrapper —
    # easiest: head always reports the *current chain tip* the peer has,
    # and after iteration 1 has consumed entries[0:2], iteration 2 must
    # see a different head than what we already stored.
    #
    # We sidestep that bookkeeping by keeping head fixed at entries[3]
    # throughout. The loop will then call get_entries_since twice with
    # different ``since`` values: GENESIS first, then entries[1]'s hash.
    transport.heads["http://peer"] = entries[-1]["entry_hash"]
    transport.entries_responses["http://peer"] = [
        # First iteration: serve entries[0:2].
        {"entries": entries[0:2], "head_hash": entries[-1]["entry_hash"]},
        # Second iteration: serve entries[2:4].
        {"entries": entries[2:4], "head_hash": entries[-1]["entry_hash"]},
        # Subsequent iterations: empty (so the test doesn't hang trying
        # to consume more from the bucket).
    ]

    peer_log = _new_peer_log(tmp_path)
    stop_event = asyncio.Event()

    async def _stopper() -> None:
        # Wait for at least two iterations.
        await asyncio.sleep(0.3)
        stop_event.set()

    loop_task = asyncio.create_task(
        run_pull_loop(
            transport=transport,
            peer_urls=["http://peer"],
            peer_log=peer_log,
            interval=0.05,
            batch=100,
            stop_event=stop_event,
        )
    )
    stopper = asyncio.create_task(_stopper())

    await asyncio.wait_for(asyncio.gather(loop_task, stopper), timeout=2.0)

    # Walk the recorded calls and find the first two get_entries_since calls.
    entries_calls = [c for c in transport.calls if c[0] == "get_entries_since"]
    assert len(entries_calls) >= 2, transport.calls

    # First call: since == "GENESIS"
    _, _, since_1, _ = entries_calls[0]
    assert since_1 == "GENESIS"

    # Second call: since == hash of last successfully-stored entry from first
    # batch — entries[1]'s entry_hash.
    _, _, since_2, _ = entries_calls[1]
    assert since_2 == entries[1]["entry_hash"]

    # All four entries on disk.
    out = peer_log.read_entries_for(str(foreign_identity.identity_hash))
    assert [e["entry_hash"] for e in out] == [e["entry_hash"] for e in entries]


# ---------------------------------------------------------------------------
# run_pull_loop — initial_state seeded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_pull_loop_initial_state_seeds_since(tmp_path: Path) -> None:
    """An ``initial_state`` mapping seeds the first-iteration ``since`` for
    each peer instead of using GENESIS."""
    seeded_hash = "deadbeef" * 8  # 64 hex chars

    transport = MockPeerTransport()
    # Head is different from seeded_hash so the loop will issue
    # get_entries_since on iteration 1.
    transport.heads["http://peer"] = "1" * 64
    transport.entries_responses["http://peer"] = [
        {"entries": [], "head_hash": "1" * 64}
    ]

    peer_log = _new_peer_log(tmp_path)
    stop_event = asyncio.Event()

    async def _stopper() -> None:
        await asyncio.sleep(0.15)
        stop_event.set()

    loop_task = asyncio.create_task(
        run_pull_loop(
            transport=transport,
            peer_urls=["http://peer"],
            peer_log=peer_log,
            interval=0.05,
            batch=100,
            stop_event=stop_event,
            initial_state={"http://peer": seeded_hash},
        )
    )
    stopper = asyncio.create_task(_stopper())

    await asyncio.wait_for(asyncio.gather(loop_task, stopper), timeout=2.0)

    entries_calls = [c for c in transport.calls if c[0] == "get_entries_since"]
    assert entries_calls, "expected at least one get_entries_since call"
    _, _peer_url, since_1, _ = entries_calls[0]
    assert since_1 == seeded_hash, (
        f"first iteration should use seeded since, got {since_1!r}"
    )


# ---------------------------------------------------------------------------
# run_pull_loop — exits even with no peers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_pull_loop_empty_peer_list_exits_on_stop(tmp_path: Path) -> None:
    """An empty peer list still respects stop_event (degenerate but correct)."""
    transport = MockPeerTransport()
    peer_log = _new_peer_log(tmp_path)
    stop_event = asyncio.Event()

    loop_task = asyncio.create_task(
        run_pull_loop(
            transport=transport,
            peer_urls=[],
            peer_log=peer_log,
            interval=0.05,
            batch=10,
            stop_event=stop_event,
        )
    )
    await asyncio.sleep(0.1)
    stop_event.set()
    await asyncio.wait_for(loop_task, timeout=1.0)
    assert loop_task.done()


# ---------------------------------------------------------------------------
# Integration — server.build_app(peers=[...]) end-to-end one-cycle convergence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_build_app_with_peers_pulls_alice_into_bobs_peer_log(
    tmp_path: Path,
) -> None:
    """End-to-end: alice writes self entries; bob has alice in ``peers``;
    bob's PeerLog ends up with alice's entries inside one interval.

    Uses ``HttpPeerTransport`` against ASGI-mounted alice via a
    transport-factory injection on bob. This exercises the full stack:
    build_app accepting ``peers``/``pull_interval``/``pull_batch``, the
    lifespan handler spawning ``run_pull_loop``, and the algorithm storing
    pulled entries in PeerLog.
    """
    from signed_log.integration.peer_transport import HttpPeerTransport
    from signed_log.integration.server import build_app

    # Alice (the source). Use the existing ``build_app`` plus a seeded log.
    alice_id = _make_identity(tmp_path, "alice.pem")
    alice_log = str(tmp_path / "alice.log")
    alice_peer_log_dir = str(tmp_path / "alice_peer_logs")
    alice_app = build_app(alice_id, alice_log, alice_peer_log_dir)

    # Seed alice's chain.
    wrapper = SignedAppendOnlyLog(alice_id, alice_log)
    seed: list[dict] = []
    for i in range(3):
        seed.append(
            wrapper.append_event(
                reporter_id=str(alice_id.identity_hash),
                subject_id=str(alice_id.identity_hash),
                action=f"alice_act_{i}",
                details={"i": i},
            )
        )

    # The transport-factory must use an ASGI client mounted on alice's app
    # so HTTP traffic doesn't actually hit the network.
    alice_url = "http://alice"
    alice_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=alice_app),
        base_url=alice_url,
    )

    def _factory() -> tuple[Any, HttpPeerTransport]:
        # Returns (cleanup_handle, transport). Green phase decides the
        # exact factory contract — this test only requires that build_app
        # accepts a kwarg named ``transport_factory`` (or similar) that
        # defers transport construction to the lifespan handler.
        return (alice_client, HttpPeerTransport(alice_client, timeout=5.0))

    # Bob — receives alice's entries via pull.
    bob_id = _make_identity(tmp_path, "bob.pem")
    bob_log = str(tmp_path / "bob.log")
    bob_peer_log_dir = str(tmp_path / "bob_peer_logs")

    bob_app = build_app(
        bob_id,
        bob_log,
        bob_peer_log_dir,
        peers=[alice_url],
        pull_interval=0.05,
        pull_batch=100,
        transport_factory=_factory,
    )

    # ASGI test transports don't dispatch the lifespan protocol, so
    # call the explicit start/stop hooks the server exposes on
    # ``app.state``. (Production code path under uvicorn drives the
    # same coroutines via lifespan.)
    await bob_app.state.start_pull_loop()
    try:
        # Wait long enough for at least one pull cycle to land alice's entries.
        deadline = asyncio.get_event_loop().time() + 2.0
        expected = Path(bob_peer_log_dir) / f"{alice_id.identity_hash}.jsonl"
        while asyncio.get_event_loop().time() < deadline:
            if expected.exists():
                text = expected.read_text(encoding="utf-8")
                lines = [ln for ln in text.splitlines() if ln]
                if len(lines) >= len(seed):
                    break
            await asyncio.sleep(0.05)
        else:
            pytest.fail(
                "alice's entries did not appear in bob's peer_log within 2s"
            )

        # Verify the expected entries landed.
        text = expected.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln]
        parsed = [json.loads(ln) for ln in lines]
        assert {p["entry_hash"] for p in parsed} == {
            e["entry_hash"] for e in seed
        }
    finally:
        await bob_app.state.stop_pull_loop()
        await alice_client.aclose()


# ---------------------------------------------------------------------------
# build_app — peer URL scheme validation
# ---------------------------------------------------------------------------


def test_build_app_rejects_non_http_peer_url(tmp_path: Path) -> None:
    """``build_app`` must reject peer URLs that don't use http(s) scheme.

    Defence-in-depth: ``main()``'s argparse layer also rejects bad
    schemes, but a programmatic caller of ``build_app`` could bypass
    that. Without this guard, ``HttpPeerTransport`` would happily
    issue requests against ``file://``, ``data:`` etc. depending on
    httpx config.
    """
    from signed_log.integration.server import build_app

    identity = _make_identity(tmp_path, "v.pem")
    log_path = str(tmp_path / "v.log")
    peer_log_dir = str(tmp_path / "v_peer_logs")

    for bad_url in ("file:///etc/passwd", "ftp://peer", "peer.example", ""):
        with pytest.raises(ValueError, match="http://"):
            build_app(
                identity,
                log_path,
                peer_log_dir,
                peers=[bad_url],
            )
