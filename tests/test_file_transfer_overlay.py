"""Live two-node push-path test for the file_transfer overlay.

Drives the *demo* path (not the conformance scenario): a seeder node with a
multi-chunk file in ``served`` answers a fetcher's FETCH_REQUEST by streaming a
manifest + numbered chunks; the fetcher reassembles and hash-verifies them. This
is the transfer the file_transfer scenario relies on, exercised over real IPv8
dispatch with the reference implementation on both sides.
"""

from __future__ import annotations

import hashlib

import pytest

from _live_llm import compile_source
from experiments.fixtures import get_spec
from experiments.live_interop import TwoNodeNetwork, load_overlay


def _message(parsed, name: str):
    return next(m for m in parsed.messages if m.name == name)


def _ft_source() -> str:
    """A real live compilation of the file_transfer spec (skips offline)."""
    return compile_source(get_spec("file_transfer").md_text)


@pytest.mark.asyncio
async def test_multichunk_file_transfers_and_verifies() -> None:
    """A 600-byte file (CHUNK_SIZE=256 -> 3 chunks) moves seeder->fetcher,
    reassembles in order, and verifies. Mirrors the demo's tool path: seed
    ``served`` on the seeder, send FETCH_REQUEST from the fetcher, read the
    result off ``transfers``."""
    spec = get_spec("file_transfer")
    cid = bytes.fromhex(spec.community_id_hex)
    src = _ft_source()
    seeder = load_overlay(src, cid)
    fetcher = load_overlay(src, cid)

    content = bytes(range(256)) * 2 + b"tail-bytes"   # 522 bytes -> 3 chunks
    content_id = hashlib.sha1(content).digest()[:20]

    async with TwoNodeNetwork(seeder, fetcher, cid) as net:
        # node 0 = seeder: seed its served store (what cli._apply_seed_content does)
        net.overlay(0).served = {content_id: content}

        # node 1 = fetcher: send FETCH_REQUEST to the seeder
        fetch_req = _message(spec.parsed, "FETCH_REQUEST")
        await net.send(1, 0, fetch_req, {"content_id": content_id.hex()})

        # The seeder streamed manifest + chunks back; let them settle.
        from experiments.live_interop import deliver_messages
        await deliver_messages()

        key = content_id.hex()
        entry = net.state(1, "transfers").get(key)
        assert entry is not None and entry["complete"] and entry["ok"], entry
        reassembled = b"".join(entry["chunks"][s] for s in range(entry["total"]))
        assert reassembled == content
        # Seeder recorded the fetcher's success verdict.
        assert net.state(0, "completed").get(key) is True


@pytest.mark.asyncio
async def test_unknown_content_id_is_dropped() -> None:
    """A FETCH_REQUEST for content the seeder does not hold produces no
    transfer entry (silent drop), not a crash."""
    spec = get_spec("file_transfer")
    cid = bytes.fromhex(spec.community_id_hex)
    src = _ft_source()
    async with TwoNodeNetwork(load_overlay(src, cid), load_overlay(src, cid), cid) as net:
        net.overlay(0).served = {}
        fetch_req = _message(spec.parsed, "FETCH_REQUEST")
        await net.send(1, 0, fetch_req, {"content_id": "ab" * 20})
        assert net.state(1, "transfers") == {}
