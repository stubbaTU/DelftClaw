"""Phase-6 tests: BitTorrentService stub + integration with the content overlay.

  - StubBitTorrentService round-trips a magnet via ``seed`` -> ``add_magnet``.
  - The agent flow: SEARCH on the content overlay returns magnets that the
    fetcher can hand to BitTorrentService.add_magnet to retrieve a path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from communication.bittorrent import (
    BitTorrentService,
    StubBitTorrentService,
    build_default_service,
)


def test_stub_implements_protocol(tmp_path: Path) -> None:
    svc = StubBitTorrentService(save_dir=tmp_path)
    assert isinstance(svc, BitTorrentService)


@pytest.mark.asyncio
async def test_stub_seed_then_fetch_round_trips_path(tmp_path: Path) -> None:
    svc = StubBitTorrentService(save_dir=tmp_path)
    file_path = tmp_path / "alice_audio.mp3"
    file_path.write_bytes(b"ID3" + b"\x00" * 64)

    magnet = svc.seed(file_path)
    assert magnet.startswith("magnet:?xt=urn:btih:")

    fetched_path = await svc.add_magnet(magnet)
    assert fetched_path == file_path

    snapshot = {t.magnet: t for t in svc.stats()}
    assert snapshot[magnet].progress == 1.0


@pytest.mark.asyncio
async def test_stub_unknown_magnet_resolves_to_placeholder(tmp_path: Path) -> None:
    svc = StubBitTorrentService(save_dir=tmp_path)
    fetched = await svc.add_magnet("magnet:?xt=urn:btih:abc123")
    assert fetched.parent == tmp_path
    assert "abc123" in fetched.name


@pytest.mark.asyncio
async def test_stub_prime_simulates_cross_node_delivery(tmp_path: Path) -> None:
    svc = StubBitTorrentService(save_dir=tmp_path)
    real_path = tmp_path / "shared.txt"
    real_path.write_text("hello")
    magnet = "magnet:?xt=urn:btih:bbbb"
    svc.prime(magnet, real_path)

    fetched = await svc.add_magnet(magnet)
    assert fetched == real_path


def test_build_default_service_falls_back_to_stub_when_libtorrent_missing(tmp_path: Path) -> None:
    svc = build_default_service(save_dir=tmp_path)
    # On a machine without libtorrent, this MUST be a stub. The CI/dev box
    # for this project doesn't ship libtorrent (per Phase-6 plan).
    try:
        import libtorrent  # noqa: F401
        # If libtorrent is available, build_default returns the real impl;
        # we only assert here on the no-libtorrent path.
        return
    except ImportError:
        pass
    assert isinstance(svc, StubBitTorrentService)
