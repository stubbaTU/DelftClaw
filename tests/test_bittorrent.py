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
    # When the primed source and the save_dir resolve to the same path,
    # add_magnet short-circuits and returns the source directly.
    assert fetched == real_path


@pytest.mark.asyncio
async def test_stub_primed_magnet_copies_bytes_into_save_dir(tmp_path: Path) -> None:
    """When the seedbox source and the agent save_dir are different
    directories, add_magnet must perform a real local file copy: the
    returned path lives under save_dir and contains the source bytes.
    """
    seedbox_dir = tmp_path / "seedbox"
    save_dir = tmp_path / "downloads"
    seedbox_dir.mkdir()

    source = seedbox_dir / "cc_audio.txt"
    source.write_bytes(b"hello creative commons")

    svc = StubBitTorrentService(save_dir=save_dir)
    magnet = "magnet:?xt=urn:btih:1234abcd"
    svc.prime(magnet, source)

    fetched = await svc.add_magnet(magnet)

    # Bytes actually moved.
    assert fetched.parent.resolve() == save_dir.resolve()
    assert fetched.name == source.name
    assert fetched.resolve() != source.resolve()
    assert fetched.read_bytes() == source.read_bytes()
    # Source still in place (this is a copy, not a move).
    assert source.is_file()


def test_stub_record_download_registers_completed_real_file(tmp_path: Path) -> None:
    """The IPv8 CONTENT_DELIVERY path writes the verified bytes to disk and
    then calls record_download. After that, stats() must show progress=1.0
    for the *real* file at the *real* path — the signal the
    torrent_progress_gte_1 stop predicate fires on."""
    svc = StubBitTorrentService(save_dir=tmp_path)
    file_path = tmp_path / "calculus.txt"
    payload = b"chapter 1: limits\n" * 8
    file_path.write_bytes(payload)
    magnet = f"magnet:?xt=urn:btih:{'cd' * 20}&dn=calculus.txt"

    info = svc.record_download(magnet, file_path, len(payload))
    assert info.progress == 1.0
    assert info.save_path == file_path
    assert info.bytes_total == len(payload)

    snapshot = {t.magnet: t for t in svc.stats()}
    assert magnet in snapshot
    assert snapshot[magnet].progress == 1.0
    assert snapshot[magnet].save_path == file_path
    assert snapshot[magnet].save_path.read_bytes() == payload


def test_record_download_is_visible_to_a_second_instance_sharing_save_dir(tmp_path: Path) -> None:
    """The deployed file_share split: the MCP-service process downloads, the
    watchdog process builds the snapshot — two BitTorrentService instances over
    the SAME save_dir. A download recorded by one MUST appear in the other's
    stats() (via the on-disk ledger), or the snapshot never sees the download
    and the agent loops forever."""
    shared = tmp_path / "torrents"
    mcp_side = StubBitTorrentService(save_dir=shared)
    watchdog_side = StubBitTorrentService(save_dir=shared)

    # watchdog side starts blind.
    assert watchdog_side.stats() == []

    file_path = shared / "open_textbook_calculus_excerpt.txt"
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(b"calc" * 96)
    magnet = "magnet:?xt=urn:btih:ec9d91a30668b3ece1579e15d545a4b1eb43caf8&dn=calc"
    mcp_side.record_download(magnet, file_path, file_path.stat().st_size)

    # The watchdog side — a DIFFERENT instance — now sees it via the ledger.
    snap = {t.magnet: t for t in watchdog_side.stats()}
    assert magnet in snap
    assert snap[magnet].progress == 1.0
    assert snap[magnet].name == "open_textbook_calculus_excerpt.txt"
    assert snap[magnet].save_path == file_path


def test_stats_dedupes_in_memory_over_ledger(tmp_path: Path) -> None:
    """A single instance that both records in-memory AND has the ledger entry
    must not double-count the same magnet."""
    svc = StubBitTorrentService(save_dir=tmp_path)
    f = tmp_path / "x.txt"
    f.write_bytes(b"x" * 10)
    magnet = "magnet:?xt=urn:btih:abcdef&dn=x"
    svc.record_download(magnet, f, 10)  # writes in-memory AND ledger
    rows = [t for t in svc.stats() if t.magnet == magnet]
    assert len(rows) == 1


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
