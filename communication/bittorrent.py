"""Content-addressed fetch + seed surface for the content overlay.

Files are addressed by a magnet URI whose btih hex is the content_id
(``sha1(bytes)``). The actual bytes move over IPv8 (``SeedboxCommunity``
CONTENT_REQUEST / the file_transfer overlay), not a BitTorrent swarm — this
module is the content-addressing + completed-download bookkeeping the agent's
``torrent_*`` tools and the ``torrent_progress_gte_1`` stop predicate read.

``StubBitTorrentService`` is the implementation; the agent holds it behind the
``BitTorrentService`` Protocol, so a real libtorrent backend could be slotted
in later constructor-only, without touching calling code.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass
class TorrentInfo:
    """Read-only snapshot returned by :meth:`BitTorrentService.stats`."""

    magnet: str
    name: str
    progress: float          # 0.0 .. 1.0
    seeding: bool            # we are seeding this torrent
    save_path: Path | None   # final path (downloaded) or source (seeding)
    bytes_total: int = 0
    bytes_downloaded: int = 0
    peers: int = 0


# ---------------------------------------------------------------------------
# Cross-process completed-download ledger
# ---------------------------------------------------------------------------
#
# In the deployed scenario the MCP service process performs the download
# (``content_search_and_fetch`` -> ``record_download``) but the *watchdog*
# process builds the state snapshot the LLM sees — and they run separate
# ``BitTorrentService`` instances. In-memory ``record_download`` is therefore
# invisible to the snapshot, so ``has_completed_torrent`` / the
# ``torrent_progress_gte_1`` predicate never fire and the agent loops forever.
#
# Both processes share ``save_dir`` on disk (systemd units set HOME identically
# and pass ``--save-dir ${HOME}/torrents``), so a tiny append-only ledger file
# in ``save_dir`` makes a completed download visible across the process
# boundary. ``stats()`` merges it with in-memory torrents (in-memory wins).

_DOWNLOAD_LEDGER_NAME = ".download_ledger.jsonl"


def _append_download_ledger(save_dir: Path, info: "TorrentInfo") -> None:
    """Record a completed download to ``<save_dir>/.download_ledger.jsonl``.

    Best-effort: a failed write never breaks the download itself — the
    in-memory entry still exists for the recording process.
    """
    try:
        save_dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "magnet": info.magnet,
            "name": info.name,
            "save_path": str(info.save_path) if info.save_path else None,
            "bytes_total": int(info.bytes_total),
        })
        with open(save_dir / _DOWNLOAD_LEDGER_NAME, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def _read_download_ledger(save_dir: Path) -> dict[str, "TorrentInfo"]:
    """Return completed downloads recorded in ``save_dir`` keyed by magnet.

    Reconstructs ``TorrentInfo(progress=1.0, ...)`` for each ledger entry — the
    cross-process view of "this file is fully downloaded." Malformed lines are
    skipped; a missing ledger returns an empty dict.
    """
    path = save_dir / _DOWNLOAD_LEDGER_NAME
    out: dict[str, TorrentInfo] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        magnet = rec.get("magnet")
        if not magnet:
            continue
        sp = rec.get("save_path")
        out[magnet] = TorrentInfo(
            magnet=magnet,
            name=rec.get("name", ""),
            progress=1.0,
            seeding=False,
            save_path=Path(sp) if sp else None,
            bytes_total=int(rec.get("bytes_total", 0)),
            bytes_downloaded=int(rec.get("bytes_total", 0)),
            peers=1,
        )
    return out


@runtime_checkable
class BitTorrentService(Protocol):
    """Minimal magnet-fetch / seed surface the rest of the codebase consumes."""

    save_dir: Path

    def add_magnet(self, magnet_uri: str) -> "asyncio.Future[Path]":
        """Begin downloading ``magnet_uri``. Future resolves with the saved path."""
        ...

    def seed(self, path: Path) -> str:
        """Begin seeding ``path``. Returns the resulting magnet URI."""
        ...

    def stats(self) -> list[TorrentInfo]:
        """Snapshot of all active torrents."""
        ...

    def record_download(
        self, magnet: str, path: Path, total_bytes: int,
    ) -> TorrentInfo:
        """Register an externally-completed download.

        The IPv8 ``CONTENT_DELIVERY`` path verifies the bytes against the
        advertised ``content_id`` (= magnet btih) before writing them, so the
        download is complete by the time this is called. ``stats()`` /
        ``torrent_progress_gte_1`` then report ``progress=1.0`` for a *real*
        file — closing the false-green where the stub fabricated completion.
        """
        ...

    def stop(self) -> None:
        """Tear down the session and release any sockets / threads."""
        ...


# ---------------------------------------------------------------------------
# Stub
# ---------------------------------------------------------------------------

@dataclass
class StubBitTorrentService:
    """In-process fake for tests + libtorrent-less environments.

    "Seeding" stores ``path`` keyed by a deterministic magnet URI. A
    subsequent ``add_magnet`` for that URI resolves immediately to the
    same path — round-trips locally without any wire traffic. Magnet
    URIs the stub has never seen resolve to a placeholder path; callers
    can pre-seed via :meth:`prime` to simulate cross-process delivery.
    """

    save_dir: Path
    _seeded: dict[str, Path] = field(default_factory=dict)
    _torrents: dict[str, TorrentInfo] = field(default_factory=dict)

    def add_magnet(self, magnet_uri: str) -> "asyncio.Future[Path]":
        loop = asyncio.get_event_loop()
        future: asyncio.Future[Path] = loop.create_future()
        source = self._seeded.get(magnet_uri)
        known = source is not None
        self.save_dir.mkdir(parents=True, exist_ok=True)
        if source is not None and source.is_file():
            # Real local file copy: bytes move from the seedbox's primed
            # path into this agent's save_dir, so progress=1.0 reflects an
            # actual file the agent now owns. Not P2P; deliberate.
            path = self.save_dir / source.name
            if path.resolve() != source.resolve():
                path.write_bytes(source.read_bytes())
        elif source is not None:
            path = source
        else:
            path = self.save_dir / f"stub-{_magnet_btih(magnet_uri)}.bin"
            if not path.exists():
                path.write_text(f"mock payload for {magnet_uri}\n", encoding="utf-8")
        info = TorrentInfo(
            magnet=magnet_uri,
            name=path.name,
            progress=1.0,
            seeding=False,
            save_path=path,
            peers=1 if known else 0,
        )
        self._torrents[magnet_uri] = info
        future.set_result(path)
        return future

    def seed(self, path: Path) -> str:
        magnet = _stub_magnet_for(path)
        self._seeded[magnet] = path
        self._torrents[magnet] = TorrentInfo(
            magnet=magnet,
            name=path.name,
            progress=1.0,
            seeding=True,
            save_path=path,
        )
        return magnet

    def stats(self) -> list[TorrentInfo]:
        # Merge in-memory torrents with the on-disk completed-download ledger so
        # a download recorded by ANOTHER process sharing this save_dir (the MCP
        # service vs the watchdog snapshot agent) is visible here. In-memory
        # entries win on magnet collision.
        merged = _read_download_ledger(self.save_dir)
        merged.update(self._torrents)
        return list(merged.values())

    def record_download(
        self, magnet: str, path: Path, total_bytes: int,
    ) -> TorrentInfo:
        """Register an externally-completed download under ``magnet``.

        Used by the IPv8 CONTENT_DELIVERY path in ``content_search_and_fetch``
        after sha1/size verification, so a successful real transfer shows up
        in ``stats()`` exactly the same way a seeded file does — and the
        ``torrent_progress_gte_1`` stop predicate fires on real bytes only.
        Also appends to the shared on-disk ledger so a separate process
        reading the same ``save_dir`` (the watchdog snapshot agent) sees it.
        """
        info = TorrentInfo(
            magnet=magnet,
            name=path.name,
            progress=1.0,
            seeding=False,
            save_path=path,
            bytes_total=int(total_bytes),
            bytes_downloaded=int(total_bytes),
            peers=1,
        )
        self._torrents[magnet] = info
        _append_download_ledger(self.save_dir, info)
        return info

    def stop(self) -> None:
        self._torrents.clear()
        self._seeded.clear()

    def prime(self, magnet_uri: str, path: Path) -> None:
        """Pretend ``path`` was downloaded from ``magnet_uri`` (cross-process simulation)."""
        self._seeded[magnet_uri] = path


def _magnet_btih(magnet_uri: str) -> str:
    """Extract the btih hex from a magnet URI; fallback to sha1(uri) for robustness."""
    marker = "urn:btih:"
    idx = magnet_uri.find(marker)
    if idx >= 0:
        rest = magnet_uri[idx + len(marker):]
        return rest.split("&", 1)[0]
    return hashlib.sha1(magnet_uri.encode("utf-8")).hexdigest()


def _stub_magnet_for(path: Path) -> str:
    """Deterministic magnet URI for ``path`` — not real BTIH, only for the stub."""
    digest = hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()
    return f"magnet:?xt=urn:btih:{digest}&dn={path.name}"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_default_service(save_dir: Path) -> BitTorrentService:
    """The content-addressing service the agent runtime uses."""
    return StubBitTorrentService(save_dir=save_dir)
