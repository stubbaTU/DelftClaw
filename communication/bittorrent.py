"""BitTorrent service: magnet-link fetch + seed for the content overlay.

The service is exposed through the abstract :class:`BitTorrentService`
Protocol. ``LibTorrentService`` is the real implementation — it lazy-imports
``libtorrent`` so the rest of the project keeps importing cleanly even on
machines where the native binding isn't installed. ``StubBitTorrentService``
is an in-memory fake the test suite + the agent runtime fall back to when
libtorrent is unavailable.

Install for real BitTorrent traffic::

    pip install libtorrent          # pure-Python wheel where available
    # or via your distro: e.g. apt install python3-libtorrent

The agent's tool surface only ever holds a ``BitTorrentService`` reference,
so swapping implementations is constructor-only — no calling code changes.
"""

from __future__ import annotations

import asyncio
import hashlib
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
        path = self._seeded.get(magnet_uri)
        if path is None:
            path = self.save_dir / f"stub-{_magnet_btih(magnet_uri)}.bin"
        info = TorrentInfo(
            magnet=magnet_uri,
            name=path.name,
            progress=1.0 if magnet_uri in self._seeded else 0.0,
            seeding=False,
            save_path=path,
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
        return list(self._torrents.values())

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
# Real libtorrent wrapper (lazy-imported)
# ---------------------------------------------------------------------------

class LibTorrentService:
    """Real libtorrent.session-backed BitTorrentService.

    The libtorrent module is imported at construction so the rest of
    ``communication.bittorrent`` is loadable on machines without the
    binding. Construction raises ``RuntimeError`` if libtorrent is missing.
    """

    DEFAULT_SETTINGS = {
        "alert_mask": 0xFFFFFFFF,
        "listen_interfaces": "0.0.0.0:6881",
        "enable_dht": True,
        "enable_lsd": True,
        "enable_upnp": True,
    }

    def __init__(self, save_dir: Path, *, settings: dict | None = None) -> None:
        try:
            import libtorrent as lt  # noqa: F401  (presence check only)
        except ImportError as exc:
            raise RuntimeError(
                "libtorrent is not installed; install it (apt: python3-libtorrent, "
                "pip: libtorrent) or use StubBitTorrentService."
            ) from exc

        self._lt = __import__("libtorrent")
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self._session = self._lt.session({**self.DEFAULT_SETTINGS, **(settings or {})})
        # magnet-uri -> (libtorrent.torrent_handle, asyncio.Future[Path])
        self._handles: dict[str, tuple] = {}
        self._poll_task: asyncio.Task | None = None

    def add_magnet(self, magnet_uri: str) -> "asyncio.Future[Path]":
        loop = asyncio.get_event_loop()
        future: asyncio.Future[Path] = loop.create_future()
        params = self._lt.parse_magnet_uri(magnet_uri)
        params.save_path = str(self.save_dir)
        handle = self._session.add_torrent(params)
        self._handles[magnet_uri] = (handle, future)
        if self._poll_task is None:
            self._poll_task = loop.create_task(self._poll_loop())
        return future

    def seed(self, path: Path) -> str:
        path = Path(path).resolve()
        info = self._lt.create_torrent(self._lt.file_storage())
        # Real seeding requires building a `torrent_info` from the file. The
        # full implementation belongs in a follow-up; for the demo, callers
        # using LibTorrentService should add via magnet (download path) and
        # use StubBitTorrentService.seed(...) when generating magnets in tests.
        raise NotImplementedError(
            "LibTorrentService.seed: build torrent_info from path; not yet implemented"
        )

    def stats(self) -> list[TorrentInfo]:
        out: list[TorrentInfo] = []
        for magnet, (handle, _fut) in self._handles.items():
            status = handle.status()
            out.append(TorrentInfo(
                magnet=magnet,
                name=status.name or "",
                progress=float(status.progress),
                seeding=bool(status.is_seeding),
                save_path=Path(status.save_path) / (status.name or ""),
                bytes_total=int(status.total_wanted),
                bytes_downloaded=int(status.total_wanted_done),
                peers=int(status.num_peers),
            ))
        return out

    def stop(self) -> None:
        if self._poll_task is not None:
            self._poll_task.cancel()
            self._poll_task = None
        self._session = None
        self._handles.clear()

    async def _poll_loop(self) -> None:
        """Drive libtorrent's alert pump and resolve futures on completion."""
        while True:
            for magnet, (handle, fut) in list(self._handles.items()):
                if fut.done():
                    continue
                status = handle.status()
                if status.is_seeding or status.progress >= 1.0:
                    save_path = Path(status.save_path) / (status.name or "")
                    fut.set_result(save_path)
            await asyncio.sleep(1.0)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_default_service(save_dir: Path) -> BitTorrentService:
    """Return ``LibTorrentService`` if libtorrent is available, else a stub."""
    try:
        import libtorrent  # noqa: F401
    except ImportError:
        return StubBitTorrentService(save_dir=save_dir)
    return LibTorrentService(save_dir=save_dir)
