"""IPv8 lifecycle adapter: owns the IPv8 instance, registers Communities, runs the loop."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ipv8.configuration import ConfigBuilder
from ipv8_service import IPv8

from shared.logging import get_logger

_log = get_logger("ipv8_runtime")


@dataclass(frozen=True)
class NetworkConfig:
    """Static configuration for the IPv8 runtime — bootstrap peers, port, working dir."""

    bootstrap_peers: list[str] = field(default_factory=list)
    port: int = 0
    working_dir: str = "."
    address: str = "0.0.0.0"


class IPv8Runtime:
    """Owns one IPv8 instance and its asyncio lifecycle.

    Communities are registered before ``start()`` via ``register_community(cls)`` and
    looked up post-start via ``get_overlay(cls)``. The local peer is keyed off the
    provided identity object's IPv8 Ed25519 keypair (curve25519 / LibNaCLSK).
    """

    _ANCHOR_ALIAS = "anchor"

    def __init__(self, identity: Any, network_config: NetworkConfig) -> None:
        self._identity = identity
        self._cfg = network_config
        self._pending: list[type] = []
        self._extras: dict[str, type] = {}
        self._ipv8: IPv8 | None = None
        self._key_file: Path | None = None

    def register_community(self, community_cls: type) -> None:
        """Queue a Community subclass to be loaded on start()."""
        self._extras[community_cls.__name__] = community_cls
        self._pending.append(community_cls)

    async def start(self) -> None:
        """Persist the anchor key, build the IPv8 config, start the asyncio service."""
        priv_bin = self._identity.ipv8.key.key_to_bin()
        tmp = tempfile.NamedTemporaryFile(prefix="openclaw_anchor_", suffix=".key", delete=False)
        tmp.write(priv_bin)
        tmp.close()
        self._key_file = Path(tmp.name)

        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.set_port(self._cfg.port)
        builder.set_address(self._cfg.address)
        builder.set_working_directory(self._cfg.working_dir)
        builder.add_key(self._ANCHOR_ALIAS, "curve25519", str(self._key_file))

        for cls in self._pending:
            builder.add_overlay(
                cls.__name__,
                self._ANCHOR_ALIAS,
                [],          # walkers — empty; peers can be added manually in tests
                [],          # bootstrappers
                {},          # initialize kwargs
                [("started",)],
            )

        cfg = builder.finalize()
        self._ipv8 = IPv8(cfg, extra_communities=self._extras)
        await self._ipv8.start()
        _log.info("ipv8_started", port=self._cfg.port, communities=list(self._extras))

    async def stop(self) -> None:
        if self._ipv8 is not None:
            await self._ipv8.stop()
            self._ipv8 = None
        if self._key_file is not None and self._key_file.exists():
            try:
                self._key_file.unlink()
            except OSError:
                pass
            self._key_file = None
        _log.info("ipv8_stopped")

    @property
    def my_peer(self) -> Any:
        """Return the local IPv8 peer (the one keyed by the anchor)."""
        if self._ipv8 is None:
            raise RuntimeError("IPv8Runtime.start() has not been awaited yet")
        return self._ipv8.keys[self._ANCHOR_ALIAS]

    @property
    def endpoint(self) -> Any:
        if self._ipv8 is None:
            raise RuntimeError("IPv8Runtime.start() has not been awaited yet")
        return self._ipv8.endpoint

    def get_overlay(self, community_cls: type) -> Any:
        """Return the live overlay instance of ``community_cls`` (post-start)."""
        if self._ipv8 is None:
            raise RuntimeError("IPv8Runtime.start() has not been awaited yet")
        for overlay in self._ipv8.overlays:
            if isinstance(overlay, community_cls):
                return overlay
        raise KeyError(f"overlay {community_cls.__name__!r} not loaded")
