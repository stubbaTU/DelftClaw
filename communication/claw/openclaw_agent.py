from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from communication.claw.community import ClawPoCCommunity
from identity.openclaw_identity import OpenClawIdentity


@dataclass(frozen=True)
class NetworkConfig:
    host: str = "0.0.0.0"
    port: int = 9000
    working_dir: str = "."


class IPv8Runtime:
    """Small runtime adapter; replaceable by tests or a fuller IPv8 backend."""

    def __init__(self, identity: OpenClawIdentity, network_config: NetworkConfig):
        self.identity = identity
        self.network_config = network_config
        self.registered: list[type] = []
        self.overlay = None
        self.started = False
        self.stopped = False

    def register_community(self, community_cls) -> None:
        self.registered.append(community_cls)
        self.overlay = community_cls()

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    def get_overlay(self, community_cls):
        if self.overlay is None:
            self.overlay = community_cls()
        return self.overlay

    @property
    def my_peer(self):
        return self.identity.ipv8


class OpenClawAgent:
    def __init__(
        self,
        network: str = "MAINNET",
        key_path: str | Path | None = None,
        host: str = "0.0.0.0",
        port: int = 9000,
        working_dir: str = ".",
    ):
        self.identity = OpenClawIdentity(network=network, key_path=key_path)
        self.identity_hash = self.identity.get_identity_hash()
        self.network_config = NetworkConfig(host=host, port=port, working_dir=working_dir)
        self.runtime = IPv8Runtime(self.identity, self.network_config)
        self.community = None

    async def start(self) -> None:
        Path(self.network_config.working_dir).mkdir(parents=True, exist_ok=True)
        self.runtime.register_community(ClawPoCCommunity)
        await self.runtime.start()
        self.community = self.runtime.get_overlay(ClawPoCCommunity)
        self.community.wire(openclaw_identity=self.identity)
        self.community.announce_identity()

    async def stop(self) -> None:
        await self.runtime.stop()
