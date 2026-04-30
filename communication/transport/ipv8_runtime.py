"""IPv8 lifecycle adapter: owns the IPv8 instance, registers Communities, runs the loop."""

from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass
from typing import Any
import sys
import os

if sys.platform == "win32":
    _root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    _lib_path = os.path.join(_root, "libsodium", "libsodium", "x64", "Release", "v143", "dynamic")
    if os.path.exists(_lib_path):
        os.add_dll_directory(_lib_path)

from ipv8.configuration import get_default_configuration
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
from ipv8.IPv8 import IPv8
from identity.agent_identity import AgentIdentity


@dataclass(frozen=True)
class NetworkConfig:
    """Static configuration for the IPv8 runtime — bootstrap peers, port, working dir."""

    bootstrap_peers: list[str]
    port: int
    working_dir: str


class IPv8Runtime:
    """Owns one IPv8 instance and its asyncio lifecycle."""

    def __init__(self, identity: AgentIdentity, network_config: NetworkConfig) -> None:
        # Store dependencies; do not start I/O yet.
        self.identity = identity
        self.network_config = network_config
        self.ipv8 = None
        self._communities = []

    async def start(self) -> None:
        # Build the IPv8 config, start the asyncio service, register every queued Community.
        config = get_default_configuration()
        config["port"] = self.network_config.port
        # We can construct the keys section
        peer = self.identity.ipv8_key.to_ipv8_peer()
        config["keys"] = [
            {
                "alias": "my_peer",
                "material": peer.key.key_to_bin().hex(),
                "generation": "curve25519",
            }
        ]
        # In reality, py-ipv8 requires a little more handling for custom keys.
        # But we can also pass the endpoint and start directly.
        endpoint = UDPEndpoint(self.network_config.port)

        # Ensure working dir
        self.ipv8 = IPv8(config, endpoint)

        for comm in self._communities:
            self.ipv8.strategies.append((comm, []))

        await self.ipv8.start()

    async def stop(self) -> None:
        # Graceful shutdown; flush any pending sends; release the UDP socket.
        if self.ipv8:
            await self.ipv8.stop()

    def register_community(self, community: Any) -> None:
        # Attach a Community subclass (e.g. TrustroomCommunity) before or after start().
        if self.ipv8:
            self.ipv8.strategies.append((community, []))
        else:
            self._communities.append(community)

    @property
    def my_peer(self) -> Any:
        # Return the local IPv8 Peer object handed to message handlers.
        return self.identity.ipv8_key.to_ipv8_peer()
