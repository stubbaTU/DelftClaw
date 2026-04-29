"""IPv8 lifecycle adapter: owns the IPv8 instance, registers Communities, runs the loop."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
        ...

    async def start(self) -> None:
        # Build the IPv8 config, start the asyncio service, register every queued Community.
        ...

    async def stop(self) -> None:
        # Graceful shutdown; flush any pending sends; release the UDP socket.
        ...

    def register_community(self, community: Any) -> None:
        # Attach a Community subclass (e.g. TrustroomCommunity) before or after start().
        ...

    @property
    def my_peer(self) -> Any:
        # Return the local IPv8 Peer object handed to message handlers.
        ...
