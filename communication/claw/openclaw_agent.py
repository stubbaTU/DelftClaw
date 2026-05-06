"""Barebones OpenClaw agent built on the real IPv8 runtime."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from communication.claw.community import ClawPoCCommunity
from communication.transport.ipv8_runtime import IPv8Runtime, NetworkConfig
from identity.openclaw_identity import OpenClawIdentity
from shared.logging import get_logger

_log = get_logger("openclaw_agent")


class OpenClawAgent:
    """Small orchestrator that runs a real IPv8-backed OpenClaw node.

    This is the actual proof-of-concept agent: it owns the persistent OpenClaw identity,
    starts IPv8, loads the `ClawPoCCommunity`, and makes the identity available to the
    community after startup.
    """

    def __init__(
        self,
        *,
        network: str = "MAINNET",
        key_path: str | Path | None = None,
        port: int = 9000,
        address: str = "0.0.0.0",
        working_dir: str = ".",
        identity: OpenClawIdentity | None = None,
    ) -> None:
        self.identity = identity or OpenClawIdentity(network=network, key_path=key_path)
        self.runtime = IPv8Runtime(
            self.identity,
            NetworkConfig(port=port, address=address, working_dir=working_dir),
        )
        self.runtime.register_community(ClawPoCCommunity)
        self._community: ClawPoCCommunity | None = None

    async def start(self) -> None:
        """Start the IPv8 runtime and wire the community with the persistent identity."""
        await self.runtime.start()
        community = self.runtime.get_overlay(ClawPoCCommunity)
        self._community = community
        try:
            community.wire(openclaw_identity=self.identity)
        except TypeError:
            # Defensive fallback for older/alternate community implementations.
            setattr(community, "_openclaw_identity", self.identity)
        community.announce_identity()
        _log.info("openclaw_agent_started", identity_hash=self.identity.get_identity_hash())

    async def stop(self) -> None:
        """Stop the IPv8 runtime and release its temporary key file."""
        await self.runtime.stop()
        self._community = None
        _log.info("openclaw_agent_stopped")

    @property
    def community(self) -> ClawPoCCommunity | None:
        return self._community

    @property
    def my_peer(self) -> Any:
        return self.runtime.my_peer

    @property
    def identity_hash(self) -> str:
        return self.identity.get_identity_hash()

