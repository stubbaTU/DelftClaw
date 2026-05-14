"""``ServerState`` — the live runtime objects the MCP tools close over.

One instance is built by :mod:`integration.mcp_server.boot` at server start
and held by :mod:`integration.mcp_server.server` for the lifetime of the
FastMCP application.

The state holds:
* ``identity`` — the agent's :class:`AgentIdentity` (IPv8, app, wallet keys).
* ``runtime`` — the live :class:`IPv8Runtime`.
* ``channel`` — the :class:`AgentChannel` already started.
* ``peers`` — the :class:`PeerDirectory` loaded from ``peers.yaml``.
* ``issuer_priv`` — optional 32-byte raw Ed25519 issuer private key.
* ``state_lock`` — an :class:`asyncio.Lock` every state-mutating tool must
  acquire. Serialises tool calls so they don't race against IPv8 callbacks
  on the same event loop.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from communication.channel.agent_channel import AgentChannel
    from communication.transport.ipv8_runtime import IPv8Runtime
    from identity.agent_identity import AgentIdentity
    from integration.mcp_server.config import ServerConfig
    from integration.mcp_server.peer_directory import PeerDirectory


@dataclass
class ServerState:
    config: "ServerConfig"
    identity: "AgentIdentity"
    runtime: "IPv8Runtime"
    channel: "AgentChannel"
    peers: "PeerDirectory"
    issuer_priv: bytes | None = None  # 32 raw Ed25519 bytes if configured
    state_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


__all__ = ["ServerState"]
