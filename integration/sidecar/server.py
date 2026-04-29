"""The long-running JSON-RPC sidecar server."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from communication.channel.agent_channel import AgentChannel

if TYPE_CHECKING:
    from integration.rpc.methods import RpcMethodRegistry


class Sidecar:
    """JSON-RPC server bound to ~/.openclaw/trustroom.sock; one per agent."""

    def __init__(
        self,
        channel: AgentChannel,
        methods: "RpcMethodRegistry",
        socket_path: Path,
    ) -> None:
        # Hold the channel facade, the method registry, and the socket path.
        ...

    async def start(self) -> None:
        # Bind the UnixSocketServer, start AgentChannel, accept connections in a task group.
        ...

    async def stop(self) -> None:
        # Close listening socket, drain in-flight calls, stop the AgentChannel.
        ...

    async def _handle_connection(self, reader: Any, writer: Any) -> None:
        # Read a length-prefixed JSON-RPC request, dispatch via methods, write the response frame.
        ...
