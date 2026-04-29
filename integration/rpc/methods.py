"""RpcMethod protocol and the registry the Sidecar dispatches through."""

from __future__ import annotations

from typing import Any, Protocol

from communication.channel.agent_channel import AgentChannel


class RpcMethod(Protocol):
    """One JSON-RPC method: name + pydantic params/result schemas + async handler."""

    name: str
    params_schema: type
    result_schema: type

    async def __call__(self, channel: AgentChannel, params: Any) -> Any:
        # Validate params, dispatch into AgentChannel, translate exceptions to JSON-RPC errors.
        ...


class RpcMethodRegistry:
    """In-memory registry mapping method names to RpcMethod instances."""

    def __init__(self) -> None:
        # Initialise empty registry.
        ...

    def register(self, m: RpcMethod) -> None:
        # Add a method; raise on duplicate name.
        ...

    def get(self, name: str) -> RpcMethod:
        # Look up by name; raise KeyError if absent.
        ...
