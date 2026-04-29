"""open_room: create a new Trustroom with a chosen admission policy."""

from __future__ import annotations

from communication.channel.agent_channel import AgentChannel
from integration.rpc.methods import RpcMethod
from integration.rpc.schema import OpenRoomParams, OpenRoomResult


class OpenRoomMethod(RpcMethod):
    """JSON-RPC method that calls AgentChannel.create_room."""

    name = "open_room"
    params_schema = OpenRoomParams
    result_schema = OpenRoomResult

    async def __call__(
        self,
        channel: AgentChannel,
        params: OpenRoomParams,
    ) -> OpenRoomResult:
        # Translate PolicyDescriptor → AdmissionPolicy instance, call create_room, return RoomId.
        ...
