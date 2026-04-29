"""join_room: present a stored VC to join an advertised room."""

from __future__ import annotations

from communication.channel.agent_channel import AgentChannel
from integration.rpc.methods import RpcMethod
from integration.rpc.schema import JoinRoomParams, JoinRoomResult


class JoinRoomMethod(RpcMethod):
    """JSON-RPC method that calls AgentChannel.join_room."""

    name = "join_room"
    params_schema = JoinRoomParams
    result_schema = JoinRoomResult

    async def __call__(
        self,
        channel: AgentChannel,
        params: JoinRoomParams,
    ) -> JoinRoomResult:
        # Await channel.join_room; on AdmissionDenied return joined=False with reason.
        ...
