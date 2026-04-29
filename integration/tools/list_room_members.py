"""list_room_members: enumerate the current member set of a Trustroom."""

from __future__ import annotations

from communication.channel.agent_channel import AgentChannel
from integration.rpc.methods import RpcMethod
from integration.rpc.schema import ListMembersParams, ListMembersResult


class ListRoomMembersMethod(RpcMethod):
    """JSON-RPC method that calls AgentChannel.members."""

    name = "list_room_members"
    params_schema = ListMembersParams
    result_schema = ListMembersResult

    async def __call__(
        self,
        channel: AgentChannel,
        params: ListMembersParams,
    ) -> ListMembersResult:
        # Call channel.members, map AgentId → AgentIdDTO, return list.
        ...
