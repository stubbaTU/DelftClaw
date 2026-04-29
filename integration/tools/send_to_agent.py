"""send_to_agent: encrypt+ship a message (optionally with a Bitcoin payment)."""

from __future__ import annotations

from communication.channel.agent_channel import AgentChannel
from integration.rpc.methods import RpcMethod
from integration.rpc.schema import SendToAgentParams, SendToAgentResult


class SendToAgentMethod(RpcMethod):
    """JSON-RPC method that calls AgentChannel.send."""

    name = "send_to_agent"
    params_schema = SendToAgentParams
    result_schema = SendToAgentResult

    async def __call__(
        self,
        channel: AgentChannel,
        params: SendToAgentParams,
    ) -> SendToAgentResult:
        # Convert BTCPayloadDTO → BTCPayload, await channel.send, wrap MessageId in result.
        ...
