"""send_payment: compose, sign, and broadcast a Bitcoin payment."""

from __future__ import annotations

from communication.channel.agent_channel import AgentChannel
from integration.rpc.methods import RpcMethod
from integration.rpc.schema import SendPaymentParams, SendPaymentResult


class SendPaymentMethod(RpcMethod):
    """JSON-RPC method that calls AgentChannel.compose_payment + broadcast_payment."""

    name = "send_payment"
    params_schema = SendPaymentParams
    result_schema = SendPaymentResult

    async def __call__(
        self,
        channel: AgentChannel,
        params: SendPaymentParams,
    ) -> SendPaymentResult:
        # Compose BTCPayload, broadcast via the configured Broadcaster, return Txid.
        ...
