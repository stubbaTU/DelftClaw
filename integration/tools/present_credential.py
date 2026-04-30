"""present_credential: produce a holder-bound Presentation blob for a target audience."""

from __future__ import annotations

from communication.channel.agent_channel import AgentChannel
from integration.rpc.methods import RpcMethod
from integration.rpc.schema import PresentCredentialParams, PresentCredentialResult


class PresentCredentialMethod(RpcMethod):
    """JSON-RPC method that builds a Presentation via CredentialPresenter."""

    name = "present_credential"
    params_schema = PresentCredentialParams
    result_schema = PresentCredentialResult

    async def __call__(
        self,
        channel: AgentChannel,
        params: PresentCredentialParams,
    ) -> PresentCredentialResult:
        # Resolve the CredentialPresenter from the channel, build Presentation, serialise to bytes.
        ...
