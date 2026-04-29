"""JSON-RPC method registry and pydantic schemas for every method's params/results."""

from integration.rpc.methods import RpcMethod, RpcMethodRegistry
from integration.rpc.schema import (
    AgentIdDTO,
    BTCPayloadDTO,
    PolicyDescriptor,
    SendToAgentParams,
    SendToAgentResult,
    OpenRoomParams,
    OpenRoomResult,
    JoinRoomParams,
    JoinRoomResult,
    ListMembersParams,
    ListMembersResult,
    PresentCredentialParams,
    PresentCredentialResult,
    SendPaymentParams,
    SendPaymentResult,
)

__all__ = [
    "RpcMethod",
    "RpcMethodRegistry",
    "AgentIdDTO",
    "BTCPayloadDTO",
    "PolicyDescriptor",
    "SendToAgentParams",
    "SendToAgentResult",
    "OpenRoomParams",
    "OpenRoomResult",
    "JoinRoomParams",
    "JoinRoomResult",
    "ListMembersParams",
    "ListMembersResult",
    "PresentCredentialParams",
    "PresentCredentialResult",
    "SendPaymentParams",
    "SendPaymentResult",
]
