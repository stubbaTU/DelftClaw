"""pydantic DTOs for every JSON-RPC method's params and result.

The DTOs use plain `str`/`bytes` field types. Handlers convert these to the
typed ids in `shared.ids` (RoomId, MessageId, CredentialId, Txid) at
the boundary, before calling into AgentChannel. This keeps pydantic happy
without polluting `shared` with pydantic-core integration code.
"""

from __future__ import annotations

from pydantic import BaseModel


class AgentIdDTO(BaseModel):
    """Wire form of AgentId — the raw IPv8 pubkey bytes (hex-encoded over the wire)."""

    pubkey_hex: str


class BTCPayloadDTO(BaseModel):
    """Wire form of a BTCPayload."""

    amount_sats: int
    recipient_btc_pubkey_hex: str
    signed_tx_hex: str


class PolicyDescriptor(BaseModel):
    """Wire form of an admission policy choice that the host wants to enforce."""

    kind: str
    # `kind` is "openclaw-agent" | "issuer-allowlist" | "composite".
    issuer_pubkeys_hex: list[str] = []
    # `issuer_pubkeys_hex` is used by issuer-allowlist policies.


class SendToAgentParams(BaseModel):
    room_id: str
    text: str
    payment: BTCPayloadDTO | None = None


class SendToAgentResult(BaseModel):
    message_id: str


class OpenRoomParams(BaseModel):
    policy: PolicyDescriptor


class OpenRoomResult(BaseModel):
    room_id: str


class JoinRoomParams(BaseModel):
    room_id: str
    credential_id: str


class JoinRoomResult(BaseModel):
    joined: bool
    reason: str


class ListMembersParams(BaseModel):
    room_id: str


class ListMembersResult(BaseModel):
    members: list[AgentIdDTO]


class PresentCredentialParams(BaseModel):
    credential_id: str
    audience: AgentIdDTO


class PresentCredentialResult(BaseModel):
    presentation_blob: bytes


class SendPaymentParams(BaseModel):
    recipient: AgentIdDTO
    amount_sats: int


class SendPaymentResult(BaseModel):
    txid: str
