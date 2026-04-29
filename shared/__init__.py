"""Cross-package primitives. Pure typed contracts, no I/O."""

from shared.ids import AgentId, RoomId, MessageId, Nonce, Epoch, Txid, CredentialId
from shared.errors import (
    OpenClawError,
    CommunicationError,
    AdmissionDenied,
    CredentialInvalid,
    EpochMismatch,
    PayloadInvalid,
    WalletError,
    IdentityError,
)
from shared.threats import Threat
from shared.envelopes import WireFrame, ApplicationMessage, BTCPayload
from shared.credentials import (
    Credential,
    Presentation,
    VerifiedCredential,
    KeyBundle,
)

__all__ = [
    "AgentId",
    "RoomId",
    "MessageId",
    "Nonce",
    "Epoch",
    "Txid",
    "CredentialId",
    "OpenClawError",
    "CommunicationError",
    "AdmissionDenied",
    "CredentialInvalid",
    "EpochMismatch",
    "PayloadInvalid",
    "WalletError",
    "IdentityError",
    "Threat",
    "WireFrame",
    "ApplicationMessage",
    "BTCPayload",
    "Credential",
    "Presentation",
    "VerifiedCredential",
    "KeyBundle",
]
