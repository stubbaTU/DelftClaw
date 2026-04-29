"""Layer 3: VC verification, holder presentation, join-time admission gate."""

from communication.admission.verifier import CredentialVerifier, MultiFormatVerifier
from communication.admission.presenter import CredentialPresenter
from communication.admission.join_protocol import (
    AdmissionGate,
    JoinRequestPayload,
    JoinResponsePayload,
)

__all__ = [
    "CredentialVerifier",
    "MultiFormatVerifier",
    "CredentialPresenter",
    "AdmissionGate",
    "JoinRequestPayload",
    "JoinResponsePayload",
]
