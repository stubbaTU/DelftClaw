"""Join-protocol payloads and the AdmissionGate facade used by the Community."""

from __future__ import annotations

from dataclasses import dataclass

from communication.admission.verifier import CredentialVerifier
from communication.trustroom.policy import (
    AdmissionContext,
    AdmissionDecision,
    AdmissionPolicy,
)
from shared.credentials import Presentation
from shared.errors import CredentialInvalid
from shared.ids import RoomId


class AdmissionGate:
    """Single decision point that combines verification and policy."""

    def __init__(
        self,
        verifier: CredentialVerifier,
        policy: AdmissionPolicy,
    ) -> None:
        self._verifier = verifier
        self._policy = policy

    def evaluate(
        self,
        presentation: Presentation,
        ctx: AdmissionContext,
    ) -> AdmissionDecision:
        try:
            verified = self._verifier.verify(presentation)
        except CredentialInvalid as e:
            return AdmissionDecision(admitted=False, reason=f"credential invalid: {e}")
        if verified.revocation_status != "fresh":
            return AdmissionDecision(
                admitted=False,
                reason=f"revocation status is {verified.revocation_status}",
            )
        return self._policy.evaluate(verified, ctx)


@dataclass(frozen=True)
class JoinRequestPayload:
    """Wire payload of a JOIN_REQUEST IPv8 message."""

    room_id: RoomId
    presentation: Presentation
    ephemeral_key: bytes
    # `ephemeral_key` is used by Layer 4 to encrypt the welcome blob back to the joiner.


@dataclass(frozen=True)
class JoinResponsePayload:
    """Wire payload of a JOIN_RESPONSE IPv8 message."""

    room_id: RoomId
    decision: AdmissionDecision
    welcome_blob: bytes | None
    # `welcome_blob` is the MLS Welcome (Path A) or seeded ratchet state (Path B); None if denied.
