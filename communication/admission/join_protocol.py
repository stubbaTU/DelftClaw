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
from shared.logging import get_logger

_log = get_logger("admission_gate")


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
        _log.info(
            "gate_evaluating",
            room_id=ctx.room_id.to_bytes().hex(),
            requester=str(ctx.requester),
            format_id=presentation.credential.format_id,
            with_stake=presentation.stake_proof is not None,
        )
        try:
            verified = self._verifier.verify(presentation)
        except CredentialInvalid as e:
            _log.info(
                "gate_decision",
                admitted=False,
                stage="verifier",
                reason=str(e),
                room_id=ctx.room_id.to_bytes().hex(),
            )
            return AdmissionDecision(admitted=False, reason=f"credential invalid: {e}")

        _log.debug(
            "gate_credential_verified",
            verified_at=verified.verified_at.isoformat(),
            revocation_status=verified.revocation_status,
        )

        if verified.revocation_status != "fresh":
            _log.info(
                "gate_decision",
                admitted=False,
                stage="revocation",
                reason=f"revocation_status={verified.revocation_status}",
                room_id=ctx.room_id.to_bytes().hex(),
            )
            return AdmissionDecision(
                admitted=False,
                reason=f"revocation status is {verified.revocation_status}",
            )

        decision = self._policy.evaluate(verified, ctx)
        _log.info(
            "gate_decision",
            admitted=decision.admitted,
            stage="policy",
            policy=type(self._policy).__name__,
            reason=decision.reason,
            room_id=ctx.room_id.to_bytes().hex(),
        )
        return decision


@dataclass(frozen=True)
class JoinRequestPayload:
    """Wire payload of a JOIN_REQUEST IPv8 message."""

    room_id: RoomId
    presentation: Presentation


@dataclass(frozen=True)
class JoinResponsePayload:
    """Wire payload of a JOIN_RESPONSE IPv8 message."""

    room_id: RoomId
    decision: AdmissionDecision
