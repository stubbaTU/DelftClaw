"""Stake-bonded admission policy. Plugs into ``CompositePolicy`` next to VC policies."""

from __future__ import annotations

from communication.trustroom.policy import (
    AdmissionContext,
    AdmissionDecision,
    AdmissionPolicy,
)
from shared.credentials import VerifiedCredential
from stake.oracle import StakeOracle


def admission_purpose(ctx: AdmissionContext) -> str:
    """The lock-purpose string a joiner must use when locking stake for this room."""
    return f"admission:room={ctx.room_id.to_bytes().hex()}"


class StakedAdmissionPolicy(AdmissionPolicy):
    """Admit iff the joiner has at least ``min_sats`` locked under the room's purpose."""

    def __init__(self, oracle: StakeOracle, min_sats: int) -> None:
        if min_sats <= 0:
            raise ValueError("min_sats must be positive")
        self._oracle = oracle
        self._min_sats = int(min_sats)

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        proof = ctx.stake_proof
        if proof is None:
            return AdmissionDecision(admitted=False, reason="no stake proof on presentation")

        expected_purpose = admission_purpose(ctx)
        if proof.purpose != expected_purpose:
            return AdmissionDecision(
                admitted=False,
                reason=f"stake proof purpose mismatch (got {proof.purpose!r}, expected {expected_purpose!r})",
            )

        if proof.actor != ctx.requester:
            return AdmissionDecision(
                admitted=False,
                reason="stake proof actor differs from requester",
            )

        if proof.min_sats < self._min_sats:
            return AdmissionDecision(
                admitted=False,
                reason=f"stake claim below threshold ({proof.min_sats} < {self._min_sats})",
            )

        if not self._oracle.has_lock(proof.actor, expected_purpose, self._min_sats):
            return AdmissionDecision(
                admitted=False,
                reason=f"insufficient locked stake (need {self._min_sats})",
            )

        return AdmissionDecision(
            admitted=True,
            reason=f"verified stake of at least {self._min_sats} sats",
        )
