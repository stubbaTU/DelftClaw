"""Admission policies: pure functions over a VerifiedCredential."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from shared.credentials import VerifiedCredential
from shared.ids import AgentId, Nonce, RoomId

if TYPE_CHECKING:
    from stake.proof import StakeProof


@dataclass(frozen=True)
class AdmissionContext:
    """Everything the policy is allowed to look at when evaluating a join request."""

    room_id: RoomId
    requester: AgentId
    nonce: Nonce
    received_at: datetime
    stake_proof: "StakeProof | None" = None


@dataclass(frozen=True)
class AdmissionDecision:
    """Output of evaluating a presentation against a policy."""

    admitted: bool
    reason: str


class AdmissionPolicy(Protocol):
    """Pure-function policy interface; no I/O permitted inside evaluate."""

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision: ...


class OpenClawAgentPolicy(AdmissionPolicy):
    """Admit iff the VC was issued by the OpenClaw foundation issuer."""

    def __init__(self, openclaw_issuer_pubkey: bytes) -> None:
        self._pinned = bytes(openclaw_issuer_pubkey)

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        if vc.credential.issuer_pubkey == self._pinned:
            return AdmissionDecision(admitted=True, reason="issuer matches OpenClaw foundation key")
        return AdmissionDecision(admitted=False, reason="issuer is not the OpenClaw foundation key")


class IssuerAllowList(AdmissionPolicy):
    """Admit iff the issuer pubkey appears in an allow-list."""

    def __init__(self, allowed_issuers: set[bytes]) -> None:
        self._allowed = {bytes(p) for p in allowed_issuers}

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        if vc.credential.issuer_pubkey in self._allowed:
            return AdmissionDecision(admitted=True, reason="issuer in allow-list")
        return AdmissionDecision(admitted=False, reason="issuer not in allow-list")


class CompositePolicy(AdmissionPolicy):
    """Admit iff every sub-policy admits."""

    def __init__(self, policies: list[AdmissionPolicy]) -> None:
        self._policies = list(policies)

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        for p in self._policies:
            decision = p.evaluate(vc, ctx)
            if not decision.admitted:
                return decision
        return AdmissionDecision(admitted=True, reason="all sub-policies admitted")
