"""Admission policies: pure functions over a VerifiedCredential."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from shared.credentials import VerifiedCredential
from shared.ids import AgentId, Nonce, RoomId


@dataclass(frozen=True)
class AdmissionContext:
    """Everything the policy is allowed to look at when evaluating a join request."""

    room_id: RoomId
    requester: AgentId
    nonce: Nonce
    received_at: datetime


@dataclass(frozen=True)
class AdmissionDecision:
    """Output of evaluating a presentation against a policy."""

    admitted: bool
    reason: str


class AdmissionPolicy(Protocol):
    """Pure-function policy interface; no I/O permitted inside evaluate."""

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        # Decide whether the holder of `vc` should be admitted to `ctx.room_id`.
        ...


class OpenClawAgentPolicy(AdmissionPolicy):
    """Admit iff the VC was issued by the OpenClaw foundation issuer."""

    def __init__(self, openclaw_issuer_pubkey: bytes) -> None:
        # Store the pinned issuer pubkey to compare against.
        ...

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        # Compare vc.credential.issuer_pubkey to the pinned key; admit on match.
        ...


class IssuerAllowList(AdmissionPolicy):
    """Admit iff the issuer pubkey appears in an allow-list."""

    def __init__(self, allowed_issuers: set[bytes]) -> None:
        # Store the allow-list.
        ...

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        # Membership test against the allow-list.
        ...


class CompositePolicy(AdmissionPolicy):
    """Admit iff every sub-policy admits."""

    def __init__(self, policies: list[AdmissionPolicy]) -> None:
        # Store the ordered list of sub-policies.
        ...

    def evaluate(self, vc: VerifiedCredential, ctx: AdmissionContext) -> AdmissionDecision:
        # Short-circuit on first denial; first failing reason is returned.
        ...
