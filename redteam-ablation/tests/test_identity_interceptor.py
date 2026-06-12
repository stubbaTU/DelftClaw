"""P1 owner-anchored identity interceptor (the V1 defence body).

The interceptor denies any proposed tool call whose ``sender_id`` is not the
owner principal recorded in ``context['owner_id']``, and allows the owner. This
is the structured-input check the Identity-class attacks (SH-03, SH-04) trip.
"""

from __future__ import annotations

from redteam_ablation.contracts import ToolDecision
from redteam_ablation.interceptors.identity_check import (
    OwnerAnchoredIdentityInterceptor,
)

OWNER = "owner-principal-id"
NON_OWNER = "spoofed-non-owner-id"


def _decision(sender_id):
    return ToolDecision(
        tool_name="write_memory",
        tool_kwargs={"k": "v"},
        sender_id=sender_id,
    )


def test_name_is_p1_owner_identity():
    # Plan 2026-06-10 §1.1: the name carries the mode tag; the default mode is strict.
    assert OwnerAnchoredIdentityInterceptor().name == "P1-owner-identity[strict]"


def test_allows_owner_sender():
    interceptor = OwnerAnchoredIdentityInterceptor()
    verdict = interceptor.inspect(_decision(OWNER), {"owner_id": OWNER})
    assert verdict.allow is True


def test_denies_non_owner_sender():
    interceptor = OwnerAnchoredIdentityInterceptor()
    verdict = interceptor.inspect(_decision(NON_OWNER), {"owner_id": OWNER})
    assert verdict.allow is False
    assert verdict.reason  # a non-empty attribution reason is recorded


def test_denies_when_sender_is_none():
    interceptor = OwnerAnchoredIdentityInterceptor()
    verdict = interceptor.inspect(_decision(None), {"owner_id": OWNER})
    assert verdict.allow is False


def test_fails_closed_when_no_owner_in_context():
    interceptor = OwnerAnchoredIdentityInterceptor()
    verdict = interceptor.inspect(_decision(OWNER), {})
    assert verdict.allow is False
