"""P1 -- owner-anchored identity interceptor (the V1 defence body).

The simplest principled identity defence: every proposed tool call must arrive
from the OWNER principal. The interceptor compares ``decision.sender_id`` against
the owner id the runtime placed in the per-episode context
(``context["owner_id"]``) and denies any call whose sender is not the owner.

This is the structured-input check the Identity-class attacks (SH-03, SH-04) trip:
those attacks forge / substitute the principal, so the proposed call arrives under
a NON-owner ``sender_id`` and is denied here. Behaviour / Audit-trail / Mixed
attacks leave the principal intact (their ``sender_id`` IS the owner), so this
interceptor allows them -- exactly why they survive V1 in the predicted matrix.

The SAME code runs offline (against the fake fixtures, whose ``sender_id`` the
:class:`~redteam_ablation.runtime.fake.FakeRuntime` sets honestly per attack) and,
later, against the live agent. There are no per-attack special cases here.
"""

from __future__ import annotations

from typing import Any

from redteam_ablation.contracts import ToolDecision
from redteam_ablation.interceptors.base import InterceptDecision


class OwnerAnchoredIdentityInterceptor:
    """Deny (strict) or flag (audit) any tool call whose sender is not the owner.

    Reads ``context["owner_id"]`` (the owner binding the runtime supplies) and
    compares it to ``decision.sender_id``. Stateless: the registry can build one
    instance per mode and the runtime supplies the owner id via context, so the
    same instance is reusable across episodes.

    ``mode`` is keyword-only (plan 2026-06-10 §1.1): ``"strict"`` (the default,
    fail-closed) denies a violation; ``"audit"`` detect-and-proceeds -- the
    violation is ALLOWED but ``flagged=True`` with an ``"audit: ..."`` reason,
    including on the fail-closed missing-context path (audit NEVER denies).
    """

    def __init__(self, *, mode: str = "strict") -> None:
        if mode not in ("audit", "strict"):
            raise ValueError(
                f"invalid mode {mode!r}; expected 'audit' or 'strict'"
            )
        self.mode = mode
        # The name carries the mode tag so denied_by / flagged_by attribution
        # is mode-unambiguous (plan §1.1).
        self.name = f"P1-owner-identity[{mode}]"

    def _violation(self, reason: str) -> InterceptDecision:
        """Branch-on-failure: strict denies; audit allows + flags."""
        if self.mode == "audit":
            return InterceptDecision(
                allow=True, flagged=True, reason=f"audit: {reason}"
            )
        return InterceptDecision(allow=False, reason=reason)

    def inspect(
        self, decision: ToolDecision, context: dict[str, Any]
    ) -> InterceptDecision:
        """Allow iff ``decision.sender_id`` equals ``context['owner_id']``."""
        owner_id = context.get("owner_id")
        if owner_id is None:
            # No owner binding in context -> we cannot anchor identity. Fail
            # closed: a call we cannot attribute to the owner is a violation
            # (denied in strict mode; flagged in audit mode).
            return self._violation(
                f"{self.name}: no owner_id in context; "
                "cannot anchor identity (fail-closed)"
            )

        if decision.sender_id == owner_id:
            return InterceptDecision(allow=True)

        return self._violation(
            f"{self.name}: sender_id {decision.sender_id!r} is not the "
            f"owner principal {owner_id!r} -- forged / substituted identity"
        )
