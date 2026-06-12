"""P2 -- signed append-only audit log interceptor (the V2 defence body).

V2 is AUDIT-GRADE, not preventive: it produces a tamper-evident record of every
executed tool call but it NEVER denies one. ``inspect`` therefore always allows;
the work happens in the optional ``on_execute`` hook the dispatcher fires after a
successful execution, where the interceptor appends a signed entry to a
:class:`~redteam_ablation.primitives.signed_log.SignedAppendOnlyLog`.

Because V2 only observes (it does not block), its attack-success rate equals
V0's: every dangerous tool still fires. What V2 adds is accountability -- after a
run the signed log holds one entry per executed call and
``verify_integrity()`` returns ``(True, [])``. That is why, in the predicted
matrix, V2 leaves all 8 attacks succeeding while the Audit-trail class does NOT
collapse: the record is signed and chained, so deleting the live log does not
forge the signed accountability trail.

The interceptor reads the owner Ed25519 identity (``context["owner_identity"]``)
and a per-run log path (``context["signed_log_path"]``) from the dispatch context,
so the registry can build one stateless instance and the runtime / runner supplies
the run-specific wiring. The SAME code runs offline and (later) against the live
agent.
"""

from __future__ import annotations

from typing import Any

from redteam_ablation.contracts import ExecutionResult, ToolDecision
from redteam_ablation.interceptors.base import InterceptDecision
from redteam_ablation.primitives.signed_log import SignedAppendOnlyLog


class SignedLogAuditInterceptor:
    """Audit-grade interceptor: signs every executed call, never denies one.

    Stateless with respect to construction: the owner identity and the per-run
    log path are pulled from the dispatch context at ``on_execute`` time, so a
    single registry-built instance works for every episode of a run.
    """

    name = "P2-signed-log"

    def inspect(
        self, decision: ToolDecision, context: dict[str, Any]
    ) -> InterceptDecision:
        """Always allow -- V2 observes executed calls, it never blocks them."""
        return InterceptDecision(allow=True)

    def on_execute(
        self,
        decision: ToolDecision,
        result: ExecutionResult,
        context: dict[str, Any],
    ) -> None:
        """Append a signed self-entry recording the executed tool call.

        ``action`` is the executed tool name; ``details`` is the call's kwargs.
        The entry is signed by the owner identity and chained into the per-run
        signed append-only log at ``context['signed_log_path']``.
        """
        identity = context.get("owner_identity")
        log_path = context.get("signed_log_path")
        if identity is None or log_path is None:
            # Without an owner identity AND a log path we cannot produce a
            # signed, chained entry. The audit primitive degrades to a no-op
            # rather than fabricating an unsigned record. (The runner / fake
            # supply both; a context missing them is a wiring bug, not an
            # adversarial input, so we fail open on the AUDIT side -- the tool
            # already executed regardless.)
            return

        log = SignedAppendOnlyLog(identity=identity, log_path=log_path)
        owner_id = context.get("owner_id", identity.reporter_id)
        log.append_event(
            reporter_id=owner_id,
            subject_id=owner_id,
            action=decision.tool_name,
            details=dict(decision.tool_kwargs),
        )
