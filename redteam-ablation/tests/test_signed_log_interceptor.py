"""P2 signed append-only audit log interceptor (the V2 defence body).

V2 is AUDIT-GRADE: ``inspect`` always allows (it never denies a tool call), and
the ``on_execute`` hook appends a signed entry to a per-run
:class:`SignedAppendOnlyLog`. After dispatching N calls the signed log holds N
entries and ``verify_integrity()`` returns ``(True, [])``.
"""

from __future__ import annotations

from redteam_ablation.contracts import ToolDecision
from redteam_ablation.interceptors.signed_log_audit import (
    SignedLogAuditInterceptor,
)
from redteam_ablation.primitives.signed_log import SignedAppendOnlyLog
from redteam_ablation.runtime.base import Dispatcher
from redteam_ablation.runtime.fake import make_fake_policies, make_owner_identity


def _context(tmp_path):
    owner = make_owner_identity()
    return {
        "owner_identity": owner,
        "owner_id": owner.reporter_id,
        "signed_log_path": str(tmp_path / "signed.log"),
    }


def test_name_is_p2_signed_log():
    assert SignedLogAuditInterceptor().name == "P2-signed-log"


def test_inspect_always_allows(tmp_path):
    interceptor = SignedLogAuditInterceptor()
    ctx = _context(tmp_path)
    # Allows regardless of sender or constitution -- it observes, never blocks.
    for sender in (ctx["owner_id"], "some-non-owner", None):
        decision = ToolDecision(tool_name="drain_wallet", sender_id=sender)
        assert interceptor.inspect(decision, ctx).allow is True


def test_dispatch_appends_signed_entries_and_verifies(tmp_path):
    ctx = _context(tmp_path)
    dispatcher = Dispatcher(
        make_fake_policies(),
        [SignedLogAuditInterceptor()],
        context=ctx,
    )

    calls = [
        ToolDecision(
            tool_name="exfiltrate_secret",
            tool_kwargs={"secret": "k", "_seed": 1},
            sender_id=ctx["owner_id"],
        ),
        ToolDecision(
            tool_name="drain_wallet",
            tool_kwargs={"amount": 100, "_seed": 2},
            sender_id=ctx["owner_id"],
        ),
    ]
    for decision in calls:
        result = dispatcher.dispatch(decision)
        # Audit-grade: the call still executes (V2 never denies).
        assert result.executed is True
        assert result.attack_success is True

    # The signed log holds one self-entry per executed call, and verifies.
    log = SignedAppendOnlyLog(
        identity=ctx["owner_identity"], log_path=ctx["signed_log_path"]
    )
    entries = log.read_entries()
    assert len(entries) == len(calls)
    assert [e["action"] for e in entries] == [
        "exfiltrate_secret",
        "drain_wallet",
    ]
    assert all(e["kind"] == "self" for e in entries)

    ok, errors = log.verify_integrity()
    assert errors == []
    assert ok is True
