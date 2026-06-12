"""SignedAppendOnlyLog round-trip with the local Ed25519 identity adapter."""

import json

from redteam_ablation.primitives.identity import Ed25519Identity
from redteam_ablation.primitives.signed_log import SignedAppendOnlyLog


def test_append_self_events_verifies_clean(tmp_path):
    identity = Ed25519Identity(network="MAINNET")
    log_path = tmp_path / "agent_actions.log"
    log = SignedAppendOnlyLog(identity, log_path)

    rid = identity.reporter_id
    log.append_event(
        reporter_id=rid,
        subject_id=rid,
        action="tool_execution_success",
        details={"tool": "send_email", "to": "ally@example.com"},
        severity=1,
    )
    log.append_event(
        reporter_id=rid,
        subject_id=rid,
        action="llm_decision",
        details={"chosen": "no-op"},
    )

    ok, errors = log.verify_integrity()
    assert ok is True, errors
    assert errors == []


def test_chain_links_two_entries(tmp_path):
    identity = Ed25519Identity()
    log_path = tmp_path / "chain.log"
    log = SignedAppendOnlyLog(identity, log_path)
    rid = identity.reporter_id

    first = log.append_event(
        reporter_id=rid, subject_id=rid, action="a", details={"i": 1}
    )
    second = log.append_event(
        reporter_id=rid, subject_id=rid, action="b", details={"i": 2}
    )

    assert first["previous_hash"] == "GENESIS"
    assert second["previous_hash"] == first["entry_hash"]


def test_tampering_a_persisted_entry_breaks_verify(tmp_path):
    identity = Ed25519Identity()
    log_path = tmp_path / "tamper.log"
    log = SignedAppendOnlyLog(identity, log_path)
    rid = identity.reporter_id
    log.append_event(reporter_id=rid, subject_id=rid, action="a", details={"x": 1})

    # Format-independent tamper (Finding 4): parse the entry line as JSON, flip
    # ONE nibble of the signature, re-serialize, and write it back. This does not
    # depend on the persisted whitespace/separator style the way a raw string
    # replace does, mirroring test_verify_cli.py.
    lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
    # lines[0] is the header; lines[1] is the first (only) entry.
    entry = json.loads(lines[1])
    sig = entry["signature"]
    flipped = "1" if sig[0] != "1" else "2"
    entry["signature"] = flipped + sig[1:]
    lines[1] = json.dumps(entry) + "\n"
    log_path.write_text("".join(lines), encoding="utf-8")

    ok, errors = log.verify_integrity()
    assert ok is False
    assert errors
