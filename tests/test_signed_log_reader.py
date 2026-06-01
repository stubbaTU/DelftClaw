from __future__ import annotations

from pathlib import Path

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.accountability_layer.log_reader import open_accountability_log


def test_open_accountability_log_reads_signed_gateway_log(tmp_path: Path) -> None:
    key_path = tmp_path / "identity.json"
    log_path = tmp_path / "gateway.jsonl"
    identity = OpenClawIdentity(network="REGTEST", key_path=key_path)
    signed_log = SignedAppendOnlyLog(identity, log_path=log_path)
    signed_log.append_event(
        reporter_id=identity.public_bundle()["agent_id"],
        subject_id="agent-a",
        action="tool_execution_success",
        details={"tool": "register_seedbox"},
    )

    reader = open_accountability_log(log_path, network="REGTEST", key_path=key_path)
    ok, errors = reader.verify_integrity()

    assert ok is True
    assert errors == []
    assert reader.read_entries()[0]["action"] == "tool_execution_success"
