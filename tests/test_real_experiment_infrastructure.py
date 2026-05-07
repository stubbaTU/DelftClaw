from __future__ import annotations

import json
from pathlib import Path

from security.real_experiments.export_gateway_evidence import export_evidence
from security.real_experiments.save_response import save_response
from security.subq2_accountability.append_log import AppendOnlyLog


def test_append_log_adds_run_metadata(tmp_path: Path) -> None:
    log_path = tmp_path / "gateway.jsonl"
    log = AppendOnlyLog(
        str(log_path),
        run_metadata={
            "run_id": "subq1-defended-run001",
            "experiment_condition": "defended",
        },
    )

    entry = log.append_event(
        reporter_id="gateway",
        subject_id="agent",
        action="tool_execution_success",
        details={"tool": "send_message"},
    )

    assert entry["run_id"] == "subq1-defended-run001"
    assert entry["experiment_condition"] == "defended"
    assert entry["run_metadata"]["run_id"] == "subq1-defended-run001"
    assert log.verify_integrity()[0] is True


def test_save_response_and_export_evidence_with_run_rows(tmp_path: Path) -> None:
    root = tmp_path / "experiment"
    manifest_path = root / "canary_manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "canaries": [
                    {
                        "name": "mock_private_key",
                        "value": "DELFTCLAW_CANARY_TEST",
                        "sha256": "test-sha",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    save_response(
        root=root,
        run_id="subq1-defended-run001",
        prompt_id="private-key-001",
        response_text="response leaked DELFTCLAW_CANARY_TEST",
        condition="defended",
        agent_id="agent",
    )

    log_path = tmp_path / "gateway.jsonl"
    log = AppendOnlyLog(
        str(log_path),
        run_metadata={
            "run_id": "subq1-defended-run001",
            "experiment_condition": "defended",
        },
    )
    log.append_event(
        reporter_id="gateway",
        subject_id="agent",
        action="unauthorized_tool_request",
        severity=10,
        details={"tool": "exfiltrate_private_key"},
    )

    summary = export_evidence(
        log_path=log_path,
        output_dir=tmp_path / "results",
        canary_manifest=manifest_path,
        responses_dir=root / "responses",
    )

    assert summary["response_count"] == 1
    assert summary["canary_leaks"][0]["canary_name"] == "mock_private_key"
    assert summary["runs"][0]["run_id"] == "subq1-defended-run001"
    assert summary["subjects"][0]["conditions"] == "defended"
    assert (tmp_path / "results" / "real_gateway_runs.csv").exists()
