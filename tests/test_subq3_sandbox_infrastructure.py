from __future__ import annotations

from pathlib import Path

from security.subq3_integrity.prepare_sandbox_workspace import prepare_workspace
from security.subq3_integrity.sandbox_doctor import run_sandbox_checks


def test_prepare_subq3_workspace_creates_manifest_and_prompt(tmp_path: Path) -> None:
    manifest = prepare_workspace(
        root=tmp_path,
        run_id="subq3-gvisor-dryrun001",
        condition="gvisor",
        gateway_url="http://127.0.0.1:8765",
        agent_id="agent",
    )

    manifest_path = Path(manifest["manifest_path"])
    assert manifest_path.exists()
    assert Path(manifest["host_log_path"]).exists()
    assert Path(manifest["host_secret_path"]).exists()
    assert Path(manifest["iptables_rules_path"]).exists()
    assert Path(manifest["sandbox_workspace"]).exists()
    assert Path(manifest["sandbox_artifacts_dir"], "Dockerfile.gvisor").exists()

    prompt = Path(manifest["prompt_path"]).read_text(encoding="utf-8")
    assert "{LOG_PATH}" not in prompt
    assert "{HOST_SECRET_PATH}" not in prompt
    assert manifest["host_log_path"] in prompt
    assert manifest["host_secret_path"] in prompt


def test_subq3_sandbox_doctor_accepts_prepared_workspace_without_requiring_gvisor(tmp_path: Path) -> None:
    manifest = prepare_workspace(
        root=tmp_path,
        run_id="subq3-gvisor-dryrun001",
        condition="gvisor",
        agent_id="agent",
    )

    report = run_sandbox_checks(manifest["manifest_path"])

    assert report["ok"] is True
    assert report["run_id"] == "subq3-gvisor-dryrun001"
    assert report["condition"] == "gvisor"


def test_subq3_sandbox_doctor_detects_host_target_tampering(tmp_path: Path) -> None:
    manifest = prepare_workspace(
        root=tmp_path,
        run_id="subq3-gvisor-dryrun001",
        condition="gvisor",
        agent_id="agent",
    )
    Path(manifest["host_secret_path"]).write_text("tampered\n", encoding="utf-8")

    report = run_sandbox_checks(manifest["manifest_path"])
    failed = {check["name"] for check in report["checks"] if not check["ok"]}

    assert report["ok"] is False
    assert "baseline_hashes_match" in failed
