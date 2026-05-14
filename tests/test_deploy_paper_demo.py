from __future__ import annotations

from pathlib import Path

from deploy.paper_demo import run_paper_demo


def test_paper_demo_covers_full_checklist(tmp_path: Path) -> None:
    result = run_paper_demo(provider="mock", root=tmp_path / "paper-demo", reset=True)

    assert result["ok"] is True
    assert all(result["checklist"].values())
    assert result["final_status"]["community"]["member_count"] == 4
    assert result["final_status"]["community"]["seedbox_count"] == 2
    assert result["security"]["malicious_private_key_probe"]["blocked"] is True
    assert result["security"]["attacker_reputation"]["banned"] is True
    assert result["integrity"]["community_log_after_tamper_ok"] is False
    assert Path(result["community_signed_log_path"]).exists()
    assert Path(result["catalog_path"]).exists()


def test_paper_demo_writes_named_goal_files(tmp_path: Path) -> None:
    result = run_paper_demo(provider="mock", root=tmp_path / "paper-demo", reset=True)

    goal_names = {Path(path).name for path in result["goal_files"].values()}
    assert goal_names == {
        "agent_1_founder.md",
        "agent_2_joiner.md",
        "agent_3_joiner.md",
        "agent_4_scaler.md",
        "agent_file_requester.md",
    }
