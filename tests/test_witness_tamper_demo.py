"""End-to-end test for the witness-tamper-and-forward demo orchestrator."""

from __future__ import annotations

import pytest

from redteam.demo.witness_tamper.run_demo import run_demo


def test_run_demo_end_to_end_bans_b(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_demo()
    assert exit_code == 0

    out = capsys.readouterr().out

    assert "[setup]" in out
    assert "[tamper]" in out
    assert "[server]" in out
    assert "[forward] C rejected the tampered entry: HTTP 400" in out
    assert "Expelling" in out
    assert "BANNED" in out
    assert "Score: 20" in out
    assert "[done]" in out
