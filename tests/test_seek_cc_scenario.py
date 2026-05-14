"""Phase-7 sanity tests: the bundled seek_cc scenario.yaml + missions parse.

These pin the shape of the canonical demo scenario so a careless
edit to scenario.yaml or a mission.md breaks the suite, not the
``make scenario`` run on the VPS.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from deploy.scenario import parse_scenario
from deploy import scenario_boot
from deploy.scenario_boot import _instance_env_contents


REPO_ROOT = Path(__file__).resolve().parent.parent
SEEK_CC = REPO_ROOT / "deploy" / "scenarios" / "seek_cc"


@pytest.fixture(scope="module")
def scenario():
    return parse_scenario(SEEK_CC / "scenario.yaml")


# ---------------------------------------------------------------------------
# Scenario shape
# ---------------------------------------------------------------------------


def test_seek_cc_has_four_agents(scenario):
    assert set(scenario.agents) == {"alice", "bob", "charlie", "dave"}


def test_seek_cc_agent_ports_are_contiguous_within_window(scenario):
    ipv8s = [a.ipv8_port for a in scenario.agents.values()]
    mcps = [a.mcp_port for a in scenario.agents.values()]
    redteams = [a.redteam_port for a in scenario.agents.values()]
    assert sorted(ipv8s) == [8190, 8191, 8192, 8193]
    assert sorted(mcps) == [18765, 18766, 18767, 18768]
    assert sorted(redteams) == [28765, 28766, 28767, 28768]


def test_seek_cc_alice_is_founder(scenario):
    alice = scenario.agents["alice"]
    assert alice.stop_predicate == "never"
    assert alice.publish_overlays  # serves the content community overlay
    assert alice.initial_balance_sats >= 100_000  # bootstraps treasury
    # Alice has no peers entry (everyone else peers WITH her at IPv8 boot,
    # but alice doesn't need that pre-introduction).
    assert alice.peers == ()


def test_seek_cc_joiners_peer_with_alice(scenario):
    for name in ("bob", "charlie", "dave"):
        agent = scenario.agents[name]
        assert agent.peers == ("alice",)
        assert agent.stop_predicate == "torrent_progress_gte_1"
        assert agent.initial_balance_sats > 0


def test_seek_cc_joiners_have_seeker_role(scenario):
    """Joiner missions declare ``role: seeker``. Founder declares ``role: seedbox``."""
    from deploy.mission import parse_mission
    alice = parse_mission((SEEK_CC / "alice" / "mission.md").read_text())
    assert alice.role == "seedbox"
    for joiner in ("bob", "charlie", "dave"):
        mission = parse_mission((SEEK_CC / joiner / "mission.md").read_text())
        assert mission.role == "seeker"
        assert mission.name == joiner


# ---------------------------------------------------------------------------
# Env-file cross-wiring (Phase 6 pull-loop URLs)
# ---------------------------------------------------------------------------


def test_seek_cc_env_files_cross_wire_pull_loop(scenario):
    """Every agent's env file lists every OTHER agent's redteam URL."""
    expected_redteam = {
        "alice": 28765,
        "bob": 28766,
        "charlie": 28767,
        "dave": 28768,
    }
    for name, agent in scenario.agents.items():
        body = _instance_env_contents(scenario, agent)
        # Find the PEER_LOG_URLS line, parse it.
        url_lines = [ln for ln in body.split("\n") if ln.startswith("PEER_LOG_URLS=")]
        assert len(url_lines) == 1, f"{name}: missing or duplicate PEER_LOG_URLS"
        urls = url_lines[0].removeprefix("PEER_LOG_URLS=").split()
        # Cross-wired: every other agent's port should be in our peer list.
        peer_ports = sorted(int(u.rsplit(":", 1)[1]) for u in urls)
        expected_peers = sorted(
            port for other, port in expected_redteam.items() if other != name
        )
        assert peer_ports == expected_peers, (
            f"{name}: peer URLs mismatch — got {peer_ports}, expected {expected_peers}"
        )
        # Our own redteam port is in REDTEAM_PORT, not PEER_LOG_URLS.
        own_line = [ln for ln in body.split("\n") if ln.startswith("REDTEAM_PORT=")]
        assert own_line == [f"REDTEAM_PORT={expected_redteam[name]}"]


def test_openclaw_provider_config_uses_config_set(monkeypatch, tmp_path, scenario):
    """The VPS CLI may not support ``config patch --stdin``; boot uses config set."""
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        commands.append(list(cmd))
        if cmd[-2:] == ["list", "--json"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="[]")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(scenario_boot, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(scenario_boot, "_sudo", lambda *args, **kwargs: None)
    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)

    scenario_boot._provision_openclaw_workspace(scenario, scenario.agents["alice"])

    config_commands = [
        cmd for cmd in commands
        if "openclaw" in cmd
        and cmd[cmd.index("openclaw"):cmd.index("openclaw") + 3] == [
            "openclaw", "config", "set"
        ]
    ]
    paths = [cmd[cmd.index("set") + 1] for cmd in config_commands]
    assert paths == [
        "agents.defaults.timeoutSeconds",
        "models.mode",
        "models.providers.ollama",
    ]
    assert all("--stdin" not in cmd for cmd in commands)

    provider = json.loads(config_commands[2][config_commands[2].index("set") + 2])
    assert provider["api"] == "ollama"
    assert provider["models"] == [
        {
            "id": scenario_boot.QWEN_MODEL,
            "name": scenario_boot.QWEN_MODEL,
            "reasoning": False,
            "input": ["text"],
            "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
            "contextWindow": 32768,
            "maxTokens": 4096,
        }
    ]
