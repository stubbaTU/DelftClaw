"""Sanity tests: the bundled payment scenario.yaml + missions parse.

These pin the shape of the payment demo (admission Act 1 + peer-to-peer
payments Act 2 + overlay authoring) so a careless edit to scenario.yaml or
a mission.md breaks the suite, not the ``make scenario`` run on the VPS.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from deploy.scenario import parse_scenario
from deploy import scenario_boot
from deploy.scenario_boot import _build_manifest_md, _instance_env_contents


REPO_ROOT = Path(__file__).resolve().parent.parent
PAYMENT = REPO_ROOT / "deploy" / "scenarios" / "payment"


@pytest.fixture(scope="module")
def scenario():
    return parse_scenario(PAYMENT / "scenario.yaml")


# ---------------------------------------------------------------------------
# Scenario shape
# ---------------------------------------------------------------------------


def test_payment_has_three_agents(scenario):
    assert set(scenario.agents) == {"alice", "bob", "charlie"}


def test_payment_scenario_flags(scenario):
    assert scenario.payment_mode is True
    assert scenario.wire_distribute_overlays is True
    assert scenario.evolution_base_overlay == "payment_receipt"


def test_payment_agent_ports_are_contiguous_within_window(scenario):
    ipv8s = [a.ipv8_port for a in scenario.agents.values()]
    mcps = [a.mcp_port for a in scenario.agents.values()]
    signed_logs = [a.signed_log_port for a in scenario.agents.values()]
    assert sorted(ipv8s) == [8190, 8191, 8192]
    assert sorted(mcps) == [18765, 18766, 18767]
    assert sorted(signed_logs) == [28765, 28766, 28767]


def test_payment_alice_is_founder_and_publisher(scenario):
    alice = scenario.agents["alice"]
    assert alice.stop_predicate == "never"
    assert alice.overlay_author_role == ""
    # Alice publishes the payment-request overlay; joiners wire-fetch it.
    assert [p.name for p in alice.publish_overlays] == ["payment_request.md"]
    assert alice.initial_balance_sats >= 100_000  # bootstraps treasury + pays
    # No peers entry → alice is the most-referenced agent (genesis).
    assert alice.peers == ()


def test_payment_genesis_and_successor_roles(scenario):
    bob = scenario.agents["bob"]
    charlie = scenario.agents["charlie"]
    assert bob.overlay_author_role == "genesis"
    assert charlie.overlay_author_role == "successor"
    assert bob.stop_predicate == "paid_and_overlay_authored_and_announce_sent"
    assert charlie.stop_predicate == "paid_and_overlay_authored"
    # Joiners mesh with alice AND each other (genesis offers/announces to
    # the successor; the successor adopts from the genesis).
    assert set(bob.peers) == {"alice", "charlie"}
    assert set(charlie.peers) == {"alice", "bob"}


def test_payment_genesis_picks_alice(scenario):
    assert scenario_boot._pick_genesis(scenario) == "alice"


def test_payment_joiners_have_author_tools(scenario):
    """bob/charlie must have overlay_author_and_publish in their allowlist so
    the watchdog's _should_author_overlay nudge fires."""
    assert "overlay_author_and_publish" in (scenario.agents["bob"].mcp_tool_allowlist or ())
    assert "request_payment" in (scenario.agents["bob"].mcp_tool_allowlist or ())
    assert "overlay_author_and_publish" in (scenario.agents["charlie"].mcp_tool_allowlist or ())
    assert "send_payment" in (scenario.agents["alice"].mcp_tool_allowlist or ())


def test_payment_roles_in_missions(scenario):
    from deploy.mission import parse_mission
    alice = parse_mission((PAYMENT / "alice" / "mission.md").read_text())
    assert alice.role == "seedbox"
    for joiner in ("bob", "charlie"):
        mission = parse_mission((PAYMENT / joiner / "mission.md").read_text())
        assert mission.role == "seeker"
        assert mission.name == joiner


def test_payment_generated_manifest_has_overlay_no_growth(scenario):
    manifest_md = _build_manifest_md(
        scenario=scenario,
        genesis_name="alice",
        genesis_coords={
            "wallet_address": "dclaw1demo",
            "host": "127.0.0.1",
            "port": 8190,
            "pubkey_hex": "aa" * 37,
        },
        default_overlay_hashes=["b" * 40],
    )

    assert "- bootstrap_cap_sats: 100000" in manifest_md
    assert "- sha1: " + "b" * 40 in manifest_md   # alice's published overlay
    assert "max_agents_per_seedbox" not in manifest_md
    assert "seedbox_cost_sats" not in manifest_md


# ---------------------------------------------------------------------------
# Env-file cross-wiring (Phase 6 pull-loop URLs)
# ---------------------------------------------------------------------------


def test_payment_env_files_cross_wire_pull_loop(scenario):
    """Every agent's env file lists every OTHER agent's signed_log URL, and
    flips PAYMENT_MODE + the evolution env."""
    expected_signed_log = {
        "alice": 28765,
        "bob": 28766,
        "charlie": 28767,
    }
    for name, agent in scenario.agents.items():
        body = _instance_env_contents(scenario, agent)
        url_lines = [ln for ln in body.split("\n") if ln.startswith("PEER_LOG_URLS=")]
        assert len(url_lines) == 1, f"{name}: missing or duplicate PEER_LOG_URLS"
        urls = url_lines[0].removeprefix("PEER_LOG_URLS=").split()
        peer_ports = sorted(int(u.rsplit(":", 1)[1]) for u in urls)
        expected_peers = sorted(
            port for other, port in expected_signed_log.items() if other != name
        )
        assert peer_ports == expected_peers, (
            f"{name}: peer URLs mismatch — got {peer_ports}, expected {expected_peers}"
        )
        own_line = [ln for ln in body.split("\n") if ln.startswith("SIGNED_LOG_PORT=")]
        assert own_line == [f"SIGNED_LOG_PORT={expected_signed_log[name]}"]
        assert f"PAYMENT_MODE=1" in body
        assert "EVOLUTION_BASE_OVERLAY_NAME=payment_receipt" in body


def test_payment_overlay_author_mode_env(scenario):
    """bob -> genesis, charlie -> successor, alice -> '' in OVERLAY_AUTHOR_MODE."""
    modes = {}
    for name, agent in scenario.agents.items():
        body = _instance_env_contents(scenario, agent)
        line = [ln for ln in body.split("\n") if ln.startswith("OVERLAY_AUTHOR_MODE=")][0]
        modes[name] = line.removeprefix("OVERLAY_AUTHOR_MODE=")
    assert modes == {"alice": "", "bob": "genesis", "charlie": "successor"}


def test_openclaw_provider_config_uses_config_set(monkeypatch, tmp_path, scenario):
    """The VPS CLI may not support ``config patch --stdin``; boot uses config set.

    Pins the openai provider config the boot writes (the project's single
    provider, read from the LLM_* / LLM_API_PROVIDER env)."""
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:11600/v1")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_API_PROVIDER", "openai")
    monkeypatch.delenv("OPENCLAW_MODEL", raising=False)

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
        "models.providers.openai",
    ]
    assert all("--stdin" not in cmd for cmd in commands)

    provider = json.loads(config_commands[2][config_commands[2].index("set") + 2])
    assert provider["api"] == "openai-completions"
    assert provider["baseUrl"] == "http://127.0.0.1:11600/v1/"
    assert provider["models"] == [
        {
            "id": "claude-test-model",
            "name": "claude-test-model",
            "reasoning": False,
            "input": ["text"],
            "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
            "contextWindow": 32768,
            "maxTokens": 4096,
        }
    ]
