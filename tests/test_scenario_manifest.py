"""Scenario manifest parser tests.

Happy path: a minimal valid manifest produces a Scenario with the right
shape. Rejection paths: each validation rule kills the parser at boot.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from deploy.scenario import ScenarioError, parse_scenario

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Fixture: write a minimal-but-valid scenario tree into tmp_path
# ---------------------------------------------------------------------------

VALID_BASE = {
    "name": "smoke",
    "description": "smoke test scenario",
    "watchdog": {
        "interval_s": 30,
        "max_iterations_per_turn": 8,
        "max_total_turns": 50,
        "max_wall_clock_s": 1800,
    },
    "agents": {
        "alice": {
            "ipv8_port": 8190,
            "mcp_port": 18765,
            "publish_overlays": ["protocol/examples/content_community.md"],
            "mission_file": "alice/mission.md",
            "stop_predicate": "never",
        },
        "bob": {
            "ipv8_port": 8191,
            "mcp_port": 18766,
            "publish_overlays": [],
            "mission_file": "bob/mission.md",
            "stop_predicate": "torrent_progress_gte_1",
            "peers": ["alice"],
        },
    },
}


def _mission_md(name: str, stop_predicate: str = "never") -> str:
    """A minimal valid mission for tests."""
    return (
        f"# Identity\n"
        f"- name: {name}\n"
        f"- role: general\n"
        f"\n"
        f"# Intent\n"
        f"Test agent {name}; exercise the scenario parser.\n"
        f"\n"
        f"# Budget\n"
        f"- max_sats_outbound: 1000\n"
        f"- max_total_turns: 10\n"
        f"\n"
        f"# Stop\n"
        f"- predicate: {stop_predicate}\n"
    )


def _write_scenario(tmp_path: Path, manifest: dict) -> Path:
    """Materialise ``manifest`` + the per-agent mission.md files in tmp."""
    scenario_dir = tmp_path / manifest["name"]
    scenario_dir.mkdir(parents=True)
    for agent_name, agent in manifest["agents"].items():
        agent_dir = scenario_dir / agent_name
        agent_dir.mkdir()
        stop = agent.get("stop_predicate", "never")
        # stop_predicate may include parameters like "peer_count_gte_N(n=2)";
        # mission only carries the predicate name itself unchanged.
        (agent_dir / "mission.md").write_text(_mission_md(agent_name, stop))
    path = scenario_dir / "scenario.yaml"
    path.write_text(yaml.safe_dump(manifest))
    return path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_minimal_scenario_parses(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    path = _write_scenario(tmp_path, manifest)

    s = parse_scenario(path)
    assert s.name == "smoke"
    assert set(s.agents) == {"alice", "bob"}
    assert s.agents["alice"].ipv8_port == 8190
    assert s.agents["bob"].peers == ("alice",)
    assert s.watchdog.interval_s == 30
    assert s.instance_id("alice") == "smoke-alice"


def test_seed_content_parses(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["alice"]["seed_content"] = [
        {"magnet": "magnet:?xt=urn:btih:abc&dn=foo.mp3",
         "name": "foo.mp3", "size": 1234, "mime": "audio/mpeg", "tags": ["cc"]},
    ]
    path = _write_scenario(tmp_path, manifest)
    s = parse_scenario(path)
    seed = s.agents["alice"].seed_content
    assert len(seed) == 1
    assert seed[0].name == "foo.mp3"
    assert seed[0].tags == ("cc",)


# ---------------------------------------------------------------------------
# Rejection cases
# ---------------------------------------------------------------------------

def test_missing_top_level_key(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    del manifest["watchdog"]
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="watchdog"):
        parse_scenario(path)


def test_unknown_stop_predicate(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["bob"]["stop_predicate"] = "no_such_predicate"
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="stop_predicate"):
        parse_scenario(path)


def test_peer_references_unknown_agent(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["bob"]["peers"] = ["ghost"]
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="ghost"):
        parse_scenario(path)


def test_self_peer_rejected(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["bob"]["peers"] = ["bob"]
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="cannot peer with itself"):
        parse_scenario(path)


def test_ipv8_port_collision(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["bob"]["ipv8_port"] = manifest["agents"]["alice"]["ipv8_port"]
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="ipv8_port"):
        parse_scenario(path)


def test_mcp_port_collision(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["bob"]["mcp_port"] = manifest["agents"]["alice"]["mcp_port"]
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="mcp_port"):
        parse_scenario(path)


def test_same_port_for_ipv8_and_mcp_rejected(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["alice"]["mcp_port"] = manifest["agents"]["alice"]["ipv8_port"]
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="must differ"):
        parse_scenario(path)


def test_publish_overlay_path_must_exist(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["alice"]["publish_overlays"] = ["protocol/examples/no_such.md"]
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="publish_overlay"):
        parse_scenario(path)


def test_mission_file_must_exist(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    # Build the layout WITHOUT alice/mission.md so the parser fails on it.
    scenario_dir = tmp_path / manifest["name"]
    scenario_dir.mkdir(parents=True)
    (scenario_dir / "alice").mkdir()
    (scenario_dir / "bob").mkdir()
    (scenario_dir / "bob" / "mission.md").write_text(_mission_md("bob", "torrent_progress_gte_1"))
    path = scenario_dir / "scenario.yaml"
    path.write_text(yaml.safe_dump(manifest))
    with pytest.raises(ScenarioError, match="mission_file"):
        parse_scenario(path)


def test_legacy_persona_file_raises_migration_error(tmp_path: Path):
    """Pre-v5.1 scenarios with persona_file/goal_file are a fatal migration error."""
    manifest = _copy(VALID_BASE)
    manifest["agents"]["alice"]["persona_file"] = "alice/persona.md"  # legacy key
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="persona_file.*removed in v5.1"):
        parse_scenario(path)


def test_legacy_goal_file_raises_migration_error(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["bob"]["goal_file"] = "bob/goal.md"  # legacy key
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match="goal_file.*removed in v5.1"):
        parse_scenario(path)


def test_mission_with_recipe_rejected_at_scenario_parse(tmp_path: Path):
    """A mission whose # Intent embeds a step recipe kills scenario boot."""
    manifest = _copy(VALID_BASE)
    scenario_dir = tmp_path / manifest["name"]
    scenario_dir.mkdir(parents=True)
    for agent_name in manifest["agents"]:
        agent_dir = scenario_dir / agent_name
        agent_dir.mkdir()
    # alice's mission contains a 3-step list inside # Intent — recipe heuristic.
    bad_mission = (
        "# Identity\n- name: alice\n- role: general\n\n"
        "# Intent\nDo this:\n1. First step\n2. Second step\n3. Third step\n\n"
        "# Budget\n- max_sats_outbound: 0\n- max_total_turns: 10\n\n"
        "# Stop\n- predicate: never\n"
    )
    (scenario_dir / "alice" / "mission.md").write_text(bad_mission)
    (scenario_dir / "bob" / "mission.md").write_text(_mission_md("bob", "torrent_progress_gte_1"))
    path = scenario_dir / "scenario.yaml"
    path.write_text(yaml.safe_dump(manifest))
    with pytest.raises(ScenarioError, match="step-by-step list"):
        parse_scenario(path)


def test_port_below_1024_rejected(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    manifest["agents"]["alice"]["ipv8_port"] = 80
    path = _write_scenario(tmp_path, manifest)
    with pytest.raises(ScenarioError, match=r"\[1024, 65535\]"):
        parse_scenario(path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _copy(d: dict) -> dict:
    """Deep-copy via yaml round-trip so test mutations stay local."""
    return yaml.safe_load(yaml.safe_dump(d))
