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
            "persona_file": "alice/persona.md",
            "goal_file": "alice/goal.md",
            "stop_predicate": "never",
        },
        "bob": {
            "ipv8_port": 8191,
            "mcp_port": 18766,
            "publish_overlays": [],
            "persona_file": "bob/persona.md",
            "goal_file": "bob/goal.md",
            "stop_predicate": "torrent_progress_gte_1",
            "peers": ["alice"],
        },
    },
}


def _write_scenario(tmp_path: Path, manifest: dict) -> Path:
    """Materialise ``manifest`` + the per-agent persona/goal files in tmp."""
    scenario_dir = tmp_path / manifest["name"]
    scenario_dir.mkdir(parents=True)
    for agent_name in manifest["agents"]:
        agent_dir = scenario_dir / agent_name
        agent_dir.mkdir()
        (agent_dir / "persona.md").write_text(f"# {agent_name} persona\n")
        (agent_dir / "goal.md").write_text(f"# {agent_name} goal\n")
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


def test_persona_file_must_exist(tmp_path: Path):
    manifest = _copy(VALID_BASE)
    # Wipe alice's persona.md after _write_scenario so the rest of the tree is intact.
    scenario_dir = tmp_path / manifest["name"]
    scenario_dir.mkdir(parents=True)
    (scenario_dir / "alice").mkdir()
    (scenario_dir / "alice" / "goal.md").write_text("goal")
    (scenario_dir / "bob").mkdir()
    (scenario_dir / "bob" / "persona.md").write_text("p")
    (scenario_dir / "bob" / "goal.md").write_text("g")
    path = scenario_dir / "scenario.yaml"
    path.write_text(yaml.safe_dump(manifest))
    with pytest.raises(ScenarioError, match="persona_file"):
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
