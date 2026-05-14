from __future__ import annotations

from pathlib import Path

from deploy.scenario import parse_scenario
from deploy.scenario_boot import _instance_env_contents
from deploy.stop_predicates import resolve


REPO_ROOT = Path(__file__).resolve().parent.parent
PAPER_DEMO = REPO_ROOT / "deploy" / "scenarios" / "paper_demo"


def test_paper_demo_scenario_has_real_openclaw_agents() -> None:
    scenario = parse_scenario(PAPER_DEMO / "scenario.yaml")

    assert set(scenario.agents) == {"agent_1", "agent_2", "agent_3", "agent_4"}
    assert scenario.agents["agent_1"].publish_overlays
    assert scenario.agents["agent_1"].seed_content
    assert scenario.agents["agent_2"].stop_predicate == "torrent_progress_gte_1"
    assert scenario.agents["agent_4"].stop_predicate == "community_seedbox_count_gte_N(n=2)"


def test_paper_demo_env_points_to_seed_content_file() -> None:
    scenario = parse_scenario(PAPER_DEMO / "scenario.yaml")
    body = _instance_env_contents(scenario, scenario.agents["agent_1"]).replace("\\", "/")

    assert "SEED_CONTENT_FILE=/etc/delftclaw/scenarios/paper_demo-agent_1/seed_content.json" in body
    assert "COMMUNITY_LOG_PATH=/var/lib/delftclaw/paper_demo/agent_1/community.log" in body
    assert "PEER_LOG_URLS=http://127.0.0.1:28771 http://127.0.0.1:28772 http://127.0.0.1:28773" in body


def test_community_stop_predicates_read_snapshot() -> None:
    seedbox_done = resolve("community_seedbox_count_gte_N(n=2)")
    member_done = resolve("community_member_count_gte_N(n=3)")

    assert seedbox_done({"community": {"seedbox_count": 2}})
    assert not seedbox_done({"community": {"seedbox_count": 1}})
    assert member_done({"community": {"member_count": 3}})
    assert not member_done({"community": {"member_count": 2}})
