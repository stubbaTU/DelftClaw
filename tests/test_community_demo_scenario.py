from __future__ import annotations

from pathlib import Path

import pytest

from deploy.scenario import parse_scenario
from deploy import scenario_boot
from deploy.scenario_boot import _instance_env_contents
from deploy.stop_predicates import resolve


REPO_ROOT = Path(__file__).resolve().parent.parent
COMMUNITY_DEMO = REPO_ROOT / "deploy" / "scenarios" / "community_demo"


def test_community_demo_scenario_has_real_openclaw_agents() -> None:
    scenario = parse_scenario(COMMUNITY_DEMO / "scenario.yaml")

    assert set(scenario.agents) == {"agent_1", "agent_2", "agent_3", "agent_4"}
    assert scenario.agents["agent_1"].publish_overlays
    assert scenario.agents["agent_1"].seed_content
    assert scenario.agents["agent_2"].stop_predicate == "torrent_progress_gte_1"
    assert scenario.agents["agent_4"].stop_predicate == "community_seedbox_count_gte_N(n=2)"


def test_community_demo_env_points_to_seed_content_file() -> None:
    scenario = parse_scenario(COMMUNITY_DEMO / "scenario.yaml")
    body = _instance_env_contents(scenario, scenario.agents["agent_1"]).replace("\\", "/")

    assert "SEED_CONTENT_FILE=/etc/delftclaw/scenarios/community_demo-agent_1/seed_content.json" in body
    assert "COMMUNITY_LOG_PATH=/var/lib/delftclaw/community_demo/agent_1/community.log" in body
    assert "PEER_LOG_URLS=http://127.0.0.1:28771 http://127.0.0.1:28772 http://127.0.0.1:28773" in body


def test_openclaw_api_keys_are_assigned_per_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    scenario = parse_scenario(COMMUNITY_DEMO / "scenario.yaml")
    monkeypatch.setattr(
        scenario_boot,
        "OPENCLAW_LLM",
        {
            "provider": "gemini",
            "api": "openai",
            "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
            "model": "gemini-2.5-flash",
            "api_key_env": "GEMINI_API_KEY",
            "api_key_value": "",
            "api_keys": "key_a\nkey_b",
        },
    )

    env_1 = _instance_env_contents(scenario, scenario.agents["agent_1"])
    env_2 = _instance_env_contents(scenario, scenario.agents["agent_2"])
    env_3 = _instance_env_contents(scenario, scenario.agents["agent_3"])

    assert "GEMINI_API_KEY=key_a" in env_1
    assert "GEMINI_API_KEY=key_b" in env_2
    assert "GEMINI_API_KEY=key_a" in env_3


def test_openrouter_provider_defaults_to_openrouter_key_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    host_env = tmp_path / "host.env"
    host_env.write_text(
        "\n".join([
            "OPENCLAW_PROVIDER=openrouter",
            "OPENCLAW_BASE_URL=https://openrouter.ai/api/v1",
            "OPENCLAW_MODEL=openai/gpt-4o-mini",
            "OPENROUTER_API_KEY=sk-test",
        ]),
        encoding="utf-8",
    )
    monkeypatch.delenv("OPENCLAW_PROVIDER", raising=False)
    monkeypatch.delenv("OPENCLAW_API_KEY_ENV", raising=False)

    resolved = scenario_boot._resolve_openclaw_provider(host_env)

    assert resolved["provider"] == "openrouter"
    assert resolved["api"] == "openai-completions"
    assert resolved["base_url"] == "https://openrouter.ai/api/v1"
    assert resolved["model"] == "openai/gpt-4o-mini"
    assert resolved["api_key_env"] == "OPENROUTER_API_KEY"
    assert resolved["api_key_value"] == "sk-test"


def test_community_stop_predicates_read_snapshot() -> None:
    seedbox_done = resolve("community_seedbox_count_gte_N(n=2)")
    member_done = resolve("community_member_count_gte_N(n=3)")

    assert seedbox_done({"community": {"seedbox_count": 2}})
    assert not seedbox_done({"community": {"seedbox_count": 1}})
    assert member_done({"community": {"member_count": 3}})
    assert not member_done({"community": {"member_count": 2}})
