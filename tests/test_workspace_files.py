"""Tests for ``deploy.scenario_boot._render_workspace_files``.

Path A of the openclaw-identity refactor: agent identity + operating
instructions + tool catalog move out of the per-turn user-message and
into static workspace files (``SOUL.md``, ``AGENTS.md``, ``HEARTBEAT.md``)
that openclaw auto-injects into the system prompt once per call.

These tests pin the *content contract* of those files — what the LLM
must see in its system prompt before any turn-specific prose is shown.
They are intentionally written against real scenario YAML (no mocks) so
the contract is anchored to the canonical seek_cc agents the demo runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deploy.scenario import AgentSpec, parse_scenario


REPO_ROOT = Path(__file__).resolve().parent.parent
SEEK_CC_YAML = REPO_ROOT / "deploy" / "scenarios" / "seek_cc" / "scenario.yaml"


@pytest.fixture(scope="module")
def seek_cc_agents() -> dict[str, AgentSpec]:
    """Parse the real seek_cc scenario and return its agent specs."""
    scenario = parse_scenario(SEEK_CC_YAML)
    return scenario.agents


@pytest.fixture()
def bob_spec(seek_cc_agents: dict[str, AgentSpec]) -> AgentSpec:
    return seek_cc_agents["bob"]


@pytest.fixture()
def alice_spec(seek_cc_agents: dict[str, AgentSpec]) -> AgentSpec:
    return seek_cc_agents["alice"]


def _render(spec: AgentSpec) -> dict[str, str]:
    """Indirect import: the symbol does not yet exist (Red phase)."""
    from deploy.scenario_boot import _render_workspace_files  # type: ignore[attr-defined]
    return _render_workspace_files(spec)


# ---------------------------------------------------------------------------
# Shape of the returned dict
# ---------------------------------------------------------------------------

def test_render_returns_three_files(bob_spec: AgentSpec) -> None:
    files = _render(bob_spec)
    assert set(files.keys()) == {"SOUL.md", "AGENTS.md", "HEARTBEAT.md"}


def test_render_is_deterministic(bob_spec: AgentSpec) -> None:
    a = _render(bob_spec)
    b = _render(bob_spec)
    assert a == b


# ---------------------------------------------------------------------------
# SOUL.md — identity + intent (the "who am I, why am I here" file)
# ---------------------------------------------------------------------------

def test_soul_contains_mission_identity_and_intent(bob_spec: AgentSpec) -> None:
    soul = _render(bob_spec)["SOUL.md"]
    assert "name: bob" in soul
    assert "role: seeker" in soul
    assert "Acquire a Creative Commons audio file" in soul


def test_alice_soul_differs_from_bob_soul(
    alice_spec: AgentSpec, bob_spec: AgentSpec
) -> None:
    # alice is role=seedbox, bob is role=seeker; their identity files
    # must diverge or we've collapsed two agents into one prompt.
    alice_soul = _render(alice_spec)["SOUL.md"]
    bob_soul = _render(bob_spec)["SOUL.md"]
    assert alice_soul != bob_soul
    assert "role: seedbox" in alice_soul
    assert "role: seeker" in bob_soul


# ---------------------------------------------------------------------------
# AGENTS.md — the operating loop the LLM lives inside
# ---------------------------------------------------------------------------

def test_agents_md_describes_operating_loop(bob_spec: AgentSpec) -> None:
    agents_md = _render(bob_spec)["AGENTS.md"].lower()
    # Single-tool-call-per-turn discipline.
    assert "exactly one" in agents_md
    assert "tool call" in agents_md
    # Watchdog (not the LLM) owns mission completion.
    assert "watchdog" in agents_md
    assert "stop" in agents_md


def test_agents_md_enumerates_tool_names(bob_spec: AgentSpec) -> None:
    # Tool catalog migrated out of turn_builder._AVAILABLE_TOOLS.
    agents_md = _render(bob_spec)["AGENTS.md"]
    for tool in (
        "wallet_balance",
        "peers_list",
        "seedbox_donate_and_join",
        "overlay_fetch_and_load",
        "torrent_fetch",
    ):
        assert tool in agents_md, f"AGENTS.md missing tool name {tool!r}"


# ---------------------------------------------------------------------------
# HEARTBEAT.md — the tick rhythm (what the agent sees each wake-up)
# ---------------------------------------------------------------------------

def test_heartbeat_describes_tick_rhythm(bob_spec: AgentSpec) -> None:
    heartbeat = _render(bob_spec)["HEARTBEAT.md"].lower()
    # The rhythm framing — at least one of these words must appear.
    assert any(token in heartbeat for token in ("wake", "tick", "heartbeat")), (
        "HEARTBEAT.md must describe the tick rhythm (wake/tick/heartbeat)"
    )
    # What the agent will see each tick.
    assert "state snapshot" in heartbeat
