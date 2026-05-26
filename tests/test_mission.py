"""Tests for ``deploy.mission.parse_mission``.

The parser is the teeth that keep mission.md from drifting back into a
recipe. Covers:

  * Happy path: a minimal valid mission for each role.
  * Section presence + ordering.
  * Identity validation (name format, role allowlist).
  * Intent recipe filter: backtick-quoted tool names, ≥3-step lists.
  * Budget value ranges.
  * Stop predicate resolves via deploy.stop_predicates.
  * Bundled seek_cc mission files actually parse.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deploy.mission import (
    Budget,
    Mission,
    MissionParseError,
    parse_mission,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


GOOD = """\
# Identity
- name: bob
- role: seeker

# Intent
Acquire a Creative Commons audio file from the DelftClaw network.

# Budget
- max_sats_outbound: 10000
- max_total_turns: 20

# Stop
- predicate: torrent_progress_gte_1
"""


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_parse_good_mission():
    m = parse_mission(GOOD)
    assert isinstance(m, Mission)
    assert m.name == "bob"
    assert m.role == "seeker"
    assert m.intent_text.startswith("Acquire a Creative")
    assert isinstance(m.budget, Budget)
    assert m.budget.max_sats_outbound == 10000
    assert m.budget.max_total_turns == 20
    assert m.stop_predicate == "torrent_progress_gte_1"


def test_parse_bundled_seek_cc_missions():
    """The mission.md files the repo ships parse cleanly."""
    for agent in ("alice", "bob", "charlie", "dave"):
        path = REPO_ROOT / "deploy" / "scenarios" / "seek_cc" / agent / "mission.md"
        m = parse_mission(path.read_text(encoding="utf-8"))
        assert m.name == agent


# ---------------------------------------------------------------------------
# Section presence + ordering
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", ["Identity", "Intent", "Budget", "Stop"])
def test_missing_section_rejected(section: str):
    text = GOOD.replace(f"# {section}", f"## {section}_renamed")
    with pytest.raises(MissionParseError, match="missing required sections"):
        parse_mission(text)


def test_sections_out_of_order_rejected():
    swapped = (
        "# Intent\nx\n\n"
        "# Identity\n- name: x\n- role: general\n\n"
        "# Budget\n- max_sats_outbound: 0\n- max_total_turns: 1\n\n"
        "# Stop\n- predicate: never\n"
    )
    with pytest.raises(MissionParseError, match="in order"):
        parse_mission(swapped)


# ---------------------------------------------------------------------------
# Identity validation
# ---------------------------------------------------------------------------

def test_identity_name_not_snake_case_rejected():
    text = GOOD.replace("- name: bob", "- name: Bob")
    with pytest.raises(MissionParseError, match="snake_case"):
        parse_mission(text)


def test_identity_role_must_be_in_allowlist():
    text = GOOD.replace("- role: seeker", "- role: gatekeeper")
    with pytest.raises(MissionParseError, match="role must be one of"):
        parse_mission(text)


# ---------------------------------------------------------------------------
# Intent recipe filter
# ---------------------------------------------------------------------------

def test_intent_with_backtick_tool_name_rejected():
    text = GOOD.replace(
        "Acquire a Creative Commons audio file from the DelftClaw network.",
        "Just call `community_donate_and_join` and you're done.",
    )
    with pytest.raises(MissionParseError, match="community_donate_and_join"):
        parse_mission(text)


def test_intent_with_three_numbered_steps_rejected():
    text = GOOD.replace(
        "Acquire a Creative Commons audio file from the DelftClaw network.",
        "Do this:\n1. First\n2. Second\n3. Third",
    )
    with pytest.raises(MissionParseError, match="step-by-step list"):
        parse_mission(text)


def test_intent_with_three_bulleted_steps_rejected():
    text = GOOD.replace(
        "Acquire a Creative Commons audio file from the DelftClaw network.",
        "Procedure:\n- First\n- Second\n- Third",
    )
    with pytest.raises(MissionParseError, match="step-by-step list"):
        parse_mission(text)


def test_intent_with_two_constraint_bullets_accepted():
    """Two bullets are tolerated for genuine constraint lists."""
    text = GOOD.replace(
        "Acquire a Creative Commons audio file from the DelftClaw network.",
        "Acquire content under these constraints:\n"
        "- Creative Commons only.\n"
        "- Do not exceed budget.",
    )
    m = parse_mission(text)
    assert "Creative Commons" in m.intent_text


def test_intent_must_not_be_empty():
    text = GOOD.replace(
        "Acquire a Creative Commons audio file from the DelftClaw network.\n",
        "\n",
    )
    with pytest.raises(MissionParseError, match="Intent must not be empty"):
        parse_mission(text)


# ---------------------------------------------------------------------------
# Budget validation
# ---------------------------------------------------------------------------

def test_budget_missing_max_sats_outbound_rejected():
    text = GOOD.replace("- max_sats_outbound: 10000\n", "")
    with pytest.raises(MissionParseError, match="max_sats_outbound"):
        parse_mission(text)


def test_budget_negative_sats_rejected():
    text = GOOD.replace("- max_sats_outbound: 10000", "- max_sats_outbound: -1")
    with pytest.raises(MissionParseError, match=">= 0"):
        parse_mission(text)


def test_budget_zero_turns_rejected():
    text = GOOD.replace("- max_total_turns: 20", "- max_total_turns: 0")
    with pytest.raises(MissionParseError, match=">= 1"):
        parse_mission(text)


def test_budget_non_integer_rejected():
    text = GOOD.replace("- max_sats_outbound: 10000", "- max_sats_outbound: ten")
    with pytest.raises(MissionParseError, match="integer"):
        parse_mission(text)


# ---------------------------------------------------------------------------
# Stop predicate validation
# ---------------------------------------------------------------------------

def test_stop_predicate_unknown_rejected():
    text = GOOD.replace(
        "- predicate: torrent_progress_gte_1", "- predicate: no_such_predicate"
    )
    with pytest.raises(MissionParseError, match="predicate"):
        parse_mission(text)


def test_stop_predicate_parameterised_accepted():
    """``peer_count_gte_N(n=2)`` is a real predicate name; the parser should accept it."""
    text = GOOD.replace(
        "- predicate: torrent_progress_gte_1",
        "- predicate: peer_count_gte_N(n=2)",
    )
    m = parse_mission(text)
    assert m.stop_predicate == "peer_count_gte_N(n=2)"


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------

def test_non_str_input_rejected():
    with pytest.raises(MissionParseError, match="must be str"):
        parse_mission(b"hi")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Optional # Tools section — MCP tool allowlist
# ---------------------------------------------------------------------------

def test_tools_section_absent_yields_none():
    """Legacy missions without `# Tools` keep the historical no-allowlist behaviour."""
    m = parse_mission(GOOD)
    assert m.tools is None


def test_tools_section_empty_yields_empty_tuple():
    """`# Tools` present with no entries is the explicit no-action sentinel."""
    text = GOOD + "\n# Tools\n"
    m = parse_mission(text)
    assert m.tools == ()


def test_tools_section_with_valid_names_parses():
    """A bulleted list of valid tool names round-trips into Mission.tools."""
    text = GOOD + "\n# Tools\n- content_search_and_fetch\n- torrent_stats\n"
    m = parse_mission(text)
    assert m.tools == ("content_search_and_fetch", "torrent_stats")


def test_tools_section_accepts_star_bullets():
    """Asterisk-style bullets work too, matching the parser's prose tolerance."""
    text = GOOD + "\n# Tools\n* peers_list\n* wallet_address\n"
    m = parse_mission(text)
    assert m.tools == ("peers_list", "wallet_address")


def test_tools_section_strips_backticks():
    """Tool names wrapped in backticks (operator habit) parse cleanly."""
    text = GOOD + "\n# Tools\n- `torrent_stats`\n"
    m = parse_mission(text)
    assert m.tools == ("torrent_stats",)


def test_tools_section_ignores_freetext_lines():
    """Operator may annotate the list with prose without breaking parse."""
    text = (
        GOOD
        + "\n# Tools\n"
        + "Only these two are needed for this scenario:\n"
        + "- content_search_and_fetch\n"
        + "- torrent_stats\n"
    )
    m = parse_mission(text)
    assert m.tools == ("content_search_and_fetch", "torrent_stats")


def test_tools_section_deduplicates_repeated_entries():
    text = GOOD + "\n# Tools\n- torrent_stats\n- torrent_stats\n- peers_list\n"
    m = parse_mission(text)
    assert m.tools == ("torrent_stats", "peers_list")


def test_tools_section_rejects_unknown_name():
    text = GOOD + "\n# Tools\n- no_such_tool\n"
    with pytest.raises(MissionParseError, match="no_such_tool"):
        parse_mission(text)


def test_tools_section_rejects_unknown_alongside_known():
    text = GOOD + "\n# Tools\n- content_search_and_fetch\n- typo_tool_name\n"
    with pytest.raises(MissionParseError, match="typo_tool_name"):
        parse_mission(text)


def test_bundled_file_share_missions_parse_with_tools():
    """The repo-tracked file_share missions ship with `# Tools` sections."""
    expected = {
        "seeder": ("torrent_stats",),
        "fetcher_1": ("content_search_and_fetch", "torrent_stats"),
        "fetcher_2": ("content_search_and_fetch", "torrent_stats"),
    }
    for agent_name, tools in expected.items():
        path = (
            REPO_ROOT
            / "deploy" / "scenarios" / "file_share" / agent_name / "mission.md"
        )
        m = parse_mission(path.read_text(encoding="utf-8"))
        assert m.name == agent_name
        assert m.tools == tools, f"{agent_name}: got {m.tools!r}"
