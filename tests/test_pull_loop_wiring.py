"""Phase-6 wiring tests: pull-loop integration with OpenClawAgent.

Three layers covered:

  - AgentConfig accepts ``peer_log_urls`` + ``pull_interval_s`` + ``pull_batch``.
  - ``OpenClawAgent.start()`` spawns the pull-loop task iff URLs are non-empty;
    ``stop()`` cancels it cleanly.
  - End-to-end: alice's FastAPI server (built via ``redteam.integration.server``
    against alice's signed log) → bob's pull-loop fetches alice's entries
    into bob's PeerLog → bob's ``community_state()`` reflects alice's donation.

The end-to-end test uses ``httpx.ASGITransport`` so we drive alice's
FastAPI app directly (no real TCP port). The HttpPeerTransport is
constructed with that ASGI client so the pull loop runs in-process.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from agent import AgentConfig, OpenClawAgent, build_tools
from agent.community_state import replay_community
from communication.bittorrent import StubBitTorrentService
from identity.agent_identity import AgentIdentity
from identity.openclaw_identity import OpenClawIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient


MANIFEST_TEMPLATE = """\
# Identity

- name: pull_loop_test
- version: 1.0.0
- description: Phase-6 pull-loop wiring test fixture.

# Admission

- gatekeeper_address: {gatekeeper_address}
- min_sats: 10000
- min_confirmations: 0
- bootstrap_cap_sats: 100000
- max_agents_per_seedbox: 3
- seedbox_cost_sats: 50000

# Genesis Peers

| host | port | pubkey_hex |
|------|------|------------|
| 127.0.0.1 | 8190 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |

# Default Overlays

- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a
"""


# ---------------------------------------------------------------------------
# AgentConfig + Scenario.yaml plumbing
# ---------------------------------------------------------------------------


def test_agent_config_accepts_pull_loop_fields():
    config = AgentConfig(
        peer_log_urls=("http://127.0.0.1:28765", "http://127.0.0.1:28766"),
        pull_interval_s=1.0,
        pull_batch=42,
    )
    assert config.peer_log_urls == (
        "http://127.0.0.1:28765",
        "http://127.0.0.1:28766",
    )
    assert config.pull_interval_s == 1.0
    assert config.pull_batch == 42


def test_agent_config_defaults_to_pull_loop_disabled():
    config = AgentConfig()
    assert config.peer_log_urls == ()
    assert config.pull_interval_s == 5.0
    assert config.pull_batch == 100


# ---------------------------------------------------------------------------
# OpenClawAgent.start() does/doesn't spawn pull task
# ---------------------------------------------------------------------------


def _build_agent(tmp_path, *, peer_log_urls=()):
    seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    return OpenClawAgent(
        identity=AgentIdentity.from_seed(seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=tmp_path,
            community_log_path=tmp_path / "community.log",
            peer_log_dir=tmp_path / "peer_logs",
            peer_log_urls=peer_log_urls,
            pull_interval_s=0.05,   # tight for tests
            pull_batch=10,
        ),
        bt_service=StubBitTorrentService(save_dir=tmp_path),
    )


@pytest.mark.asyncio
async def test_start_does_not_spawn_pull_task_when_no_peer_urls(tmp_path):
    agent = _build_agent(tmp_path)
    await agent.start()
    try:
        assert agent._pull_task is None
        assert agent._pull_stop_event is None
        assert agent._pull_transport_handle is None
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_start_spawns_pull_task_when_peer_urls_present(tmp_path):
    # Use a known-unreachable URL — the pull loop logs errors and keeps
    # going, which is exactly what we want: we just want to observe that
    # the task started.
    agent = _build_agent(tmp_path, peer_log_urls=("http://127.0.0.1:1",))
    await agent.start()
    try:
        assert agent._pull_task is not None
        assert not agent._pull_task.done()
        assert agent._pull_stop_event is not None
        assert agent._pull_transport_handle is not None
    finally:
        await agent.stop()
        # After stop, the task and handle are cleared.
        assert agent._pull_task is None
        assert agent._pull_transport_handle is None


@pytest.mark.asyncio
async def test_stop_pull_loop_is_idempotent(tmp_path):
    """Calling stop() twice (or before start) doesn't blow up."""
    agent = _build_agent(tmp_path)
    await agent._stop_pull_loop()   # before start
    await agent.start()
    await agent.stop()
    await agent._stop_pull_loop()   # after stop


# ---------------------------------------------------------------------------
# End-to-end: alice's FastAPI server feeds bob's pull loop
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def alice_and_bob_with_pull(tmp_path):
    """Alice writes a donation_intent; bob's pull loop fetches it.

    Wires bob's pull loop to alice's FastAPI app via an ``httpx.ASGITransport``
    — no real TCP port. Convergence is then a function of the pull
    interval (set to 0.05s for the test) plus the round-trip cost.
    """
    a_dir = tmp_path / "alice"
    a_dir.mkdir()
    b_dir = tmp_path / "bob"
    b_dir.mkdir()

    alice_seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(alice_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=a_dir,
            initial_balance_sats=200_000,
            community_log_path=a_dir / "community.log",
            peer_log_dir=a_dir / "peer_logs",
            # Alice doesn't pull from anyone — she's the publisher.
        ),
        bt_service=StubBitTorrentService(save_dir=a_dir),
    )

    bob_seed = MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load()
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(bob_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=b_dir,
            initial_balance_sats=200_000,
            community_log_path=b_dir / "community.log",
            peer_log_dir=b_dir / "peer_logs",
            # peer_log_urls overridden after start() so we can hand bob
            # an ASGI-backed httpx client instead of a real one.
        ),
        bt_service=StubBitTorrentService(save_dir=b_dir),
    )
    await alice.start()
    await bob.start()

    manifest_md = MANIFEST_TEMPLATE.format(gatekeeper_address=alice.wallet.address())
    alice.load_manifest(manifest_md)
    bob.load_manifest(manifest_md)

    # Alice writes a donation_intent into her own log — exactly what
    # the community_donate_and_join tool would do, but in-process so we
    # don't need IPv8 wiring for this test.
    a_tools = build_tools(alice)
    await a_tools.dispatch("community_donate_and_join", {"amount_sats": 60_000})

    # Build alice's FastAPI app and bob's pull loop using ASGI transport.
    from redteam.integration.server import build_app
    from redteam.integration.peer_transport import HttpPeerTransport
    from redteam.integration.pull_loop import run_pull_loop

    alice_oc = OpenClawIdentity.from_agent_identity(alice.identity)
    app = build_app(
        identity=alice_oc,
        log_path=str(a_dir / "community.log"),
        peer_log_dir=str(a_dir / "peer_logs"),
        peers=[],
    )
    asgi = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=asgi, base_url="http://alice")
    transport = HttpPeerTransport(client)

    stop_event = asyncio.Event()
    pull_task = asyncio.create_task(
        run_pull_loop(
            transport=transport,
            peer_urls=["http://alice"],
            peer_log=bob.peer_log,
            interval=0.05,
            batch=50,
            stop_event=stop_event,
        ),
    )

    yield alice, bob, pull_task, stop_event, client

    stop_event.set()
    try:
        await asyncio.wait_for(pull_task, timeout=2.0)
    except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
        pull_task.cancel()
    await client.aclose()
    await alice.stop()
    await bob.stop()


@pytest.mark.asyncio
async def test_pull_loop_replicates_alice_donation_into_bob_peer_log(
    alice_and_bob_with_pull,
):
    """Wait up to ~2s for bob's pull-loop to catch alice's donation entry."""
    alice, bob, _task, _stop, _client = alice_and_bob_with_pull

    alice_id = OpenClawIdentity.from_agent_identity(alice.identity).identity_hash
    deadline = asyncio.get_event_loop().time() + 2.0
    while asyncio.get_event_loop().time() < deadline:
        entries = bob.peer_log.read_entries_for(alice_id)
        if entries:
            break
        await asyncio.sleep(0.05)

    entries = bob.peer_log.read_entries_for(alice_id)
    assert len(entries) >= 1, "bob's pull loop never caught alice's entry"
    assert entries[0]["action"] == "donation_intent"
    assert entries[0]["reporter_id"] == alice_id


@pytest.mark.asyncio
async def test_pull_loop_makes_bob_see_alice_in_community_state(
    alice_and_bob_with_pull,
):
    """After convergence, bob's replay returns alice in the member set + treasury."""
    alice, bob, _task, _stop, _client = alice_and_bob_with_pull

    deadline = asyncio.get_event_loop().time() + 2.0
    while asyncio.get_event_loop().time() < deadline:
        state = bob.community_state()
        if state is not None and alice.community_reporter_id in state.members:
            break
        await asyncio.sleep(0.05)

    state = bob.community_state()
    assert state is not None
    assert alice.community_reporter_id in state.members
    assert state.balance_sats == 60_000
    assert state.member_count == 1


# ---------------------------------------------------------------------------
# Scenario YAML wiring (redteam_port collision, parse, env-file shape)
# ---------------------------------------------------------------------------


def test_scenario_parses_redteam_port():
    import yaml as _yaml
    from deploy.scenario import parse_scenario

    manifest = {
        "name": "growth_test",
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
                "redteam_port": 28765,
                "publish_overlays": [],
                "mission_file": "alice/mission.md",
                "stop_predicate": "never",
            },
            "bob": {
                "ipv8_port": 8191,
                "mcp_port": 18766,
                "redteam_port": 28766,
                "publish_overlays": [],
                "mission_file": "bob/mission.md",
                "stop_predicate": "never",
                "peers": ["alice"],
            },
        },
    }
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "alice").mkdir()
        (tmp_path / "bob").mkdir()
        _write_mission(tmp_path / "alice" / "mission.md")
        _write_mission(tmp_path / "bob" / "mission.md")
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text(_yaml.safe_dump(manifest), encoding="utf-8")

        scenario = parse_scenario(scenario_path)
        assert scenario.agents["alice"].redteam_port == 28765
        assert scenario.agents["bob"].redteam_port == 28766


def test_scenario_rejects_redteam_port_collision():
    """Two agents declaring the same redteam_port is a parse error."""
    import yaml as _yaml
    import tempfile
    from deploy.scenario import ScenarioError, parse_scenario

    manifest = {
        "name": "growth_test",
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
                "redteam_port": 28765,
                "publish_overlays": [],
                "mission_file": "alice/mission.md",
                "stop_predicate": "never",
            },
            "bob": {
                "ipv8_port": 8191,
                "mcp_port": 18766,
                "redteam_port": 28765,  # same as alice → conflict
                "publish_overlays": [],
                "mission_file": "bob/mission.md",
                "stop_predicate": "never",
            },
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "alice").mkdir()
        (tmp_path / "bob").mkdir()
        _write_mission(tmp_path / "alice" / "mission.md")
        _write_mission(tmp_path / "bob" / "mission.md")
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text(_yaml.safe_dump(manifest), encoding="utf-8")
        with pytest.raises(ScenarioError, match="redteam_port"):
            parse_scenario(scenario_path)


def test_scenario_env_file_includes_peer_log_urls_and_redteam_port():
    """``_instance_env_contents`` cross-wires every other agent's URL."""
    import yaml as _yaml
    import tempfile
    from deploy.scenario import parse_scenario
    from deploy.scenario_boot import _instance_env_contents

    manifest = {
        "name": "growth_test",
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
                "redteam_port": 28765,
                "publish_overlays": [],
                "mission_file": "alice/mission.md",
                "stop_predicate": "never",
            },
            "bob": {
                "ipv8_port": 8191,
                "mcp_port": 18766,
                "redteam_port": 28766,
                "publish_overlays": [],
                "mission_file": "bob/mission.md",
                "stop_predicate": "never",
                "peers": ["alice"],
            },
            "charlie": {
                "ipv8_port": 8192,
                "mcp_port": 18767,
                "redteam_port": 28767,
                "publish_overlays": [],
                "mission_file": "charlie/mission.md",
                "stop_predicate": "never",
                "peers": ["alice"],
            },
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for n in ("alice", "bob", "charlie"):
            (tmp_path / n).mkdir()
            _write_mission(tmp_path / n / "mission.md")
        scenario_path = tmp_path / "scenario.yaml"
        scenario_path.write_text(_yaml.safe_dump(manifest), encoding="utf-8")

        scenario = parse_scenario(scenario_path)

        body = _instance_env_contents(scenario, scenario.agents["bob"])
        # Bob's peer list = alice + charlie (everyone except bob).
        assert "PEER_LOG_URLS=http://127.0.0.1:28765 http://127.0.0.1:28767" in body
        assert "REDTEAM_PORT=28766" in body
        # Alice's peer list = bob + charlie.
        body_alice = _instance_env_contents(scenario, scenario.agents["alice"])
        assert "http://127.0.0.1:28766" in body_alice
        assert "http://127.0.0.1:28767" in body_alice
        assert "REDTEAM_PORT=28765" in body_alice


def _write_mission(path: Path) -> None:
    """Minimal valid mission.md for scenario-parse fixtures."""
    path.write_text(
        "# Identity\n\n- name: x\n- role: general\n\n"
        "# Intent\n\nDo nothing.\n\n"
        "# Budget\n\n- max_sats_outbound: 1000\n- max_total_turns: 5\n\n"
        "# Stop\n\n- predicate: never\n",
        encoding="utf-8",
    )
