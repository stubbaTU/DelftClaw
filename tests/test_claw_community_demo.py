from __future__ import annotations

import csv
import hashlib
from pathlib import Path

import pytest

from claw_community.goal_runner import GoalRunner
from claw_community.communication_adapter import AgentContentCommunicationPort
from claw_community.run_demo import run_demo
from claw_community.service import ClawCommunityService
from claw_community.state import CommunityStore


def test_run_demo_creates_four_member_two_seedbox_community(tmp_path: Path) -> None:
    result = run_demo(provider="mock", root=tmp_path / "demo", reset=True)

    assert result["ok"] is True
    assert result["signed_log_integrity_ok"] is True
    assert result["final_status"]["community"]["member_count"] == 4
    assert result["final_status"]["community"]["seedbox_count"] == 2
    first_seedbox_id = result["steps"][1]["result"]["seedbox"]["seedbox_id"]
    assert {item["provider"] for item in result["final_status"]["community"]["seedboxes"].values()} == {"mock"}
    founder_id = result["final_status"]["community"]["founder_agent_id"]
    assert result["final_status"]["community"]["members"][founder_id]["assigned_seedbox_id"] == first_seedbox_id
    assert Path(result["state_path"]).exists()
    assert Path(result["signed_log_path"]).exists()


def test_community_state_reloads_seedboxes_members_and_files(tmp_path: Path) -> None:
    service = ClawCommunityService(
        store=CommunityStore(tmp_path / "state.json"),
        seedbox_root=tmp_path / "seedboxes",
    )
    service.create_community(
        community_id="reload-demo",
        founder_agent_id="agent-1",
        founder_wallet_address="wallet-1",
        initial_funding_sats=5000,
        join_fee_sats=1000,
        seedbox_capacity_agents=3,
        seedbox_purchase_threshold_sats=1000,
    )
    seedbox = service.buy_seedbox(community_id="reload-demo", actor_id="agent-1", provider="mock")["seedbox"]
    content_path = tmp_path / "demo.txt"
    content_path.write_text("reloadable content\n", encoding="utf-8")
    digest = hashlib.sha256(content_path.read_bytes()).hexdigest()
    catalog_path = tmp_path / "catalog.csv"
    with catalog_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["file_id", "name", "tags", "sha256", "size_bytes", "seedbox_id", "content_url", "magnet_uri"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "file-1",
                "name": "Reloadable Demo File",
                "tags": "demo,reload",
                "sha256": digest,
                "size_bytes": content_path.stat().st_size,
                "seedbox_id": seedbox["seedbox_id"],
                "content_url": str(content_path),
                "magnet_uri": "",
            }
        )
    service.import_file_catalog(community_id="reload-demo", csv_path=catalog_path)

    reloaded = ClawCommunityService(
        store=CommunityStore(tmp_path / "state.json"),
        seedbox_root=tmp_path / "seedboxes",
    )
    status = reloaded.get_status(community_id="reload-demo")["community"]
    search = reloaded.find_file(community_id="reload-demo", requester_agent_id="agent-1", query="reloadable")

    assert status["member_count"] == 1
    assert status["seedbox_count"] == 1
    assert status["files"]["file-1"]["sha256"] == digest
    assert search["count"] == 1


def test_goal_runner_executes_json_goal_blocks(tmp_path: Path) -> None:
    service = ClawCommunityService(
        store=CommunityStore(tmp_path / "state.json"),
        seedbox_root=tmp_path / "seedboxes",
    )
    goal_path = tmp_path / "goal.md"
    goal_path.write_text(
        """# Demo goal

```json
{
  "tool": "create_community",
  "args": {
    "community_id": "goal-demo",
    "founder_agent_id": "agent-1",
    "founder_wallet_address": "wallet-1",
    "initial_funding_sats": 3000,
    "join_fee_sats": 1000,
    "seedbox_capacity_agents": 3,
    "seedbox_purchase_threshold_sats": 1000
  }
}
```

```json
{
  "tool": "buy_seedbox",
  "args": {
    "community_id": "goal-demo",
    "actor_id": "agent-1",
    "provider": "mock"
  }
}
```
""",
        encoding="utf-8",
    )

    results = GoalRunner(service).run_goal_file(goal_path)

    assert len(results) == 2
    assert results[-1]["seedbox"]["provider"] == "mock"


@pytest.mark.asyncio
async def test_agent_content_communication_port_queries_real_content_overlay(tmp_path: Path) -> None:
    pytest.importorskip("fastmcp")
    pytest.importorskip("libnacl")
    from agent import AgentConfig, OpenClawAgent
    from communication.bittorrent import StubBitTorrentService
    from communication.community import overlay_id
    from identity.agent_identity import AgentIdentity
    from identity.seed import MnemonicSeedSource
    from ipv8.peer import Peer
    from protocol import StubLLMClient, community_id_from_md
    from protocol.examples.content_community_stub import CONTENT_COMMUNITY_SOURCE

    content_md = (Path(__file__).resolve().parent.parent / "protocol" / "examples" / "content_community.md").read_text()
    content_hash = overlay_id(content_md)
    llm = StubLLMClient(
        sources={community_id_from_md(content_md).hex(): "```python\n" + CONTENT_COMMUNITY_SOURCE + "```"}
    )
    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(
            MnemonicSeedSource("army van defense carry jealous true garbage claim echo media make crunch").load(),
            network="TESTNET",
        ),
        llm=llm,
        config=AgentConfig(port=0, save_dir=tmp_path / "alice"),
        bt_service=StubBitTorrentService(save_dir=tmp_path / "alice"),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(
            MnemonicSeedSource(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            ).load(),
            network="TESTNET",
        ),
        llm=llm,
        config=AgentConfig(port=0, save_dir=tmp_path / "bob"),
        bt_service=StubBitTorrentService(save_dir=tmp_path / "bob"),
    )
    await alice.start()
    await bob.start()
    try:
        alice.seedbox.network.add_verified_peer(Peer(bob.seedbox.my_peer.public_key, address=bob.address))
        bob.seedbox.network.add_verified_peer(Peer(alice.seedbox.my_peer.public_key, address=alice.address))
        alice.publish_overlay(content_md)
        bob.publish_overlay(content_md)
        content_a = alice.registry.get(content_hash)
        content_b = bob.registry.get(content_hash)
        content_a.network.add_verified_peer(Peer(content_b.my_peer.public_key, address=bob.address))
        content_b.network.add_verified_peer(Peer(content_a.my_peer.public_key, address=alice.address))
        content_a.local_index = [
            {
                "magnet": "magnet:?xt=urn:btih:abc",
                "name": "Creative Commons Audio",
                "size": 123,
                "mime": "audio/mpeg",
                "tags": ["Creative Commons", "demo"],
            }
        ]

        port = AgentContentCommunicationPort(bob, timeout_s=2.0)
        result = await port.async_request_file_location(
            sender_id="bob",
            community_id="claw-demo",
            query="Creative Commons",
        )

        assert result["ok"] is True
        assert result["transport"] == "content-overlay"
        assert any(item["name"] == "Creative Commons Audio" for item in result["remote_results"])
    finally:
        await bob.stop()
        await alice.stop()
