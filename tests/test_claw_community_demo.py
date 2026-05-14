from __future__ import annotations

import csv
import hashlib
from pathlib import Path

from claw_community.goal_runner import GoalRunner
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
