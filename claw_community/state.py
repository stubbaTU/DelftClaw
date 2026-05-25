from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from claw_community.models import (
    Community,
    CommunityFile,
    CommunityMember,
    CommunitySeedbox,
    CommunityTreasury,
)


DEFAULT_STATE_PATH = Path("claw_community_state/community_state.json")


class CommunityStore:
    def __init__(self, path: str | Path = DEFAULT_STATE_PATH) -> None:
        self.path = Path(path)

    def load_all(self) -> dict[str, Community]:
        if not self.path.exists():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return {
            community_id: _community_from_dict(value)
            for community_id, value in payload.get("communities", {}).items()
        }

    def save_all(self, communities: dict[str, Community]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "communities": {
                community_id: asdict(community)
                for community_id, community in sorted(communities.items())
            }
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _community_from_dict(value: dict[str, Any]) -> Community:
    treasury = CommunityTreasury(**value["treasury"])
    members = {
        agent_id: CommunityMember(
            agent_id=str(member["agent_id"]),
            wallet_address=str(member["wallet_address"]),
            joined_at=str(member["joined_at"]),
            donation_txid=str(member["donation_txid"]),
            donated_sats=int(member["donated_sats"]),
            initial_trust=float(member["initial_trust"]),
            assigned_seedbox_id=member.get("assigned_seedbox_id"),
        )
        for agent_id, member in value.get("members", {}).items()
    }
    seedboxes = {
        seedbox_id: CommunitySeedbox(
            seedbox_id=str(seedbox["seedbox_id"]),
            provider=str(seedbox["provider"]),
            machine_id=str(seedbox["machine_id"]),
            hostname=str(seedbox["hostname"]),
            ip=str(seedbox["ip"]),
            content_dir=str(seedbox["content_dir"]),
            health_status=str(seedbox["health_status"]),
            capacity_agents=int(seedbox["capacity_agents"]),
            logs_path=str(seedbox["logs_path"]),
            created_at=str(seedbox["created_at"]),
        )
        for seedbox_id, seedbox in value.get("seedboxes", {}).items()
    }
    files = {
        file_id: CommunityFile(
            file_id=str(item["file_id"]),
            name=str(item["name"]),
            tags=tuple(str(tag) for tag in item.get("tags", ())),
            sha256=str(item.get("sha256", "")),
            size_bytes=int(item.get("size_bytes", 0)),
            seedbox_id=str(item["seedbox_id"]),
            content_url=str(item["content_url"]),
            magnet_uri=str(item.get("magnet_uri", "")),
        )
        for file_id, item in value.get("files", {}).items()
    }
    return Community(
        community_id=str(value["community_id"]),
        founder_agent_id=str(value["founder_agent_id"]),
        treasury=treasury,
        join_fee_sats=int(value["join_fee_sats"]),
        seedbox_capacity_agents=int(value["seedbox_capacity_agents"]),
        seedbox_purchase_threshold_sats=int(value["seedbox_purchase_threshold_sats"]),
        members=members,
        seedboxes=seedboxes,
        files=files,
        created_at=str(value["created_at"]),
    )
