from __future__ import annotations

import csv
import hashlib
from dataclasses import asdict
from pathlib import Path
from typing import Any

from claw_community.models import (
    Community,
    CommunityFile,
    CommunityMember,
    CommunitySeedbox,
    CommunityTreasury,
    utc_now,
)
from claw_community.ports import CommunityAuditLog, CommunityCommunicationPort, LocalCommunicationPlaceholder, NullCommunityAuditLog
from claw_community.seedbox_providers import provider_for
from claw_community.state import CommunityStore


class ClawCommunityService:
    def __init__(
        self,
        *,
        store: CommunityStore | None = None,
        audit: CommunityAuditLog | None = None,
        communication: CommunityCommunicationPort | None = None,
        seedbox_root: str | Path = "seedbox_artifacts",
    ) -> None:
        self.store = store or CommunityStore()
        self.audit = audit or NullCommunityAuditLog()
        self.communication = communication or LocalCommunicationPlaceholder()
        self.seedbox_root = Path(seedbox_root)

    def create_community(
        self,
        *,
        community_id: str,
        founder_agent_id: str,
        founder_wallet_address: str,
        initial_funding_sats: int,
        join_fee_sats: int,
        seedbox_capacity_agents: int = 3,
        seedbox_purchase_threshold_sats: int = 3_000,
    ) -> dict[str, Any]:
        communities = self.store.load_all()
        if community_id in communities:
            raise ValueError(f"community already exists: {community_id}")
        treasury = CommunityTreasury(wallet_address=_treasury_wallet(community_id))
        community = Community(
            community_id=community_id,
            founder_agent_id=founder_agent_id,
            treasury=treasury,
            join_fee_sats=join_fee_sats,
            seedbox_capacity_agents=seedbox_capacity_agents,
            seedbox_purchase_threshold_sats=seedbox_purchase_threshold_sats,
        )
        communities[community_id] = community
        founder_txid = f"mocktx-{community_id}-founder-funding"
        founder_initial_trust = round(
            min(10.0, max(1.0, initial_funding_sats / join_fee_sats)),
            2,
        )
        self._fund_treasury(
            community,
            agent_id=founder_agent_id,
            wallet_address=founder_wallet_address,
            amount_sats=initial_funding_sats,
            txid=founder_txid,
        )
        community.members[founder_agent_id] = CommunityMember(
            agent_id=founder_agent_id,
            wallet_address=founder_wallet_address,
            joined_at=utc_now(),
            donation_txid=founder_txid,
            donated_sats=initial_funding_sats,
            initial_trust=founder_initial_trust,
        )
        self.store.save_all(communities)
        self.audit.record(
            actor_id=founder_agent_id,
            subject_id=community_id,
            action="community_created",
            details={
                "community_id": community_id,
                "treasury_wallet_address": treasury.wallet_address,
                "join_fee_sats": join_fee_sats,
                "seedbox_capacity_agents": seedbox_capacity_agents,
                "seedbox_purchase_threshold_sats": seedbox_purchase_threshold_sats,
                "initial_funding_sats": initial_funding_sats,
                "founder_agent_id": founder_agent_id,
                "founder_wallet_address": founder_wallet_address,
                "founder_donation_txid": founder_txid,
                "founder_initial_trust": founder_initial_trust,
            },
        )
        return {"ok": True, "community": self._community_payload(community)}

    def fund_treasury(
        self,
        *,
        community_id: str,
        agent_id: str,
        wallet_address: str,
        amount_sats: int,
        txid: str | None = None,
    ) -> dict[str, Any]:
        communities = self.store.load_all()
        community = self._require_community(communities, community_id)
        donation_txid = txid or f"mocktx-{community_id}-{agent_id}-{community.treasury.incoming_sats + amount_sats}"
        self._fund_treasury(
            community,
            agent_id=agent_id,
            wallet_address=wallet_address,
            amount_sats=amount_sats,
            txid=donation_txid,
        )
        self.store.save_all(communities)
        self.audit.record(
            actor_id=agent_id,
            subject_id=community_id,
            action="community_treasury_funded",
            details={
                "community_id": community_id,
                "wallet_address": wallet_address,
                "amount_sats": amount_sats,
                "txid": donation_txid,
                "treasury_balance_sats": community.treasury.balance_sats,
            },
        )
        return {"ok": True, "community": self._community_payload(community), "txid": donation_txid}

    def buy_seedbox(
        self,
        *,
        community_id: str,
        actor_id: str,
        provider: str = "local",
        hostname: str | None = None,
        capacity_gb: int = 100,
        cost_sats: int | None = None,
    ) -> dict[str, Any]:
        communities = self.store.load_all()
        community = self._require_community(communities, community_id)
        price = community.seedbox_purchase_threshold_sats if cost_sats is None else cost_sats
        if community.treasury.balance_sats < price:
            raise ValueError("community treasury does not have enough funds to buy seedbox")

        seedbox_number = len(community.seedboxes) + 1
        seedbox_hostname = hostname or f"{community_id}-seedbox-{seedbox_number}"
        provider_impl = provider_for(provider, root=self.seedbox_root)
        metadata = provider_impl.launch(
            hostname=seedbox_hostname,
            content_dir=self.seedbox_root / seedbox_hostname / "content",
            capacity_gb=capacity_gb,
        )
        seedbox_id = f"{community_id}-{metadata.machine_id}"
        community.treasury.balance_sats -= price
        community.treasury.outgoing_sats += price
        seedbox = CommunitySeedbox(
            seedbox_id=seedbox_id,
            provider=metadata.provider,
            machine_id=metadata.machine_id,
            hostname=metadata.hostname,
            ip=metadata.ip,
            content_dir=metadata.content_dir,
            health_status=metadata.health_status,
            capacity_agents=community.seedbox_capacity_agents,
            logs_path=metadata.logs_path,
            created_at=metadata.created_at,
        )
        community.seedboxes[seedbox_id] = seedbox
        self._rebalance_members(community)
        self.store.save_all(communities)
        self.audit.record(
            actor_id=actor_id,
            subject_id=community_id,
            action="seedbox_registered",
            details={
                "community_id": community_id,
                "seedbox": asdict(seedbox),
                "cost_sats": price,
                "treasury_balance_sats": community.treasury.balance_sats,
            },
        )
        return {"ok": True, "seedbox": asdict(seedbox), "community": self._community_payload(community)}

    def join_community(
        self,
        *,
        community_id: str,
        agent_id: str,
        wallet_address: str,
        amount_sats: int,
        txid: str | None = None,
    ) -> dict[str, Any]:
        communities = self.store.load_all()
        community = self._require_community(communities, community_id)
        if amount_sats < community.join_fee_sats:
            raise ValueError("donation below required join fee")
        donation_txid = txid or f"mocktx-{community_id}-{agent_id}-join"
        self._fund_treasury(
            community,
            agent_id=agent_id,
            wallet_address=wallet_address,
            amount_sats=amount_sats,
            txid=donation_txid,
        )
        member = CommunityMember(
            agent_id=agent_id,
            wallet_address=wallet_address,
            joined_at=utc_now(),
            donation_txid=donation_txid,
            donated_sats=amount_sats,
            initial_trust=round(min(10.0, amount_sats / community.join_fee_sats), 2),
        )
        community.members[agent_id] = member
        self._rebalance_members(community)
        self.audit.record(
            actor_id=agent_id,
            subject_id=agent_id,
            action="community_member_added",
            details={
                "community_id": community_id,
                "wallet_address": wallet_address,
                "amount_sats": amount_sats,
                "txid": donation_txid,
                "initial_trust": member.initial_trust,
                "assigned_seedbox_id": member.assigned_seedbox_id,
            },
        )
        self.store.save_all(communities)
        expansion = self.maybe_expand_seedboxes(community, actor_id=agent_id)
        community = self._require_community(self.store.load_all(), community_id)
        return {
            "ok": True,
            "member": asdict(community.members[agent_id]),
            "expansion": expansion,
            "community": self._community_payload(community),
        }

    def maybe_expand_seedboxes(self, community: Community, *, actor_id: str) -> dict[str, Any]:
        required = community.required_seedbox_count()
        current = community.seedbox_count()
        if required <= current:
            return {"expanded": False, "reason": "capacity_available", "required_seedboxes": required}
        self.audit.record(
            actor_id=actor_id,
            subject_id=community.community_id,
            action="seedbox_capacity_reached",
            details={
                "community_id": community.community_id,
                "member_count": community.member_count(),
                "current_seedboxes": current,
                "required_seedboxes": required,
                "treasury_balance_sats": community.treasury.balance_sats,
            },
        )
        if community.treasury.balance_sats < community.seedbox_purchase_threshold_sats:
            return {"expanded": False, "reason": "insufficient_treasury", "required_seedboxes": required}
        existing_seedboxes = sorted(community.seedboxes.values(), key=lambda item: item.created_at)
        expansion_provider = existing_seedboxes[0].provider if existing_seedboxes else "local"
        result = self.buy_seedbox(
            community_id=community.community_id,
            actor_id=actor_id,
            provider=expansion_provider,
            capacity_gb=100,
        )
        return {"expanded": True, "reason": "threshold_reached", "seedbox": result["seedbox"]}

    def import_file_catalog(self, *, community_id: str, csv_path: str | Path) -> dict[str, Any]:
        communities = self.store.load_all()
        community = self._require_community(communities, community_id)
        count = 0
        with Path(csv_path).open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                file_id = row["file_id"]
                community.files[file_id] = CommunityFile(
                    file_id=file_id,
                    name=row["name"],
                    tags=tuple(tag.strip() for tag in row.get("tags", "").split(",") if tag.strip()),
                    sha256=row.get("sha256", ""),
                    size_bytes=int(row.get("size_bytes") or 0),
                    seedbox_id=row["seedbox_id"],
                    content_url=row["content_url"],
                    magnet_uri=row.get("magnet_uri", ""),
                )
                count += 1
        self.store.save_all(communities)
        self.audit.record(
            actor_id=community.founder_agent_id,
            subject_id=community_id,
            action="file_catalog_imported",
            details={"community_id": community_id, "csv_path": str(csv_path), "file_count": count},
        )
        return {"ok": True, "file_count": count, "community": self._community_payload(community)}

    def find_file(self, *, community_id: str, requester_agent_id: str, query: str) -> dict[str, Any]:
        communities = self.store.load_all()
        community = self._require_community(communities, community_id)
        normalized = query.casefold().strip()
        matches = [
            item
            for item in community.files.values()
            if normalized in item.name.casefold()
            or normalized in item.content_url.casefold()
            or any(normalized in tag.casefold() for tag in item.tags)
        ]
        comm_result = self.communication.request_file_location(
            sender_id=requester_agent_id,
            community_id=community_id,
            query=query,
        )
        self.audit.record(
            actor_id=requester_agent_id,
            subject_id=community_id,
            action="file_search_requested",
            details={
                "community_id": community_id,
                "query": query,
                "match_count": len(matches),
                "communication": comm_result,
            },
        )
        return {"ok": True, "query": query, "count": len(matches), "files": [asdict(item) for item in matches]}

    def retrieve_file(self, *, community_id: str, requester_agent_id: str, file_id: str) -> dict[str, Any]:
        communities = self.store.load_all()
        community = self._require_community(communities, community_id)
        file_item = community.files[file_id]
        verified = self._verify_file_item(file_item)
        action = "file_retrieval_verified" if verified else "file_retrieved"
        self.audit.record(
            actor_id=requester_agent_id,
            subject_id=community_id,
            action=action,
            details={
                "community_id": community_id,
                "file": asdict(file_item),
                "verified": verified,
                "retrieval_trust_delta": 1 if verified else -2,
            },
        )
        return {"ok": True, "file": asdict(file_item), "verified": verified}

    def get_status(self, *, community_id: str) -> dict[str, Any]:
        community = self._require_community(self.store.load_all(), community_id)
        return {"ok": True, "community": self._community_payload(community)}

    @staticmethod
    def _fund_treasury(
        community: Community,
        *,
        agent_id: str,
        wallet_address: str,
        amount_sats: int,
        txid: str,
    ) -> None:
        del agent_id, wallet_address, txid
        community.treasury.balance_sats += amount_sats
        community.treasury.incoming_sats += amount_sats

    @staticmethod
    def _require_community(communities: dict[str, Community], community_id: str) -> Community:
        try:
            return communities[community_id]
        except KeyError as exc:
            raise KeyError(f"unknown community {community_id}") from exc

    @staticmethod
    def _rebalance_members(community: Community) -> None:
        seedbox_ids = [
            seedbox.seedbox_id for seedbox in sorted(community.seedboxes.values(), key=lambda item: item.created_at)
        ]
        if not seedbox_ids:
            return
        members = sorted(community.members.values(), key=lambda item: item.joined_at)
        for index, member in enumerate(members):
            member.assigned_seedbox_id = seedbox_ids[min(index // community.seedbox_capacity_agents, len(seedbox_ids) - 1)]

    @staticmethod
    def _verify_file_item(file_item: CommunityFile) -> bool:
        if not file_item.sha256:
            return True
        path = Path(file_item.content_url)
        if not path.exists() or not path.is_file():
            return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == file_item.sha256

    @staticmethod
    def _community_payload(community: Community) -> dict[str, Any]:
        payload = asdict(community)
        payload["member_count"] = community.member_count()
        payload["seedbox_count"] = community.seedbox_count()
        payload["required_seedbox_count"] = community.required_seedbox_count()
        return payload


def _treasury_wallet(community_id: str) -> str:
    digest = hashlib.sha256(f"community-treasury:{community_id}".encode("utf-8")).hexdigest()[:40]
    return f"dclaw-treasury-{digest}"
