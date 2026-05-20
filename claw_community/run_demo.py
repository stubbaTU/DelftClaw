from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from claw_community.service import ClawCommunityService
from claw_community.state import CommunityStore
from identity.openclaw_identity import OpenClawIdentity
from security.community_audit import SignedCommunityAuditLog


def run_demo(
    *,
    provider: str = "local",
    root: str | Path = "claw_community_state/demo",
    reset: bool = False,
) -> dict[str, Any]:
    root_path = Path(root)
    state_path = root_path / "community_state.json"
    log_path = root_path / "signed_community_log.jsonl"
    seedbox_root = root_path / "seedboxes"
    content_root = root_path / "content"
    if reset and root_path.exists():
        shutil.rmtree(root_path)
    root_path.mkdir(parents=True, exist_ok=True)

    identity = OpenClawIdentity(network="REGTEST", key_path=root_path / "founder_identity.json")
    audit = SignedCommunityAuditLog(log_path=log_path, identity=identity)
    service = ClawCommunityService(
        store=CommunityStore(state_path),
        audit=audit,
        seedbox_root=seedbox_root,
    )

    steps: list[dict[str, Any]] = []
    founder_id = identity.public_bundle()["agent_id"]
    founder_wallet = identity.wallet_address

    steps.append(
        {
            "step": "create_community",
            "result": service.create_community(
                community_id="claw-demo",
                founder_agent_id=founder_id,
                founder_wallet_address=founder_wallet,
                initial_funding_sats=8_000,
                join_fee_sats=1_000,
                seedbox_capacity_agents=3,
                seedbox_purchase_threshold_sats=2_000,
            ),
        }
    )
    steps.append(
        {
            "step": "buy_first_seedbox",
            "result": service.buy_seedbox(
                community_id="claw-demo",
                actor_id=founder_id,
                provider=provider,
                hostname="claw-demo-seedbox-1",
                capacity_gb=100,
            ),
        }
    )
    first_seedbox = steps[-1]["result"]["seedbox"]["seedbox_id"]
    catalog_path = _write_demo_catalog(content_root, first_seedbox)
    steps.append(
        {
            "step": "import_file_catalog",
            "result": service.import_file_catalog(community_id="claw-demo", csv_path=catalog_path),
        }
    )
    for index in (2, 3):
        steps.append(
            {
                "step": f"agent_{index}_joins",
                "result": service.join_community(
                    community_id="claw-demo",
                    agent_id=f"demo-agent-{index}",
                    wallet_address=f"dclaw-wallet-demo-agent-{index}",
                    amount_sats=1_000,
                    txid=f"mocktx-demo-agent-{index}-join",
                ),
            }
        )
    steps.append(
        {
            "step": "find_file",
            "result": service.find_file(
                community_id="claw-demo",
                requester_agent_id=founder_id,
                query="Creative Commons Audio",
            ),
        }
    )
    file_id = steps[-1]["result"]["files"][0]["file_id"]
    steps.append(
        {
            "step": "retrieve_file",
            "result": service.retrieve_file(
                community_id="claw-demo",
                requester_agent_id=founder_id,
                file_id=file_id,
            ),
        }
    )
    steps.append(
        {
            "step": "agent_4_joins_and_triggers_expansion",
            "result": service.join_community(
                community_id="claw-demo",
                agent_id="demo-agent-4",
                wallet_address="dclaw-wallet-demo-agent-4",
                amount_sats=1_000,
                txid="mocktx-demo-agent-4-join",
            ),
        }
    )
    status = service.get_status(community_id="claw-demo")
    integrity_ok, integrity_errors = audit.log.verify_integrity()
    return {
        "ok": integrity_ok and status["community"]["member_count"] == 4 and status["community"]["seedbox_count"] == 2,
        "provider": provider,
        "state_path": str(state_path),
        "signed_log_path": str(log_path),
        "catalog_path": str(catalog_path),
        "steps": steps,
        "final_status": status,
        "signed_log_integrity_ok": integrity_ok,
        "signed_log_integrity_errors": integrity_errors,
    }


def _write_demo_catalog(content_root: Path, seedbox_id: str) -> Path:
    content_root.mkdir(parents=True, exist_ok=True)
    audio_path = content_root / "creative_commons_audio.txt"
    audio_path.write_text("Creative Commons Audio demo payload\n", encoding="utf-8")
    digest = hashlib.sha256(audio_path.read_bytes()).hexdigest()
    catalog_path = content_root / "demo_files.csv"
    with catalog_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["file_id", "name", "tags", "sha256", "size_bytes", "seedbox_id", "content_url", "magnet_uri"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "cc-audio-001",
                "name": "Creative Commons Audio",
                "tags": "Creative Commons,audio,demo",
                "sha256": digest,
                "size_bytes": audio_path.stat().st_size,
                "seedbox_id": seedbox_id,
                "content_url": str(audio_path),
                "magnet_uri": f"magnet:?xt=urn:btih:{digest[:40]}&dn=creative_commons_audio.txt",
            }
        )
    return catalog_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the full Claw community professor demo.")
    parser.add_argument("--provider", choices=("mock", "local"), default="local")
    parser.add_argument("--root", default="claw_community_state/demo")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run_demo(provider=args.provider, root=args.root, reset=args.reset), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
