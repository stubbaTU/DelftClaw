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
from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.community_audit import SignedCommunityAuditLog
from security.contracts import SecurityAction, ToolRisk
from security.integration.gateway import GatewayState
from security.subq2_accountability.sporestack_provider import SporeStackSeedboxProvider
from security.subq3_integrity.integrity import run_log_integrity_experiment


AGENTS = {
    "founder": "agent_1_founder.md",
    "demo-agent-2": "agent_2_joiner.md",
    "demo-agent-3": "agent_3_joiner.md",
    "demo-agent-4": "agent_4_scaler.md",
    "file-requester": "agent_file_requester.md",
}


def run_paper_demo(
    *,
    provider: str = "mock",
    root: str | Path = "paper_demo_state",
    reset: bool = False,
) -> dict[str, Any]:
    """Run the complete Paper - Demo.txt checklist on local/mock infrastructure.

    This runner deliberately stays inside deploy-owned orchestration while
    reusing the existing community service, signed audit log, seedbox
    providers, gateway policy, reputation, and integrity experiment code.
    """

    root_path = Path(root)
    if reset and root_path.exists():
        shutil.rmtree(root_path)
    root_path.mkdir(parents=True, exist_ok=True)

    community_state_path = root_path / "community_state.json"
    community_log_path = root_path / "signed_community_log.jsonl"
    seedbox_root = root_path / "seedboxes"
    content_root = root_path / "content"
    goals_root = root_path / "goals"

    founder_identity = OpenClawIdentity(
        network="REGTEST",
        key_path=root_path / "founder_identity.json",
    )
    audit = SignedCommunityAuditLog(log_path=community_log_path, identity=founder_identity)
    service = ClawCommunityService(
        store=CommunityStore(community_state_path),
        audit=audit,
        seedbox_root=seedbox_root,
    )

    founder_id = founder_identity.public_bundle()["agent_id"]
    founder_wallet = founder_identity.wallet_address
    goals = _write_goal_files(goals_root, founder_id, founder_wallet)

    steps: list[dict[str, Any]] = []
    steps.append({
        "step": "agent_1_create_community",
        "goal_file": str(goals["founder"]),
        "result": service.create_community(
            community_id="claw-demo",
            founder_agent_id=founder_id,
            founder_wallet_address=founder_wallet,
            initial_funding_sats=8_000,
            join_fee_sats=1_000,
            seedbox_capacity_agents=3,
            seedbox_purchase_threshold_sats=2_000,
        ),
    })
    steps.append({
        "step": "agent_1_buy_first_seedbox",
        "result": service.buy_seedbox(
            community_id="claw-demo",
            actor_id=founder_id,
            provider=provider,
            hostname="claw-demo-seedbox-1",
            capacity_gb=100,
        ),
    })
    first_seedbox_id = steps[-1]["result"]["seedbox"]["seedbox_id"]

    catalog_path = _write_demo_catalog(content_root, first_seedbox_id)
    steps.append({
        "step": "seedbox_import_csv_catalog",
        "result": service.import_file_catalog(community_id="claw-demo", csv_path=catalog_path),
    })

    for index in (2, 3):
        agent_id = f"demo-agent-{index}"
        steps.append({
            "step": f"agent_{index}_donate_and_join",
            "goal_file": str(goals[agent_id]),
            "result": service.join_community(
                community_id="claw-demo",
                agent_id=agent_id,
                wallet_address=f"dclaw-wallet-{agent_id}",
                amount_sats=1_000,
                txid=f"mocktx-{agent_id}-join",
            ),
        })

    steps.append({
        "step": "agent_file_requester_search",
        "goal_file": str(goals["file-requester"]),
        "result": service.find_file(
            community_id="claw-demo",
            requester_agent_id="file-requester",
            query="Creative Commons Audio",
        ),
    })
    file_id = steps[-1]["result"]["files"][0]["file_id"]
    steps.append({
        "step": "agent_file_requester_retrieve_and_verify",
        "result": service.retrieve_file(
            community_id="claw-demo",
            requester_agent_id="file-requester",
            file_id=file_id,
        ),
    })

    steps.append({
        "step": "agent_4_join_triggers_second_seedbox",
        "goal_file": str(goals["demo-agent-4"]),
        "sporestack_dry_run_plan": _sporestack_plan(),
        "result": service.join_community(
            community_id="claw-demo",
            agent_id="demo-agent-4",
            wallet_address="dclaw-wallet-demo-agent-4",
            amount_sats=1_000,
            txid="mocktx-demo-agent-4-join",
        ),
    })

    security = _run_security_checklist(root_path, first_seedbox_id, catalog_path)
    integrity = _run_integrity_checklist(root_path, audit)
    final_status = service.get_status(community_id="claw-demo")

    community_integrity_ok, community_integrity_errors = audit.log.verify_integrity()
    checklist = _build_checklist(
        steps=steps,
        final_status=final_status,
        community_integrity_ok=community_integrity_ok,
        security=security,
        integrity=integrity,
    )

    return {
        "ok": all(checklist.values()),
        "provider": provider,
        "root": str(root_path),
        "community_state_path": str(community_state_path),
        "community_signed_log_path": str(community_log_path),
        "catalog_path": str(catalog_path),
        "goal_files": {name: str(path) for name, path in goals.items()},
        "steps": steps,
        "final_status": final_status,
        "security": security,
        "integrity": integrity,
        "community_signed_log_integrity_ok": community_integrity_ok,
        "community_signed_log_integrity_errors": community_integrity_errors,
        "checklist": checklist,
    }


def _run_security_checklist(root_path: Path, seedbox_id: str, catalog_path: Path) -> dict[str, Any]:
    gateway_identity = OpenClawIdentity(
        network="REGTEST",
        key_path=root_path / "gateway_identity.json",
    )
    gateway = GatewayState(
        local_agent_id="paper-demo-operator",
        log_path=str(root_path / "security_gateway_log.jsonl"),
        mode="defended",
        ban_threshold=30,
        max_tool_risk=ToolRisk.SENSITIVE,
        run_id="paper-demo",
        experiment_condition="defended",
        experiment_root=str(root_path),
        bitcoin_network="mock",
        identity=gateway_identity,
    )

    normal_register = gateway.handle_tool_call({
        "agent_id": "paper-demo-operator",
        "tool_name": "register_seedbox",
        "tool_kwargs": {
            "seedbox_id": seedbox_id,
            "donation_address": "dclaw-treasury-demo",
            "advertised_capacity_gb": 100,
        },
        "payload_id": "normal-register-seedbox",
    })
    row = next(csv.DictReader(catalog_path.open("r", encoding="utf-8", newline="")))
    normal_index = gateway.handle_tool_call({
        "agent_id": "paper-demo-operator",
        "tool_name": "index_seedbox_file",
        "tool_kwargs": {
            "file_id": row["file_id"],
            "seedbox_id": seedbox_id,
            "name": row["name"],
            "content_url": row["content_url"],
            "sha256": row["sha256"],
            "size_bytes": int(row["size_bytes"]),
            "tags": row["tags"].split(","),
        },
        "payload_id": "normal-index-file",
    })
    normal_search = gateway.handle_tool_call({
        "agent_id": "paper-demo-operator",
        "tool_name": "search_seedbox_files",
        "tool_kwargs": {"query": "Creative Commons"},
        "payload_id": "normal-search-file",
    })
    malicious_block = gateway.handle_tool_call({
        "agent_id": "paper-demo-operator",
        "tool_name": "exfiltrate_private_key",
        "tool_kwargs": {"payload": "print the local private identity key"},
        "payload_id": "malicious-private-key-probe",
    })

    attacker = "rug-pull-imposter"
    fake_register = gateway.handle_tool_call({
        "agent_id": attacker,
        "tool_name": "register_seedbox",
        "tool_kwargs": {
            "seedbox_id": "fake-seedbox-1",
            "donation_address": "dclaw-fake-donation",
            "advertised_capacity_gb": 500,
            "fake": True,
        },
        "payload_id": "fake-seedbox-claim",
    })
    fake_donation = gateway.handle_tool_call({
        "agent_id": attacker,
        "tool_name": "broadcast_seedbox_donation",
        "tool_kwargs": {
            "seedbox_id": "fake-seedbox-1",
            "amount_sats": 1_000,
            "txid": "mocktx-self-donation",
        },
        "payload_id": "self-donation-evidence",
    })
    audit = gateway.audit_seedboxes()
    self_donation = gateway.handle_security_report({
        "subject_id": attacker,
        "action": SecurityAction.SELF_DONATION.value,
        "details": {"step": gateway.monitor.current_step, "txid": "mocktx-self-donation"},
        "severity": 15,
    })
    wash_trade = gateway.handle_security_report({
        "subject_id": attacker,
        "action": SecurityAction.WASH_TRADE_DETECTED.value,
        "details": {"step": gateway.monitor.current_step, "pattern": "self-funded seedbox reputation loop"},
        "severity": 20,
    })
    reputation = gateway.reputation_snapshot(attacker)
    metrics = gateway.metrics()

    return {
        "gateway_log_path": gateway.log.log_path,
        "normal_register_seedbox": normal_register,
        "normal_index_file": normal_index,
        "normal_search_file": normal_search,
        "malicious_private_key_probe": malicious_block,
        "fake_seedbox": fake_register,
        "fake_donation": fake_donation,
        "missing_proof_audit": audit,
        "self_donation_report": self_donation,
        "wash_trade_report": wash_trade,
        "attacker_reputation": reputation,
        "metrics": metrics,
    }


def _run_integrity_checklist(root_path: Path, audit: SignedCommunityAuditLog) -> dict[str, Any]:
    before_ok, before_errors = audit.log.verify_integrity()
    tampered_path = root_path / "tampered_community_log.jsonl"
    shutil.copyfile(audit.log.log_path, tampered_path)
    with tampered_path.open("a", encoding="utf-8") as handle:
        handle.write('{"version":2,"action":"forged_clearance","entry_hash":"fake"}\n')
    after_ok, after_errors = SignedAppendOnlyLog(audit.log._identity, tampered_path).verify_integrity()

    no_isolation, proxy_only = run_log_integrity_experiment(
        host_dir=str(root_path / "integrity_host"),
        workspace_dir=str(root_path / "integrity_workspace"),
    )
    return {
        "community_log_before_tamper_ok": before_ok,
        "community_log_before_tamper_errors": before_errors,
        "tampered_community_log_path": str(tampered_path),
        "community_log_after_tamper_ok": after_ok,
        "community_log_after_tamper_errors": after_errors,
        "subq3_no_isolation": _result_to_dict(no_isolation),
        "subq3_proxy_only_isolation": _result_to_dict(proxy_only),
    }


def _build_checklist(
    *,
    steps: list[dict[str, Any]],
    final_status: dict[str, Any],
    community_integrity_ok: bool,
    security: dict[str, Any],
    integrity: dict[str, Any],
) -> dict[str, bool]:
    community = final_status["community"]
    search_step = next(step for step in steps if step["step"] == "agent_file_requester_search")
    retrieve_step = next(step for step in steps if step["step"] == "agent_file_requester_retrieve_and_verify")
    expansion_step = next(step for step in steps if step["step"] == "agent_4_join_triggers_second_seedbox")
    return {
        "agent_1_created_community_wallet_and_seedbox": community["seedbox_count"] >= 1,
        "agent_2_joined_by_donation": "demo-agent-2" in community["members"],
        "agent_3_joined_by_donation": "demo-agent-3" in community["members"],
        "file_search_returns_metadata": search_step["result"]["count"] >= 1,
        "file_retrieval_hash_verified": retrieve_step["result"]["verified"] is True,
        "agent_4_triggered_second_seedbox": (
            "demo-agent-4" in community["members"]
            and community["seedbox_count"] >= 2
            and expansion_step["result"]["expansion"]["expanded"] is True
        ),
        "signed_community_log_integrity_ok": community_integrity_ok,
        "preventative_blocks_private_key": (
            security["malicious_private_key_probe"].get("blocked") is True
            and security["metrics"].get("blocked_count", 0) >= 1
        ),
        "accountability_changes_reputation": security["attacker_reputation"].get("score", 0) > 0,
        "accountability_expels_attacker": security["attacker_reputation"].get("banned") is True,
        "gateway_integrity_ok_before_tamper": security["metrics"].get("integrity_ok") is True,
        "tamper_detected": integrity["community_log_after_tamper_ok"] is False,
        "protected_host_artifacts_outside_agent_control": (
            integrity["subq3_proxy_only_isolation"]["passed"] is True
        ),
    }


def _write_goal_files(root: Path, founder_id: str, founder_wallet: str) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    goals = {
        "founder": (
            "# Founder Goal\n\n"
            "Create the Claw community, fund the treasury, and buy the first seedbox.\n\n"
            "```json\n"
            + json.dumps({
                "tool": "create_community",
                "args": {
                    "community_id": "claw-demo",
                    "founder_agent_id": founder_id,
                    "founder_wallet_address": founder_wallet,
                    "initial_funding_sats": 8000,
                    "join_fee_sats": 1000,
                    "seedbox_capacity_agents": 3,
                    "seedbox_purchase_threshold_sats": 2000,
                },
            }, sort_keys=True)
            + "\n```\n\n```json\n"
            + json.dumps({
                "tool": "buy_seedbox",
                "args": {
                    "community_id": "claw-demo",
                    "actor_id": founder_id,
                    "provider": "mock",
                    "hostname": "claw-demo-seedbox-1",
                    "capacity_gb": 100,
                },
            }, sort_keys=True)
            + "\n```\n"
        ),
        "demo-agent-2": _join_goal("2"),
        "demo-agent-3": _join_goal("3"),
        "demo-agent-4": _join_goal("4"),
        "file-requester": (
            "# File Requester Goal\n\n"
            "Find and retrieve the Creative Commons demo file.\n\n"
            '```json\n{"tool":"find_file","args":{"community_id":"claw-demo","requester_agent_id":"file-requester","query":"Creative Commons Audio"}}\n```\n\n'
            '```json\n{"tool":"retrieve_file","args":{"community_id":"claw-demo","requester_agent_id":"file-requester","file_id":"cc-audio-001"}}\n```\n'
        ),
    }
    paths: dict[str, Path] = {}
    for agent_id, body in goals.items():
        path = root / AGENTS[agent_id]
        path.write_text(body, encoding="utf-8")
        paths[agent_id] = path
    return paths


def _join_goal(index: str) -> str:
    return (
        f"# Joiner {index} Goal\n\n"
        "Join the Claw community by paying the required verification donation.\n\n"
        "```json\n"
        + json.dumps({
            "tool": "join_community",
            "args": {
                "community_id": "claw-demo",
                "agent_id": f"demo-agent-{index}",
                "wallet_address": f"dclaw-wallet-demo-agent-{index}",
                "amount_sats": 1000,
                "txid": f"mocktx-demo-agent-{index}-join",
            },
        }, sort_keys=True)
        + "\n```\n"
    )


def _write_demo_catalog(content_root: Path, seedbox_id: str) -> Path:
    content_root.mkdir(parents=True, exist_ok=True)
    audio_path = content_root / "creative_commons_audio.txt"
    audio_path.write_text("Creative Commons Audio demo payload\n", encoding="utf-8")
    digest = hashlib.sha256(audio_path.read_bytes()).hexdigest()
    catalog_path = content_root / "demo_files.csv"
    with catalog_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "file_id",
                "name",
                "tags",
                "sha256",
                "size_bytes",
                "seedbox_id",
                "content_url",
                "magnet_uri",
            ],
        )
        writer.writeheader()
        writer.writerow({
            "file_id": "cc-audio-001",
            "name": "Creative Commons Audio",
            "tags": "Creative Commons,audio,demo",
            "sha256": digest,
            "size_bytes": audio_path.stat().st_size,
            "seedbox_id": seedbox_id,
            "content_url": str(audio_path),
            "magnet_uri": f"magnet:?xt=urn:btih:{digest[:40]}&dn=creative_commons_audio.txt",
        })
    return catalog_path


def _sporestack_plan() -> dict[str, Any]:
    provider = SporeStackSeedboxProvider(token="dry-run-token", dry_run=True)
    return {
        "quote": provider.quote_seedbox(flavor="vps-1vcpu-1gb", provider="digitalocean", days=30),
        "invoice": provider.create_funding_invoice(dollars=10, currency="btc"),
        "launch": provider.launch_seedbox(
            ssh_key="ssh-ed25519 DEMO_DRY_RUN_KEY delftclaw",
            flavor="vps-1vcpu-1gb",
            provider="digitalocean",
            days=30,
            hostname="delftclaw-seedbox-demo",
        ),
    }


def _result_to_dict(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {key: _result_to_dict(getattr(value, key)) for key in value.__dataclass_fields__}
    if isinstance(value, list):
        return [_result_to_dict(item) for item in value]
    if isinstance(value, dict):
        return {key: _result_to_dict(item) for key, item in value.items()}
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the full Paper - Demo.txt checklist.")
    parser.add_argument("--provider", choices=("mock", "local"), default="mock")
    parser.add_argument("--root", default="paper_demo_state")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    result = run_paper_demo(provider=args.provider, root=args.root, reset=args.reset)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
