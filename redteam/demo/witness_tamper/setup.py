"""Bootstrap the witness-tamper-and-forward demo preconditions."""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import (
    SignedAppendOnlyLog,
    _canonical_bytes,
    _stable_hash,
)

_NETWORK = "witness-tamper-demo"
_LIVE_NETWORK = "TESTNET"


@dataclass
class BootstrapResult:
    a_identity: OpenClawIdentity
    b_identity: OpenClawIdentity
    c_identity: OpenClawIdentity
    a_log_path: Path
    b_log_path: Path
    c_log_path: Path
    b_log: SignedAppendOnlyLog
    c_log: SignedAppendOnlyLog
    witness_entry: dict
    network: str


def bootstrap(tmp_root: Path) -> BootstrapResult:
    tmp_root = Path(tmp_root)
    tmp_root.mkdir(parents=True, exist_ok=True)

    a = OpenClawIdentity(network=_NETWORK, key_path=tmp_root / "A.key.json")
    b = OpenClawIdentity(network=_NETWORK, key_path=tmp_root / "B.key.json")
    c = OpenClawIdentity(network=_NETWORK, key_path=tmp_root / "C.key.json")

    a_log_path = tmp_root / "A.log"
    b_log_path = tmp_root / "B.log"
    c_log_path = tmp_root / "C.log"

    # Touch A's log so the file exists with just the header.
    SignedAppendOnlyLog(a, a_log_path)
    b_log = SignedAppendOnlyLog(b, b_log_path)
    c_log = SignedAppendOnlyLog(c, c_log_path)

    details = {"amount": 5, "recipient": "community_alpha"}
    subject_claim = {
        "kind": "claim",
        "version": 1,
        "subject_id": a.identity_hash,
        "action": "donation",
        "details_hash": _stable_hash(details),
        "claim_timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_hex(16),
    }
    subject_signature = a.sign(_canonical_bytes(subject_claim))

    witness_entry = b_log.append_witness_event(
        reporter_id=b.identity_hash,
        subject_id=a.identity_hash,
        subject_pubkey=a.public_key,
        subject_claim=subject_claim,
        subject_signature=subject_signature,
        action="donation",
        details=details,
    )

    return BootstrapResult(
        a_identity=a,
        b_identity=b,
        c_identity=c,
        a_log_path=a_log_path,
        b_log_path=b_log_path,
        c_log_path=c_log_path,
        b_log=b_log,
        c_log=c_log,
        witness_entry=witness_entry,
        network=a.network,
    )


_LIVE_MANIFEST_TEMPLATE = """\
# Identity

- name: witness_tamper_demo_live
- version: 1.0.0
- description: Live-agent witness-tamper demo manifest.

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


def live_bootstrap(tmp_root: Path) -> BootstrapResult:
    """Run the live MCP-tool flow to produce a real witness entry on B's log.

    Spins up A and B as full OpenClawAgent instances, has A call
    ``community_donate_and_join`` to produce a signed claim envelope, then
    has B call ``community_witness_donation`` to record a real witness entry
    in B's actual community log. C is created as a synthetic identity/log
    pair (C is the auditor, not a live agent in this demo).

    The returned ``BootstrapResult`` is shape-compatible with ``bootstrap``
    so the downstream tamper+forward+ban pipeline consumes it unchanged.
    """
    from agent import AgentConfig, OpenClawAgent, build_tools
    from communication.bittorrent import StubBitTorrentService
    from identity.agent_identity import AgentIdentity
    from identity.seed import MnemonicSeedSource
    from protocol import StubLLMClient

    tmp_root = Path(tmp_root)
    tmp_root.mkdir(parents=True, exist_ok=True)

    alice_dir = tmp_root / "alice"
    bob_dir = tmp_root / "bob"
    alice_dir.mkdir(parents=True, exist_ok=True)
    bob_dir.mkdir(parents=True, exist_ok=True)

    seed_a = MnemonicSeedSource(
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    ).load()
    seed_b = MnemonicSeedSource(
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
    ).load()

    def _make_agent(seed, save_dir: Path) -> OpenClawAgent:
        return OpenClawAgent(
            identity=AgentIdentity.from_seed(seed, network=_LIVE_NETWORK),
            llm=StubLLMClient(sources={}),
            config=AgentConfig(
                port=0,
                save_dir=save_dir,
                initial_balance_sats=200_000,
                community_log_path=save_dir / "community.log",
                peer_log_dir=save_dir / "peer_logs",
            ),
            bt_service=StubBitTorrentService(save_dir=save_dir),
        )

    alice = _make_agent(seed_a, alice_dir)
    bob = _make_agent(seed_b, bob_dir)

    async def _run() -> tuple[dict, OpenClawIdentity, OpenClawIdentity, Path]:
        await alice.start()
        await bob.start()
        try:
            manifest_md = _LIVE_MANIFEST_TEMPLATE.format(
                gatekeeper_address=alice.wallet.address()
            )
            alice.load_manifest(manifest_md)
            bob.load_manifest(manifest_md)

            tools_a = build_tools(alice)
            tools_b = build_tools(bob)

            donate = await tools_a.dispatch(
                "community_donate_and_join", {"amount_sats": 50_000}
            )
            if "subject_claim" not in donate:
                raise RuntimeError(f"donate_and_join failed: {donate}")

            witness = await tools_b.dispatch("community_witness_event", {
                "action": "donation_intent",
                "details": {
                    "amount_sats": donate["amount_sats"],
                    "network_id_hex": donate["network_id_hex"],
                },
                "subject_claim": donate["subject_claim"],
                "subject_signature_hex": donate["subject_signature_hex"],
                "subject_pubkey_hex": donate["subject_pubkey_hex"],
            })
            if "error" in witness:
                raise RuntimeError(f"witness_event failed: {witness}")

            entries = list(bob.community_log.read_entries())
            witness_entry = next(
                (e for e in reversed(entries) if e.get("entry_hash") == witness["entry_hash"]),
                None,
            )
            if witness_entry is None:
                raise RuntimeError("witness entry not found on B's log after live flow")

            alice_oc = OpenClawIdentity.from_agent_identity(alice.identity)
            bob_oc = OpenClawIdentity.from_agent_identity(bob.identity)
            bob_log_path = Path(bob.community_log.log_path)
            return witness_entry, alice_oc, bob_oc, bob_log_path
        finally:
            await alice.stop()
            await bob.stop()

    witness_entry, alice_oc, bob_oc, bob_log_path = asyncio.run(_run())

    c_identity = OpenClawIdentity(
        network=alice_oc.network, key_path=tmp_root / "C.key.json"
    )
    c_log_path = tmp_root / "C.log"
    c_log = SignedAppendOnlyLog(c_identity, c_log_path)

    return BootstrapResult(
        a_identity=alice_oc,
        b_identity=bob_oc,
        c_identity=c_identity,
        a_log_path=Path(alice.community_log.log_path),
        b_log_path=bob_log_path,
        c_log_path=c_log_path,
        b_log=bob.community_log,
        c_log=c_log,
        witness_entry=witness_entry,
        network=alice_oc.network,
    )
