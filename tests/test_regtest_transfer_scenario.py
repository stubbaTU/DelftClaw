from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from ipv8.peer import Peer

from agent import AgentConfig, OpenClawAgent, build_tools
from agent.regtest_wallet import RegtestWallet
from communication.bittorrent import StubBitTorrentService
from deploy.scenario import parse_scenario
from deploy.scenario_boot import _instance_env_contents
from identity.agent_identity import AgentIdentity
from identity.openclaw_identity import OpenClawIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient


REPO_ROOT = Path(__file__).resolve().parent.parent
REGTEST_TRANSFER = REPO_ROOT / "deploy" / "scenarios" / "regtest_transfer"


MANIFEST_TEMPLATE = """\
# Identity

- name: regtest_transfer
- version: 1.0.0
- description: Regtest transfer admission fixture.

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
| 127.0.0.1 | 8200 | {alice_pubkey_hex} |

# Default Overlays

- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a
"""


class _FakeRegtestRPC:
    def __init__(self, wallet_name: str, address: str, balance_sat: int = 200_000) -> None:
        self.wallet_name = wallet_name
        self.address = address
        self.balance_sat = balance_sat
        self.sent: list[tuple[str, int]] = []

    async def get_balance_sat(self, wallet: str | None = None) -> int:  # noqa: ARG002
        return self.balance_sat

    async def get_or_create_labeled_address(
        self,
        label: str,
        address_type: str = "bech32",  # noqa: ARG002
    ) -> str:
        assert label == f"delftclaw:{self.wallet_name}:primary"
        return self.address

    async def send_to_address(
        self,
        to_address: str,
        amount_sat: int,
        wallet: str | None = None,  # noqa: ARG002
        fee_rate_sat_per_vb: int | None = None,  # noqa: ARG002
    ) -> str:
        self.sent.append((to_address, amount_sat))
        return f"{self.wallet_name[:1]}" * 64


@pytest.fixture(scope="module")
def scenario():
    return parse_scenario(REGTEST_TRANSFER / "scenario.yaml")


def test_regtest_transfer_cross_wires_signed_log_pull_loop(scenario):
    alice_env = _instance_env_contents(scenario, scenario.agents["alice"])
    bob_env = _instance_env_contents(scenario, scenario.agents["bob"])

    assert scenario.agents["alice"].bootstrap_community_sats == 10_000
    assert "REDTEAM_PORT=28865" in alice_env
    assert "PEER_LOG_URLS=http://127.0.0.1:28866" in alice_env
    assert "REDTEAM_PORT=28866" in bob_env
    assert "PEER_LOG_URLS=http://127.0.0.1:28865" in bob_env


@pytest.mark.asyncio
async def test_regtest_transfer_bob_join_is_onchain_and_visible_to_alice(tmp_path):
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    alice_dir.mkdir()
    bob_dir.mkdir()

    alice_seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    bob_seed = MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load()

    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(alice_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=alice_dir,
            initial_balance_sats=200_000,
            btc_network="regtest",
            community_log_path=alice_dir / "community.log",
            peer_log_dir=alice_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=alice_dir),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(bob_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=bob_dir,
            initial_balance_sats=10_000,
            btc_network="regtest",
            community_log_path=bob_dir / "community.log",
            peer_log_dir=bob_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=bob_dir),
    )

    await alice.start()
    await bob.start()
    stop_event = asyncio.Event()
    pull_task = None
    client = None
    try:
        alice_rpc = _FakeRegtestRPC(
            "alice",
            "bcrt1qexamplexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        )
        bob_rpc = _FakeRegtestRPC(
            "bob",
            "bcrt1qrecipientxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            balance_sat=10_000,
        )
        alice.wallet = RegtestWallet(
            alice.wallet,
            rpc_client=alice_rpc,  # type: ignore[arg-type]
            use_onchain=True,
        )
        bob.wallet = RegtestWallet(
            bob.wallet,
            rpc_client=bob_rpc,  # type: ignore[arg-type]
            use_onchain=True,
        )
        alice_onchain = await alice.wallet.get_onchain_address()  # type: ignore[attr-defined]
        bob_onchain = await bob.wallet.get_onchain_address()  # type: ignore[attr-defined]
        alice.seedbox.configure(wallet_address=alice_onchain)
        bob.seedbox.configure(wallet_address=bob_onchain)

        alice.seedbox.network.add_verified_peer(
            Peer(bob.seedbox.my_peer.public_key, address=bob.address),
        )
        bob.seedbox.network.add_verified_peer(
            Peer(alice.seedbox.my_peer.public_key, address=alice.address),
        )

        manifest_md = MANIFEST_TEMPLATE.format(
            gatekeeper_address=alice_onchain,
            alice_pubkey_hex=alice.pubkey_hex,
        )
        alice.load_manifest(manifest_md)
        bob.load_manifest(manifest_md)

        tools = build_tools(bob)
        result: dict[str, Any] = await tools.dispatch(
            "community_join_via_peer",
            {
                "gatekeeper_mid": alice.seedbox.my_peer.mid.hex(),
                "amount_sats": 10_000,
                "timeout_s": 5.0,
            },
        )

        assert "error" not in result
        assert bob_rpc.sent == [(alice_onchain, 10_000)]
        entry = next(
            e for e in bob.community_log.read_entries()
            if e.get("entry_hash") == result["entry_hash"]
        )
        assert entry["details"]["donation_txid"] == "b" * 64

        from redteam.integration.peer_transport import HttpPeerTransport
        from redteam.integration.pull_loop import run_pull_loop
        from redteam.integration.server import build_app

        bob_oc = OpenClawIdentity.from_agent_identity(bob.identity)
        app = build_app(
            identity=bob_oc,
            log_path=str(bob_dir / "community.log"),
            peer_log_dir=str(bob_dir / "peer_logs"),
            peers=[],
        )
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://bob",
        )
        pull_task = asyncio.create_task(
            run_pull_loop(
                transport=HttpPeerTransport(client),
                peer_urls=["http://bob"],
                peer_log=alice.peer_log,
                interval=0.05,
                batch=50,
                stop_event=stop_event,
            ),
        )

        deadline = asyncio.get_event_loop().time() + 2.0
        while asyncio.get_event_loop().time() < deadline:
            state = alice.community_state()
            if state is not None and bob.community_reporter_id in state.members:
                break
            await asyncio.sleep(0.05)

        alice_state = alice.community_state()
        assert alice_state is not None
        assert bob.community_reporter_id in alice_state.members
        assert alice_state.member_count == 1
        assert alice_state.balance_sats == 10_000
    finally:
        stop_event.set()
        if pull_task is not None:
            try:
                await asyncio.wait_for(pull_task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                pull_task.cancel()
        if client is not None:
            await client.aclose()
        await alice.stop()
        await bob.stop()
