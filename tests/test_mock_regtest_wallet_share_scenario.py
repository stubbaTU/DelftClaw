from __future__ import annotations

from pathlib import Path

import pytest
from ipv8.peer import Peer

from agent import AgentConfig, OpenClawAgent, build_tools
from communication.bittorrent import StubBitTorrentService
from deploy.scenario import parse_scenario
from deploy.scenario_boot import _instance_env_contents
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol.llm import StubLLMClient


REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = REPO_ROOT / "deploy" / "scenarios" / "mock_regtest_wallet_share"


MANIFEST_TEMPLATE = """\
# Identity

- name: mock_regtest_wallet_share
- version: 1.0.0
- description: Synthetic regtest-shaped wallet sharing fixture.

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
| 127.0.0.1 | 8210 | {alice_pubkey_hex} |

# Default Overlays
"""


@pytest.fixture(scope="module")
def scenario():
    return parse_scenario(SCENARIO_DIR / "scenario.yaml")


def test_mock_regtest_wallet_share_manifest_parses(scenario):
    assert set(scenario.agents) == {"alice", "bob"}
    assert scenario.agents["alice"].btc_network == "mock_regtest"
    assert scenario.agents["bob"].btc_network == "mock_regtest"
    assert scenario.agents["alice"].bootstrap_community_sats == 10_000

    alice_env = _instance_env_contents(scenario, scenario.agents["alice"])
    assert "BTC_NETWORK=mock_regtest" in alice_env
    assert "INITIAL_BALANCE_SATS=200000" in alice_env
    assert "btc_send" not in alice_env


def test_wallet_regtest_address_is_deterministic_and_bcrt1() -> None:
    seed = MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load()
    wallet = AgentIdentity.from_seed(seed, network="TESTNET").wallet

    address = wallet.regtest_address()

    assert address.startswith("bcrt1")
    assert address == wallet.regtest_address()
    assert address != wallet.address()


@pytest.mark.asyncio
async def test_mock_regtest_addresses_use_synthetic_integer_sends(tmp_path):
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
            btc_network="mock_regtest",
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
            initial_balance_sats=100_000,
            btc_network="mock_regtest",
            community_log_path=bob_dir / "community.log",
            peer_log_dir=bob_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=bob_dir),
    )

    await alice.start()
    await bob.start()
    try:
        alice.seedbox.network.add_verified_peer(
            Peer(bob.seedbox.my_peer.public_key, address=bob.address),
        )
        bob.seedbox.network.add_verified_peer(
            Peer(alice.seedbox.my_peer.public_key, address=alice.address),
        )

        assert alice.seedbox.wallet_address is not None
        assert bob.seedbox.wallet_address is not None
        assert alice.seedbox.wallet_address.startswith("bcrt1")
        assert bob.seedbox.wallet_address.startswith("bcrt1")

        manifest_md = MANIFEST_TEMPLATE.format(
            gatekeeper_address=alice.seedbox.wallet_address,
            alice_pubkey_hex=alice.pubkey_hex,
        )
        alice.load_manifest(manifest_md)
        bob.load_manifest(manifest_md)

        alice_tools = build_tools(alice)
        bob_tools = build_tools(bob)
        assert "btc_send" not in alice_tools.names()
        assert await alice_tools.dispatch("wallet_address", {}) == alice.seedbox.wallet_address

        founder = await alice_tools.dispatch(
            "community_donate_and_join",
            {"amount_sats": 50_000},
        )
        assert "error" not in founder

        for entry in alice.community_log.read_entries():
            bob.peer_log.accept_entry(entry)

        joined = await bob_tools.dispatch(
            "community_join_via_peer",
            {
                "gatekeeper_mid": alice.seedbox.my_peer.mid.hex(),
                "amount_sats": 10_000,
                "timeout_s": 5.0,
            },
        )
        assert "error" not in joined
        assert joined["accepted"] in (True, None)

        txid = await alice_tools.dispatch(
            "wallet_send",
            {"to_address": bob.seedbox.wallet_address, "sats": 20_000},
        )
        assert isinstance(txid, str)
        assert len(txid) == 64
        assert await alice_tools.dispatch("wallet_balance", {}) == 130_000
    finally:
        await alice.stop()
        await bob.stop()
