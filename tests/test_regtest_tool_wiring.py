from __future__ import annotations

from typing import Any, cast

import pytest

from agent.runtime import AgentConfig, OpenClawAgent
from agent.regtest_wallet import RegtestWallet
from agent.tools import build_tools
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol.llm import StubLLMClient


class _FakeRegtestRPC:
    """Tiny async stub matching the subset of RegtestClient used in tests."""

    async def get_balance_sat(self, wallet: str | None = None) -> int:  # noqa: ARG002
        return 123

    async def get_new_address(self, label: str = "", address_type: str | None = None) -> str:  # noqa: ARG002
        # Any string is fine for wiring tests; no address validation occurs here.
        return "bcrt1qexampleaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    async def send_to_address(
        self,
        to_address: str,
        amount_sat: int,
        wallet: str | None = None,
        fee_rate_sat_per_vb: int | None = None,
    ) -> str:  # noqa: ARG002
        assert to_address
        assert amount_sat > 0
        return "a" * 64

    async def list_transactions(
        self,
        wallet: str | None = None,
        count: int = 100,
        skip: int = 0,
    ) -> list[dict[str, Any]]:  # noqa: ARG002
        return [
            {
                "txid": "b" * 64,
                "category": "receive",
                "amount": 0.0002,
                "confirmations": 1,
                "address": "bcrt1qexampleaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "time": 123,
            },
            {
                "txid": "c" * 64,
                "category": "send",
                "amount": -0.0001,
                "confirmations": 1,
                "time": 124,
            },
        ]


@pytest.mark.asyncio
async def test_regtest_tools_are_exposed_and_wallet_balance_is_int(tmp_path):
    seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    identity = AgentIdentity.from_seed(seed, network="TESTNET")

    agent = OpenClawAgent(
        identity=identity,
        llm=StubLLMClient(sources={}),
        config=AgentConfig(port=0, save_dir=tmp_path),
    )

    # Enable the regtest wrapper without hitting a real bitcoind.
    agent.wallet = cast(Any, RegtestWallet(agent.wallet, rpc_client=cast(Any, _FakeRegtestRPC()), use_onchain=True))

    registry = build_tools(agent)
    names = set(registry.names())

    # btc_* tools are only present when the wallet is a RegtestWallet with an RPC client.
    assert "btc_get_balance" in names
    assert "btc_get_address" in names
    assert "btc_list_transactions" in names
    assert "btc_send" in names

    # Regression: wallet_balance must not return an un-awaited coroutine.
    balance = await registry.dispatch("wallet_balance", {})
    assert isinstance(balance, int)
    assert balance == 123

    # Basic sanity: the btc_* tool uses the same RPC-backed wallet.
    reg_bal = await registry.dispatch("btc_get_balance", {})
    assert reg_bal["balance_sat"] == 123

    txs = await registry.dispatch("btc_list_transactions", {})
    assert txs["confirmed_received_sat"] == 20_000
    assert txs["count"] == 2


