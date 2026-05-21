import secrets

import pytest

from agent.runtime import AgentConfig, OpenClawAgent
from agent.tools import build_tools
from agent.regtest_wallet import RegtestWallet
from identity.agent_identity import AgentIdentity
from identity.seed import Seed
from protocol.llm import StubLLMClient


@pytest.mark.asyncio
async def test_regtest_tools_are_registered_when_wallet_is_regtestwallet(tmp_path):
    seed = Seed(bytes=secrets.token_bytes(32))
    identity = AgentIdentity.from_seed(seed, network="TESTNET")
    llm = StubLLMClient(sources={})
    cfg = AgentConfig(port=0, save_dir=tmp_path, btc_network="mock")
    agent = OpenClawAgent(identity=identity, llm=llm, config=cfg)

    await agent.start()
    try:
        # Default: no btc_* tools.
        tools = build_tools(agent)
        assert "btc_send" not in tools.names()

        # Wrap wallet: should now include btc_* tools.
        agent.wallet = RegtestWallet(agent.wallet, use_onchain=True, rpc_client=None)
        tools2 = build_tools(agent)
        # build_regtest_tools returns [] when wallet is None-configured.
        assert "btc_send" not in tools2.names()

        # Fully configured wrapper (still no network calls made).
        agent.wallet = RegtestWallet.from_seed(
            seed,
            network="TESTNET",
            agent_index=0,
            initial_balance_sats=0,
            rpc_url="http://127.0.0.1:18443",
            wallet_name="alice",
            use_onchain=True,
        )
        tools3 = build_tools(agent)
        assert "btc_send" in tools3.names()
        assert "btc_get_balance" in tools3.names()
        assert "btc_list_transactions" in tools3.names()
        assert "btc_mine_blocks" in tools3.names()
    finally:
        await agent.stop()


