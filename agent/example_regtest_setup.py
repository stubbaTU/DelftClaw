"""Example: Running agents with Regtest wallet support.

This module demonstrates how to set up agents to use the Regtest wallet
and tools instead of the synthetic wallet. You can integrate this into
agent/cli.py or deploy/scenario_boot.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

# Add repo to path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from agent.runtime import OpenClawAgent, AgentConfig
from agent.tools import build_tools, ToolRegistry, Tool
from agent.bitcoin_tools import build_regtest_tools
from agent.regtest_wallet import RegtestWallet
from identity.agent_identity import AgentIdentity
from identity.wallet import Wallet
from identity.seed import Seed
from protocol.llm import StubLLMClient



def build_tools_with_regtest(
    agent: OpenClawAgent,
    use_regtest: bool = False,
) -> ToolRegistry:
    """Build tool registry with optional Regtest tools.

    Args:
        agent: The agent instance
        use_regtest: If True, include btc_* tools (RPC-based)

    Returns:
        ToolRegistry with all tools available
    """
    # Standard tools (peers, community, overlays, etc.)
    tools = build_tools(agent)

    if use_regtest:
        # Add Regtest-specific transaction tools
        regtest_tool_specs = build_regtest_tools(agent.wallet)
        if regtest_tool_specs:
            for name, fn, params_schema in regtest_tool_specs:
                # Create Tool object with the standard pattern from tools.py
                tool = Tool(
                    name=name,
                    description=fn.__doc__ or name,
                    parameters=params_schema,
                    fn=fn,
                )
                tools._tools[name] = tool

    return tools


async def example_setup_agent_with_regtest(
    agent_name: str,
    mnemonic: str,
    ipv8_port: int = 8190,
    mcp_port: int = 18765,
    rpc_url: str = "http://127.0.0.1:18443",
    use_regtest: bool = True,
) -> OpenClawAgent:
    """Example: Set up an agent with Regtest wallet support.

    Args:
        agent_name: Name of the agent (e.g., "alice")
        mnemonic: BIP-39 mnemonic seed phrase
        ipv8_port: IPv8 UDP listen port
        mcp_port: MCP/LLM TCP listen port
        rpc_url: Bitcoin RPC endpoint
        use_regtest: If True, use real Regtest wallet instead of synthetic

    Returns:
        Configured and started OpenClawAgent

    Example usage:
        agent = await example_setup_agent_with_regtest(
            "alice",
            mnemonic="word word word ...",
            rpc_url="http://127.0.0.1:18443",
            use_regtest=True,
        )
        await agent.start()
    """

    # Step 1: Create identity from seed
    identity = AgentIdentity(
        network="REGTEST",
        agent_index=0,
        mnemonic=mnemonic,
    )

    # Step 2: Choose wallet based on mode
    if use_regtest:
        print(f"[{agent_name}] Initializing Regtest wallet (RPC: {rpc_url})")

        # Create Regtest wallet with RPC backing
        wallet = RegtestWallet.from_seed(
            Seed.from_mnemonic(mnemonic),
            network="REGTEST",
            agent_index=0,
            rpc_url=rpc_url,
            wallet_name=agent_name,
            use_onchain=True,  # Prefer real Regtest operations
        )

        # Optionally set a synthetic budget cap
        # (in case of RPC failure, agent can still do synthetic sends)
        wallet._synthetic.set_initial_balance(500_000)  # Demo budget
    else:
        print(f"[{agent_name}] Using synthetic wallet (demo mode)")

        # Keep standard synthetic wallet
        wallet = identity.wallet
        wallet.set_initial_balance(500_000)

    # Step 3: Set up agent configuration
    config = AgentConfig(
        port=ipv8_port,
        address="127.0.0.1",
        btc_network="regtest" if use_regtest else "mock",
        save_dir=Path("./downloads") / agent_name,
        initial_balance_sats=500_000,  # Demo budget
    )

    # Step 4: Create LLM client (stub for testing)
    # In production, this would be configured from environment
    llm = StubLLMClient(sources={}, model_id="stub-example")

    # Step 5: Create agent
    agent = OpenClawAgent(identity, llm, config)

    # Replace wallet if using Regtest
    if use_regtest:
        agent.wallet = wallet

    # Step 6: Manually build tools with Regtest support
    # (In agent.tools, this would be integrated into build_tools())
    agent._tools = build_tools_with_regtest(agent, use_regtest=use_regtest)

    print(f"[{agent_name}] Agent ready")
    print(f"  Wallet address (synthetic): {wallet.address()}")
    # Note: balance_sats is async, so it will be printed in the demo section below

    return agent


# ---- CLI example ----

def example_cli_main():
    """Example command-line invocation.

    Usage:
        python -m agent.example_regtest_setup \\
            --agent alice \\
            --mnemonic "word word word ..." \\
            --rpc-url http://127.0.0.1:18443 \\
            --ipv8-port 8190 \\
            --use-regtest
    """
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", required=True, help="Agent name")
    parser.add_argument(
        "--mnemonic",
        default="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        help="BIP-39 mnemonic (default: test mnemonic)",
    )
    parser.add_argument(
        "--rpc-url",
        default="http://127.0.0.1:18443",
        help="Bitcoin RPC endpoint",
    )
    parser.add_argument(
        "--ipv8-port",
        type=int,
        default=8190,
        help="IPv8 UDP port",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=18765,
        help="MCP TCP port",
    )
    parser.add_argument(
        "--use-regtest",
        action="store_true",
        help="Use Regtest wallet instead of synthetic",
    )

    args = parser.parse_args()

    # Set up agent
    agent = asyncio.run(example_setup_agent_with_regtest(
        agent_name=args.agent,
        mnemonic=args.mnemonic,
        ipv8_port=args.ipv8_port,
        mcp_port=args.mcp_port,
        rpc_url=args.rpc_url,
        use_regtest=args.use_regtest,
    ))

    # Demo: query balance
    async def demo():
        balance = await agent.wallet.balance_sats()
        print(f"[{args.agent}] Balance: {balance} sats")

        if args.use_regtest:
            onchain = await agent.wallet.balance_sats_onchain()
            print(f"[{args.agent}] On-chain balance: {onchain} sats")

    asyncio.run(demo())


if __name__ == "__main__":
    example_cli_main()

