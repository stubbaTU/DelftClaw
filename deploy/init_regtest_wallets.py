#!/usr/bin/env python3
"""Initialize Regtest wallets and fund demo agents.

This script (run on the VPS after setup_bitcoin_regtest.sh):
  1. Derives Bitcoin addresses from each agent's seed
  2. Creates named wallets in bitcoind if needed
  3. Mines initial blocks to each wallet
  4. Outputs a config file with RPC endpoints and wallet info

Usage:
    python deploy/init_regtest_wallets.py \\
        --agents alice bob charlie dave \\
        --rpc-url http://127.0.0.1:18443 \\
        --initial-balance 500000 \\
        --output config.json

Output config can be sourced by the VPS boot script to pass RPC details
to each agent.
"""

import asyncio
import json
import logging
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

# Add parent to path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from agent.bitcoin_rpc import RegtestClient, RPCError

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)


async def ensure_wallet_exists(
    client: RegtestClient,
    wallet_name: str,
    agent_index: int = 0,
) -> dict[str, Any]:
    """Ensure a wallet exists in bitcoind and return its info.

    Args:
        client: Bitcoin RPC client
        wallet_name: Name of the wallet (e.g., "alice")
        agent_index: BIP-44 account index

    Returns:
        Dict with wallet_name, address, balance_sat
    """
    try:
        # Try to load the wallet if it already exists
        try:
            await client._call_rpc("loadwallet", [wallet_name])
            _logger.info(f"Loaded existing wallet: {wallet_name}")
        except RPCError:
            # Wallet doesn't exist, create it
            await client._call_rpc("createwallet", [wallet_name])
            _logger.info(f"Created new wallet: {wallet_name}")

        # Get wallet info
        client.wallet_name = wallet_name
        balance = await client.get_balance_sat()

        # Get an address for this wallet
        addr = await client.get_new_address()

        return {
            "wallet_name": wallet_name,
            "address": addr,
            "balance_sat": balance,
            "agent_index": agent_index,
        }
    except RPCError as exc:
        _logger.error(f"Failed to set up wallet {wallet_name}: {exc}")
        raise


async def fund_wallet(
    client: RegtestClient,
    wallet_name: str,
    amount_sat: int,
) -> dict[str, Any]:
    """Mine blocks and fund a wallet to the specified amount.

    Args:
        client: Bitcoin RPC client
        wallet_name: Wallet to fund
        amount_sat: Target balance in satoshis

    Returns:
        Dict with funding_txids, blocks_mined, final_balance
    """
    client.wallet_name = wallet_name

    # Check current balance
    current_balance = await client.get_balance_sat()
    if current_balance >= amount_sat:
        _logger.info(f"Wallet {wallet_name} already has {current_balance} sats")
        return {
            "wallet_name": wallet_name,
            "final_balance": current_balance,
            "blocks_mined": 0,
            "funding_txids": [],
        }

    # Need to mine to fund this wallet
    # Get a mining address for this wallet
    mining_addr = await client.get_new_address()

    # Each block on regtest rewards 50 BTC = 5,000,000,000 sats.
    # Coinbase rewards require 100 confirmations before they are spendable,
    # so mine enough blocks to both cover the requested amount and mature it.
    satoshis_needed = amount_sat - current_balance
    sats_per_block = 5_000_000_000
    reward_blocks_needed = (satoshis_needed + sats_per_block - 1) // sats_per_block
    blocks_needed = reward_blocks_needed + 100

    _logger.info(f"Mining {blocks_needed} blocks to {mining_addr} for {wallet_name}...")

    try:
        # Mine blocks to this wallet's address
        result = await client._call_rpc("generatetoaddress", [blocks_needed, mining_addr])
        blocks_mined = len(result) if isinstance(result, list) else blocks_needed
        _logger.info(f"Mined {blocks_mined} blocks")
    except RPCError as exc:
        _logger.error(f"Mining failed: {exc}")
        raise

    # Check new balance
    final_balance = await client.get_balance_sat()
    _logger.info(f"Wallet {wallet_name} now has {final_balance} sats")

    return {
        "wallet_name": wallet_name,
        "final_balance": final_balance,
        "blocks_mined": blocks_mined,
        "funding_txids": result if isinstance(result, list) else [],
    }


async def initialize_regtest_wallets(
    agents: list[str],
    rpc_url: str = "http://127.0.0.1:18443",
    initial_balance_sat: int = 500_000,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Initialize Regtest wallets for all agents.

    Args:
        agents: List of agent names (e.g., ["alice", "bob", "charlie", "dave"])
        rpc_url: Bitcoin RPC endpoint
        initial_balance_sat: Target balance per agent
        output_path: Path to write config JSON to

    Returns:
        Config dict with wallet info and RPC details
    """
    client = RegtestClient(rpc_url)

    # Get block count and check connectivity
    try:
        block_count = await client.get_block_count()
        _logger.info(f"Connected to Bitcoin Regtest node at block {block_count}")
    except RPCError as exc:
        _logger.error(f"Failed to connect to Bitcoin RPC: {exc}")
        raise

    config: dict[str, Any] = {
        "rpc_url": rpc_url,
        "network": "regtest",
        "initial_setup_date": __import__("datetime").datetime.utcnow().isoformat(),
        "agents": {},
    }

    for idx, agent_name in enumerate(agents):
        _logger.info(f"\n--- Setting up {agent_name} ---")

        try:
            # Ensure wallet exists
            wallet_info = await ensure_wallet_exists(client, agent_name, agent_index=idx)

            # Fund it
            funding_info = await fund_wallet(client, agent_name, initial_balance_sat)

            # Combine info
            agent_config = {
                **wallet_info,
                **funding_info,
            }
            config["agents"][agent_name] = agent_config

            _logger.info(f"✓ {agent_name} setup complete")
        except Exception as exc:
            _logger.error(f"✗ {agent_name} setup failed: {exc}")
            if not "--ignore-errors" in sys.argv:
                raise

    # Write config file if requested
    if output_path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(config, f, indent=2)
        _logger.info(f"\nConfiguration written to {output}")

    return config


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agents",
        nargs="+",
        default=["alice", "bob", "charlie", "dave"],
        help="Agent names to initialize",
    )
    parser.add_argument(
        "--rpc-url",
        default="http://127.0.0.1:18443",
        help="Bitcoin RPC endpoint",
    )
    parser.add_argument(
        "--initial-balance",
        type=int,
        default=500_000,
        help="Initial balance per agent (satoshis)",
    )
    parser.add_argument(
        "--output",
        help="Path to write config JSON to",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config = asyncio.run(initialize_regtest_wallets(
            agents=args.agents,
            rpc_url=args.rpc_url,
            initial_balance_sat=args.initial_balance,
            output_path=args.output,
        ))

        # Print summary
        print("\n" + "="*70)
        print("Regtest Wallet Initialization Summary")
        print("="*70)
        print(f"RPC URL: {config['rpc_url']}")
        print(f"Network: {config['network']}")
        print("\nAgents:")
        for agent_name, agent_config in config.get("agents", {}).items():
            print(f"\n  {agent_name}:")
            print(f"    Address:       {agent_config.get('address')}")
            print(f"    Balance:       {agent_config.get('final_balance'):,} sats")
            print(f"    Blocks Mined:  {agent_config.get('blocks_mined')}")
        print()

        return 0
    except Exception as exc:
        _logger.error(f"Initialization failed: {exc}", exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

