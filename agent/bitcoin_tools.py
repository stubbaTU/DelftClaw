"""Bitcoin Regtest transaction tools for the agent.

These tools extend the standard agent tools with real on-chain Bitcoin
capabilities for Regtest networks. They follow the same pattern as the
existing tools in agent/tools.py and are designed to be composed into
the tool registry.

Tools included:
  - btc_get_balance: Query wallet balance from Regtest
  - btc_get_address: Derive or retrieve a new on-chain address
  - btc_list_utxos: List unspent outputs (UTXOs)
  - btc_list_transactions: List recent wallet transactions
  - btc_send: Send satoshis to an address (real transaction)
  - btc_transaction_status: Query transaction details and confirmations
  - btc_mine_blocks: Mine blocks to the wallet (for testing)

All tools are async and follow the standard pattern:
  - Tool function is an async callable taking named arguments
  - Returns a JSON-serializable dict with success/error fields
  - Exceptions are caught and returned as error dicts
"""

from __future__ import annotations

import logging
from typing import Any

from agent.bitcoin_rpc import RegtestClient, RPCError
from agent.regtest_wallet import RegtestWallet

_logger = logging.getLogger(__name__)


def build_regtest_tools(wallet: RegtestWallet | None = None) -> list[tuple[str, Any, dict]]:
    """Build Regtest tool definitions. Returns (name, fn, spec) tuples.

    Args:
        wallet: Optional RegtestWallet instance to use for operations

    Returns:
        List of (name, async_fn, openai_parameter_schema) tuples
    """

    if wallet is None:
        # Return empty list if no wallet is configured
        _logger.warning("No Regtest wallet configured; Regtest tools disabled")
        return []

    # ---- Tool implementations ----

    async def btc_get_balance() -> dict[str, Any]:
        """Query the wallet's on-chain Regtest balance.

        Returns a dict with:
          - balance_sat: Total balance in satoshis
          - balance_btc: Total balance in BTC
          - error: Error message if query failed
        """
        try:
            balance_sat = await wallet.balance_sats_onchain()
            balance_btc = balance_sat / 1e8
            return {
                "balance_sat": balance_sat,
                "balance_btc": f"{balance_btc:.8f}",
            }
        except Exception as exc:
            return {"error": f"balance_query_failed: {exc}"}

    async def btc_get_address() -> dict[str, Any]:
        """Generate a new receiving address on Regtest.

        Returns a dict with:
          - address: A new Bitcoin Regtest address
          - error: Error message if generation failed
        """
        try:
            address = await wallet.get_onchain_address()
            return {
                "address": address,
                "network": "regtest",
            }
        except Exception as exc:
            return {"error": f"address_generation_failed: {exc}"}

    async def btc_list_utxos(min_confirmations: int = 0) -> dict[str, Any]:
        """List unspent transaction outputs (UTXOs) in the wallet.

        Args:
            min_confirmations: Minimum confirmations required (0 for demo)

        Returns:
            Dict with:
              - utxos: List of UTXO objects with txid, vout, amount_sat, etc.
              - total_sat: Sum of all UTXO amounts
              - count: Number of UTXOs
              - error: Error message if query failed
        """
        try:
            utxos = await wallet.list_utxos(min_confirmations=min_confirmations)
            total_sat = sum(u.get("amount_sat", 0) for u in utxos)
            return {
                "utxos": utxos,
                "total_sat": total_sat,
                "count": len(utxos),
            }
        except Exception as exc:
            return {"error": f"utxo_list_failed: {exc}"}

    async def btc_list_transactions(count: int = 100) -> dict[str, Any]:
        """List recent wallet transactions on Regtest.

        The returned summary includes ``confirmed_received_sat``, which
        lets watchdog stop predicates detect incoming payments even when
        the wallet's net balance returns to its startup baseline.
        """
        try:
            txs = await wallet.list_transactions(count=count)
            compact: list[dict[str, Any]] = []
            confirmed_received_sat = 0
            for tx in txs:
                amount_sat = int(round(float(tx.get("amount", 0)) * 1e8))
                confirmations = int(tx.get("confirmations", 0) or 0)
                category = str(tx.get("category", ""))
                if category == "receive" and confirmations > 0 and amount_sat > 0:
                    confirmed_received_sat += amount_sat
                compact.append({
                    "txid": tx.get("txid"),
                    "category": category,
                    "amount_sat": amount_sat,
                    "confirmations": confirmations,
                    "address": tx.get("address"),
                    "time": tx.get("time"),
                })
            return {
                "transactions": compact,
                "count": len(compact),
                "confirmed_received_sat": confirmed_received_sat,
            }
        except Exception as exc:
            return {"error": f"transaction_list_failed: {exc}"}

    async def btc_send(to_address: str, amount_sat: int) -> dict[str, Any]:
        """Send satoshis to a Bitcoin address on Regtest.

        This creates, signs, and broadcasts a real transaction to the
        Regtest network.

        Args:
            to_address: Destination Bitcoin address
            amount_sat: Amount in satoshis (must be > 0)

        Returns:
            Dict with:
              - txid: Transaction ID (64-char hex)
              - amount_sat: Amount sent
              - to_address: Destination address
              - error: Error message if send failed
        """
        if amount_sat < 1:
            return {"error": f"amount_sat must be >= 1; got {amount_sat}"}

        if not isinstance(to_address, str) or not to_address:
            return {"error": "to_address must be a non-empty string"}

        try:
            txid = await wallet.send_onchain(to_address, amount_sat)
            return {
                "txid": txid,
                "amount_sat": amount_sat,
                "to_address": to_address,
            }
        except Exception as exc:
            return {"error": f"send_failed: {exc}"}

    async def btc_transaction_status(txid: str) -> dict[str, Any]:
        """Query the status of a transaction by ID.

        Args:
            txid: Transaction ID (64-char hex)

        Returns:
            Dict with:
              - txid: Transaction ID
              - amount: Amount in BTC
              - confirmations: Number of confirmations
              - blockhash: Block hash if confirmed (empty string if 0 conf)
              - status: 'confirmed', 'unconfirmed', or 'not_found'
              - error: Error message if query failed
        """
        if not isinstance(txid, str) or len(txid) != 64:
            return {"error": "txid must be a 64-character hex string"}

        try:
            # This uses the underlying RPC client directly
            if not wallet._rpc:
                return {"error": "RPC client not configured"}

            tx = await wallet._rpc.get_transaction(txid)
            if not tx:
                return {
                    "txid": txid,
                    "status": "not_found",
                    "error": "transaction not found in wallet",
                }

            amount = tx.get("amount", 0)
            confirmations = tx.get("confirmations", 0)
            blockhash = tx.get("blockhash", "")

            status = "confirmed" if confirmations > 0 else "unconfirmed"

            return {
                "txid": txid,
                "amount_btc": f"{abs(amount):.8f}",
                "confirmations": confirmations,
                "blockhash": blockhash,
                "status": status,
            }
        except Exception as exc:
            return {"error": f"transaction_query_failed: {exc}"}

    async def btc_mine_blocks(num_blocks: int = 1) -> dict[str, Any]:
        """Mine blocks to the wallet's address (Regtest testing utility).

        **TESTING ONLY** — This is only useful on Regtest where blocks
        can be mined on demand. On Testnet or Mainnet, this will fail.

        Args:
            num_blocks: Number of blocks to mine (default: 1, max: 100)

        Returns:
            Dict with:
              - blocks_mined: Number of blocks actually mined
              - new_block_height: Current block height
              - new_balance_sat: Wallet balance after mining
              - error: Error message if mining failed
        """
        if num_blocks < 1 or num_blocks > 100:
            return {"error": "num_blocks must be between 1 and 100"}

        try:
            if not wallet._rpc:
                return {"error": "RPC client not configured"}

            # Get current block height
            height_before = await wallet._rpc.get_block_count()

            # Get a receiving address to mine to
            addr = await wallet.get_onchain_address()

            # This is a simplified approach — in reality, you'd call generatetoaddress
            # For now, we'll call it via the RPC interface
            try:
                result = await wallet._rpc._call_rpc("generatetoaddress", [num_blocks, addr])
                blocks_generated = len(result) if isinstance(result, list) else 1
            except RPCError:
                # Fall back: try to mine without specifying address
                result = await wallet._rpc._call_rpc("generate", [num_blocks])
                blocks_generated = len(result) if isinstance(result, list) else 1

            height_after = await wallet._rpc.get_block_count()
            new_balance = await wallet.balance_sats_onchain()

            return {
                "blocks_mined": blocks_generated,
                "new_block_height": height_after,
                "new_balance_sat": new_balance,
            }
        except Exception as exc:
            return {"error": f"mining_failed: {exc}"}

    # ---- OpenAI parameter schemas ----

    P_NONE = {"type": "object", "properties": {}, "additionalProperties": False}

    return [
        ("btc_get_balance", btc_get_balance, P_NONE),

        ("btc_get_address", btc_get_address, P_NONE),

        ("btc_list_utxos",
         btc_list_utxos,
         {
             "type": "object",
             "properties": {
                 "min_confirmations": {
                     "type": "integer",
                     "minimum": 0,
                     "default": 0,
                     "description": "Minimum confirmations required (0 for Regtest demo)",
                 },
             },
             "additionalProperties": False,
         }),

        ("btc_list_transactions",
         btc_list_transactions,
         {
             "type": "object",
             "properties": {
                 "count": {
                     "type": "integer",
                     "minimum": 1,
                     "maximum": 500,
                     "default": 100,
                     "description": "Maximum recent wallet transactions to return",
                 },
             },
             "additionalProperties": False,
         }),

        ("btc_send",
         btc_send,
         {
             "type": "object",
             "properties": {
                 "to_address": {
                     "type": "string",
                     "description": "Bitcoin Regtest destination address",
                 },
                 "amount_sat": {
                     "type": "integer",
                     "minimum": 1,
                     "description": "Amount in satoshis",
                 },
             },
             "required": ["to_address", "amount_sat"],
             "additionalProperties": False,
         }),

        ("btc_transaction_status",
         btc_transaction_status,
         {
             "type": "object",
             "properties": {
                 "txid": {
                     "type": "string",
                     "description": "Transaction ID (64-char hex)",
                 },
             },
             "required": ["txid"],
             "additionalProperties": False,
         }),

        ("btc_mine_blocks",
         btc_mine_blocks,
         {
             "type": "object",
             "properties": {
                 "num_blocks": {
                     "type": "integer",
                     "minimum": 1,
                     "maximum": 100,
                     "default": 1,
                     "description": "Blocks to mine (Regtest only)",
                 },
             },
             "additionalProperties": False,
         }),
    ]

