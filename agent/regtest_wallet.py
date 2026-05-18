"""Regtest-aware wallet wrapper for bridging synthetic and real Bitcoin.

This module provides a `RegtestWallet` that wraps the existing synthetic
`Wallet` class and augments it with real Bitcoin Regtest RPC capabilities.

The wrapper maintains backward compatibility with existing code while
enabling on-chain operations when configured to do so.

Usage:
    from agent.regtest_wallet import RegtestWallet
    from identity.seed import Seed

    seed = Seed.from_mnemonic("...")
    regtest_wallet = RegtestWallet.from_seed(
        seed,
        network="REGTEST",
        rpc_url="http://127.0.0.1:18443",
        wallet_name="alice",
    )

    balance = await regtest_wallet.balance_sats_onchain()
    txid = await regtest_wallet.send_onchain("recipient", 10000)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from identity.seed import Seed
from identity.wallet import Wallet
from agent.bitcoin_rpc import RegtestClient, RPCError

_logger = logging.getLogger(__name__)


class RegtestWallet:
    """Regtest-aware wallet combining synthetic and on-chain capabilities.

    Wraps the standard `Wallet` (which provides synthetic balances for demos)
    and layers real Bitcoin Regtest RPC calls on top when configured.

    Falls back to synthetic behavior if RPC is unavailable, allowing
    graceful degradation in test/demo environments.
    """

    def __init__(
        self,
        synthetic_wallet: Wallet,
        *,
        rpc_client: Optional[RegtestClient] = None,
        use_onchain: bool = False,
    ) -> None:
        """Initialize the Regtest wallet wrapper.

        Args:
            synthetic_wallet: The underlying synthetic Wallet instance
            rpc_client: Optional RPC client for on-chain operations
            use_onchain: If True, prefer on-chain operations over synthetic
        """
        self._synthetic = synthetic_wallet
        self._rpc = rpc_client
        self._use_onchain = use_onchain and rpc_client is not None

    @classmethod
    def from_seed(
        cls,
        seed: Seed,
        *,
        network: str = "REGTEST",
        agent_index: int = 0,
        initial_balance_sats: int = 0,
        rpc_url: str = "http://127.0.0.1:18443",
        wallet_name: str = "",
        use_onchain: bool = False,
    ) -> "RegtestWallet":
        """Create a Regtest wallet from a seed.

        Args:
            seed: BIP-39 seed
            network: Network tag (REGTEST, TESTNET, MAINNET)
            agent_index: BIP-44 account index
            initial_balance_sats: Synthetic balance (demo budget)
            rpc_url: Bitcoin RPC endpoint
            wallet_name: Wallet name for RPC operations
            use_onchain: If True, query/use real Regtest balances

        Returns:
            RegtestWallet instance
        """
        synthetic = Wallet.from_seed(
            seed,
            network=network,
            agent_index=agent_index,
            initial_balance_sats=initial_balance_sats,
        )

        rpc_client = None
        if wallet_name:
            rpc_client = RegtestClient(rpc_url, wallet_name=wallet_name)

        return cls(
            synthetic,
            rpc_client=rpc_client,
            use_onchain=use_onchain,
        )

    # ---- Delegated properties from synthetic wallet ----

    @property
    def network(self) -> str:
        """Network tag (REGTEST, TESTNET, MAINNET)."""
        return self._synthetic.network

    @property
    def path(self) -> str:
        """BIP-44 derivation path."""
        return self._synthetic.path

    @property
    def xpub(self) -> str:
        """Extended public key."""
        return self._synthetic.xpub

    @property
    def pubkey(self) -> bytes:
        """Ed25519 public key bytes."""
        return self._synthetic.pubkey

    def address(self) -> str:
        """Return the wallet's address.

        Returns the synthetic address (dclaw1...) used by the demos.
        For on-chain operations, use get_onchain_address() instead.
        """
        return self._synthetic.address()

    async def get_onchain_address(self) -> str:
        """Get a new on-chain Bitcoin address from Regtest.

        Returns:
            A real Bitcoin Regtest address, or raises if RPC unavailable
        """
        if not self._rpc:
            raise RuntimeError("RPC client not configured")
        try:
            return await self._rpc.get_new_address()
        except RPCError as exc:
            _logger.error(f"Failed to get on-chain address: {exc}")
            raise

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary data with the wallet's Ed25519 key."""
        return self._synthetic.sign(data)

    @staticmethod
    def verify(pubkey: bytes, data: bytes, signature: bytes) -> bool:
        """Verify a signature."""
        return Wallet.verify(pubkey, data, signature)

    # ---- Balance operations ----

    async def balance_sats(self, *, refresh: bool = False) -> int:
        """Get wallet balance in satoshis.

        If on-chain mode is enabled and RPC is available, returns the real
        Regtest balance. Otherwise returns the synthetic balance (demo budget).

        Args:
            refresh: Ignored (for API compatibility)

        Returns:
            Balance in satoshis
        """
        if self._use_onchain and self._rpc:
            try:
                return await self._rpc.get_balance_sat()
            except RPCError as exc:
                _logger.warning(f"RPC balance query failed, falling back to synthetic: {exc}")

        # Fall back to synthetic
        return self._synthetic.balance_sats(refresh=refresh)

    async def balance_sats_synthetic(self) -> int:
        """Get the synthetic (demo budget) balance in satoshis."""
        return self._synthetic.balance_sats()

    async def balance_sats_onchain(self) -> int:
        """Query the real Regtest balance in satoshis.

        Only works if RPC is configured.

        Returns:
            Balance in satoshis, or 0 if query fails
        """
        if not self._rpc:
            return 0

        try:
            return await self._rpc.get_balance_sat()
        except RPCError as exc:
            _logger.warning(f"Failed to query on-chain balance: {exc}")
            return 0

    # ---- Send operations ----

    async def send(self, to_address: str, sats: int) -> str:
        """Send satoshis to an address.

        If on-chain mode is enabled and RPC is available, sends real Bitcoin
        to the Regtest network. Otherwise returns a synthetic txid (demo mode).

        Args:
            to_address: Destination address
            sats: Amount in satoshis

        Returns:
            Transaction ID (hex string)
        """
        if self._use_onchain and self._rpc:
            try:
                return await self._rpc.send_to_address(to_address, sats)
            except RPCError as exc:
                _logger.error(f"On-chain send failed: {exc}")
                raise

        # Fall back to synthetic
        return self._synthetic.send(to_address, sats)

    async def send_onchain(self, to_address: str, sats: int) -> str:
        """Send real Bitcoin on the Regtest network.

        This is a no-fallback method — it will raise if RPC is not configured.

        Args:
            to_address: Destination address
            sats: Amount in satoshis

        Returns:
            Transaction ID (txid) hex string
        """
        if not self._rpc:
            raise RuntimeError("RPC client not configured for on-chain operations")
        return await self._rpc.send_to_address(to_address, sats)

    async def send_synthetic(self, to_address: str, sats: int) -> str:
        """Send using the synthetic (demo) method.

        This always returns a deterministic synthetic txid; never broadcasts.

        Args:
            to_address: Destination address (not validated)
            sats: Amount in satoshis

        Returns:
            Synthetic transaction ID (deterministic)
        """
        return self._synthetic.send(to_address, sats)

    # ---- UTXO management (on-chain only) ----

    async def list_utxos(self, min_confirmations: int = 0) -> list[dict]:
        """List unspent outputs (on-chain only).

        Args:
            min_confirmations: Minimum confirmations required

        Returns:
            List of UTXO dicts with txid, vout, amount, address, etc.
        """
        if not self._rpc:
            return []

        try:
            utxos = await self._rpc.list_unspent(min_confirmations=min_confirmations)
            return [
                {
                    "txid": u.txid,
                    "vout": u.vout,
                    "address": u.address,
                    "amount_sat": int(u.amount * 1e8),
                    "confirmations": u.confirmations,
                    "spendable": u.spendable,
                }
                for u in utxos
            ]
        except RPCError as exc:
            _logger.warning(f"UTXO list failed: {exc}")
            return []

    # ---- Advanced transaction operations (on-chain only) ----

    async def create_and_sign_raw_tx(
        self,
        inputs: list[dict],
        outputs: dict[str, float],
    ) -> str:
        """Create and sign a raw transaction.

        Args:
            inputs: List of {"txid": str, "vout": int} dicts
            outputs: Dict mapping address -> btc_amount

        Returns:
            Signed transaction hex

        Raises:
            RuntimeError: If RPC is not configured
        """
        if not self._rpc:
            raise RuntimeError("RPC client not configured")

        raw_tx = await self._rpc.create_raw_transaction(inputs, outputs)
        signed_tx, is_complete = await self._rpc.sign_raw_transaction(raw_tx)

        if not is_complete:
            _logger.warning("Transaction signing incomplete; some inputs may remain unsigned")

        return signed_tx

    async def broadcast_raw_tx(self, signed_tx_hex: str) -> str:
        """Broadcast a signed raw transaction.

        Args:
            signed_tx_hex: Signed transaction hex

        Returns:
            Transaction ID (txid)
        """
        if not self._rpc:
            raise RuntimeError("RPC client not configured")
        return await self._rpc.broadcast_transaction(signed_tx_hex)

    # ---- Legacy compatibility methods ----

    def get_private_key(self) -> str:
        """Return the raw Ed25519 private key as hex (for tests)."""
        return self._synthetic.get_private_key()

    def get_balance(self, as_string: bool = False) -> int | str:
        """Get balance (legacy method for compatibility)."""
        if as_string:
            return f"{self._synthetic.balance_sats() / 1e8:.8f} BTC"
        return self._synthetic.balance_sats()

    def get_utxos(self) -> list:
        """Get UTXOs (legacy method; always returns empty)."""
        return self._synthetic.get_utxos()

