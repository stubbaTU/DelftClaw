"""Bitcoin Regtest RPC client for transaction operations.

This module provides a lightweight wrapper around the Bitcoin Core JSON-RPC API,
designed to work with Regtest networks for testing and demo scenarios.

Features:
  - Wallet balance queries
  - Address derivation from seeds
  - UTXO management and transaction construction
  - Transaction signing via bitcoin-cli
  - Broadcasting to the Regtest network

Usage:
    from agent.bitcoin_rpc import RegtestClient

    client = RegtestClient("http://127.0.0.1:18443")
    balance = await client.get_balance("alice")
    utxos = await client.list_unspent("alice")
    txid = await client.send_to_address("alice", "recipient_addr", 10000)
"""

from __future__ import annotations

import asyncio
import os
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

RpcParams = list[Any] | dict[str, Any]

import httpx

_logger = logging.getLogger(__name__)


@dataclass
class UTXOInfo:
    """Unspent transaction output."""
    txid: str
    vout: int
    address: str
    amount: float          # BTC
    confirmations: int
    spendable: bool


@dataclass
class TransactionInfo:
    """Signed transaction info."""
    txid: str
    amount_sat: int
    fee_sat: int
    inputs: int
    outputs: int


class RPCError(Exception):
    """Raised when Bitcoin RPC call fails."""
    pass


class RegtestClient:
    """Bitcoin Regtest RPC client for transaction operations.

    Each method communicates with a local bitcoind instance via HTTP JSON-RPC.
    The client is designed for Regtest networks where confirmation requirements
    and other real-chain constraints are relaxed for testing.
    """

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:18443",
        *,
        username: str = "",
        password: str = "",
        cookie_path: str | None = None,
        datadir: str | None = None,
        wallet_name: str = "",
        timeout_s: float = 30.0,
    ) -> None:
        """Initialize the RPC client.

        Args:
            rpc_url: Bitcoin JSON-RPC endpoint (e.g., http://127.0.0.1:18443)
            username: RPC username (optional, if auth is configured)
            password: RPC password (optional, if auth is configured)
            cookie_path: Optional path to Bitcoin Core's ``.cookie`` auth file
            datadir: Optional Bitcoin data directory used to discover ``.cookie``
            wallet_name: Default wallet to use for operations
            timeout_s: HTTP request timeout
        """
        self.rpc_url = rpc_url.rstrip("/")
        self.username = username
        self.password = password
        self.cookie_path = cookie_path
        self.datadir = datadir
        self.wallet_name = wallet_name
        self.timeout_s = timeout_s
        self._auth_cache: tuple[str, str] | None = None
        # Wallet-scoped RPC endpoints (/wallet/<name>) error if the wallet
        # doesn't exist or isn't loaded. Scenario runs frequently start from a
        # fresh regtest datadir, so we lazily ensure the wallet exists.
        self._wallet_ready: set[str] = set()

    def _candidate_datadirs(self) -> list[Path]:
        """Return plausible Bitcoin Core data directories for the host OS."""
        candidates: list[Path] = []

        if self.datadir:
            candidates.append(Path(self.datadir).expanduser())

        for env_name in (
            "BITCOIN_DATA_DIR",
            "BITCOIN_DATADIR",
            "BITCOIN_DATA",
            "OPENCLAW_BITCOIN_DATA",
        ):
            raw = os.getenv(env_name)
            if raw:
                candidates.append(Path(raw).expanduser())

        home = Path.home()
        appdata = os.getenv("APPDATA")
        localappdata = os.getenv("LOCALAPPDATA")

        if appdata:
            candidates.append(Path(appdata) / "Bitcoin")
        if localappdata:
            candidates.append(Path(localappdata) / "Bitcoin")

        candidates.extend(
            [
                home / ".bitcoin",
                home / "AppData" / "Roaming" / "Bitcoin",
                home / "Library" / "Application Support" / "Bitcoin",
            ]
        )

        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate).lower()
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        return unique

    def _candidate_cookie_paths(self) -> list[Path]:
        """Return plausible paths to Bitcoin Core's regtest cookie file."""
        candidates: list[Path] = []

        if self.cookie_path:
            candidates.append(Path(self.cookie_path).expanduser())

        for datadir in self._candidate_datadirs():
            candidates.extend(
                [
                    datadir / "regtest" / ".cookie",
                    datadir / ".cookie",
                ]
            )

        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate).lower()
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        return unique

    def _resolve_auth(self) -> tuple[str, str] | None:
        """Resolve RPC auth from explicit credentials or Bitcoin Core cookie."""
        if self.username and self.password:
            return (self.username, self.password)

        if self._auth_cache is not None:
            return self._auth_cache

        for cookie_file in self._candidate_cookie_paths():
            if not cookie_file.exists():
                continue

            try:
                raw = cookie_file.read_text(encoding="utf-8").strip()
            except OSError:
                continue

            if ":" not in raw:
                continue

            username, password = raw.split(":", 1)
            if username and password:
                self._auth_cache = (username, password)
                return self._auth_cache

        return None

    async def _call_rpc(
        self,
        method: str,
        params: RpcParams | None = None,
        wallet: str | None = None,
    ) -> Any:
        """Make a JSON-RPC call to bitcoind.

        Args:
            method: RPC method name (e.g., "getblockcount")
            params: RPC parameters
            wallet: Specific wallet to target; overrides default

        Returns:
            The result field of the RPC response

        Raises:
            RPCError: If the RPC call fails
        """
        if params is None:
            params = []

        # Build request payload
        payload = {
            "jsonrpc": "1.0",
            "id": "delftclaw",
            "method": method,
            "params": params,
        }

        # Build URL with wallet route if specified.
        #
        # ``wallet=None`` means "use the client's default wallet".
        # ``wallet=""`` means "do NOT scope this call to any wallet" (base RPC).
        url = self.rpc_url
        wallet_target = self.wallet_name if wallet is None else wallet

        # Lazily ensure wallet exists for wallet-scoped calls. Skip for wallet
        # management / global introspection methods to avoid recursion.
        if wallet_target and wallet_target not in self._wallet_ready and method not in {
            "listwallets",
            "listwalletdir",
            "createwallet",
            "loadwallet",
            "unloadwallet",
        }:
            await self._ensure_wallet_loaded(wallet_target)

        if wallet_target:
            url = f"{url}/wallet/{wallet_target}"

        # Prepare auth if configured
        auth = self._resolve_auth()

        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                response = await client.post(url, json=payload, auth=auth)

                # Bitcoin Core often returns HTTP 500 *with* a JSON-RPC error
                # body. Don't raise_for_status() before we decode the body.
                try:
                    data = response.json()
                except json.JSONDecodeError as exc:
                    # If the body isn't JSON, report a short preview.
                    preview = (response.text or "").strip().replace("\n", " ")[:200]
                    raise RPCError(
                        f"Invalid JSON response (HTTP {response.status_code}): {preview}"
                    ) from exc

                if response.status_code >= 400:
                    err = data.get("error") if isinstance(data, dict) else None
                    if isinstance(err, dict):
                        code = err.get("code")
                        msg = err.get("message", "unknown error")
                        raise RPCError(f"RPC error (HTTP {response.status_code}, code={code}): {msg}")
                    raise RPCError(f"HTTP {response.status_code}: {data!r}")

                if isinstance(data, dict) and data.get("error") is not None:
                    err = data.get("error")
                    if isinstance(err, dict):
                        code = err.get("code")
                        msg = err.get("message", "unknown error")
                        raise RPCError(f"RPC error (code={code}): {msg}")
                    raise RPCError(f"RPC error: {err!r}")

                if not isinstance(data, dict):
                    raise RPCError(f"Invalid RPC response: {data!r}")

                return data.get("result")

        except httpx.HTTPError as exc:
            raise RPCError(f"HTTP error: {exc}") from exc


    async def _ensure_wallet_loaded(self, wallet_name: str) -> None:
        """Best-effort ensure ``wallet_name`` exists and is loaded.

        Regtest scenarios frequently run against a fresh datadir, so the per-agent
        wallet (alice/bob) may not exist yet. Bitcoin Core requires wallet-scoped
        endpoints to target an existing loaded wallet.

        This uses base RPC calls (no /wallet/<name> route) to:
          1) check listwallets
          2) attempt loadwallet
          3) attempt createwallet
        """
        if not wallet_name or wallet_name in self._wallet_ready:
            return

        async def _listwallets() -> list[str]:
            result = await self._call_rpc("listwallets", wallet="")
            if isinstance(result, list):
                return [str(x) for x in result]
            return []

        wallets = await _listwallets()
        if wallet_name in wallets:
            self._wallet_ready.add(wallet_name)
            return

        # Try to load an existing wallet from disk.
        try:
            await self._call_rpc("loadwallet", [wallet_name], wallet="")
        except RPCError:
            pass

        wallets = await _listwallets()
        if wallet_name in wallets:
            self._wallet_ready.add(wallet_name)
            return

        # Create (and load) the wallet if it doesn't exist.
        try:
            await self._call_rpc("createwallet", [wallet_name], wallet="")
        except RPCError:
            # Already exists / already loaded are fine.
            pass

        wallets = await _listwallets()
        if wallet_name in wallets:
            self._wallet_ready.add(wallet_name)
            return

        raise RPCError(f"wallet not loaded/created: {wallet_name}")

    async def get_block_count(self) -> int:
        """Get the current block height."""
        result = await self._call_rpc("getblockcount")
        return int(result)

    async def get_balance(self, wallet: str | None = None) -> float:
        """Get the wallet's total balance in BTC.

        Args:
            wallet: Wallet name; uses default if not specified

        Returns:
            Balance in BTC (float)
        """
        result = await self._call_rpc("getbalance", wallet=wallet)
        return float(result)

    async def get_balance_sat(self, wallet: str | None = None) -> int:
        """Get the wallet's total balance in satoshis."""
        btc_balance = await self.get_balance(wallet)
        return int(btc_balance * 1e8)

    async def list_unspent(
        self,
        wallet: str | None = None,
        min_confirmations: int = 0,
    ) -> list[UTXOInfo]:
        """List unspent outputs (UTXOs) in the wallet.

        Args:
            wallet: Wallet name; uses default if not specified
            min_confirmations: Minimum confirmations required (default: 0 for Regtest)

        Returns:
            List of UTXO info objects
        """
        result = await self._call_rpc(
            "listunspent",
            [min_confirmations],
            wallet=wallet,
        )
        return [
            UTXOInfo(
                txid=utxo["txid"],
                vout=utxo["vout"],
                address=utxo["address"],
                amount=float(utxo["amount"]),
                confirmations=int(utxo["confirmations"]),
                spendable=bool(utxo.get("spendable", True)),
            )
            for utxo in result
        ]

    async def get_new_address(self, wallet: str | None = None) -> str:
        """Generate a new receiving address.

        Args:
            wallet: Wallet name; uses default if not specified

        Returns:
            A new Bitcoin address
        """
        result = await self._call_rpc("getnewaddress", wallet=wallet)
        return str(result)

    async def get_or_create_labeled_address(
        self,
        label: str,
        address_type: str = "bech32",
        wallet: str | None = None,
    ) -> str:
        """Return a stable receiving address for ``label``, creating it once.

        Bitcoin Core's ``getnewaddress`` intentionally mints a fresh address on
        each call. Regtest scenarios need a stable per-agent address so setup
        scripts, MCP ``wallet_address``, and generated manifests all refer to
        the same wallet endpoint. Labels give us that stable rendezvous point.
        """
        try:
            result = await self._call_rpc("getaddressesbylabel", [label], wallet=wallet)
        except RPCError:
            result = {}

        if isinstance(result, dict) and result:
            return sorted(str(address) for address in result.keys())[0]

        new_address = await self._call_rpc(
            "getnewaddress",
            [label, address_type],
            wallet=wallet,
        )
        return str(new_address)

    async def get_address_balance(
        self,
        address: str,
        wallet: str | None = None,
    ) -> int:
        """Get balance of a specific address in satoshis.

        Note: Only works if address indexing is enabled (addressindex=1 in bitcoin.conf).

        Args:
            address: Bitcoin address
            wallet: Wallet name; uses default if not specified

        Returns:
            Balance in satoshis
        """
        try:
            result = await self._call_rpc(
                "getaddressbalance",
                [{"addresses": [address]}],
                wallet=wallet,
            )
            return int(float(result["balance"]))
        except RPCError as exc:
            _logger.warning(f"Could not get address balance: {exc}")
            return 0

    async def send_to_address(
        self,
        to_address: str,
        amount_sat: int,
        wallet: str | None = None,
        fee_rate_sat_per_vb: Optional[int] = 1,
    ) -> str:
        """Send satoshis to an address.

        Args:
            to_address: Destination Bitcoin address
            amount_sat: Amount in satoshis
            wallet: Wallet name; uses default if not specified
            fee_rate_sat_per_vb: Fee rate in sat/vB; defaults to 1 so
                regtest sends do not depend on fallback fee estimation.

        Returns:
            Transaction ID (txid) as hex string

        Raises:
            RPCError: If the send fails
        """
        if not isinstance(amount_sat, int) or amount_sat < 1:
            raise RPCError(f"amount_sat must be a positive integer; got {amount_sat!r}")

        amount_btc = f"{amount_sat // 100_000_000}.{amount_sat % 100_000_000:08d}"
        params: RpcParams = {"address": to_address, "amount": amount_btc}
        if fee_rate_sat_per_vb is not None:
            params["fee_rate"] = fee_rate_sat_per_vb

        result = await self._call_rpc(
            "sendtoaddress",
            params,
            wallet=wallet,
        )
        return str(result)

    async def create_raw_transaction(
        self,
        inputs: list[dict[str, Any]],
        outputs: dict[str, float],
    ) -> str:
        """Create an unsigned raw transaction.

        Args:
            inputs: List of {"txid": str, "vout": int} dicts
            outputs: Dict mapping address -> amount_in_BTC

        Returns:
            Hex-encoded raw transaction
        """
        result = await self._call_rpc("createrawtransaction", [inputs, outputs])
        return str(result)

    async def sign_raw_transaction(
        self,
        raw_tx_hex: str,
        wallet: str | None = None,
    ) -> tuple[str, bool]:
        """Sign a raw transaction with wallet keys.

        Args:
            raw_tx_hex: Unsigned raw transaction hex
            wallet: Wallet name; uses default if not specified

        Returns:
            Tuple of (signed_tx_hex, is_complete)
        """
        result = await self._call_rpc(
            "signrawtransactionwithwallet",
            [raw_tx_hex],
            wallet=wallet,
        )
        return str(result["hex"]), bool(result.get("complete", False))

    async def broadcast_transaction(self, signed_tx_hex: str) -> str:
        """Broadcast a signed transaction to the network.

        Args:
            signed_tx_hex: Signed raw transaction hex

        Returns:
            Transaction ID (txid) as hex string
        """
        result = await self._call_rpc("sendrawtransaction", [signed_tx_hex])
        return str(result)

    async def decode_rawtransaction(self, raw_tx_hex: str) -> dict[str, Any]:
        """Decode a raw transaction to its components.

        Args:
            raw_tx_hex: Raw transaction hex

        Returns:
            Decoded transaction dict
        """
        result = await self._call_rpc("decoderawtransaction", [raw_tx_hex])
        return dict(result) if result else {}

    async def get_transaction(
        self,
        txid: str,
        wallet: str | None = None,
    ) -> dict[str, Any]:
        """Get transaction details.

        Args:
            txid: Transaction ID
            wallet: Wallet name; uses default if not specified

        Returns:
            Transaction info dict
        """
        result = await self._call_rpc("gettransaction", [txid], wallet=wallet)
        return dict(result) if result else {}

    async def list_transactions(
        self,
        wallet: str | None = None,
        count: int = 100,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """Return recent wallet transactions.

        Args:
            wallet: Wallet name; uses default if not specified.
            count: Maximum transactions to return.
            skip: Number of recent transactions to skip.

        Returns:
            Bitcoin Core ``listtransactions`` entries as dictionaries.
        """
        result = await self._call_rpc(
            "listtransactions",
            ["*", int(count), int(skip), True],
            wallet=wallet,
        )
        if not isinstance(result, list):
            return []
        return [dict(tx) for tx in result if isinstance(tx, dict)]

    async def estimate_smart_fee(self, conf_target: int = 6) -> float:
        """Estimate fee rate in BTC/vB.

        Args:
            conf_target: Confirmation target in blocks

        Returns:
            Fee rate in BTC/vB
        """
        result = await self._call_rpc("estimatesmartfee", [conf_target])
        return float(result.get("feerate", 0.001))


# Convenience function for creating a client pointed at standard Regtest
def regtest_client(
    rpc_url: str = "http://127.0.0.1:18443",
    *,
    wallet: str = "",
) -> RegtestClient:
    """Create a standard Regtest client.

    Args:
        rpc_url: Bitcoin RPC endpoint (default: standard Regtest)
        wallet: Default wallet name (optional)

    Returns:
        RegtestClient instance
    """
    return RegtestClient(rpc_url, wallet_name=wallet)

