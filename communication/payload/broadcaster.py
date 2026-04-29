"""Where signed Bitcoin txs go: testnet RPC or in-memory synthetic ledger."""

from __future__ import annotations

from typing import Protocol

from communication.payload.bitcoin_payment import UTXOProvider
from identity.wallet import UTXO
from shared.envelopes import BTCPayload
from shared.ids import Txid


class Broadcaster(Protocol):
    """Strategy for shipping a signed BTCPayload onto a Bitcoin-shaped network."""

    def broadcast(self, payload: BTCPayload) -> Txid:
        # Submit the signed tx; return its Txid on acceptance, raise WalletError on rejection.
        ...


class TestnetBroadcaster(Broadcaster):
    """Concrete broadcaster: sendrawtransaction against a real Bitcoin testnet RPC."""

    def __init__(self, rpc_url: str) -> None:
        # Store the RPC endpoint; lazy HTTP client.
        ...

    def broadcast(self, payload: BTCPayload) -> Txid:
        # POST sendrawtransaction with payload.signed_tx; raise WalletError on RPC error.
        ...


class SyntheticLedgerBroadcaster(Broadcaster, UTXOProvider):
    """In-memory ledger used for latency benchmarks; doubles as a UTXOProvider for tests."""

    def __init__(self) -> None:
        # Initialise empty in-memory mempool / utxo set.
        ...

    def broadcast(self, payload: BTCPayload) -> Txid:
        # Apply the tx to the in-memory ledger immediately; return a deterministic Txid.
        ...

    def utxos_of(self, pubkey: bytes) -> list[UTXO]:
        # Return the UTXOs currently owned by `pubkey` in the in-memory ledger.
        ...
