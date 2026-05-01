"""Bridge `Wallet` → SporeStack token: pay an invoice in BTC out of the agent's wallet.

`fund_replica_token` is the orchestrator's entry point: it generates a token,
asks SporeStack to issue an invoice in BTC, then composes a payment from the
parent's wallet to the invoice address and broadcasts it.
"""

from __future__ import annotations

from dataclasses import dataclass

from communication.payload.bitcoin_payment import PaymentBuilder, UTXOProvider
from communication.payload.broadcaster import Broadcaster
from identity.wallet import Wallet
from replication.provisioning import SporeStackProvisioner
from shared.envelopes import BTCPayload
from shared.ids import Txid


@dataclass(frozen=True)
class FundingResult:
    """What the caller gets back after funding a replica's token."""

    token: str
    btc_payload: BTCPayload
    txid: Txid


def fund_replica_token(
    parent_wallet: Wallet,
    utxo_provider: UTXOProvider,
    broadcaster: Broadcaster,
    provisioner: SporeStackProvisioner,
    dollars: int,
) -> FundingResult:
    token = SporeStackProvisioner.fresh_token()
    invoice = provisioner.fund_token(token=token, dollars=dollars)
    # Invoice exposes payment_uri / cryptocurrency / address; the field names depend on the
    # sporestack version. Treat `invoice.cryptos[0].address` as the canonical lookup, with
    # `invoice.cryptos[0].amount` as sats. Adjust if the field shape changes upstream.
    btc_invoice = next(c for c in invoice.cryptos if c.cryptocurrency == "btc")
    recipient_pubkey_or_addr = btc_invoice.address.encode("ascii")
    amount_sats = int(btc_invoice.amount)

    builder = PaymentBuilder(parent_wallet, utxo_provider)
    btc_payload = builder.compose(recipient_pubkey_or_addr, amount_sats)
    txid = broadcaster.broadcast(btc_payload)
    return FundingResult(token=token, btc_payload=btc_payload, txid=txid)
