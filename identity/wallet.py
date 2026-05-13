"""Bitcoin HD wallet derived from the master Seed.

Defaults to testnet; segwit (P2WPKH, bech32) addresses. Wraps
``bitcoinlib.wallets.Wallet`` and keys it off the project's BIP-39 seed so
the wallet is deterministic from the same mnemonic.

Used by the seedbox-admission flow: a joiner calls ``wallet.send(seedbox_addr, sats)``
to produce a donation txid, which is then verified by the gatekeeper via
``replication.verification.donation_verifier.DonationVerifier``.
"""

from __future__ import annotations

import hashlib

from bitcoinlib.keys import HDKey
from bitcoinlib.wallets import Wallet as _BLWallet, wallet_create_or_open

from identity.seed import Seed


def _wallet_name(seed: Seed, btc_network: str) -> str:
    """Stable per-(seed, network) wallet name so the bitcoinlib DB row is reused."""
    digest = hashlib.sha256(seed.bytes + btc_network.encode("utf-8")).hexdigest()[:16]
    return f"delftclaw_{btc_network}_{digest}"


class Wallet:
    """Bitcoin HD wallet keyed off a project ``Seed``.

    ``from_seed(seed)`` is the canonical entry. Defaults to testnet so
    development can pull from a faucet without spending mainnet sats.
    """

    DEFAULT_NETWORK = "testnet"

    def __init__(self, bl_wallet: _BLWallet, hdkey: HDKey, btc_network: str) -> None:
        self._wallet = bl_wallet
        self._hdkey = hdkey
        self._btc_network = btc_network

    @classmethod
    def from_seed(cls, seed: Seed, btc_network: str = DEFAULT_NETWORK) -> "Wallet":
        """Open (or create) the deterministic HD wallet for this seed + network."""
        master = HDKey.from_seed(seed.bytes, network=btc_network, witness_type="segwit")
        bl_wallet = wallet_create_or_open(
            name=_wallet_name(seed, btc_network),
            keys=master.wif(is_private=True),
            network=btc_network,
            witness_type="segwit",
        )
        return cls(bl_wallet, master, btc_network)

    @property
    def network(self) -> str:
        """Bitcoin network name (e.g. ``testnet``, ``bitcoin``)."""
        return self._btc_network

    @property
    def pubkey(self) -> bytes:
        """Compressed secp256k1 public key of the master HD key (33 bytes)."""
        return self._hdkey.public_byte

    def address(self) -> str:
        """Bech32 receiving address for this wallet."""
        return self._wallet.get_key().address

    def balance_sats(self, *, refresh: bool = True) -> int:
        """Total wallet balance in satoshis. ``refresh`` re-scans UTXOs over the network."""
        if refresh:
            self._wallet.scan(scan_gap_limit=5)
        return int(self._wallet.balance())

    def send(
        self,
        to_address: str,
        sats: int,
        *,
        fee_sats: int | None = None,
        min_confirms: int = 0,
        broadcast: bool = True,
    ) -> str:
        """Send ``sats`` to ``to_address``. Returns the broadcast txid (hex).

        ``fee_sats=None`` lets bitcoinlib estimate the fee from a service provider.
        ``broadcast=False`` produces a signed transaction without broadcasting; the
        returned value is still the txid hex.
        """
        tx = self._wallet.send_to(
            to_address,
            sats,
            fee=fee_sats,
            min_confirms=min_confirms,
            broadcast=broadcast,
        )
        return tx.txid


def _load_seed_from_args(args) -> Seed:
    from identity.seed import MnemonicSeedSource, EnvSeedSource, KeyfileSeedSource
    if args.mnemonic:
        return MnemonicSeedSource(args.mnemonic).load()
    if args.seed_file:
        return KeyfileSeedSource(args.seed_file).load()
    if args.use_env:
        return EnvSeedSource().load()
    return KeyfileSeedSource().load()


def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m identity.wallet")
    parser.add_argument("--mnemonic", help="BIP-39 mnemonic phrase")
    parser.add_argument("--seed-file", help="path to a hex-encoded 32-byte seed file")
    parser.add_argument("--use-env", action="store_true",
                        help="read OPENCLAW_SEED env var")
    parser.add_argument("--btc-network", default=Wallet.DEFAULT_NETWORK,
                        help="Bitcoin network: testnet (default) or bitcoin")

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("address", help="print the receiving address")
    sub.add_parser("balance", help="print the wallet balance in satoshis")
    send = sub.add_parser("send", help="send satoshis to an address")
    send.add_argument("to_address")
    send.add_argument("sats", type=int)
    send.add_argument("--fee-sats", type=int, default=None)
    send.add_argument("--no-broadcast", action="store_true",
                      help="sign but do not broadcast")

    args = parser.parse_args()
    seed = _load_seed_from_args(args)
    wallet = Wallet.from_seed(seed, btc_network=args.btc_network)

    if args.cmd == "address":
        print(wallet.address())
    elif args.cmd == "balance":
        print(wallet.balance_sats())
    elif args.cmd == "send":
        txid = wallet.send(
            args.to_address,
            args.sats,
            fee_sats=args.fee_sats,
            broadcast=not args.no_broadcast,
        )
        print(txid)
    else:
        parser.error(f"unknown command: {args.cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
