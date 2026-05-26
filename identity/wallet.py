"""Synthetic BIP-32-derived wallet for DelftClaw agents.

This wallet is **deterministic, local, and synthetic** — there is no
real Bitcoin involvement. The address is a stable ``dclaw1...`` string
derived from the wallet's Ed25519 public key; ``send()`` returns a
deterministic synthetic txid (no broadcast, no UTXO management);
``balance_sats()`` returns 0 unless the host process tracks balance
elsewhere.

The seedbox-admission flow in ``communication.community.SeedboxCommunity``
verifies these synthetic txids via
``admission.donation_verifier.DonationVerifier`` when its ``network`` is
``"mock"`` (auto-admit any non-empty txid). A future commit can add a
real-bitcoinlib path back behind ``network="testnet"`` once the supervisor
demo needs on-chain admission; for v5.1 the mock path is the canonical
flow and removes the bitcoinlib provider-rotation latency that was
stalling Bob's first turn.

The dual-purpose interface deliberately satisfies two callers:

* ``identity.agent_identity.AgentIdentity`` — uses ``address()``,
  ``xpub``, ``pubkey``, ``path``.
* ``agent.runtime.OpenClawAgent`` / ``agent.tools`` — uses ``address()``,
  ``balance_sats(refresh=...)``, ``send(to_address, sats)``, ``network``.
"""

from __future__ import annotations

import hashlib
import itertools
from typing import Any

from bip_utils import P2WPKHAddrEncoder
from bitcoinlib.keys import HDKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.derivation import DerivationPath, wallet_path
from identity.seed import Seed


UTXO = Any
SignedTransaction = Any


# Per-process monotonic counter that participates in the deterministic
# synthetic-txid digest so successive identical sends produce distinct ids.
_SEND_NONCE = itertools.count(1)


def _bitcoin_network(network: str) -> str:
    """Map the project's logical network tag to bitcoinlib's network name."""
    normalized = network.strip().upper()
    if normalized == "MAINNET":
        return "bitcoin"
    if normalized in {"TESTNET", "REGTEST"}:
        return "testnet"
    raise ValueError(f"Unsupported network: {network}")


class Wallet:
    """BIP-32-derived synthetic wallet used by DelftClaw agents.

    Construction goes through ``Wallet.from_seed(seed, network=...)``.
    The Ed25519 key derived from the BIP-44 wallet-path child key
    drives a deterministic ``dclaw1<digest>`` address; ``send()`` and
    ``balance_sats()`` operate on that synthetic identity (no
    blockchain involvement).
    """

    DEFAULT_NETWORK = "TESTNET"

    def __init__(
        self,
        root: HDKey,
        child: HDKey,
        *,
        path: DerivationPath,
        network: str,
        initial_balance_sats: int = 0,
    ) -> None:
        self._root = root
        self._child = child
        self._path = path
        self._network = network
        signing_seed = hashlib.sha256(child.private_byte).digest()
        self.key = Ed25519PrivateKey.from_private_bytes(signing_seed)
        # Synthetic balance tracking — see ``balance_sats`` / ``send``.
        # An "initial_balance_sats=0" wallet behaves like the legacy
        # always-zero mock; an "initial_balance_sats=N" wallet exposes
        # a per-agent budget the LLM can spend down (capped at zero).
        if initial_balance_sats < 0:
            raise ValueError(f"initial_balance_sats must be >= 0; got {initial_balance_sats}")
        self._initial_balance_sats = initial_balance_sats
        self._spent_sats = 0

    @classmethod
    def from_seed(
        cls,
        seed: Seed,
        *,
        network: str = DEFAULT_NETWORK,
        agent_index: int = 0,
        path: DerivationPath | None = None,
        initial_balance_sats: int = 0,
    ) -> "Wallet":
        """Derive wallet keys at ``m/44'/0'/agent_index'/0/0`` by default."""
        net = _bitcoin_network(network)
        root = HDKey.from_seed(seed.bytes, network=net)
        resolved_path = path or wallet_path(agent_index)
        child = root.subkey_for_path(str(resolved_path))
        return cls(
            root, child,
            path=resolved_path,
            network=network.strip().upper(),
            initial_balance_sats=initial_balance_sats,
        )

    # ------------------------------------------------------------------
    # Identity / metadata accessors
    # ------------------------------------------------------------------

    @property
    def network(self) -> str:
        """Logical network tag (``TESTNET``, ``REGTEST``, ``MAINNET``)."""
        return self._network

    @property
    def path(self) -> str:
        """Derivation path used to create this wallet child key."""
        return str(self._path)

    @property
    def xpub(self) -> str:
        """Return the public extended key for identity metadata."""
        return str(self._child.public_master())

    @property
    def pubkey(self) -> bytes:
        """Return the wallet's canonical Ed25519 public key bytes."""
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def address(self) -> str:
        """Return a stable synthetic address for local DelftClaw experiments.

        Deterministic from the wallet's Ed25519 public key. Format:
        ``dclaw1<sha256(pubkey)[:40]>``.
        """
        digest = hashlib.sha256(self.pubkey).hexdigest()
        return f"dclaw1{digest[:40]}"

    def regtest_address(self) -> str:
        """Return a deterministic regtest-style bech32 address.

        This is derived from the same BIP-44 wallet child key used by the
        synthetic wallet, but encoded with Bitcoin regtest's ``bcrt`` HRP.
        It is useful for mock scenarios that should share addresses shaped
        like real regtest wallets without requiring Bitcoin Core RPC.
        """
        return P2WPKHAddrEncoder.EncodeKey(
            self._child.public_compressed_byte,
            hrp="bcrt",
        )

    def set_initial_balance(self, sats: int) -> None:
        """Late-binding setter so callers that construct the wallet via
        ``AgentIdentity.from_seed`` (which doesn't know about per-deploy
        balance) can populate the synthetic balance after the fact.
        Reset semantics: setting ``sats`` rewinds the spent counter to 0.
        """
        if sats < 0:
            raise ValueError(f"initial_balance_sats must be >= 0; got {sats}")
        self._initial_balance_sats = sats
        self._spent_sats = 0

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary bytes with the wallet's Ed25519 key.

        Used by the community-shared-log layer to sign ``donation_intent``
        and ``seedbox_purchase_intent`` entries before they're appended.
        Verification by peers uses the wallet's ``pubkey`` (the public
        side of the same Ed25519 key) — see ``Wallet.verify`` and
        ``cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.verify``.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"sign expects bytes; got {type(data).__name__}")
        return self.key.sign(bytes(data))

    @staticmethod
    def verify(pubkey: bytes, data: bytes, signature: bytes) -> bool:
        """Verify ``signature`` over ``data`` using a wallet's raw Ed25519 ``pubkey``.

        Static so a replay-time verifier doesn't need to materialise the
        signer's Wallet — only their public key. Returns ``True`` iff
        the signature is valid; never raises (invalid → False).
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(bytes(pubkey)).verify(
                bytes(signature), bytes(data),
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    # ------------------------------------------------------------------
    # Balance + transfer (synthetic)
    # ------------------------------------------------------------------

    def balance_sats(self, *, refresh: bool = False) -> int:
        """Synthetic balance: ``initial_balance_sats - sum(send amounts)``.

        Floored at 0. ``refresh`` is accepted for API parity with the
        on-chain path. A wallet constructed with the default
        ``initial_balance_sats=0`` always returns 0 (legacy mock behaviour).
        """
        remaining = self._initial_balance_sats - self._spent_sats
        return max(0, remaining)

    def send(self, to_address: str, sats: int) -> str:
        """Synthetic send: deterministic txid hex; no broadcast.

        The txid is ``sha256(from || to || sats || nonce)`` where ``nonce``
        is a per-process monotonic counter — so successive identical
        sends from the same wallet produce distinct ids. The matching
        ``DonationVerifier(network="mock")`` admits any non-empty txid;
        the donation gate is *ceremonial* in mock mode and provides no
        admission control.

        If the wallet was constructed with a positive
        ``initial_balance_sats``, an over-spend raises ``ValueError``
        (so the LLM gets a clean "insufficient funds" surface instead
        of broadcasting a phantom donation that the verifier could not
        possibly have observed).
        """
        if sats < 1:
            raise ValueError(f"sats must be >= 1; got {sats}")
        if not isinstance(to_address, str) or not to_address:
            raise ValueError("to_address must be a non-empty string")
        if self._initial_balance_sats > 0:
            remaining = self._initial_balance_sats - self._spent_sats
            if sats > remaining:
                raise ValueError(
                    f"insufficient funds: have {remaining} sats, "
                    f"tried to send {sats}"
                )
        nonce = next(_SEND_NONCE)
        body = f"{self.address()}|{to_address}|{sats}|{nonce}".encode("utf-8")
        self._spent_sats += sats
        return hashlib.sha256(body).hexdigest()

    # ------------------------------------------------------------------
    # Master-side test helpers (preserved for identity/tests/)
    # ------------------------------------------------------------------

    def get_private_key(self) -> str:
        """Return the raw Ed25519 private key as hex for local tests."""
        return self.key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex()

    def get_balance(self, as_string: bool = False) -> int | str:
        """Synthetic balance accessor used by identity tests. Always zero."""
        if as_string:
            return "0.00000000 BTC"
        return 0

    def get_utxos(self) -> list[UTXO]:
        """Synthetic UTXO listing — always empty."""
        return []


# ---------------------------------------------------------------------------
# CLI: ``python -m identity.wallet {address,balance,send}``
# ---------------------------------------------------------------------------

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
    parser.add_argument("--network", default=Wallet.DEFAULT_NETWORK,
                        help="logical network: TESTNET (default), REGTEST, MAINNET")

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("address", help="print the synthetic receiving address")
    sub.add_parser("balance", help="print the wallet balance in satoshis (synthetic: always 0)")
    send = sub.add_parser("send", help="generate a deterministic synthetic txid")
    send.add_argument("to_address")
    send.add_argument("sats", type=int)

    args = parser.parse_args()
    seed = _load_seed_from_args(args)
    wallet = Wallet.from_seed(seed, network=args.network)

    if args.cmd == "address":
        print(wallet.address())
    elif args.cmd == "balance":
        print(wallet.balance_sats())
    elif args.cmd == "send":
        print(wallet.send(args.to_address, args.sats))
    else:
        parser.error(f"unknown command: {args.cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
