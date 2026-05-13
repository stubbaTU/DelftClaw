"""End-to-end donation admission demo: wallet.send -> JOIN_REQUEST -> verify -> accept.

Two IPv8 instances (Alice as joiner, Bob as gatekeeper) in one process,
sharing a localhost UDP transport. Alice signs and broadcasts a Bitcoin
transaction to Bob's seedbox address, then sends a JOIN_REQUEST carrying
the txid. Bob's ``DonationVerifier`` fetches the tx via bitcoinlib's
service layer and replies with ``JoinResponsePayload(accepted=True)`` if
it paid the seedbox.

Modes:

  ``--mock-verifier``       skip the bitcoinlib network call; accept iff
                            the donation txid begins with the magic byte
                            ``0xAA``. Lets you exercise the full wire path
                            without a funded testnet wallet.

  ``--txid HEX``            skip the send step and reuse a previously
                            broadcast txid. Useful when iterating after a
                            real testnet send.

  default                   real testnet send: Alice signs+broadcasts via
                            her HD wallet, then both peers wait for the
                            verifier to confirm. Requires Alice's wallet
                            to be funded from a testnet faucet.

Setup for a real run:
  1. Run the script once with ``--show-addresses`` to print Alice's
     receiving address.
  2. Top up that address from a testnet faucet (e.g.
     https://coinfaucet.eu/en/btc-testnet/).
  3. Wait one confirmation, then re-run without ``--show-addresses``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass

from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import SeedboxCommunity
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from admission.donation_verifier import (
    DonationVerification,
    DonationVerifier,
)


ALICE_MNEMONIC = (
    "army van defense carry jealous true garbage claim echo media make crunch"
)
BOB_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


@dataclass
class _Mocked:
    """Stand-in for DonationVerifier; accepts iff txid starts with 0xAA."""

    seedbox_address: str
    min_sats: int

    def verify(self, txid: str) -> DonationVerification:
        if txid.startswith("aa"):
            return DonationVerification(True, "ok (mock)", paid_sats=self.min_sats, confirmations=99)
        return DonationVerification(False, "rejected (mock)")


def _build_node(identity: AgentIdentity, port: int, key_file: str) -> IPv8:
    """Build a 1-overlay IPv8 instance bound to 127.0.0.1:port."""
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    # Persist the IPv8 transport key alongside the wallet so re-runs re-use it.
    open(key_file, "wb").write(identity.ipv8.key.key_to_bin())
    builder.add_key("anchor", "curve25519", key_file)
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(builder.finalize(), extra_communities={"SeedboxCommunity": SeedboxCommunity})


def _overlay(service: IPv8) -> SeedboxCommunity:
    for o in service.overlays:
        if isinstance(o, SeedboxCommunity):
            return o
    raise RuntimeError("SeedboxCommunity not loaded")


async def _run(args: argparse.Namespace) -> int:
    alice_id = AgentIdentity.from_seed(MnemonicSeedSource(ALICE_MNEMONIC).load(), network="TESTNET")
    bob_id = AgentIdentity.from_seed(MnemonicSeedSource(BOB_MNEMONIC).load(), network="TESTNET")

    if args.show_addresses:
        print(f"Alice (joiner)     wallet: {alice_id.wallet.address()}")
        print(f"Bob   (gatekeeper) wallet: {bob_id.wallet.address()}  <-- seedbox address")
        return 0

    # Build the two IPv8 nodes.
    alice = _build_node(alice_id, port=8190, key_file="/tmp/donation_demo_alice.key")
    bob = _build_node(bob_id, port=8191, key_file="/tmp/donation_demo_bob.key")
    await alice.start()
    await bob.start()

    try:
        alice_overlay = _overlay(alice)
        bob_overlay = _overlay(bob)

        # Wire Bob's verifier (mock or real).
        seedbox_addr = bob_id.wallet.address()
        if args.mock_verifier:
            verifier = _Mocked(seedbox_address=seedbox_addr, min_sats=args.sats)
            print(f"verifier: MOCK (accepts txid starting with 'aa'); seedbox={seedbox_addr}")
        else:
            verifier = DonationVerifier(
                seedbox_address=seedbox_addr,
                min_sats=args.sats,
                min_confirmations=args.min_confirmations,
                network="testnet",
            )
            print(f"verifier: live testnet; seedbox={seedbox_addr}, min_sats={args.sats}, min_confirms={args.min_confirmations}")
        bob_overlay.configure(verifier=verifier)

        # Tell Alice about Bob's address (skip walker discovery).
        bob_peer_for_alice = Peer(bob_overlay.my_peer.public_key, address=("127.0.0.1", 8191))
        alice_overlay.network.add_verified_peer(bob_peer_for_alice)

        # Resolve donation txid.
        if args.txid:
            txid = args.txid
            print(f"reusing txid: {txid}")
        elif args.mock_verifier:
            txid = "aa" * 32
            print(f"mock txid (accepted by mock verifier): {txid}")
        else:
            print(f"alice.balance: {alice_id.wallet.balance_sats()} sats")
            print(f"alice -> bob  : {args.sats} sats -> {seedbox_addr}")
            txid = alice_id.wallet.send(seedbox_addr, args.sats)
            print(f"broadcast txid: {txid}")

        # Send JOIN_REQUEST(txid) and wait for the response.
        future = alice_overlay.request_join(bob_peer_for_alice, bytes.fromhex(txid))
        try:
            accepted = await asyncio.wait_for(future, timeout=args.timeout)
        except asyncio.TimeoutError:
            print(f"timeout after {args.timeout}s waiting for JOIN_RESPONSE", file=sys.stderr)
            return 2

        if accepted:
            print(f"ACCEPTED. Alice is now in Bob's verified_peers ({len(bob_overlay.network.verified_peers)} peers).")
            return 0
        print("REJECTED.", file=sys.stderr)
        return 1
    finally:
        await alice.stop()
        await bob.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mock-verifier", action="store_true",
                        help="skip the bitcoinlib network call; accept any txid starting with 0xAA")
    parser.add_argument("--txid", help="reuse an already-broadcast donation txid (hex)")
    parser.add_argument("--sats", type=int, default=10_000, help="donation amount (default: 10000)")
    parser.add_argument("--min-confirmations", type=int, default=0,
                        help="confirmations required by the live verifier (default: 0)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="seconds to wait for JOIN_RESPONSE (default: 30)")
    parser.add_argument("--show-addresses", action="store_true",
                        help="print Alice's and Bob's wallet addresses then exit")
    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
