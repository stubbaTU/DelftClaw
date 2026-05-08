"""Run two HelloCommunity instances locally and exchange one message.

Usage (from the repo root, with the project venv active):

    python -m examples.ipv8_hello.run_two_peers

What it does, step by step:

1. Builds two ``IPv8`` services bound to ``127.0.0.1:9091`` and
   ``127.0.0.1:9092``. Each gets its own ephemeral curve25519 key persisted
   to a tempfile (IPv8 reads keys from disk).
2. Loads ``HelloCommunity`` as an overlay on both services.
3. Manually attaches B's ``Peer`` (with B's UDP address) to A's network.
   This skips the IPv8 walker/bootstrap stack — fine for a localhost demo,
   but a real deployment uses bootstrap servers or DHT-based discovery.
4. A sends one ``HelloPayload`` to B; the script polls B's inbox.
5. Tears the services down and unlinks the key files.

If you want to extend this, good first changes:
  - Send several messages with varying ``counter`` and confirm ordering.
  - Add a second ``VariablePayload`` (say, ``GoodbyePayload``) and a second
    handler.
  - Have B ``ez_send`` a reply back to A inside ``on_hello``.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from ipv8.configuration import ConfigBuilder
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8_service import IPv8

from examples.ipv8_hello.hello_community import HelloCommunity


def _persist_key(prefix: str) -> Path:
    """Generate a fresh curve25519 key, write it to a tempfile, return the path."""
    key = default_eccrypto.generate_key("curve25519")
    tmp = tempfile.NamedTemporaryFile(prefix=prefix, suffix=".key", delete=False)
    tmp.write(key.key_to_bin())
    tmp.close()
    return Path(tmp.name)


def _build_service(port: int, key_file: Path) -> IPv8:
    """Build an IPv8 service with one HelloCommunity overlay on ``127.0.0.1:port``."""
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_file))
    builder.add_overlay(
        "HelloCommunity",  # must match the class name in extra_communities
        "anchor",          # which key the overlay uses
        [],                # walkers — empty for a self-contained demo
        [],                # bootstrappers — empty
        {},                # initialize kwargs
        [("started",)],    # call ``started()`` once loaded
    )
    return IPv8(builder.finalize(), extra_communities={"HelloCommunity": HelloCommunity})


def _get_overlay(service: IPv8, cls: type) -> HelloCommunity:
    for overlay in service.overlays:
        if isinstance(overlay, cls):
            return overlay  # type: ignore[return-value]
    raise RuntimeError(f"{cls.__name__} not loaded")


async def main() -> None:
    key_a = _persist_key("hello_a_")
    key_b = _persist_key("hello_b_")
    service_a = _build_service(port=9091, key_file=key_a)
    service_b = _build_service(port=9092, key_file=key_b)

    await service_a.start()
    await service_b.start()
    try:
        comm_a = _get_overlay(service_a, HelloCommunity)
        comm_b = _get_overlay(service_b, HelloCommunity)

        # Tell A about B without going through the discovery walker.
        peer_b = Peer(comm_b.my_peer.public_key, address=("127.0.0.1", 9092))
        comm_a.network.add_verified_peer(peer_b)
        comm_a.network.discover_services(peer_b, [HelloCommunity.community_id])

        # Send.
        comm_a.say_hello(peer_b, text="hello from A", counter=42)

        # Wait briefly for the UDP datagram to land.
        for _ in range(40):
            if comm_b.received:
                break
            await asyncio.sleep(0.05)

        if comm_b.received:
            print("\nexample succeeded — B received the HelloPayload from A")
        else:
            print("\nexample timed out — B never received anything")
    finally:
        await service_a.stop()
        await service_b.stop()
        for path in (key_a, key_b):
            try:
                path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    asyncio.run(main())
