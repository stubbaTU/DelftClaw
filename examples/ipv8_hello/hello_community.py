"""A minimal IPv8 community: one message type, one handler.

This is the smallest possible py-ipv8 example. Everything that's *not*
required to send a message peer-to-peer has been stripped: no walkers, no
bootstrappers, no application-layer signing, no encryption. The goal is to
isolate three concepts:

1. Defining a wire-format message via ``VariablePayload`` + ``vp_compile``.
2. Subclassing ``ipv8.community.Community`` and registering a handler.
3. Sending with ``self.ez_send(peer, payload)`` and receiving via a
   ``@lazy_wrapper``-decorated method.

The ``run_two_peers.py`` script in this folder boots two HelloCommunity
instances on different UDP ports, attaches them to each other, and
exchanges one HelloPayload.
"""

from __future__ import annotations

from typing import Any

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile


@vp_compile
class HelloPayload(VariablePayload):
    """One greeting on the wire.

    ``msg_id`` is the discriminant IPv8 uses to route a received datagram to a
    handler in this community. ``format_list``/``names`` declare the on-wire
    fields; ``vp_compile`` generates the (de)serialisation code.

    Field types:
      - ``varlenH`` — uint16-length-prefixed bytes
      - ``I``       — uint32 big-endian
    """

    msg_id = 1
    format_list = ["varlenH", "I"]
    names = ["text", "counter"]


class HelloCommunity(Community):
    """One-message-type community for the example.

    A 20-byte ``community_id`` is the IPv8 contract — packets whose prefix
    does not match this id are not delivered to this overlay's handlers.
    """

    community_id = b"hellocommunityexampl"  # 20 bytes

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Inbox the runner script polls. In a real community you would route
        # received messages into your application, not into a list.
        self.received: list[tuple[Any, str, int]] = []

        # Wire the HelloPayload class to the handler. IPv8 calls
        # ``on_hello(self, peer, raw_bytes)`` with the demarshalled payload
        # because of the ``@lazy_wrapper(HelloPayload)`` below.
        self.add_message_handler(HelloPayload, self.on_hello)

    def started(self) -> None:
        """IPv8 fires this once the overlay is loaded — log a heartbeat."""
        print(f"[{self.my_peer.mid.hex()[:8]}] HelloCommunity started")

    def say_hello(self, peer: Any, text: str, counter: int) -> None:
        """Send one HelloPayload to ``peer`` via IPv8.

        ``ez_send`` prefixes the community id and message id, signs with the
        local Ed25519 key, and ships the resulting datagram.
        """
        self.ez_send(peer, HelloPayload(text=text.encode("utf-8"), counter=counter))

    @lazy_wrapper(HelloPayload)
    def on_hello(self, peer: Any, payload: HelloPayload) -> None:
        """Handle an inbound HelloPayload.

        ``lazy_wrapper`` deserialises ``payload`` from the raw bytes IPv8
        delivered, so we receive a ready-to-use object.
        """
        text = payload.text.decode("utf-8", errors="replace")
        print(
            f"[{self.my_peer.mid.hex()[:8]}] received hello "
            f"text={text!r} counter={payload.counter} "
            f"from peer={peer.mid.hex()[:8]}"
        )
        self.received.append((peer, text, payload.counter))
