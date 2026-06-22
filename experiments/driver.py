"""Programmable N-node mock network for SQ3 scenarios.

``sq3.live_interop.TwoNodeNetwork`` wires exactly two nodes and auto-settles a
single round trip — enough for the echo spike, but the conformance batteries need
more: a third peer (so a payment payer's per-requester keying can be exercised by
two distinct senders) and explicit, ordered delivery (so a fetcher's
out-of-order / duplicate-chunk tolerance can be driven deterministically rather
than relying on the seeder's in-order emission).

``ProgrammableNetwork`` generalizes the two-node harness to ``n`` nodes,
cross-introducing every pair and exposing a single ``send(src, dst, …)`` that
delivers one crafted message at a time. Reordering, duplication, and loss are
expressed simply as the order (and presence) of ``send`` calls the scenario
makes — no packet interception required, and every byte still travels through
IPv8's real serializer and handler dispatch.

It reuses the two-node harness's building blocks verbatim
(``deliver_messages``, ``_peer_for``, the curve) so the two stay behaviourally
identical on the paths they share.
"""

from __future__ import annotations

import logging
from typing import Any

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8.test.mocking.endpoint import internet
from ipv8.test.mocking.ipv8 import MockIPv8

from protocol.compiler import MessageDef, _coerce_field_value, _payload_class_for
from experiments.live_interop import _CURVE, LoadedOverlay, _peer_for, deliver_messages


class ProgrammableNetwork:
    """``n`` ``MockIPv8`` nodes, each running one overlay, wired as
    mutually-verified peers of the same community. Use as an async context
    manager::

        async with ProgrammableNetwork([a, b, c], community_id) as net:
            await net.send(0, 1, msg, {"field": value})
            assert net.state(1, "pending_requests") == {...}
    """

    def __init__(self, overlays: list[LoadedOverlay], community_id: bytes) -> None:
        if len(overlays) < 2:
            raise ValueError("ProgrammableNetwork needs at least two overlays")
        self._overlays = overlays
        self._community_id = community_id
        self.nodes: list[MockIPv8] = []
        self._ns: list[dict[str, Any]] = []

    async def __aenter__(self) -> "ProgrammableNetwork":
        # A generated handler raising mid-exchange is a MEASURED outcome here (a
        # non-conformant / non-interoperating compile crashing on a peer's
        # message), not a harness fault — IPv8 catches it and we record the
        # resulting state divergence. Silence the per-packet exception logging so
        # the run log stays readable; restored on exit.
        #
        # IPv8 logs these under ``getLogger(self.__class__.__name__)`` (overlay.py)
        # — i.e. the *generated* community's class name, not "ipv8" — so we cannot
        # target one named logger. ``logging.disable`` suppresses everything at or
        # below the given level process-wide for the (sub-second, mock_lock-
        # serialized) exchange window, then restores the prior threshold.
        self._prev_disable = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        self.nodes = [
            MockIPv8(Peer(default_eccrypto.generate_key(_CURVE)), ov.community_cls)
            for ov in self._overlays
        ]
        self._ns = [ov.namespace for ov in self._overlays]

        # Cross-introduce every pair directly in their Networks — the same
        # shortcut TestBase.initialize uses (skips the walk handshake).
        for node in self.nodes:
            for other in self.nodes:
                if other is node:
                    continue
                priv = other.my_peer
                public_peer = Peer(priv.public_key, priv.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(public_peer, [self._community_id])

        # Fire the lifecycle hook if present; guarded — a missing/throwing
        # started() is itself a behavioural observation, not a harness abort.
        for node in self.nodes:
            started = getattr(node.overlay, "started", None)
            if callable(started):
                try:
                    started()
                except Exception:  # noqa: BLE001
                    pass
        return self

    async def __aexit__(self, *exc: object) -> None:
        for node in self.nodes:
            try:
                await node.stop()
            except Exception:  # noqa: BLE001 — teardown best-effort
                pass
        internet.clear()
        logging.disable(self._prev_disable)

    def overlay(self, i: int) -> Any:
        return self.nodes[i].overlay

    def state(self, i: int, attr: str) -> Any:
        return getattr(self.nodes[i].overlay, attr)

    def _build_payload(self, message: MessageDef, fields: dict[str, Any], ns: dict[str, Any]) -> Any:
        cls = _payload_class_for(message, ns)
        coerced = [_coerce_field_value(fields[f.name], f.encoding) for f in message.fields]
        return cls(*coerced)

    async def send(
        self,
        src: int,
        dst: int,
        message: MessageDef,
        fields: dict[str, Any],
        *,
        settle: bool = True,
    ) -> None:
        """Send ``message`` (built with ``src``'s own payload class) from node
        ``src`` to node ``dst`` via real ``ez_send``, then pump delivery. Driving
        sends one at a time, in scenario order, is how reordering/duplication is
        expressed."""
        payload = self._build_payload(message, fields, self._ns[src])
        self.nodes[src].overlay.ez_send(_peer_for(self.nodes[dst]), payload)
        if settle:
            await deliver_messages()
