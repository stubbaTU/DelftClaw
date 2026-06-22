"""Live two-node interop — the SQ3 *behavioral* conformance measurement.

Where ``interop.py`` checks the byte-level wire format (pack with compile A's
payload class, unpack with compile B's), this module exercises two independent
LLM compilations as *real* IPv8 communities on an in-memory mock network:
node A runs compile A, node B runs compile B, they are introduced as peers, and
a scripted scenario drives messages through IPv8's actual packet dispatch into
the generated handlers. Conformance is then judged on *observable behavior* —
the runtime-state attributes named by the spec's ``# Runtime State`` table and
any messages a handler sends back — not on the wire format.

The wire format is over-determined by the descriptor's ``| name | encoding |``
tables, so wire interop sits at ~100% whenever both sides compile. The handler
logic is specified only in prose, so it is where two compilations can diverge.
That divergence is exactly what this harness can see and ``interop.py`` cannot.

Everything here runs on IPv8's own test doubles (``MockIPv8`` over the
in-memory ``internet`` registry): real serialization, real ``ez_send`` /
``add_message_handler`` dispatch, real handler execution — just no UDP.
"""

from __future__ import annotations

from asyncio import all_tasks, sleep
from dataclasses import dataclass
from typing import Any

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8.test.mocking.endpoint import internet
from ipv8.test.mocking.ipv8 import MockIPv8

from protocol.compiler import (
    MessageDef,
    _coerce_field_value,
    _payload_class_for,
    strip_code_fences,
)
from protocol.sandbox import safe_exec


# Elliptic curve for the mock peers. IPv8's default security levels ("low" etc.)
# use binary SECT curves that modern OpenSSL/``cryptography`` backends disable;
# ``curve25519`` (libnacl) is the curve the DelftClaw runtime actually uses and
# the only one that generates here. Passing a pre-built Peer lets us override
# MockIPv8's hard-coded "low" default.
_CURVE = "curve25519"


# ---------------------------------------------------------------------------
# Loading a generated source into a live community class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LoadedOverlay:
    """One independent compile, ready to instantiate as an IPv8 community."""
    community_cls: type
    namespace: dict[str, Any]


def load_overlay(source: str, community_id: bytes) -> LoadedOverlay:
    """Run a generated source through the sandbox and pull out its community
    class.

    Matches the compiler's own class-resolution rule (``compiler.compile``):
    prefer the class declaring the expected ``community_id``, fall back to one
    literally named ``GeneratedCommunity``. Raises ``ValueError`` if neither is
    present so a degenerate compile surfaces rather than instantiating the wrong
    class.
    """
    from ipv8.community import Community

    namespace = safe_exec(strip_code_fences(source))
    by_cid = [
        v for v in namespace.values()
        if isinstance(v, type)
        and issubclass(v, Community)
        and v is not Community
        and getattr(v, "community_id", None) == community_id
    ]
    if by_cid:
        return LoadedOverlay(community_cls=by_cid[0], namespace=namespace)
    if "GeneratedCommunity" in namespace:
        return LoadedOverlay(community_cls=namespace["GeneratedCommunity"], namespace=namespace)
    raise ValueError(
        f"source declares no Community with community_id {community_id.hex()} "
        "nor a class named GeneratedCommunity"
    )


# ---------------------------------------------------------------------------
# Two-node mock network
# ---------------------------------------------------------------------------

def _peer_for(node: MockIPv8) -> Peer:
    """A public ``Peer`` handle for ``node`` (mirrors ``TestBase.peer``)."""
    return Peer(node.my_peer.public_key.key_to_bin(), node.endpoint.wan_address)


async def deliver_messages(timeout: float = 0.5) -> None:
    """Pump the event loop until message delivery settles.

    Reimplements ``TestBase.deliver_messages`` (we don't subclass the unittest
    ``TestBase`` because the runner drives this outside a test case): wait until
    the count of non-background asyncio tasks drops below two twice in a row, or
    until ``timeout`` elapses.
    """
    rtime = 0.0
    probable_exit = False
    while rtime < timeout:
        await sleep(0.01)
        rtime += 0.01
        live = [t for t in all_tasks() if not t.get_name().endswith("_check_tasks")]
        if len(live) < 2:
            if probable_exit:
                break
            probable_exit = True
        else:
            probable_exit = False


class TwoNodeNetwork:
    """Two ``MockIPv8`` nodes — A runs compile A, B runs compile B — wired as
    mutually-verified peers of the same community.

    Use as an async context manager::

        async with TwoNodeNetwork(loaded_a, loaded_b, community_id) as net:
            await net.send(0, 1, msg, {"field": value})
            assert net.state(1, "admitted_peers") == [...]
    """

    def __init__(self, a: LoadedOverlay, b: LoadedOverlay, community_id: bytes) -> None:
        self._a = a
        self._b = b
        self._community_id = community_id
        self.nodes: list[MockIPv8] = []

    async def __aenter__(self) -> TwoNodeNetwork:
        node_a = MockIPv8(Peer(default_eccrypto.generate_key(_CURVE)), self._a.community_cls)
        node_b = MockIPv8(Peer(default_eccrypto.generate_key(_CURVE)), self._b.community_cls)
        self.nodes = [node_a, node_b]
        self._ns = [self._a.namespace, self._b.namespace]

        # Introduce the two nodes to each other directly in their Networks —
        # the same shortcut TestBase.initialize uses (skips the walk handshake).
        for node in self.nodes:
            for other in self.nodes:
                if other is node:
                    continue
                priv = other.my_peer
                public_peer = Peer(priv.public_key, priv.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(public_peer, [self._community_id])

        # Fire the lifecycle hook if the generated class declares one (the
        # peer-observer lifecycle registers itself here). Guarded: a missing or
        # throwing started() must not abort the run — it is itself a behavioral
        # observation the scenario can check.
        for node in self.nodes:
            started = getattr(node.overlay, "started", None)
            if callable(started):
                try:
                    started()
                except Exception:  # noqa: BLE001 — surfaced via behavior, not here
                    pass
        return self

    async def __aexit__(self, *exc: object) -> None:
        for node in self.nodes:
            try:
                await node.stop()
            except Exception:  # noqa: BLE001 — teardown best-effort
                pass
        internet.clear()

    def overlay(self, i: int) -> Any:
        """The live community instance of node ``i``."""
        return self.nodes[i].overlay

    def state(self, i: int, attr: str) -> Any:
        """Read a runtime-state attribute (named per the spec's ``# Runtime
        State`` table) off node ``i``'s community. Returns a sentinel-free value
        or raises ``AttributeError`` if the compile never declared it — which is
        itself a conformance failure the caller records."""
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
        """Send ``message`` (built from ``src``'s own payload class) from node
        ``src`` to node ``dst`` via real ``ez_send``, then pump delivery.

        Building the payload with the *sender's* class is the point: it tests
        that ``dst``'s independently-compiled handler accepts ``src``'s wire
        bytes and reacts as the spec prescribes.
        """
        payload = self._build_payload(message, fields, self._ns[src])
        self.nodes[src].overlay.ez_send(_peer_for(self.nodes[dst]), payload)
        if settle:
            await deliver_messages()
