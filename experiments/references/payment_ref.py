"""Reference implementation of ``protocol/examples/payment_request.md``.

The stateful-exchange rung. The behaviour the encoding tables cannot express,
and where independent compilations are most likely to diverge, is the
PAYMENT_REQUEST handler's de-duplication: requests are keyed by the sender's
peer mid, a duplicate from the same peer is dropped (first request wins), and the
table is capped at ``MAX_PENDING_REQUESTS``.

The descriptor declares an ``expire_requests`` periodic task (drop entries older
than the TTL). It is intentionally NOT registered here: the example descriptor's
``pending_requests`` value carries no per-entry timestamp, so age is not
computable as written, and the conformance battery never advances the 600 s of
mock time the task would need. The handler behaviour — all that the scenarios
observe — is reproduced exactly.
"""

from __future__ import annotations

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver

from protocol.compiler import community_id_from_md
from experiments.fixtures import get_spec

COMMUNITY_ID = community_id_from_md(get_spec("payment").md_text)  # I2


@vp_compile
class PaymentRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["Q", "varlenH"]
    names = ["amount_sats", "memo"]


@vp_compile
class PaymentOfferPayload(VariablePayload):
    msg_id = 2
    format_list = ["Q", "varlenH"]
    names = ["amount_sats", "memo"]


@vp_compile
class PaymentNotifyPayload(VariablePayload):
    msg_id = 3
    format_list = ["Q", "varlenH"]
    names = ["amount_sats", "txid"]


@vp_compile
class PaymentDeclinePayload(VariablePayload):
    msg_id = 4
    format_list = ["varlenH"]
    names = ["reason"]


class PaymentReferenceCommunity(Community, PeerObserver):
    """Reference payment-request community (lifecycle: peer-observer)."""

    community_id = COMMUNITY_ID
    MAX_PENDING_REQUESTS = 64
    PENDING_REQUEST_TTL_S = 600

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Runtime State: pending_requests (dict keyed by requester mid hex),
        # received_offers, received_payments, declined.
        self.pending_requests: dict[str, dict] = {}
        self.received_offers: list[dict] = []
        self.received_payments: list[dict] = []
        self.declined: list[dict] = []
        self.add_message_handler(PaymentRequestPayload, self.on_payment_request)
        self.add_message_handler(PaymentOfferPayload, self.on_payment_offer)
        self.add_message_handler(PaymentNotifyPayload, self.on_payment_notify)
        self.add_message_handler(PaymentDeclinePayload, self.on_payment_decline)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    @lazy_wrapper(PaymentRequestPayload)
    def on_payment_request(self, peer: Peer, payload: PaymentRequestPayload) -> None:
        # "record the request in self.pending_requests keyed by the sending
        # peer's mid hex. If an entry for that mid is already present, drop the
        # duplicate without overwriting it (first request wins). If
        # pending_requests already holds MAX_PENDING_REQUESTS entries, drop."
        key = peer.mid.hex()
        if key in self.pending_requests:
            return
        if len(self.pending_requests) >= self.MAX_PENDING_REQUESTS:
            return
        self.pending_requests[key] = {
            "amount_sats": payload.amount_sats,
            "memo": payload.memo.decode("utf-8"),
        }

    @lazy_wrapper(PaymentOfferPayload)
    def on_payment_offer(self, peer: Peer, payload: PaymentOfferPayload) -> None:
        self.received_offers.append({
            "amount_sats": payload.amount_sats,
            "memo": payload.memo.decode("utf-8"),
        })

    @lazy_wrapper(PaymentNotifyPayload)
    def on_payment_notify(self, peer: Peer, payload: PaymentNotifyPayload) -> None:
        self.received_payments.append({
            "amount_sats": payload.amount_sats,
            "txid": payload.txid.decode("utf-8"),
        })

    @lazy_wrapper(PaymentDeclinePayload)
    def on_payment_decline(self, peer: Peer, payload: PaymentDeclinePayload) -> None:
        self.declined.append({"reason": payload.reason.decode("utf-8")})
