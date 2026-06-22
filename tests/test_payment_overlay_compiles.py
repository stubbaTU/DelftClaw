"""Regression guard for the SQ3 payment-request spec.

``protocol/examples/payment_request.md`` must parse, validate, and compile
cleanly through ``compile_overlay`` against a conformant inline implementation.
This is the offline check that the spec's:

  * required sections are in order
  * encodings come from the allowlist
  * test vectors round-trip the IPv8 serializer
  * runtime-state slots are initialised by the LLM-emitted ``__init__``
  * declared task has a matching ``register_task`` call
  * lifecycle: peer-observer subclass contract is honored

…all hold for the spec as shipped. Any future edit to the spec that breaks
any of these gates fails this test before it hits a real-LLM run.
"""

from __future__ import annotations

from pathlib import Path

from protocol import (
    community_id_from_md,
    compile_overlay,
    parse_md,
)
from protocol.compiler import validate_schema
from _live_llm import noop_llm


REPO_ROOT = Path(__file__).resolve().parent.parent
PAYMENT_MD = (REPO_ROOT / "protocol" / "examples" / "payment_request.md").read_text(encoding="utf-8")
PAYMENT_CID = community_id_from_md(PAYMENT_MD).hex()


def _conformant_payment_source(cid_hex: str) -> str:
    """A hand-matched, schema-conformant implementation for the payment spec.

    Mirrors the spec's four messages, four runtime-state slots, two
    constants, and one periodic task. Kept here (not in protocol/examples/)
    so the spec's compile path is exercised end-to-end while keeping the
    example directory focused on shipped artifacts.
    """
    return (
        "```python\n"
        "from ipv8.community import Community, CommunitySettings\n"
        "from ipv8.lazy_community import lazy_wrapper\n"
        "from ipv8.messaging.lazy_payload import VariablePayload, vp_compile\n"
        "from ipv8.peer import Peer\n"
        "from ipv8.peerdiscovery.network import PeerObserver\n"
        "\n"
        "@vp_compile\n"
        "class PaymentRequestPayload(VariablePayload):\n"
        "    msg_id = 1\n"
        '    format_list = ["Q", "varlenH"]\n'
        '    names = ["amount_sats", "memo"]\n'
        "\n"
        "@vp_compile\n"
        "class PaymentOfferPayload(VariablePayload):\n"
        "    msg_id = 2\n"
        '    format_list = ["Q", "varlenH"]\n'
        '    names = ["amount_sats", "memo"]\n'
        "\n"
        "@vp_compile\n"
        "class PaymentNotifyPayload(VariablePayload):\n"
        "    msg_id = 3\n"
        '    format_list = ["Q", "varlenH"]\n'
        '    names = ["amount_sats", "txid"]\n'
        "\n"
        "@vp_compile\n"
        "class PaymentDeclinePayload(VariablePayload):\n"
        "    msg_id = 4\n"
        '    format_list = ["varlenH"]\n'
        '    names = ["reason"]\n'
        "\n"
        "class GeneratedCommunity(Community, PeerObserver):\n"
        f'    community_id = bytes.fromhex("{cid_hex}")\n'
        "    MAX_PENDING_REQUESTS = 64\n"
        "    PENDING_REQUEST_TTL_S = 600\n"
        "\n"
        "    def __init__(self, settings: CommunitySettings) -> None:\n"
        "        super().__init__(settings)\n"
        "        self.pending_requests = {}\n"
        "        self.received_offers = []\n"
        "        self.received_payments = []\n"
        "        self.declined = []\n"
        "        self.add_message_handler(PaymentRequestPayload, self.on_payment_request)\n"
        "        self.add_message_handler(PaymentOfferPayload, self.on_payment_offer)\n"
        "        self.add_message_handler(PaymentNotifyPayload, self.on_payment_notify)\n"
        "        self.add_message_handler(PaymentDeclinePayload, self.on_payment_decline)\n"
        '        self.register_task("expire_requests", self._expire_requests, interval=60)\n'
        "\n"
        "    def started(self) -> None:\n"
        "        self.network.add_peer_observer(self)\n"
        "    def on_peer_added(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    def on_peer_removed(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    def _expire_requests(self) -> None:\n"
        "        pass\n"
        "\n"
        "    @lazy_wrapper(PaymentRequestPayload)\n"
        "    def on_payment_request(self, peer, payload):\n"
        "        key = peer.mid.hex()\n"
        "        if key not in self.pending_requests and len(self.pending_requests) < self.MAX_PENDING_REQUESTS:\n"
        "            self.pending_requests[key] = {\n"
        '                "amount_sats": payload.amount_sats,\n'
        '                "memo": payload.memo.decode("utf-8", "replace"),\n'
        "            }\n"
        "    @lazy_wrapper(PaymentOfferPayload)\n"
        "    def on_payment_offer(self, peer, payload):\n"
        "        self.received_offers.append({\n"
        '            "amount_sats": payload.amount_sats,\n'
        '            "memo": payload.memo.decode("utf-8", "replace"),\n'
        "        })\n"
        "    @lazy_wrapper(PaymentNotifyPayload)\n"
        "    def on_payment_notify(self, peer, payload):\n"
        "        self.received_payments.append({\n"
        '            "amount_sats": payload.amount_sats,\n'
        '            "txid": payload.txid.decode("utf-8", "replace"),\n'
        "        })\n"
        "    @lazy_wrapper(PaymentDeclinePayload)\n"
        "    def on_payment_decline(self, peer, payload):\n"
        '        self.declined.append({"reason": payload.reason.decode("utf-8", "replace")})\n'
        "```"
    )


def test_payment_overlay_parses_required_sections():
    parsed = parse_md(PAYMENT_MD)
    validate_schema(parsed)
    assert parsed.identity["name"] == "payment_request"
    assert parsed.identity["version"] == "1.0.0"
    assert parsed.lifecycle == "peer-observer"
    assert [m.name for m in parsed.messages] == [
        "PAYMENT_REQUEST", "PAYMENT_OFFER", "PAYMENT_NOTIFY", "PAYMENT_DECLINE",
    ]
    assert {s.name for s in parsed.runtime_state} == {
        "pending_requests", "received_offers", "received_payments", "declined",
    }
    assert {c.name for c in parsed.constants} == {"MAX_PENDING_REQUESTS", "PENDING_REQUEST_TTL_S"}
    assert [t.name for t in parsed.tasks] == ["expire_requests"]


def test_payment_overlay_test_vectors_have_two_per_message():
    """The schema's ≥2-vectors-per-message rule. Compiler runs both on
    compile_overlay; this just confirms the count up front."""
    parsed = parse_md(PAYMENT_MD)
    by_msg: dict[str, int] = {}
    for tv in parsed.test_vectors:
        by_msg[tv.message] = by_msg.get(tv.message, 0) + 1
    for m in parsed.messages:
        assert by_msg.get(m.name, 0) >= 2, (
            f"message {m.name} has {by_msg.get(m.name, 0)} test vectors; "
            f"schema requires ≥ 2"
        )


def test_payment_overlay_compiles_through_real_pipeline():
    """The load-bearing test: the spec compiles cleanly via ``compile_overlay``
    against a conformant inline implementation fed through llm_source (no live
    model). That means: parse, schema validation, AST sandbox, structural
    contract (constants + runtime state + lifecycle + tasks), AND every test
    vector's encode/decode round-trip all pass for the spec as shipped."""
    compiled = compile_overlay(PAYMENT_MD, noop_llm(),
                               llm_source=_conformant_payment_source(PAYMENT_CID))
    assert compiled.parsed.identity["name"] == "payment_request"
    assert "PAYMENT_REQUEST" in compiled.payload_classes
    assert "PAYMENT_NOTIFY" in compiled.payload_classes
