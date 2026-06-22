"""Tests for the boundary battery (sq3.boundaries) and the strengthened adoption
interop that uses it.

The integration tests use a one-message "log" protocol and three compiles that
all agree on the document's own sample (`"hi"`) but diverge once demanding inputs
are pushed: one dedups (caught by the duplicate probe), one skips empty strings
(caught by the `""` boundary value). The single-sample exchange this replaced
would have called all three interoperable; the battery does not.
"""

from __future__ import annotations

import pytest

from agent.overlay_authoring import synthesize_overlay_markdown
from protocol.compiler import MessageDef, MessageField, community_id_from_md, parse_md
from experiments.adoption import adoption_interop
from experiments.boundaries import boundary_payloads, values_for
from experiments.live_interop import load_overlay


# ---------------------------------------------------------------------------
# boundary_payloads — unit
# ---------------------------------------------------------------------------

def _msg(fields: list[tuple[str, str]]) -> MessageDef:
    return MessageDef(name="M", msg_id=1, handler_text="",
                      fields=[MessageField(name=n, encoding=e, description="") for n, e in fields])


def test_uint_boundaries_stay_in_range() -> None:
    assert values_for("uint8") == [0, 1, 255]            # not 256
    assert values_for("uint16-be")[-1] == 65535
    assert values_for("bool") == [False, True]


def test_utf8_includes_empty_and_multibyte() -> None:
    vals = values_for("varlenH-utf8")
    assert "" in vals and "café" in vals


def test_payloads_sweep_each_field_and_keep_full_shape() -> None:
    payloads = boundary_payloads(_msg([("a", "uint8"), ("b", "bool")]))
    assert {0, 1, 255} <= {p["a"] for p in payloads}
    assert {False, True} <= {p["b"] for p in payloads}
    assert all(set(p) == {"a", "b"} for p in payloads)   # every field present every time
    assert len(payloads) == len({tuple(sorted(p.items())) for p in payloads})  # deduped


def test_empty_message_yields_one_empty_payload() -> None:
    assert boundary_payloads(_msg([])) == [{}]


# ---------------------------------------------------------------------------
# adoption interop with the battery — integration
# ---------------------------------------------------------------------------

_LOG_MD = synthesize_overlay_markdown(
    name="logproto", version="1.0.0", description="d", change_summary="c",
    messages=[{"name": "LOG", "msg_id": 1,
               "fields": [{"name": "text", "encoding": "varlenH-utf8", "description": "t"}],
               "handler": "append the text to received"}],
    runtime_state=[{"name": "received", "type": "list[str]", "description": "r"}],
    samples={"LOG": {"text": "hi"}}, author_id="dclaw1study")
_LOG_PARSED = parse_md(_LOG_MD)
_LOG_CID = community_id_from_md(_LOG_MD)

_LOG_SOURCE = '''
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class LogPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH"]
    names = ["text"]


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex("{cid}")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.received = []
        self.add_message_handler(LogPayload, self.on_log)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer) -> None:
        pass

    def on_peer_removed(self, peer) -> None:
        pass

    @lazy_wrapper(LogPayload)
    def on_log(self, peer, payload) -> None:
        text = payload.text.decode("utf-8")
        {body}
'''

_RECORD_ALL = "self.received.append(text)"
_DEDUP = "if text not in self.received:\n            self.received.append(text)"
_SKIP_EMPTY = 'if text != "":\n            self.received.append(text)'


def _load(body: str):
    return load_overlay(_LOG_SOURCE.format(cid=_LOG_CID.hex(), body=body), _LOG_CID)


@pytest.mark.asyncio
async def test_identical_compiles_adopt_under_battery() -> None:
    result = await adoption_interop(_load(_RECORD_ALL), _load(_RECORD_ALL), _LOG_PARSED, _LOG_CID)
    assert result.ok


@pytest.mark.asyncio
async def test_dedup_divergence_caught_by_duplicate_probe() -> None:
    """Both record each distinct value once, so every boundary VALUE agrees — only
    the duplicate probe (baseline sent twice) exposes accumulate-vs-dedup."""
    result = await adoption_interop(_load(_RECORD_ALL), _load(_DEDUP), _LOG_PARSED, _LOG_CID)
    assert not result.ok
    assert result.detail and "received" in result.detail


@pytest.mark.asyncio
async def test_empty_string_divergence_caught_by_boundary_value() -> None:
    """The two agree on the sample `"hi"`; they diverge only on the `""` boundary
    value, which the battery sends and the single sample never did."""
    result = await adoption_interop(_load(_RECORD_ALL), _load(_SKIP_EMPTY), _LOG_PARSED, _LOG_CID)
    assert not result.ok
