"""Step 1 acceptance gate for the SQ3 reference oracle.

Fully offline (no LLM endpoint). Proves the four hand-written reference
communities are (I2) in the right IPv8 community, (I1) wire-byte-identical to a
compiled overlay, behaviourally correct on the demo happy paths, and that the
oracle's comparator is discriminating (a deliberately broken reference fails) and
deterministic. This is the linchpin: everything downstream is judged against
these references, so if the gate is green the oracle is a sound, non-circular
ground truth.
"""

from __future__ import annotations

import csv
import hashlib

import pytest

from ipv8.lazy_community import lazy_wrapper

from protocol.compiler import _payload_class_for, _run_test_vector
from experiments.fixtures import EXAMPLES_DIR, get_spec
from experiments.oracle import (
    Checkpoint,
    LoadedOverlay,
    Seed,
    Send,
    canonicalize,
    reference_overlay,
    run_scenario,
)
from experiments.references import payment_ref

SPEC_NAMES = ["echo", "content_community", "payment", "file_transfer"]


def _transfer_status(transfers: dict) -> dict:
    """Project a fetcher's ``transfers`` to just the verdict fields."""
    return {k: {"complete": v["complete"], "ok": v["ok"]} for k, v in transfers.items()}


def _load_catalog() -> list[dict]:
    """The seeder's ``local_index``, parsed from the real CC library CSV
    (size -> int, tags -> list[str]) exactly as the deployed seeder seeds it."""
    path = EXAMPLES_DIR / "cc_library" / "content_catalog.csv"
    with open(path, newline="", encoding="utf-8") as handle:
        rows = []
        for row in csv.DictReader(handle):
            rows.append({
                "magnet": row["magnet"],
                "name": row["name"],
                "size": int(row["size"]),
                "mime": row["mime"],
                "tags": [t for t in row["tags"].split(";") if t],
            })
    return rows


# ---------------------------------------------------------------------------
# I2 — shared community
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_name", SPEC_NAMES)
def test_reference_community_id_matches_fixture(spec_name: str) -> None:
    """Each reference's community_id is the descriptor's content hash, so it can
    share an IPv8 community with a compiled overlay of the same spec."""
    overlay = reference_overlay(spec_name)
    expected = bytes.fromhex(get_spec(spec_name).community_id_hex)
    assert overlay.community_cls.community_id == expected


# ---------------------------------------------------------------------------
# I1 — wire-byte identity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_name", SPEC_NAMES)
def test_reference_payloads_are_wire_byte_identical(spec_name: str) -> None:
    """Every descriptor test vector packs through the reference payload class to
    exactly its recorded bytes (and round-trips back). Uses the compiler's own
    ``_run_test_vector``, so the reference is held to the identical wire contract
    a compiled overlay is."""
    spec = get_spec(spec_name)
    namespace = reference_overlay(spec_name).namespace
    msg_by_name = {m.name: m for m in spec.parsed.messages}
    assert spec.parsed.test_vectors, "spec has no test vectors"
    for tv in spec.parsed.test_vectors:
        msg = msg_by_name[tv.message]
        payload_cls = _payload_class_for(msg, namespace)
        encodings = [f.encoding for f in msg.fields]
        _run_test_vector(payload_cls, tv, encodings)  # raises on any mismatch


# ---------------------------------------------------------------------------
# Reference correctness on the demo happy paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_echo_reference_replies_and_records() -> None:
    spec = get_spec("echo").parsed
    steps = [
        Send("A", "ECHO_REQUEST", {"payload": "hi"}),
        Checkpoint("A", "received_responses", ["hi!"]),
        Checkpoint("B", "received_responses", []),
    ]
    trace = await run_scenario(
        reference_overlay("echo"), reference_overlay("echo"), steps, spec=spec)
    assert trace.passed, trace.failures()


@pytest.mark.asyncio
async def test_content_reference_search_matches_and_caches() -> None:
    spec = get_spec("content_community").parsed
    catalog = _load_catalog()
    calculus = next(e for e in catalog if "calculus" in e["name"].lower())
    expected = [{k: calculus[k] for k in ("magnet", "name", "size", "mime")}]
    steps = [
        Seed("B", "local_index", catalog),
        Send("A", "SEARCH_REQUEST", {"query": "calculus"}),
        Checkpoint("A", "response_cache", expected),
    ]
    trace = await run_scenario(
        reference_overlay("content_community"),
        reference_overlay("content_community"), steps, spec=spec)
    assert trace.passed, trace.failures()


@pytest.mark.asyncio
async def test_payment_reference_dedup_and_append() -> None:
    """First-wins dedup keyed by sender (a second request from the same peer is
    dropped, keeping the first value), plus the offer/notify/decline appends."""
    spec = get_spec("payment").parsed
    steps = [
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 5000, "memo": "rent"}),
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 9999, "memo": "second"}),  # dup
        Send("A", "PAYMENT_OFFER", {"amount_sats": 2500, "memo": "gift"}),
        Send("A", "PAYMENT_NOTIFY", {"amount_sats": 5000, "txid": "deadbeef"}),
        Send("A", "PAYMENT_DECLINE", {"reason": "broke"}),
        Checkpoint("B", "pending_requests", {"A": {"amount_sats": 5000, "memo": "rent"}}),
        Checkpoint("B", "received_offers", [{"amount_sats": 2500, "memo": "gift"}]),
        Checkpoint("B", "received_payments", [{"amount_sats": 5000, "txid": "deadbeef"}]),
        Checkpoint("B", "declined", [{"reason": "broke"}]),
    ]
    trace = await run_scenario(
        reference_overlay("payment"), reference_overlay("payment"), steps, spec=spec)
    assert trace.passed, trace.failures()


@pytest.mark.asyncio
async def test_file_transfer_reference_reassembles_and_verifies() -> None:
    """A multi-chunk transfer: manifest + 3 chunks reassemble in order, the
    sha256 matches, the fetcher marks the transfer ok, and the seeder records the
    verdict — the demo's ``torrent_progress_gte_1`` behaviour."""
    spec = get_spec("file_transfer").parsed
    blob = bytes(i % 251 for i in range(600))  # 600 bytes -> 3 chunks of 256/256/88
    cid = hashlib.sha1(blob).digest()[:20]
    steps = [
        Seed("B", "served", {cid: blob}),
        Send("A", "FETCH_REQUEST", {"content_id": cid.hex()}),
        Checkpoint("A", "transfers", {cid.hex(): {"complete": True, "ok": True}},
                   project=_transfer_status),
        Checkpoint("B", "completed", {cid.hex(): True}),
    ]
    trace = await run_scenario(
        reference_overlay("file_transfer"),
        reference_overlay("file_transfer"), steps, spec=spec)
    assert trace.passed, trace.failures()


# ---------------------------------------------------------------------------
# Negative control — the comparator must catch a real divergence
# ---------------------------------------------------------------------------

class _BrokenPaymentCommunity(payment_ref.PaymentReferenceCommunity):
    """Payment reference with the de-duplication removed (last write wins). Used
    only to prove the gate has teeth: it must FAIL the dedup checkpoint."""

    @lazy_wrapper(payment_ref.PaymentRequestPayload)
    def on_payment_request(self, peer, payload) -> None:  # type: ignore[override]
        self.pending_requests[peer.mid.hex()] = {
            "amount_sats": payload.amount_sats,
            "memo": payload.memo.decode("utf-8"),
        }


@pytest.mark.asyncio
async def test_negative_control_broken_dedup_is_caught() -> None:
    spec = get_spec("payment").parsed
    broken_b = LoadedOverlay(
        community_cls=_BrokenPaymentCommunity, namespace=vars(payment_ref))
    steps = [
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 5000, "memo": "rent"}),
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 9999, "memo": "second"}),
        Checkpoint("B", "pending_requests", {"A": {"amount_sats": 5000, "memo": "rent"}}),
    ]
    trace = await run_scenario(reference_overlay("payment"), broken_b, steps, spec=spec)
    assert not trace.passed
    failed = trace.failures()
    assert len(failed) == 1 and failed[0].attr == "pending_requests"
    # broken keeps the SECOND (last) write, exposing the missing first-wins rule
    assert failed[0].actual == {"A": {"amount_sats": 9999, "memo": "second"}}


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reference_run_is_deterministic() -> None:
    spec = get_spec("echo").parsed
    steps = [
        Send("A", "ECHO_REQUEST", {"payload": "ping"}),
        Checkpoint("A", "received_responses", ["ping!"]),
    ]
    trace_1 = await run_scenario(
        reference_overlay("echo"), reference_overlay("echo"), steps, spec=spec)
    trace_2 = await run_scenario(
        reference_overlay("echo"), reference_overlay("echo"), steps, spec=spec)
    assert trace_1.checks == trace_2.checks


# ---------------------------------------------------------------------------
# Comparator (I4) unit tests
# ---------------------------------------------------------------------------

def test_canonicalize_remaps_peer_mid_keys() -> None:
    mid_to_role = {"aa" * 20: "A", "bb" * 20: "B"}
    raw = {"aa" * 20: {"amount_sats": 5000, "memo": "rent"}}
    assert canonicalize(raw, mid_to_role=mid_to_role) == {
        "A": {"amount_sats": 5000, "memo": "rent"}}


def test_canonicalize_normalizes_nested_collections_full_value() -> None:
    mid_to_role: dict[str, str] = {}
    raw = [{"name": "x", "size": 1}, {"name": "y", "size": 2}]
    # full value preserved (no len() reduction) and list order kept
    assert canonicalize(raw, mid_to_role=mid_to_role) == raw
    # a different value must NOT compare equal
    assert canonicalize(raw, mid_to_role=mid_to_role) != [{"name": "x", "size": 1}]


def test_canonicalize_coerces_bytearray_to_bytes() -> None:
    assert canonicalize(bytearray(b"\x01\x02"), mid_to_role={}) == b"\x01\x02"
