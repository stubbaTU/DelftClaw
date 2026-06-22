"""The SQ3 conformance batteries — scripted scenarios per protocol rung.

Each scenario is a faithful, deterministic exercise of one descriptor's
behaviour, in two tiers:

  * **Tier 1 (demo path)** reproduces what the deployed agents actually do — an
    echo round trip, a catalogue search, a payment request, a chunked transfer to
    a verified file — and checks the goal-state the demo's stop-predicate keys on.
  * **Tier 2 (edge battery)** drives the behaviours the encoding tables cannot
    express and where independent compilations most plausibly diverge: search
    ordering / truncation / no-match, per-requester de-duplication across two
    distinct senders, and out-of-order + duplicate + corrupted chunk delivery.

A scenario is a list of ``sq3.oracle`` steps plus the number of peer roles it
needs. The reference implementations pass every scenario (that is the Step 2
gate); a compiled overlay is conformant exactly insofar as it reproduces the same
checkpoints (Steps 4+).
"""

from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass

from experiments.fixtures import EXAMPLES_DIR
from experiments.oracle import Checkpoint, Seed, Send, Step

# Result projection: SEARCH_RESPONSE carries {magnet, name, size, mime} (no tags).
_RESULT_KEYS = ("magnet", "name", "size", "mime")


def _project(entry: dict) -> dict:
    return {k: entry.get(k) for k in _RESULT_KEYS}


def transfer_status(transfers: dict) -> dict:
    """Reduce a fetcher's ``transfers`` to the {complete, ok} verdict per id."""
    return {k: {"complete": v["complete"], "ok": v["ok"]} for k, v in transfers.items()}


# ---------------------------------------------------------------------------
# Deterministic fixture data
# ---------------------------------------------------------------------------

def _load_catalog() -> list[dict]:
    """The seeder's ``local_index`` from the real CC library CSV (size -> int,
    tags -> list[str]), exactly as the deployed seeder seeds it at boot."""
    path = EXAMPLES_DIR / "cc_library" / "content_catalog.csv"
    with open(path, newline="", encoding="utf-8") as handle:
        return [
            {
                "magnet": row["magnet"],
                "name": row["name"],
                "size": int(row["size"]),
                "mime": row["mime"],
                "tags": [t for t in row["tags"].split(";") if t],
            }
            for row in csv.DictReader(handle)
        ]


CATALOG = _load_catalog()
_CALCULUS = next(e for e in CATALOG if "calculus" in e["name"].lower())

# 60 synthetic entries to exercise truncation to MAX_RESULTS (50).
BIG_INDEX: list[dict] = [
    {"magnet": f"magnet:item{i}", "name": f"item_{i:03d}",
     "size": 100 + i, "mime": "text/plain", "tags": []}
    for i in range(60)
]

# Deliberately NON-alphabetical names sharing the substring "doc": the spec says
# results come back in declared (local_index) order, so a compile that sorts them
# diverges. Order: zebra, apple, mango (not a/m/z).
ORDER_INDEX: list[dict] = [
    {"magnet": "mZ", "name": "zebra_doc", "size": 1, "mime": "text/plain", "tags": []},
    {"magnet": "mA", "name": "apple_doc", "size": 2, "mime": "text/plain", "tags": []},
    {"magnet": "mM", "name": "mango_doc", "size": 3, "mime": "text/plain", "tags": []},
]
# Exactly 50 matching entries: the result must be all 50 (the boundary of the
# MAX_RESULTS=50 cap), in order.
EXACT_50: list[dict] = [
    {"magnet": f"x{i}", "name": f"doc_{i:03d}", "size": i, "mime": "text/plain", "tags": []}
    for i in range(50)
]

# A multi-chunk blob: 600 bytes -> 3 chunks of 256/256/88.
FT_BLOB = bytes(i % 251 for i in range(600))
FT_CID = hashlib.sha1(FT_BLOB).digest()[:20]
FT_HASH = hashlib.sha256(FT_BLOB).digest()
FT_CHUNKS = [FT_BLOB[i:i + 256] for i in range(0, len(FT_BLOB), 256)]
FT_TOTAL = len(FT_CHUNKS)
UNKNOWN_CID = bytes(20)


@dataclass(frozen=True)
class Scenario:
    """One scripted conformance exercise."""
    name: str
    rung: str
    n_roles: int
    steps: list[Step]


# ---------------------------------------------------------------------------
# echo
# ---------------------------------------------------------------------------

_ECHO: list[Scenario] = [
    Scenario("echo_happy", "echo", 2, [
        Send("A", "ECHO_REQUEST", {"payload": "hi"}, dst_role="B"),
        Checkpoint("A", "received_responses", ["hi!"]),
        Checkpoint("B", "received_responses", []),
    ]),
    Scenario("echo_empty_and_unicode", "echo", 2, [
        Send("A", "ECHO_REQUEST", {"payload": ""}, dst_role="B"),
        Send("A", "ECHO_REQUEST", {"payload": "café"}, dst_role="B"),
        Checkpoint("A", "received_responses", ["!", "café!"]),
    ]),
    # Edge: three replies must accumulate in arrival order (not sorted/deduped).
    Scenario("echo_accumulates_in_order", "echo", 2, [
        Send("A", "ECHO_REQUEST", {"payload": "gamma"}, dst_role="B"),
        Send("A", "ECHO_REQUEST", {"payload": "alpha"}, dst_role="B"),
        Send("A", "ECHO_REQUEST", {"payload": "alpha"}, dst_role="B"),
        Checkpoint("A", "received_responses", ["gamma!", "alpha!", "alpha!"]),
    ]),
]


# ---------------------------------------------------------------------------
# content_community
# ---------------------------------------------------------------------------

_CONTENT: list[Scenario] = [
    Scenario("content_match_calculus", "content_community", 2, [
        Seed("B", "local_index", CATALOG),
        Send("A", "SEARCH_REQUEST", {"query": "calculus"}, dst_role="B"),
        Checkpoint("A", "response_cache", [_project(_CALCULUS)]),
    ]),
    Scenario("content_empty_returns_full_index", "content_community", 2, [
        Seed("B", "local_index", CATALOG),
        Send("A", "SEARCH_REQUEST", {"query": ""}, dst_role="B"),
        Checkpoint("A", "response_cache", [_project(e) for e in CATALOG]),
    ]),
    Scenario("content_no_match_returns_empty", "content_community", 2, [
        Seed("B", "local_index", CATALOG),
        Send("A", "SEARCH_REQUEST", {"query": "zzz-no-such-thing"}, dst_role="B"),
        Checkpoint("A", "response_cache", []),
    ]),
    Scenario("content_truncates_to_max_results", "content_community", 2, [
        Seed("B", "local_index", BIG_INDEX),
        Send("A", "SEARCH_REQUEST", {"query": ""}, dst_role="B"),
        Checkpoint("A", "response_cache", [_project(e) for e in BIG_INDEX[:50]]),
    ]),
    # Edge: the match is case-insensitive, so an upper-case query still finds the
    # lower-case title.
    Scenario("content_match_is_case_insensitive", "content_community", 2, [
        Seed("B", "local_index", CATALOG),
        Send("A", "SEARCH_REQUEST", {"query": "CALCULUS"}, dst_role="B"),
        Checkpoint("A", "response_cache", [_project(_CALCULUS)]),
    ]),
    # Edge: the query matches a free-text TAG ("math"), not the name — a compile
    # that searches names only returns nothing.
    Scenario("content_matches_on_tags", "content_community", 2, [
        Seed("B", "local_index", CATALOG),
        Send("A", "SEARCH_REQUEST", {"query": "math"}, dst_role="B"),
        Checkpoint("A", "response_cache", [_project(_CALCULUS)]),
    ]),
    # Edge: results come back in declared order, not sorted.
    Scenario("content_preserves_declared_order", "content_community", 2, [
        Seed("B", "local_index", ORDER_INDEX),
        Send("A", "SEARCH_REQUEST", {"query": "doc"}, dst_role="B"),
        Checkpoint("A", "response_cache", [_project(e) for e in ORDER_INDEX]),
    ]),
    # Edge: exactly MAX_RESULTS matches must all be returned (the cap boundary).
    Scenario("content_returns_exactly_max", "content_community", 2, [
        Seed("B", "local_index", EXACT_50),
        Send("A", "SEARCH_REQUEST", {"query": "doc"}, dst_role="B"),
        Checkpoint("A", "response_cache", [_project(e) for e in EXACT_50]),
    ]),
]


# ---------------------------------------------------------------------------
# payment
# ---------------------------------------------------------------------------

_PAYMENT: list[Scenario] = [
    Scenario("payment_dedup_and_appends", "payment", 2, [
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 5000, "memo": "rent"}, dst_role="B"),
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 9999, "memo": "second"}, dst_role="B"),
        Send("A", "PAYMENT_OFFER", {"amount_sats": 2500, "memo": "gift"}, dst_role="B"),
        Send("A", "PAYMENT_NOTIFY", {"amount_sats": 5000, "txid": "deadbeef"}, dst_role="B"),
        Send("A", "PAYMENT_DECLINE", {"reason": "broke"}, dst_role="B"),
        Checkpoint("B", "pending_requests", {"A": {"amount_sats": 5000, "memo": "rent"}}),
        Checkpoint("B", "received_offers", [{"amount_sats": 2500, "memo": "gift"}]),
        Checkpoint("B", "received_payments", [{"amount_sats": 5000, "txid": "deadbeef"}]),
        Checkpoint("B", "declined", [{"reason": "broke"}]),
    ]),
    Scenario("payment_keys_two_distinct_requesters", "payment", 3, [
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 5000, "memo": "rent"}, dst_role="B"),
        Send("C", "PAYMENT_REQUEST", {"amount_sats": 3000, "memo": "food"}, dst_role="B"),
        Send("A", "PAYMENT_REQUEST", {"amount_sats": 9999, "memo": "dup"}, dst_role="B"),  # A dup
        Checkpoint("B", "pending_requests", {
            "A": {"amount_sats": 5000, "memo": "rent"},
            "C": {"amount_sats": 3000, "memo": "food"},
        }),
    ]),
    # Edge: a NOTIFY with no prior request is still recorded (the handler does not
    # require a matching pending request) and leaves pending_requests empty.
    Scenario("payment_notify_without_request", "payment", 2, [
        Send("A", "PAYMENT_NOTIFY", {"amount_sats": 7000, "txid": "abc123"}, dst_role="B"),
        Checkpoint("B", "received_payments", [{"amount_sats": 7000, "txid": "abc123"}]),
        Checkpoint("B", "pending_requests", {}),
    ]),
    # Edge: repeated offers and declines accumulate in order (lists, not deduped).
    Scenario("payment_offers_and_declines_accumulate", "payment", 2, [
        Send("A", "PAYMENT_OFFER", {"amount_sats": 100, "memo": "a"}, dst_role="B"),
        Send("A", "PAYMENT_OFFER", {"amount_sats": 100, "memo": "a"}, dst_role="B"),
        Send("A", "PAYMENT_DECLINE", {"reason": "no"}, dst_role="B"),
        Send("A", "PAYMENT_DECLINE", {"reason": "no"}, dst_role="B"),
        Checkpoint("B", "received_offers",
                   [{"amount_sats": 100, "memo": "a"}, {"amount_sats": 100, "memo": "a"}]),
        Checkpoint("B", "declined", [{"reason": "no"}, {"reason": "no"}]),
    ]),
]


# ---------------------------------------------------------------------------
# file_transfer  (A = fetcher, B = seeder)
# ---------------------------------------------------------------------------

def _manifest(seq_order: list[int], chunks: list[bytes]) -> list[Step]:
    """Seeder B hand-delivers a manifest then chunks in ``seq_order`` (so the
    fetcher's out-of-order tolerance is driven explicitly), each carrying
    ``chunks[seq]``."""
    steps: list[Step] = [
        Send("B", "FETCH_MANIFEST", {
            "content_id": FT_CID.hex(), "total_chunks": FT_TOTAL,
            "content_hash": FT_HASH.hex()}, dst_role="A"),
    ]
    for seq in seq_order:
        steps.append(Send("B", "CHUNK", {
            "content_id": FT_CID.hex(), "seq": seq, "data": chunks[seq]}, dst_role="A"))
    return steps


def _ft_manifest_send() -> Step:
    return Send("B", "FETCH_MANIFEST", {
        "content_id": FT_CID.hex(), "total_chunks": FT_TOTAL,
        "content_hash": FT_HASH.hex()}, dst_role="A")


def _ft_chunk_send(seq: int) -> Step:
    return Send("B", "CHUNK", {
        "content_id": FT_CID.hex(), "seq": seq, "data": FT_CHUNKS[seq]}, dst_role="A")


_FT: list[Scenario] = [
    Scenario("ft_happy_seeder_streams", "file_transfer", 2, [
        Seed("B", "served", {FT_CID: FT_BLOB}),
        Send("A", "FETCH_REQUEST", {"content_id": FT_CID.hex()}, dst_role="B"),
        Checkpoint("A", "transfers", {FT_CID.hex(): {"complete": True, "ok": True}},
                   project=transfer_status),
        Checkpoint("B", "completed", {FT_CID.hex(): True}),
    ]),
    Scenario("ft_out_of_order_with_duplicate", "file_transfer", 2,
             _manifest([2, 0, 2, 1], FT_CHUNKS) + [  # seq 2 arrives twice, then 1 completes
                 Checkpoint("A", "transfers", {FT_CID.hex(): {"complete": True, "ok": True}},
                            project=transfer_status),
                 Checkpoint("B", "completed", {FT_CID.hex(): True}),
             ]),
    Scenario("ft_corrupted_chunk_fails_verification", "file_transfer", 2,
             _manifest([0, 1, 2], [FT_CHUNKS[0], bytes(len(FT_CHUNKS[1])), FT_CHUNKS[2]]) + [
                 Checkpoint("A", "transfers", {FT_CID.hex(): {"complete": True, "ok": False}},
                            project=transfer_status),
                 Checkpoint("B", "completed", {FT_CID.hex(): False}),
             ]),
    Scenario("ft_unknown_content_is_dropped", "file_transfer", 2, [
        Seed("B", "served", {FT_CID: FT_BLOB}),
        Send("A", "FETCH_REQUEST", {"content_id": UNKNOWN_CID.hex()}, dst_role="B"),
        Checkpoint("A", "transfers", {}),
        Checkpoint("B", "completed", {}),
    ]),
    # Edge: a repeated manifest resets the transfer; the second round of chunks
    # must still reassemble and verify.
    Scenario("ft_duplicate_manifest_resets", "file_transfer", 2, [
        _ft_manifest_send(),
        _ft_chunk_send(0),
        _ft_manifest_send(),                 # reset: clears the partial buffer
        _ft_chunk_send(0), _ft_chunk_send(1), _ft_chunk_send(2),
        Checkpoint("A", "transfers", {FT_CID.hex(): {"complete": True, "ok": True}},
                   project=transfer_status),
        Checkpoint("B", "completed", {FT_CID.hex(): True}),
    ]),
    # Edge: a chunk that arrives before any manifest has no transfer and is
    # dropped; it must not corrupt the transfer that the manifest then starts.
    Scenario("ft_chunk_before_manifest_is_dropped", "file_transfer", 2, [
        _ft_chunk_send(0),                   # no transfer yet -> dropped
        _ft_manifest_send(),
        _ft_chunk_send(0), _ft_chunk_send(1), _ft_chunk_send(2),
        Checkpoint("A", "transfers", {FT_CID.hex(): {"complete": True, "ok": True}},
                   project=transfer_status),
        Checkpoint("B", "completed", {FT_CID.hex(): True}),
    ]),
]


ALL_SCENARIOS: list[Scenario] = _ECHO + _CONTENT + _PAYMENT + _FT


def scenarios_for(rung: str) -> list[Scenario]:
    return [s for s in ALL_SCENARIOS if s.rung == rung]
