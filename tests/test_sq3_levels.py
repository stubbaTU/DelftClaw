"""The functional level has teeth: it passes a correct compile and FAILS one
whose handler logic is broken, even though the broken one still compiles and
passes its own wire vectors.

This is the evidence that 100% functional agreement is a real result, not a
lenient metric: the contract projection drops only metadata (timestamps, tags,
field names), never the logic-bearing fields, so a wrong dedup, a missing
truncation, or a skipped hash check all surface as functional disagreement.
"""

from __future__ import annotations

import pytest

from ipv8.lazy_community import lazy_wrapper

from experiments.levels import _agree_both, _conformant_both, _golden
from experiments.live_interop import LoadedOverlay
from experiments.oracle import reference_overlay
from experiments.references import content_ref, file_transfer_ref, payment_ref


# --- Negative controls: each breaks exactly one piece of handler logic --------

class _BrokenPaymentNoDedup(payment_ref.PaymentReferenceCommunity):
    """Last-write-wins instead of first-wins de-duplication."""

    @lazy_wrapper(payment_ref.PaymentRequestPayload)
    def on_payment_request(self, peer, payload) -> None:  # type: ignore[override]
        self.pending_requests[peer.mid.hex()] = {
            "amount_sats": payload.amount_sats, "memo": payload.memo.decode("utf-8")}


class _BrokenContentNoTruncate(content_ref.ContentReferenceCommunity):
    """Forgets to cap results at MAX_RESULTS."""

    @lazy_wrapper(content_ref.SearchRequestPayload)
    def on_search_request(self, peer, payload) -> None:  # type: ignore[override]
        import msgpack
        query = payload.query.decode("utf-8").lower()
        matches = []
        for entry in self.local_index:
            name = str(entry.get("name", "")).lower()
            tags = [str(t).lower() for t in entry.get("tags", []) or []]
            if query == "" or query in name or any(query in t for t in tags):
                matches.append({k: entry.get(k) for k in ("magnet", "name", "size", "mime")})
        self.ez_send(peer, content_ref.SearchResponsePayload(msgpack.packb(matches, use_bin_type=True)))


class _BrokenFtNoVerify(file_transfer_ref.FileTransferReferenceCommunity):
    """Marks a completed transfer ok without checking the hash."""

    @lazy_wrapper(file_transfer_ref.ChunkPayload)
    def on_chunk(self, peer, payload) -> None:  # type: ignore[override]
        transfer = self.transfers.get(payload.content_id.hex())
        if transfer is None or transfer["complete"]:
            return
        if payload.seq >= transfer["total"]:
            return
        transfer["chunks"][payload.seq] = payload.data
        if len(transfer["chunks"]) == transfer["total"]:
            transfer["ok"] = True  # BUG: no sha256 verification
            transfer["complete"] = True
            self.ez_send(peer, file_transfer_ref.FetchCompletePayload(payload.content_id, True))


_BROKEN = [
    ("payment", _BrokenPaymentNoDedup, payment_ref),
    ("content_community", _BrokenContentNoTruncate, content_ref),
    ("file_transfer", _BrokenFtNoVerify, file_transfer_ref),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("rung,broken_cls,module", _BROKEN, ids=[b[0] for b in _BROKEN])
async def test_functional_level_catches_broken_logic(rung, broken_cls, module) -> None:
    """A compile with one broken handler must FAIL functional conformance — proof
    the metric is not lenient. (It also fails representationally, but the point is
    that the *functional* projection does not hide the logic error.)"""
    golden = await _golden(rung, 0.4)
    broken = LoadedOverlay(community_cls=broken_cls, namespace=vars(module))
    func_ok, repr_ok = await _conformant_both(broken, rung, golden, settle_max=0.4)
    assert func_ok is False, f"{rung}: functional level did NOT catch the broken logic"
    assert repr_ok is False


@pytest.mark.asyncio
@pytest.mark.parametrize("rung", ["echo", "content_community", "payment", "file_transfer"])
async def test_functional_level_passes_correct_compile(rung) -> None:
    """Sanity: the reference reaches its own functional behaviour (and a second
    instance interoperates with it), so the metric is not failing everything."""
    golden = await _golden(rung, 0.4)
    func_ok, _ = await _conformant_both(reference_overlay(rung), rung, golden, settle_max=0.4)
    assert func_ok is True
    interop_func, _ = await _agree_both(reference_overlay(rung), reference_overlay(rung), rung)
    assert interop_func is True


@pytest.mark.asyncio
async def test_functional_executes_the_loaded_compiled_source() -> None:
    """The measurement runs the loaded COMPILED SOURCE on live nodes, not a stub
    or the reference. We load two echo source *strings* through the production
    ``load_overlay`` path (the same path the 360 saved compiles take): a correct
    one passes functional, and one whose reply logic is broken fails it. A static
    or stubbed measurement could not tell them apart."""
    from _echo_sources import BROKEN_BEHAVIOUR, ECHO_CID, GOOD
    from experiments.live_interop import load_overlay

    golden = await _golden("echo", 0.4)
    good = load_overlay(GOOD, ECHO_CID)              # appends "!"
    broken = load_overlay(BROKEN_BEHAVIOUR, ECHO_CID)  # appends "?" instead

    # The loaded class is the compiled one (sandbox namespace), not the reference.
    assert good.community_cls.__module__ == "overlay_sandbox"

    good_ok, _ = await _conformant_both(good, "echo", golden, settle_max=0.4)
    broken_ok, _ = await _conformant_both(broken, "echo", golden, settle_max=0.4)
    assert good_ok is True
    assert broken_ok is False   # editing the reply logic flips the result -> live exec
