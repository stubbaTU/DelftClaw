"""Step 2 gate: the conformance batteries pass on the references and catch
divergence.

Offline. Every Tier-1 + Tier-2 scenario in ``sq3.scenarios`` must pass when both
(or all three) roles run the hand-written reference — that pins the reference as
correct on the full battery, including the out-of-order / duplicate / corrupted
chunk paths and the per-requester payment keying. The negative controls then
prove each hard behaviour is actually *tested*: a reference with that one
behaviour broken fails exactly the scenario built to catch it.
"""

from __future__ import annotations

import pytest

from ipv8.lazy_community import lazy_wrapper

from experiments.fixtures import get_spec
from experiments.oracle import ROLE_TO_IDX, LoadedOverlay, reference_overlay, run_scenario
from experiments.references import content_ref, file_transfer_ref, payment_ref
from experiments.scenarios import ALL_SCENARIOS, Scenario


async def _run(scenario: Scenario, overrides: dict[str, LoadedOverlay] | None = None):
    """Run a scenario with the reference in every role, except roles named in
    ``overrides`` (used to inject a deliberately broken implementation)."""
    spec = get_spec(scenario.rung).parsed
    impls = [reference_overlay(scenario.rung) for _ in range(scenario.n_roles)]
    for role, overlay in (overrides or {}).items():
        impls[ROLE_TO_IDX[role]] = overlay
    extra = impls[2:] or None
    return await run_scenario(impls[0], impls[1], scenario.steps, spec=spec, extra=extra)


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=lambda s: s.name)
async def test_reference_passes_every_scenario(scenario: Scenario) -> None:
    trace = await _run(scenario)
    assert trace.passed, trace.failures()


# ---------------------------------------------------------------------------
# Negative controls — one broken behaviour, one failing scenario each
# ---------------------------------------------------------------------------

class _BrokenContentNoTruncate(content_ref.ContentReferenceCommunity):
    """Content reference that forgets to truncate to MAX_RESULTS."""

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
    """File-transfer reference that marks every completed transfer ok without
    checking the hash."""

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


class _BrokenPaymentNoDedup(payment_ref.PaymentReferenceCommunity):
    """Payment reference without first-wins de-duplication (last write wins)."""

    @lazy_wrapper(payment_ref.PaymentRequestPayload)
    def on_payment_request(self, peer, payload) -> None:  # type: ignore[override]
        self.pending_requests[peer.mid.hex()] = {
            "amount_sats": payload.amount_sats, "memo": payload.memo.decode("utf-8")}


def _scenario(name: str) -> Scenario:
    return next(s for s in ALL_SCENARIOS if s.name == name)


@pytest.mark.asyncio
async def test_broken_truncation_fails_truncation_scenario() -> None:
    broken = LoadedOverlay(community_cls=_BrokenContentNoTruncate, namespace=vars(content_ref))
    trace = await _run(_scenario("content_truncates_to_max_results"), overrides={"B": broken})
    assert not trace.passed


@pytest.mark.asyncio
async def test_broken_hash_verify_fails_corruption_scenario() -> None:
    broken = LoadedOverlay(community_cls=_BrokenFtNoVerify, namespace=vars(file_transfer_ref))
    # A is the fetcher (runs on_chunk) in the corruption scenario.
    trace = await _run(_scenario("ft_corrupted_chunk_fails_verification"), overrides={"A": broken})
    assert not trace.passed


@pytest.mark.asyncio
async def test_broken_dedup_fails_multi_requester_scenario() -> None:
    broken = LoadedOverlay(community_cls=_BrokenPaymentNoDedup, namespace=vars(payment_ref))
    trace = await _run(_scenario("payment_keys_two_distinct_requesters"), overrides={"B": broken})
    assert not trace.passed
