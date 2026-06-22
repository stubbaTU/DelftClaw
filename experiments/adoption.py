"""Flow B — adoption interop, the authoring arm's reference-free agreement test.

The deployed evolution step has one agent author a protocol and a *different*
agent adopt it: fetch the document, compile it with its own model, and
interoperate. There is no human reference, so conformance-against-an-oracle is
unavailable. Instead each compilation serves as the other's oracle: the question
is whether the adopter, fed the author's messages, reaches the same observable
state the author's own implementation reaches on the same input.

Concretely, ``adoption_interop`` runs an auto-generated *boundary battery*
(every message the document declares, each field swept across its encoding's
empty / min / max values, sent both directions, plus a duplicate probe) twice —
once author-against-author (the de-facto behaviour of the document, as its author
realises it) and once author-against-adopter — and requires the *full* observable
state of *both* nodes to match between the two runs. Pushing demanding inputs
rather than the model's own sample is what makes the check strict: two compiles
that agree on the easy case but diverge at a boundary (an empty string, a maximum
integer, a repeated message) are caught here. Reading both nodes is essential: a
divergence in a reply handler shows up only on the side that receives the reply,
the failure mode the old length-equality ``behaves_alike`` could not see.

Because the comparator is identity-aware (``sq3.oracle.canonicalize`` remaps peer
mids to role labels), the two runs' different ephemeral peer ids do not defeat
the comparison of mid-keyed state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from protocol.compiler import MessageDef, ParsedOverlay
from experiments.boundaries import boundary_payloads
from experiments.driver import ProgrammableNetwork
from experiments.live_interop import LoadedOverlay
from experiments.oracle import canonicalize

_SENTINEL = object()  # marks a runtime-state slot a compile never declared


async def _safe_send(net: ProgrammableNetwork, src: int, dst: int,
                     message: MessageDef, fields: dict[str, Any]) -> None:
    """Deliver one crafted message, swallowing a pack/dispatch failure. An input
    that will not even encode is itself an observation (the receiver's state just
    will not change); it must not abort the whole exchange."""
    try:
        await net.send(src, dst, message, fields)
    except Exception:  # noqa: BLE001 — undeliverable input is a measured outcome
        pass


async def _exchange_states(
    node0: LoadedOverlay, node1: LoadedOverlay, parsed: ParsedOverlay, community_id: bytes,
) -> dict[str, dict[str, Any]]:
    """Drive a *boundary battery* between two compiles and return both nodes'
    canonicalized runtime state, keyed by role.

    For every message the document declares we send the full set of
    ``boundary_payloads`` (each field swept across its encoding's empty / min /
    max values) in both directions, then re-send the baseline once more — a
    duplicate probe that exposes dedup-vs-accumulate divergence. Two compiles
    that agree only on the model's own sample but diverge at a boundary are
    caught here; the single-sample exchange this replaced could not see them."""
    slots = [s.name for s in parsed.runtime_state]

    async with ProgrammableNetwork([node0, node1], community_id) as net:
        mid_to_role = {
            net.nodes[0].my_peer.mid.hex(): "A",
            net.nodes[1].my_peer.mid.hex(): "B",
        }
        for m in parsed.messages:
            payloads = boundary_payloads(m)
            for fields in payloads:
                await _safe_send(net, 0, 1, m, fields)
                await _safe_send(net, 1, 0, m, fields)
            if payloads:  # duplicate probe: re-send the baseline
                await _safe_send(net, 0, 1, m, payloads[0])
                await _safe_send(net, 1, 0, m, payloads[0])

        def read(idx: int) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for s in slots:
                raw = getattr(net.nodes[idx].overlay, s, _SENTINEL)
                out[s] = "<undeclared>" if raw is _SENTINEL else canonicalize(raw, mid_to_role=mid_to_role)
            return out

        return {"A": read(0), "B": read(1)}


@dataclass(frozen=True)
class AdoptionResult:
    ok: bool
    detail: str | None = None


async def adoption_interop(
    author: LoadedOverlay,
    adopter: LoadedOverlay,
    parsed: ParsedOverlay,
    community_id: bytes,
) -> AdoptionResult:
    """Does ``adopter`` reproduce ``author``'s behaviour on the document they
    both compiled? Returns ``ok=True`` iff the author↔adopter exchange leaves
    both nodes in the same state the author↔author exchange does."""
    golden = await _exchange_states(author, author, parsed, community_id)
    trial = await _exchange_states(author, adopter, parsed, community_id)
    if golden == trial:
        return AdoptionResult(ok=True)
    diverged = [
        f"{role}.{slot}" for role in ("A", "B") for slot in golden[role]
        if golden[role][slot] != trial[role][slot]
    ]
    return AdoptionResult(ok=False, detail="diverged at " + ", ".join(diverged))
